"""
Remote Command Server
======================
Listens on an SSL/TLS-encrypted TCP port, authenticates clients with a
PBKDF2-hashed password, and executes shell commands with the privileges of
the service account (LocalSystem = full admin when installed as a service).

Security features
-----------------
  • TLS 1.2+ encryption on every connection
  • PBKDF2-HMAC-SHA256 password verification (hash stored in config.json)
  • Per-IP brute-force protection:
      – 5 consecutive wrong passwords  →  1-minute temporary block
      – 3rd temporary block (15 total wrong attempts)  →  permanent blacklist
  • Permanent blacklist persisted to blacklist.json

Windows Service usage (run as Administrator)
--------------------------------------------
    python server.py --startup auto install   # install + set to auto-start
    python server.py start                    # start the service
    python server.py stop                     # stop the service
    python server.py restart                  # restart
    python server.py remove                   # uninstall

Standalone / debug usage
------------------------
    python server.py debug    # run in foreground via pywin32 debug mode
    python server.py run      # run in foreground without pywin32
"""

import base64
import datetime
import hashlib
import hmac
import json
import locale
import logging
import os
import queue
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid

# Set by SvcStop or KeyboardInterrupt – all loops check this to know when to quit.
_stop_flag = threading.Event()

# ---------------------------------------------------------------------------
# Ensure the directory that contains this script is on sys.path so that the
# security module can always be found, even when launched by SCM.
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from security import SecurityManager   # noqa: E402 (after sys.path manipulation)

CONFIG_FILE       = os.path.join(BASE_DIR, "config.json")
STATS_FILE        = os.path.join(BASE_DIR, "server_stats.json")
PBKDF2_ITERATIONS = 200_000

# ---------------------------------------------------------------------------
# Live stats – written to STATS_FILE so watermark.py can display them
# ---------------------------------------------------------------------------
_stats_lock = threading.Lock()
_stats: dict = {
    "active_clients":    0,
    "total_connections": 0,
    "auth_failures":     0,
    "started_at":        "",
    "last_ip":           "",
}


def _init_stats() -> None:
    with _stats_lock:
        _stats["active_clients"]    = 0
        _stats["total_connections"] = 0
        _stats["auth_failures"]     = 0
        _stats["started_at"]        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _stats["last_ip"]           = ""
    _write_stats()


def _write_stats() -> None:
    try:
        with _stats_lock:
            snapshot = dict(_stats)
        with open(STATS_FILE, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("RemoteCommandServer")
    if logger.handlers:          # already configured (e.g. called twice in same process)
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger


def _verify_password(plaintext: str, stored_hash: str, salt_b64: str) -> bool:
    salt     = base64.b64decode(salt_b64)
    dk       = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt,
                                   PBKDF2_ITERATIONS)
    computed = base64.b64encode(dk).decode()
    return hmac.compare_digest(computed, stored_hash)


# ---------------------------------------------------------------------------
# Wire protocol  –  4-byte big-endian length prefix + UTF-8 JSON payload
# ---------------------------------------------------------------------------
MAX_MSG_BYTES = 10 * 1024 * 1024   # 10 MB


def _send(conn: ssl.SSLSocket, msg: dict) -> None:
    data   = json.dumps(msg).encode("utf-8")
    header = struct.pack(">I", len(data))
    conn.sendall(header + data)


def _recv(conn: ssl.SSLSocket):
    raw = _recv_exactly(conn, 4)
    if raw is None:
        return None
    length = struct.unpack(">I", raw)[0]
    if length == 0 or length > MAX_MSG_BYTES:
        return None
    payload = _recv_exactly(conn, length)
    if payload is None:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _recv_exactly(conn, n: int):
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Simple streaming shell
# ---------------------------------------------------------------------------
_SYS_ENC = locale.getpreferredencoding(False) or "cp850"

def _run_shell(conn: ssl.SSLSocket, ip: str, logger: logging.Logger):
    """Spawns a cmd.exe process and blindly streams IO back and forth."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        "cmd.exe",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd="C:\\",
        shell=False,
        creationflags=flags,
    )

    def output_relay():
        try:
            while True:
                # read1 is crucial here to flush partial lines like prompts
                chunk = proc.stdout.read1(4096)
                if not chunk:
                    break
                _send(conn, {"type": "output_chunk", "data": chunk.decode(_SYS_ENC, errors="replace")})
        except Exception:
            pass
        finally:
            try:
                _send(conn, {"type": "command_done", "returncode": -1, "cwd": ""})
            except Exception:
                pass

    t = threading.Thread(target=output_relay, daemon=True, name=f"shell-output-{ip}")
    t.start()

    try:
        while True:
            msg = _recv(conn)
            if msg is None:
                logger.info(f"Connection closed by {ip}")
                break

            mtype = msg.get("type")

            if mtype == "quit":
                _send(conn, {"type": "bye"})
                break

            elif mtype in ("command", "input"):
                data = msg.get("cmd", "") if mtype == "command" else msg.get("data", "")
                if mtype == "command" and not data.endswith("\n"):
                    data += "\n"
                
                # Normalize line endings to \r\n for Windows apps
                if data:
                    data = data.replace("\r\n", "\n").replace("\n", "\r\n")
                    try:
                        proc.stdin.write(data.encode(_SYS_ENC, errors="replace"))
                        proc.stdin.flush()
                    except Exception:
                        break
            else:
                _send(conn, {"type": "error", "message": f"Unknown message type: {mtype!r}"})
    finally:
        try:
            proc.kill()
        except Exception:
            pass



# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def _handle_client(conn: ssl.SSLSocket, addr: tuple,
                   config: dict, security: SecurityManager,
                   logger: logging.Logger) -> None:
    ip = addr[0]
    authenticated = False
    logger.info(f"Connection from {ip}:{addr[1]}")
    try:
        # --- Gate: is this IP blocked? ------------------------------------
        blocked, reason = security.is_blocked(ip)
        if blocked:
            logger.warning(f"Rejected {ip}: {reason}")
            _send(conn, {"type": "error", "message": f"Access denied: {reason}"})
            return

        conn.settimeout(30)

        # --- Authentication --------------------------------------------
        msg = _recv(conn)
        if not msg or msg.get("type") != "auth":
            logger.warning(f"Invalid handshake from {ip}")
            return

        if not config.get("password_hash") or not config.get("password_salt"):
            logger.error("Server password not configured. Run setup_password.py first.")
            _send(conn, {"type": "auth_result", "success": False,
                         "message": "Server not configured. Contact administrator."})
            return

        password = msg.get("password", "")

        if _verify_password(password, config["password_hash"], config["password_salt"]):
            authenticated = True
            with _stats_lock:
                _stats["active_clients"]    += 1
                _stats["total_connections"] += 1
                _stats["last_ip"]            = ip
            _write_stats()
            security.record_success(ip)
            logger.info(f"Auth success from {ip}")
            _send(conn, {"type": "auth_result", "success": True,
                         "message": "Authenticated. Welcome."})

            # --- Simple streaming shell ------------
            conn.settimeout(None)  # No timeout for interactive shell
            _run_shell(conn, ip, logger)

        else:
            # --- Auth failure – apply brute-force rules ---------------
            with _stats_lock:
                _stats["auth_failures"] += 1
            _write_stats()
            outcome       = security.record_failure(ip)
            failures      = security.get_failures(ip)
            block_count   = security.get_block_count(ip)

            if outcome == "permanent":
                logger.warning(f"[SECURITY] {ip} permanently blacklisted.")
                _send(conn, {"type": "auth_result", "success": False,
                             "message": "Too many failures. IP permanently blacklisted."})

            elif outcome == "temp_blocked":
                logger.warning(f"[SECURITY] {ip} temp-blocked "
                               f"(cycle {block_count}/{security.MAX_TEMP_BLOCKS if hasattr(security,'MAX_TEMP_BLOCKS') else 3}).")
                _send(conn, {"type": "auth_result", "success": False,
                             "message": (f"Too many failures. IP blocked for 1 minute. "
                                         f"(Cycle {block_count}/3 – "
                                         f"permanent ban after 3rd cycle.)")})

            else:
                remaining = 5 - failures
                logger.warning(f"[SECURITY] Auth failure from {ip} "
                               f"({failures}/5 in round, cycle {block_count}/3).")
                _send(conn, {"type": "auth_result", "success": False,
                             "message": (f"Invalid password. "
                                         f"{remaining} attempt(s) left before "
                                         f"1-minute block (cycle {block_count+1}/3).")})

    except socket.timeout:
        logger.info(f"Connection from {ip} timed out.")
    except Exception as exc:
        logger.error(f"Error handling {ip}: {exc}")
    finally:
        if authenticated:
            with _stats_lock:
                _stats["active_clients"] = max(0, _stats["active_clients"] - 1)
            _write_stats()
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Server core
# ---------------------------------------------------------------------------

class Server:
    def __init__(self, config: dict, security: SecurityManager,
                 logger: logging.Logger):
        self.config   = config
        self.security = security
        self.logger   = logger
        self.running  = False
        self._sock    = None

    def start(self) -> None:
        cert_file = os.path.join(BASE_DIR, self.config["cert_file"])
        key_file  = os.path.join(BASE_DIR, self.config["key_file"])

        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            raise FileNotFoundError(
                "SSL certificate/key not found. Run:  python gen_certs.py\n"
                f"  Expected cert : {cert_file}\n"
                f"  Expected key  : {key_file}"
            )

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        host = self.config["host"]
        port = self.config["port"]
        try:
            self._sock.bind((host, port))
        except OSError as exc:
            # Provide an actionable message when the port is already in use.
            # Port 443 conflicts are common when IIS or HTTP.sys is running.
            if exc.errno in (98, 10048):   # EADDRINUSE on Linux / Windows
                hint = ""
                if port == 443:
                    hint = (
                        "\n  Port 443 is already in use (IIS / HTTP.sys / WinRM)."
                        "\n  Options:"
                        "\n    1. Stop IIS:   net stop W3SVC"
                        "\n    2. Stop WinRM: net stop WinRM"
                        "\n    3. Use a different port – change 'port' in config.json"
                        "\n       to 8443 or another free port, then update the client."
                    )
                raise OSError(
                    f"Cannot bind to {host}:{port} – port is already in use.{hint}"
                ) from exc
            raise

        self._sock.listen(self.config.get("max_connections", 10))
        self._sock.settimeout(1.0)   # allow periodic stop checks

        self.running = True
        self.logger.info(
            f"Server listening on {host}:{port} (TLS) – "
            f"traffic on port {port} passes most firewalls without rule changes."
        )

        while self.running:
            try:
                raw_conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    self.logger.error("Socket accept error.")
                break

            try:
                ssl_conn = ssl_ctx.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as exc:
                self.logger.warning(f"TLS handshake failed from {addr[0]}: {exc}")
                try:
                    raw_conn.close()
                except Exception:
                    pass
                continue

            threading.Thread(
                target=_handle_client,
                args=(ssl_conn, addr, self.config, self.security, self.logger),
                daemon=True,
            ).start()

        self.logger.info("Server stopped.")

    def stop(self) -> None:
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


def _load_components() -> tuple:
    """Load config, create logger, SecurityManager, and return all three."""
    cfg      = _load_config()
    log_path = os.path.join(BASE_DIR, cfg.get("log_file", "server.log"))
    logger   = _setup_logging(log_path)
    sec      = SecurityManager(
        os.path.join(BASE_DIR, cfg.get("blacklist_file", "blacklist.json"))
    )
    return cfg, logger, sec


# ---------------------------------------------------------------------------
# Shared helper: read a newline-terminated line from a plain (non-TLS) socket
# ---------------------------------------------------------------------------

def _readline_raw(sock: socket.socket, max_bytes: int = 256) -> str:
    buf = b""
    while len(buf) < max_bytes:
        try:
            b = sock.recv(1)
        except Exception:
            return ""
        if not b:
            return ""
        if b == b"\n":
            return buf.decode("ascii", errors="replace").strip()
        buf += b
    return ""


# ---------------------------------------------------------------------------
# Reverse mode  –  server dials OUT to the admin's listener
#
# The admin's machine runs:  python client.py --listen --listen-port 4444
# The server (behind firewall) connects out to that IP:port.
#
# TLS roles:
#   Remote machine (server.py) = TLS SERVER  (has cert + key, server_side=True)
#   Admin machine  (client.py) = TLS CLIENT  (verifies with server.crt)
# This is intentionally backwards from the TCP direction – SSL supports this.
# ---------------------------------------------------------------------------

def _reverse_loop(cfg: dict, logger: logging.Logger, sec: SecurityManager) -> None:
    host     = cfg.get("reverse_host", "")
    port     = int(cfg.get("reverse_port", 4444))
    interval = int(cfg.get("reverse_interval", 30))

    if not host:
        logger.error("[REVERSE] 'reverse_host' not set in config.json. Cannot start.")
        return

    cert_file = os.path.join(BASE_DIR, cfg["cert_file"])
    key_file  = os.path.join(BASE_DIR, cfg["key_file"])

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    logger.info(f"[REVERSE] Mode active. Will connect OUT to {host}:{port} every {interval}s.")

    while not _stop_flag.is_set():
        raw = None
        try:
            logger.info(f"[REVERSE] Dialling {host}:{port} …")
            raw = socket.create_connection((host, port), timeout=10)
            # We are the TCP client but the TLS *server* (we present our cert)
            ssl_conn = ssl_ctx.wrap_socket(raw, server_side=True)
            logger.info(f"[REVERSE] TLS handshake OK. Waiting for admin to authenticate.")
            _handle_client(ssl_conn, (host, port), cfg, sec, logger)
        except ssl.SSLError as exc:
            logger.warning(f"[REVERSE] TLS error: {exc}")
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            logger.info(f"[REVERSE] Could not reach {host}:{port}: {exc}")
        except Exception as exc:
            logger.warning(f"[REVERSE] Unexpected error: {exc}")
        finally:
            if raw:
                try:
                    raw.close()
                except Exception:
                    pass

        if not _stop_flag.is_set():
            logger.info(f"[REVERSE] Retrying in {interval}s …")
            _stop_flag.wait(timeout=interval)


# ---------------------------------------------------------------------------
# Relay mode  –  server dials OUT to a relay, which bridges it to the admin
#
# Run relay.py on any public machine (VPS/cloud).
# Admin connects with:  python client.py --relay <relay>:<port> --relay-token <tok>
#
# Relay protocol (plain text before TLS):
#   → send "S <token>\n"
#   ← receive "WAITING\n" or "PAIRED\n"
#   If WAITING: wait for "PAIRED\n"
#   After PAIRED: do TLS SERVER handshake on the bridged pipe
# ---------------------------------------------------------------------------

def _relay_loop(cfg: dict, logger: logging.Logger, sec: SecurityManager) -> None:
    relay_host = cfg.get("relay_host", "")
    relay_port = int(cfg.get("relay_port", 4443))
    token      = cfg.get("relay_token", "session01")
    interval   = int(cfg.get("relay_interval", 30))

    if not relay_host:
        logger.error("[RELAY] 'relay_host' not set in config.json. Cannot start.")
        return

    cert_file = os.path.join(BASE_DIR, cfg["cert_file"])
    key_file  = os.path.join(BASE_DIR, cfg["key_file"])

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    logger.info(f"[RELAY] Mode active. Relay={relay_host}:{relay_port}  token={token!r}")

    while not _stop_flag.is_set():
        raw = None
        try:
            logger.info(f"[RELAY] Connecting to relay {relay_host}:{relay_port} …")
            raw = socket.create_connection((relay_host, relay_port), timeout=10)
            raw.settimeout(30)

            # Relay handshake
            raw.sendall(f"S {token}\n".encode())
            resp = _readline_raw(raw)
            if resp not in ("WAITING", "PAIRED"):
                logger.warning(f"[RELAY] Unexpected relay response: {resp!r}")
                raw.close()
                _stop_flag.wait(timeout=interval)
                continue

            if resp == "WAITING":
                logger.info("[RELAY] Waiting for admin to connect via relay …")
                raw.settimeout(300)   # wait up to 5 minutes
                resp = _readline_raw(raw)

            if resp != "PAIRED":
                logger.warning(f"[RELAY] Expected PAIRED, got: {resp!r}")
                raw.close()
                _stop_flag.wait(timeout=interval)
                continue

            logger.info("[RELAY] Paired! Starting TLS handshake …")
            raw.settimeout(None)
            ssl_conn = ssl_ctx.wrap_socket(raw, server_side=True)
            logger.info("[RELAY] TLS OK. Waiting for admin to authenticate.")
            _handle_client(ssl_conn, (relay_host, relay_port), cfg, sec, logger)

        except ssl.SSLError as exc:
            logger.warning(f"[RELAY] TLS error: {exc}")
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            logger.info(f"[RELAY] Could not reach relay {relay_host}:{relay_port}: {exc}")
        except Exception as exc:
            logger.warning(f"[RELAY] Unexpected error: {exc}")
        finally:
            if raw:
                try:
                    raw.close()
                except Exception:
                    pass

        if not _stop_flag.is_set():
            logger.info(f"[RELAY] Reconnecting in {interval}s …")
            _stop_flag.wait(timeout=interval)


# ---------------------------------------------------------------------------
# Dispatcher: pick the right mode based on config
# ---------------------------------------------------------------------------

def _heartbeat_loop() -> None:
    """Write stats every 5 s so watermark.py can detect liveness by file age."""
    while not _stop_flag.is_set():
        _write_stats()
        _stop_flag.wait(timeout=5)


def _dispatch(cfg: dict, logger: logging.Logger, sec: SecurityManager) -> None:
    _init_stats()
    threading.Thread(target=_heartbeat_loop, daemon=True, name="heartbeat").start()
    mode = cfg.get("mode", "listen").lower()
    logger.info(f"Starting in mode: {mode!r}")

    if mode == "listen":
        server = Server(cfg, sec, logger)
        server.start()

    elif mode == "reverse":
        _reverse_loop(cfg, logger, sec)

    elif mode == "relay":
        _relay_loop(cfg, logger, sec)

    else:
        logger.error(f"Unknown mode {mode!r}. Valid values: listen | reverse | relay")


# ---------------------------------------------------------------------------
# Windows Service wrapper
# ---------------------------------------------------------------------------
try:
    import win32event
    import win32service
    import win32serviceutil
    import servicemanager

    class RemoteCommandService(win32serviceutil.ServiceFramework):
        _svc_name_         = "RemoteCommandServer"
        _svc_display_name_ = "Remote Command Server"
        _svc_description_  = ("Encrypted remote shell server with firewall bypass. "
                               "Modes: listen | reverse | relay")

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._server   = None   # only used in 'listen' mode

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
            _stop_flag.set()
            if self._server:
                self._server.stop()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                cfg, logger, sec = _load_components()
                if cfg.get("mode", "listen") == "listen":
                    self._server = Server(cfg, sec, logger)
                logger.info("Windows service starting.")
                _dispatch(cfg, logger, sec)
            except Exception as exc:
                servicemanager.LogErrorMsg(f"RemoteCommandServer fatal error: {exc}")

    WIN32_AVAILABLE = True

except ImportError:
    WIN32_AVAILABLE = False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _run_standalone() -> None:
    cfg, logger, sec = _load_components()
    logger.info("Running in standalone mode (Ctrl+C to stop).")
    try:
        _dispatch(cfg, logger, sec)
    except KeyboardInterrupt:
        _stop_flag.set()
        logger.info("Server stopped by user.")


if __name__ == "__main__":
    if not WIN32_AVAILABLE:
        print("pywin32 not available – running in standalone mode.")
        _run_standalone()

    elif len(sys.argv) == 1:
        # Launched with no arguments by Service Control Manager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(RemoteCommandService)
        servicemanager.StartServiceCtrlDispatcher()

    elif sys.argv[1] == "run":
        # Manual foreground run:  python server.py run
        _run_standalone()

    else:
        # install / start / stop / restart / remove / debug / update …
        win32serviceutil.HandleCommandLine(RemoteCommandService)
