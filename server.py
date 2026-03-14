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

# --- Auto-inject user's roaming site-packages for Windows Service mode ---
# When running as LocalSystem, the user-level site-packages are not in sys.path.
# If Python is installed in the user profile, we try to add their Roaming packages.
try:
    _exe_path = sys.executable
    if "AppData" in _exe_path:
        _user_profile = _exe_path.split("AppData")[0].rstrip("\\/")
        _py_ver = f"Python{sys.version_info.major}{sys.version_info.minor}"
        _roaming_site = os.path.join(_user_profile, "AppData", "Roaming", "Python", _py_ver, "site-packages")
        if os.path.isdir(_roaming_site) and _roaming_site not in sys.path:
            sys.path.append(_roaming_site)
except Exception:
    pass

# Set by SvcStop or KeyboardInterrupt – all loops check this to know when to quit.
_stop_flag = threading.Event()

# Track all active network sockets to close them forcefully when stopping the service.
_active_sockets = set()
_active_sockets_lock = threading.Lock()

def _register_socket(sock) -> None:
    if sock is not None:
        with _active_sockets_lock:
            _active_sockets.add(sock)

def _unregister_socket(sock) -> None:
    if sock is not None:
        with _active_sockets_lock:
            _active_sockets.discard(sock)

def _close_all_sockets() -> None:
    with _active_sockets_lock:
        for sock in list(_active_sockets):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        _active_sockets.clear()

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

def _run_shell(conn: ssl.SSLSocket, ip: str, logger: logging.Logger, use_pty: bool = False):
    """Spawns a cmd.exe process and blindly streams IO back and forth."""
    
    # Try to use ConPTY (pywinpty) if available to support interactive features like Tab completion.
    pty_available = False
    try:
        import winpty
        pty_available = True
    except ImportError:
        pass

    if use_pty and pty_available:
        try:
            import winpty
            pty = winpty.PTY(120, 30)
            pty.spawn(r"C:\Windows\System32\cmd.exe")

            # Initialization sequence for PTY: change directory and clear screen
            pty.write("cd /d C:\\\r\ncls\r\n")

            def output_relay():
                try:
                    while True:
                        chunk = pty.read(blocking=True)
                        if not chunk:
                            break
                        _send(conn, {"type": "output_chunk", "data": chunk})
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
                        try:
                            _send(conn, {"type": "bye"})
                        except Exception:
                            pass
                        break

                    elif mtype in ("command", "input"):
                        data = msg.get("cmd", "") if mtype == "command" else msg.get("data", "")
                        if mtype == "command" and not data.endswith("\n"):
                            data += "\n"
                        
                        if data:
                            # Normalize line endings to \r\n for ConPTY
                            data = data.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
                            try:
                                pty.write(data)
                            except Exception:
                                break
                    else:
                        try:
                            _send(conn, {"type": "error", "message": f"Unknown message type: {mtype!r}"})
                        except Exception:
                            pass
            except Exception as e:
                logger.warning(f"Connection error from {ip} in PTY mode: {e}")
            finally:
                try:
                    # Closing the conn forces the relay handler to terminate if it hasn't already
                    conn.close()
                except Exception:
                    pass
                try:
                    del pty
                except Exception:
                    pass
            return
        except Exception as e:
            logger.warning(f"ConPTY failed to start: {e}. Falling back to standard pipes.")

    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    
    # Pass the current environment variables so PATH is preserved
    env = os.environ.copy()
    
    # Try to load the System PATH and all user PATHs if running as a service
    try:
        import winreg
        paths_to_add = []
        
        # System Path
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager\Environment") as key:
                paths_to_add.append(winreg.QueryValueEx(key, "Path")[0])
        except Exception:
            pass
            
        # All Users Path
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, "") as users_key:
                for i in range(winreg.QueryInfoKey(users_key)[0]):
                    sid = winreg.EnumKey(users_key, i)
                    if not sid.endswith("_Classes"):
                        try:
                            with winreg.OpenKey(winreg.HKEY_USERS, rf"{sid}\Environment") as env_key:
                                paths_to_add.append(winreg.QueryValueEx(env_key, "Path")[0])
                        except Exception:
                            pass
        except Exception:
            pass
            
        combined_path = ";".join(paths_to_add)
        
        path_key = "PATH"
        for k in env.keys():
            if k.upper() == "PATH":
                path_key = k
                break
                
        if path_key in env:
            env[path_key] = f"{env[path_key]};{combined_path}"
        else:
            env["PATH"] = combined_path
    except Exception:
        pass
    
    proc = subprocess.Popen(
        "cmd.exe",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd="C:\\",
        shell=False,
        creationflags=flags,
        env=env
    )

    current_cwd = ["C:\\"]
    tab_state = {"last_completed_cmd": None, "matches": [], "index": 0, "prefix_len": 0}

    def output_relay():
        import re
        prompt_re = re.compile(r'(?:^|\n)([a-zA-Z]:\\[^>]*?)>')
        try:
            while True:
                # read1 is crucial here to flush partial lines like prompts
                chunk = proc.stdout.read1(4096)
                if not chunk:
                    break
                decoded = chunk.decode(_SYS_ENC, errors="replace")
                
                # extract last prompt to maintain CWD
                matches = prompt_re.findall(decoded)
                if matches:
                    current_cwd[0] = matches[-1]
                
                _send(conn, {"type": "output_chunk", "data": decoded})
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
                try:
                    _send(conn, {"type": "bye"})
                except Exception:
                    pass
                break

            elif mtype in ("command", "input"):
                data = msg.get("cmd", "") if mtype == "command" else msg.get("data", "")
                if mtype == "command" and not data.endswith("\n"):
                    data += "\n"
                
                # Normalize line endings to \r\n for Windows apps
                if data:
                    data = data.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
                    
                    # Force Python interactive mode so it doesn't block waiting for EOF in non-PTY mode
                    cmd_stripped = data.strip()
                    if cmd_stripped in ("python", "python.exe", "python3", "python3.exe"):
                        data = data.replace(cmd_stripped, cmd_stripped + " -i")
                        
                    try:
                        proc.stdin.write(data.encode(_SYS_ENC, errors="replace"))
                        proc.stdin.flush()
                    except Exception:
                        break
            elif mtype == "signal" and msg.get("signal") == "SIGINT":
                try:
                    import signal
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                except Exception as e:
                    logger.warning(f"Failed to send SIGINT to proc {proc.pid}: {e}")
            elif mtype == "simulate_tab":
                cmd_line = msg.get("data", "")
                if not cmd_line:
                    continue
                
                try:
                    import glob
                    import shlex
                    
                    if tab_state["last_completed_cmd"] == cmd_line and tab_state["matches"]:
                        # we are cycling
                        tab_state["index"] = (tab_state["index"] + 1) % len(tab_state["matches"])
                        match = tab_state["matches"][tab_state["index"]]
                        prefix_len = tab_state["prefix_len"]
                    else:
                        # new search
                        if cmd_line.endswith(" "):
                            last_part = ""
                            search_part = ""
                        else:
                            try:
                                parts = shlex.split(cmd_line, posix=False)
                            except ValueError:
                                parts = cmd_line.split(" ")
                            
                            if not parts:
                                continue
                            last_part = parts[-1]
                            search_part = last_part.strip('"\'')
                        
                        if search_part:
                            if not os.path.isabs(search_part):
                                search_path = os.path.join(current_cwd[0], search_part)
                            else:
                                search_path = search_part
                        else:
                            search_path = os.path.join(current_cwd[0], "")
                            
                        matches = glob.glob(search_path + "*")
                        if not matches:
                            continue
                            
                        # sort matches by name length or alphabetically
                        matches.sort(key=str.lower)
                        
                        tab_state["matches"] = []
                        tab_state["index"] = 0
                        
                        for m in matches:
                            is_dir = os.path.isdir(m)
                            base_name = os.path.basename(m.rstrip("\\/"))
                            
                            if search_part and os.path.dirname(search_part):
                                replacement = os.path.join(os.path.dirname(search_part), base_name)
                            else:
                                replacement = base_name
                                
                            if is_dir and not replacement.endswith("\\"):
                                replacement += "\\"
                                    
                            if " " in replacement and not last_part.startswith('"'):
                                replacement = f'"{replacement}"'
                            elif last_part.startswith('"') and not replacement.endswith('"'):
                                replacement = f'"{replacement}"'
                                
                            tab_state["matches"].append(replacement)
                            
                        prefix_len = len(cmd_line) - len(last_part)
                        tab_state["prefix_len"] = prefix_len
                        match = tab_state["matches"][0]

                    completed_cmd = cmd_line[:prefix_len] + match
                    tab_state["last_completed_cmd"] = completed_cmd
                    
                    _send(conn, {"type": "tab_completed", "data": completed_cmd})
                except Exception as e:
                    logger.warning(f"Simulate tab failed: {e}")
            else:
                try:
                    _send(conn, {"type": "error", "message": f"Unknown message type: {mtype!r}"})
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"Connection error from {ip} in legacy shell mode: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
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
    _register_socket(conn)
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
            use_pty_requested = msg.get("use_pty", False)
            pty_enabled = False
            if use_pty_requested:
                try:
                    import winpty
                    pty_enabled = True
                except ImportError:
                    pass

            _send(conn, {"type": "auth_result", "success": True,
                         "message": "Authenticated. Welcome.",
                         "pty_enabled": pty_enabled})

            # --- Simple streaming shell ------------
            conn.settimeout(None)  # No timeout for interactive shell
            _run_shell(conn, ip, logger, use_pty=pty_enabled)

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
    except ConnectionResetError:
        logger.info(f"Connection from {ip} was reset by peer.")
    except Exception as exc:
        logger.error(f"Error handling {ip}: {exc}")
    finally:
        _unregister_socket(conn)
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
            _register_socket(self._sock)
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
            _unregister_socket(self._sock)
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
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
    import select
    buf = b""
    while len(buf) < max_bytes:
        if _stop_flag.is_set():
            return ""
        try:
            # Wait up to 1 second for data to become available
            r, _, _ = select.select([sock], [], [], 1.0)
            if not r:
                continue
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
            _register_socket(raw)
            # We are the TCP client but the TLS *server* (we present our cert)
            ssl_conn = ssl_ctx.wrap_socket(raw, server_side=True)
            _register_socket(ssl_conn)
            logger.info(f"[REVERSE] TLS handshake OK. Waiting for admin to authenticate.")
            
            # Spawn a thread so we don't block the loop on the connection, allowing _stop_flag to be checked
            t = threading.Thread(
                target=_handle_client,
                args=(ssl_conn, (host, port), cfg, sec, logger),
                daemon=True
            )
            t.start()
            
            # Now wait for the thread to exit, or the stop flag to be set
            while t.is_alive() and not _stop_flag.is_set():
                t.join(1.0)
                
        except ssl.SSLError as exc:
            logger.warning(f"[REVERSE] TLS error: {exc}")
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            logger.info(f"[REVERSE] Could not reach {host}:{port}: {exc}")
        except Exception as exc:
            logger.warning(f"[REVERSE] Unexpected error: {exc}")
        finally:
            if raw:
                _unregister_socket(raw)
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
            _register_socket(raw)
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

            logger.info("[RELAY] Paired! Handing off to client thread …")
            raw.settimeout(None)
            
            def _relay_client_handler(sock, r_host, r_port):
                try:
                    ssl_conn = ssl_ctx.wrap_socket(sock, server_side=True)
                    logger.info("[RELAY] TLS OK. Waiting for admin to authenticate.")
                    ssl_conn.settimeout(30) # Ensure auth handshake doesn't block forever
                    _handle_client(ssl_conn, (r_host, r_port), cfg, sec, logger)
                except Exception as e:
                    logger.warning(f"[RELAY] Handler error: {e}")
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
            
            t = threading.Thread(
                target=_relay_client_handler,
                args=(raw, relay_host, relay_port),
                daemon=True
            )
            t.start()
            raw = None  # Clear so the finally block doesn't close it, allowing the loop to immediately wait for the next client.

        except ssl.SSLError as exc:
            logger.warning(f"[RELAY] TLS error: {exc}")
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            logger.info(f"[RELAY] Could not reach relay {relay_host}:{relay_port}: {exc}")
        except Exception as exc:
            logger.warning(f"[RELAY] Unexpected error: {exc}")
        finally:
            if raw:
                _unregister_socket(raw)
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


def _dispatch(cfg: dict, logger: logging.Logger, sec: SecurityManager, existing_server=None) -> None:
    _init_stats()
    threading.Thread(target=_heartbeat_loop, daemon=True, name="heartbeat").start()
    mode = cfg.get("mode", "listen").lower()
    logger.info(f"Starting in mode: {mode!r}")

    if mode == "listen":
        server = existing_server if existing_server else Server(cfg, sec, logger)
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
            _close_all_sockets()
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
                _dispatch(cfg, logger, sec, existing_server=self._server)
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
        _close_all_sockets()
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
