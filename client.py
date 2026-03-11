"""
Remote Command Client
======================
Connects to a Remote Command Server over TLS and provides an interactive
shell.  Three connection strategies handle every firewall scenario:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRATEGY 1 – Direct  (default)
  Your machine → server  (server needs at least one open inbound port)

    python client.py --host 10.0.0.5 --cert server.crt

  Tip: set "port": 443 in server config.json – port 443 (HTTPS) is rarely
  blocked.  If your network routes all TCP through an HTTP proxy, add:
    --proxy proxyhost:8080  [--proxy-auth DOMAIN\\user:pass]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRATEGY 2 – Reverse  (server behind firewall, YOUR machine is reachable)
  Server → your machine  (no inbound port needed on the server)

  Step 1 – on YOUR machine (admin), start listener:
    python client.py --listen --listen-port 4444 --cert server.crt

  Step 2 – in server config.json:
    "mode":         "reverse",
    "reverse_host": "<your-IP>",
    "reverse_port": 4444

  The server dials your listener and the session starts automatically.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRATEGY 3 – Relay  (BOTH sides behind firewalls – nothing is reachable)
  Server → relay ← your machine  (both connect OUT; relay.py is the bridge)

  Step 1 – on ANY public machine (VPS/cloud), run:
    python relay.py --port 443

  Step 2 – in server config.json:
    "mode":        "relay",
    "relay_host":  "<relay-IP>",
    "relay_port":  443,
    "relay_token": "mysecret01"

  Step 3 – on your admin machine:
    python client.py --relay <relay-IP>:443 --relay-token mysecret01
                     --cert server.crt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

All options
-----------
  --host HOST              Server hostname or IP  (required for direct mode)
  --port PORT              Server port            (default: 443)
  --cert PATH              Server cert for TLS verification (default: server.crt)
  --no-verify              Skip TLS cert verification  [insecure]
  --password PASS          Password (prompted if omitted)
  --proxy HOST:PORT        HTTP CONNECT proxy
  --proxy-auth USER:PASS   Proxy credentials (Basic auth)
  -c / --command CMD       Run single command and exit

  --listen                 Reverse-mode: wait for server to call in
  --listen-port PORT       Port to listen on for reverse mode (default: 4444)

  --relay HOST:PORT        Relay-mode: connect through relay.py
  --relay-token TOKEN      Session token matching server config (default: session01)
"""

import argparse
import base64
import datetime
import getpass
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time

MAX_MSG_BYTES = 10 * 1024 * 1024


# ---------------------------------------------------------------------------
# Wire protocol  (must match server.py)
# ---------------------------------------------------------------------------

def _send(conn, msg: dict) -> None:
    data   = json.dumps(msg).encode("utf-8")
    header = struct.pack(">I", len(data))
    conn.sendall(header + data)


def _recv(conn):
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


def _readline_raw(conn, max_bytes: int = 256) -> str:
    """Read a newline-terminated line from a plain (pre-TLS) socket."""
    buf = b""
    while len(buf) < max_bytes:
        try:
            b = conn.recv(1)
        except Exception:
            return ""
        if not b:
            return ""
        if b == b"\n":
            return buf.decode("ascii", errors="replace").strip()
        buf += b
    return ""


# ---------------------------------------------------------------------------
# TLS context builders
# ---------------------------------------------------------------------------

def _make_tls_client_ctx(cert_path: str, no_verify: bool) -> ssl.SSLContext:
    """TLS CLIENT context (for direct and relay modes)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if no_verify:
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        if cert_path and os.path.isfile(cert_path):
            ctx.load_verify_locations(cafile=cert_path)
        else:
            ctx.load_default_certs()
    return ctx


def _make_tls_server_ctx_from_memory() -> ssl.SSLContext:
    """
    TLS SERVER context for --listen mode.
    Generates a temporary self-signed cert in memory (valid 24 h).
    The remote server.py verifies the session using the password, not this cert.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("[ERROR] 'cryptography' package not installed.  Run: pip install cryptography")
        sys.exit(1)

    key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rc-controller")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(hours=24))
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem  = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    # Write to temp files, load into context, then delete
    tf_cert = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    tf_key  = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    try:
        tf_cert.write(cert_pem); tf_cert.close()
        tf_key.write(key_pem);   tf_key.close()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=tf_cert.name, keyfile=tf_key.name)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    finally:
        for f in (tf_cert.name, tf_key.name):
            try:
                os.unlink(f)
            except Exception:
                pass

    return ctx


# ---------------------------------------------------------------------------
# Connection strategies
# ---------------------------------------------------------------------------

def _connect_direct(host: str, port: int, ssl_ctx: ssl.SSLContext,
                    proxy: str = "", proxy_auth: str = "") -> ssl.SSLSocket:
    """Direct or proxy-tunnelled connection (Strategy 1)."""
    if proxy:
        raw = _connect_via_http_proxy(host, port, proxy, proxy_auth)
    else:
        raw = socket.create_connection((host, port), timeout=10)
    return ssl_ctx.wrap_socket(raw, server_hostname=host)


def _connect_via_http_proxy(host: str, port: int,
                             proxy: str, proxy_auth: str) -> socket.socket:
    """Open a raw TCP tunnel through an HTTP CONNECT proxy."""
    if ":" not in proxy:
        raise ValueError(f"Bad --proxy value {proxy!r}. Expected HOST:PORT.")
    proxy_host, proxy_port_s = proxy.rsplit(":", 1)
    proxy_port = int(proxy_port_s)

    print(f"  Tunnelling through proxy {proxy_host}:{proxy_port} …")
    raw = socket.create_connection((proxy_host, proxy_port), timeout=10)

    hdrs = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if proxy_auth:
        user, _, pw = proxy_auth.partition(":")
        creds = base64.b64encode(f"{user}:{pw}".encode()).decode()
        hdrs.append(f"Proxy-Authorization: Basic {creds}")
    hdrs += ["", ""]
    raw.sendall("\r\n".join(hdrs).encode())

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = raw.recv(4096)
        if not chunk:
            raw.close()
            raise ConnectionError("Proxy closed connection without responding.")
        resp += chunk
        if len(resp) > 8192:
            raw.close()
            raise ConnectionError("Proxy response too large.")

    status = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200 " not in status and not status.endswith(" 200"):
        raw.close()
        raise ConnectionError(f"Proxy refused CONNECT: {status}")

    print(f"  Tunnel OK ({status.strip()})")
    return raw


def _connect_relay(relay_addr: str, token: str,
                   ssl_ctx: ssl.SSLContext, server_host: str) -> ssl.SSLSocket:
    """
    Connect to relay.py as the CLIENT side (Strategy 3).
    After PAIRED, wraps the raw pipe with TLS CLIENT.
    """
    if ":" not in relay_addr:
        raise ValueError(f"Bad --relay value {relay_addr!r}. Expected HOST:PORT.")
    relay_host, relay_port_s = relay_addr.rsplit(":", 1)
    relay_port = int(relay_port_s)

    print(f"  Connecting to relay {relay_host}:{relay_port} …")
    raw = socket.create_connection((relay_host, relay_port), timeout=10)
    raw.settimeout(300)

    raw.sendall(f"C {token}\n".encode())
    resp = _readline_raw(raw)

    if resp == "WAITING":
        print(f"  Relay: waiting for server to connect with token {token!r} …")
        resp = _readline_raw(raw)

    if resp != "PAIRED":
        raw.close()
        raise ConnectionError(f"Relay error: unexpected response {resp!r}")

    print("  Relay: paired with server. Starting TLS …")
    raw.settimeout(None)
    # server.py wraps the other end as TLS SERVER; we wrap as TLS CLIENT
    return ssl_ctx.wrap_socket(raw, server_hostname=server_host or relay_host)


# ---------------------------------------------------------------------------
# Protocol operations
# ---------------------------------------------------------------------------

def _authenticate(conn, password: str):
    _send(conn, {"type": "auth", "password": password})
    resp = _recv(conn)
    if resp is None:
        return False, "No response from server."
    return resp.get("success", False), resp.get("message", "Unknown error.")


def _stdin_ready() -> bool:
    """Non-blocking check: is there data waiting on stdin?"""
    try:
        import msvcrt          # Windows
        return msvcrt.kbhit()
    except ImportError:
        import select          # Unix/macOS
        r, _, _ = select.select([sys.stdin], [], [], 0)
        return bool(r)


def _exec_single_command(conn, cmd: str) -> int:
    """Run a single command, stream output, and exit."""
    # Append exit so the remote shell terminates after the command
    if not cmd.endswith("\n"):
        cmd += "\n"
    cmd += "exit\n"
    
    _send(conn, {"type": "command", "cmd": cmd})

    while True:
        msg = _recv(conn)
        if msg is None:
            break

        mtype = msg.get("type")

        if mtype == "output_chunk":
            sys.stdout.write(msg.get("data", ""))
            sys.stdout.flush()
        elif mtype == "command_done" or mtype == "bye":
            break
        elif mtype == "error":
            print(f"\n[SERVER ERROR] {msg.get('message', '?')}")
            return -1

    return 0


def _quit(conn) -> None:
    try:
        _send(conn, {"type": "quit"})
        _recv(conn)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------

def _interactive(conn, host: str) -> None:
    print(f"\nConnected to {host}.\n")

    stop_event = threading.Event()

    def receive_output():
        try:
            while not stop_event.is_set():
                msg = _recv(conn)
                if msg is None:
                    break

                mtype = msg.get("type")

                if mtype == "output_chunk":
                    sys.stdout.write(msg.get("data", ""))
                    sys.stdout.flush()
                elif mtype in ("command_done", "bye"):
                    break
                elif mtype == "error":
                    print(f"\n[SERVER ERROR] {msg.get('message', '?')}")
        finally:
            stop_event.set()

    recv_thread = threading.Thread(target=receive_output, daemon=True)
    recv_thread.start()

    # Trigger the first prompt
    _send(conn, {"type": "input", "data": "\n"})

    try:
        while not stop_event.is_set():
            if _stdin_ready():
                try:
                    line = sys.stdin.readline()
                    if not line:
                        break

                    _send(conn, {"type": "input", "data": line})
                except Exception:
                    break
            else:
                time.sleep(0.05)
    except KeyboardInterrupt:
        pass

    _quit(conn)


# ---------------------------------------------------------------------------
# Strategy 2: --listen   (wait for server to call in)
# ---------------------------------------------------------------------------

def _listen_mode(args) -> None:
    """
    Listen for an incoming reverse connection from server.py.
    server.py acts as TLS SERVER (has the cert); we act as TLS CLIENT.
    """
    listen_port = args.listen_port
    cert_file   = args.cert if not args.no_verify else None

    ssl_ctx = _make_tls_client_ctx(cert_file, args.no_verify)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", listen_port))
    except OSError as exc:
        print(f"[ERROR] Cannot listen on port {listen_port}: {exc}")
        sys.exit(1)
    sock.listen(5)

    print(f"[LISTEN] Waiting for server to connect on port {listen_port} …")
    print(f"         Server config.json must have:")
    print(f'           "mode":         "reverse"')
    print(f'           "reverse_host": "<your-IP>"')
    print(f'           "reverse_port": {listen_port}')
    print(f"         Press Ctrl+C to cancel.")

    try:
        while True:
            try:
                sock.settimeout(1.0)
                try:
                    raw_conn, addr = sock.accept()
                except socket.timeout:
                    continue

                print(f"\n[LISTEN] Incoming from {addr[0]}:{addr[1]}")
                raw_conn.settimeout(15)

                try:
                    # server.py connects as TLS SERVER; we connect as TLS CLIENT
                    ssl_conn = ssl_ctx.wrap_socket(raw_conn, server_side=False)
                except ssl.SSLError as exc:
                    print(f"[LISTEN] TLS handshake failed: {exc}")
                    raw_conn.close()
                    continue

                ssl_conn.settimeout(30)

                password = args.password
                if not password:
                    try:
                        password = getpass.getpass("Password: ")
                    except KeyboardInterrupt:
                        ssl_conn.close()
                        break

                ok, message = _authenticate(ssl_conn, password)
                if not ok:
                    print(f"[AUTH FAILED] {message}")
                    ssl_conn.close()
                    print("[LISTEN] Waiting for next connection …")
                    continue

                print(f"[AUTH OK] {message}")
                ssl_conn.settimeout(None)
                _interactive(ssl_conn, addr[0])
                ssl_conn.close()
                print("\n[LISTEN] Session ended. Waiting for next connection …")

            except KeyboardInterrupt:
                break
    finally:
        sock.close()
        print("\n[LISTEN] Stopped.")


# ---------------------------------------------------------------------------
# Firewall hint helper
# ---------------------------------------------------------------------------

def _firewall_hint(host: str, port: int) -> str:
    return (
        f"  Firewall troubleshooting:\n"
        f"  • Port {port} may be blocked.  Try port 443 (HTTPS-like traffic).\n"
        f"  • If behind an HTTP proxy:  --proxy proxyhost:8080\n"
        f"  • If ALL ports are blocked on the server:\n"
        f"      Use REVERSE mode – server dials out TO you:\n"
        f"        python client.py --listen --listen-port 4444 --cert server.crt\n"
        f"        (set server config: mode=reverse, reverse_host=<your-IP>)\n"
        f"  • If BOTH sides are firewalled:\n"
        f"      Use RELAY mode – both connect out to a public relay:\n"
        f"        python relay.py  (run on any VPS/cloud)\n"
        f"        python client.py --relay <relay-IP>:443 --relay-token session01\n"
        f"        (set server config: mode=relay, relay_host=<relay-IP>)"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Remote Command Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host",        default="",
                    help="Server hostname or IP  (required for direct mode)")
    ap.add_argument("--port",        type=int, default=443,
                    help="Server port (default: 443)")
    ap.add_argument("--cert",        default="server.crt",
                    help="Server certificate for TLS verification (default: server.crt)")
    ap.add_argument("--no-verify",   action="store_true",
                    help="Disable TLS certificate verification  [insecure]")
    ap.add_argument("--password",    default=None,
                    help="Password (prompted if omitted)")
    ap.add_argument("--proxy",       default="",
                    help="HTTP CONNECT proxy  HOST:PORT")
    ap.add_argument("--proxy-auth",  default="",
                    help="Proxy credentials  USER:PASS  (Basic auth)")
    ap.add_argument("-c", "--command", default=None,
                    help="Run a single command and exit (non-interactive)")

    # Reverse mode
    ap.add_argument("--listen",      action="store_true",
                    help="REVERSE MODE: listen for server to connect in")
    ap.add_argument("--listen-port", type=int, default=4444,
                    help="Port to listen on in reverse mode (default: 4444)")

    # Relay mode
    ap.add_argument("--relay",       default="",
                    help="RELAY MODE: connect via relay.py  HOST:PORT")
    ap.add_argument("--relay-token", default="session01",
                    help="Relay session token (must match server config, default: session01)")

    args = ap.parse_args()

    if args.no_verify:
        print("[WARNING] TLS certificate verification is DISABLED.")

    # ── Strategy 2: reverse (--listen) ────────────────────────────────────
    if args.listen:
        _listen_mode(args)
        return

    # ── Need a password for strategies 1 & 3 ─────────────────────────────
    password = args.password
    if not password:
        prompt = f"Password for {args.host or args.relay}: "
        try:
            password = getpass.getpass(prompt)
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)

    cert_file = args.cert if not args.no_verify else None
    ssl_ctx   = _make_tls_client_ctx(cert_file, args.no_verify)

    conn = None

    # ── Strategy 3: relay ─────────────────────────────────────────────────
    if args.relay:
        print(f"Connecting via relay {args.relay}  token={args.relay_token!r} …")
        try:
            conn = _connect_relay(args.relay, args.relay_token, ssl_ctx, args.host)
        except Exception as exc:
            print(f"[ERROR] Relay connection failed: {exc}")
            print(_firewall_hint(args.host, args.port))
            sys.exit(1)

    # ── Strategy 1: direct (or through HTTP proxy) ────────────────────────
    else:
        if not args.host:
            ap.error("--host is required unless --listen or --relay is used.")
        via = f" via proxy {args.proxy}" if args.proxy else ""
        print(f"Connecting to {args.host}:{args.port}{via} …")
        try:
            conn = _connect_direct(args.host, args.port, ssl_ctx,
                                   proxy=args.proxy, proxy_auth=args.proxy_auth)
        except ssl.SSLCertVerificationError as exc:
            print(f"[ERROR] Certificate verification failed: {exc}")
            print("        Copy server.crt from the server and use --cert server.crt")
            sys.exit(1)
        except (ConnectionRefusedError, ConnectionError) as exc:
            print(f"[ERROR] Could not connect: {exc}")
            print(_firewall_hint(args.host, args.port))
            sys.exit(1)
        except socket.timeout:
            print("[ERROR] Connection timed out – host or port may be blocked.")
            print(_firewall_hint(args.host, args.port))
            sys.exit(1)
        except OSError as exc:
            print(f"[ERROR] Network error: {exc}")
            print(_firewall_hint(args.host, args.port))
            sys.exit(1)
        except Exception as exc:
            print(f"[ERROR] {exc}")
            print(_firewall_hint(args.host, args.port))
            sys.exit(1)

    conn.settimeout(30)

    # ── Authenticate ──────────────────────────────────────────────────────
    ok, message = _authenticate(conn, password)
    if not ok:
        print(f"[AUTH FAILED] {message}")
        try:
            conn.close()
        except Exception:
            pass
        sys.exit(1)

    print(f"[AUTH OK] {message}")
    conn.settimeout(None)

    # ── Run ───────────────────────────────────────────────────────────────
    display_host = args.host or args.relay
    if args.command:
        rc = _exec_single_command(conn, args.command)
        _quit(conn)
        try:
            conn.close()
        except Exception:
            pass
        sys.exit(rc)
    else:
        _interactive(conn, display_host)
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
