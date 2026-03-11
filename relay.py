"""
Remote Command - TCP Relay
===========================
Run this on ANY publicly reachable machine (VPS, cloud instance, home server
with any single open port).  Both the controlled server AND the admin client
connect OUTBOUND to this relay – no inbound ports need to be opened anywhere.

The relay is fully TLS-transparent: it forwards raw bytes without decrypting
anything, so end-to-end encryption is preserved.

Usage
-----
    python relay.py                   # listens on port 4443
    python relay.py --port 443        # use 443 for maximum firewall bypass

Then configure the server (config.json):
    "mode":        "relay",
    "relay_host":  "<this-relay-IP>",
    "relay_port":  4443,
    "relay_token": "mysecret01"

Connect the client:
    python client.py --host <server-name> --relay <relay-IP>:4443
                     --relay-token mysecret01 --cert server.crt

Protocol (plain text handshake BEFORE TLS):
    Client → Relay:  "S <token>\\n"   (S = server/remote machine)
                  or "C <token>\\n"   (C = client/admin)
    Relay  → Client: "WAITING\\n"     (waiting for the other side)
                  or "PAIRED\\n"      (both sides ready – start TLS now)
    Relay  → Waiter: "PAIRED\\n"      (sent when the partner arrives)
    After PAIRED: raw bytes are forwarded in both directions (TLS pass-through).
"""

import argparse
import socket
import threading
import time


# ---------------------------------------------------------------------------
# Session registry
# ---------------------------------------------------------------------------

class _Waiter:
    def __init__(self, conn: socket.socket):
        self.conn = conn
        self.ev   = threading.Event()   # set when partner arrives


_pending: dict = {}    # "ROLE:token" -> _Waiter
_plock          = threading.Lock()


# ---------------------------------------------------------------------------
# Byte forwarding (raw, no TLS awareness)
# ---------------------------------------------------------------------------

def _fwd(src: socket.socket, dst: socket.socket) -> None:
    """Forward bytes from src to dst until either end closes."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass


def _readline(conn: socket.socket, max_bytes: int = 256) -> str:
    buf = b""
    while len(buf) < max_bytes:
        try:
            b = conn.recv(1)
        except Exception:
            return ""
        if not b:
            return ""
        if b == b"\n":
            return buf.decode("utf-8", errors="replace").strip()
        buf += b
    return ""


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def _handle(conn: socket.socket, addr: tuple) -> None:
    ip = f"{addr[0]}:{addr[1]}"
    is_master    = False
    matched_conn = None

    try:
        conn.settimeout(30)

        # ── Relay handshake ────────────────────────────────────────────────
        line = _readline(conn)
        if not line:
            return
        parts = line.split(None, 1)
        if len(parts) != 2 or parts[0] not in ("S", "C"):
            conn.sendall(b"ERR bad header\n")
            return

        role, token = parts
        opp_role = "C" if role == "S" else "S"
        my_key   = f"{role}:{token}"
        opp_key  = f"{opp_role}:{token}"

        print(f"[relay] {ip}  role={role}  token={token[:16]!r}")

        waiter = _Waiter(conn)
        with _plock:
            if opp_key in _pending:
                opp_w = _pending.pop(opp_key)
                # Tell the waiting thread it has a partner
                opp_w.conn.settimeout(None)
                matched_conn  = opp_w.conn
                is_master     = True
                opp_w.ev.set()        # wake waiter thread so it can exit cleanly
            else:
                _pending[my_key] = waiter

        # ── Branch: we are the bridge master (second to arrive) ────────────
        if is_master:
            conn.settimeout(None)
            # Notify both sides that the bridge is ready
            matched_conn.sendall(b"PAIRED\n")
            conn.sendall(b"PAIRED\n")

            peer_ip = matched_conn.getpeername()[0]
            print(f"[relay] BRIDGING  {addr[0]} ({role}) <--> {peer_ip} ({opp_role})  "
                  f"token={token[:16]!r}")

            # Forward in both directions concurrently
            t = threading.Thread(target=_fwd, args=(matched_conn, conn), daemon=True)
            t.start()
            _fwd(conn, matched_conn)   # blocks until done
            t.join(timeout=5)

            print(f"[relay] Bridge ended  token={token[:16]!r}")

            for s in (conn, matched_conn):
                try:
                    s.close()
                except Exception:
                    pass

        # ── Branch: we are the waiter (first to arrive) ───────────────────
        else:
            conn.sendall(b"WAITING\n")
            conn.settimeout(None)

            paired = waiter.ev.wait(timeout=300)   # wait up to 5 minutes
            if not paired:
                print(f"[relay] {ip}: timeout, no partner arrived for token={token[:16]!r}")
                with _plock:
                    _pending.pop(my_key, None)
                conn.close()
            # If paired: bridge master owns both sockets now. This thread just exits.

    except Exception as exc:
        print(f"[relay] {ip} error: {exc}")
        if not is_master:
            try:
                conn.close()
            except Exception:
                pass
        if matched_conn and is_master:
            try:
                matched_conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Remote Command TCP Relay – run on any public machine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--host", default="0.0.0.0",
                    help="Bind address (default: 0.0.0.0)")
    ap.add_argument("--port", type=int, default=4443,
                    help="Listening port (default: 4443).  Use 443 to bypass most firewalls.")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(20)

    print(f"[relay] Listening on {args.host}:{args.port}")
    print(f"[relay] TLS-transparent – end-to-end encryption is fully preserved")
    print(f"[relay] Waiting for server+client pairs …")
    print()

    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[relay] Shutting down.")
            break
        except Exception as exc:
            print(f"[relay] accept error: {exc}")
            time.sleep(1)


if __name__ == "__main__":
    main()
