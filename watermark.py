"""
RC Server Watermark Indicator
==============================
A small floating badge in the bottom-right corner (above the taskbar)
that shows live status of the RemoteCommandServer Windows service.

  Row 1 – status dot + state label
    Green dot  = Running
    Red dot    = Stopped
    (hidden)   = Service not installed

  Row 2 – live stats (read from server_stats.json written by server.py)
    Blue text  = Running with active client(s)
    Gray text  = Running but idle
    Dim text   = Stopped / stale

Right-click  → Start / Stop / Restart service, view logs, close
Double-click → Open server.log
Left-drag    → Reposition anywhere on screen

Auto-added to Windows Startup by install.bat.
"""

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import queue
import tkinter as tk
import tkinter.messagebox as mb

# ---------------------------------------------------------------------------
# Single-instance guard – only one watermark may run at a time
# ---------------------------------------------------------------------------
_MUTEX_NAME = "Global\\RCServerWatermark_SingleInstance"
_mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, True, _MUTEX_NAME)
if ctypes.windll.kernel32.GetLastError() == 183:   # ERROR_ALREADY_EXISTS
    sys.exit(0)

BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
SERVICE_NAME      = "RemoteCommandServer"
LOG_FILE          = os.path.join(BASE_DIR, "server.log")
STATS_FILE        = os.path.join(BASE_DIR, "server_stats.json")
POLL_MS           = 3000   # refresh every 3 seconds
STATS_MAX_AGE_S   = 12     # stats file older than this → server is gone

# Row 1: (dot-colour, text-colour, label)
_STATUS_CFG = {
    "running": ("#2dba4e", "#e6edf3", "RC Server   Running"),
    "stopped": ("#f85149", "#8b949e", "RC Server   Stopped"),
    "unknown": ("#d29922", "#8b949e", "RC Server   Unknown"),
}

# Row 2 stats colours
_COL_ACTIVE  = "#58a6ff"   # blue  – clients connected
_COL_IDLE    = "#8b949e"   # gray  – running but idle
_COL_STALE   = "#484f58"   # dim   – service stopped / no data

BG_COL  = "#0d1117"
BDR_COL = "#30363d"
SEP_COL = "#21262d"
W, H    = 224, 44


# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

def _get_status() -> str:
    """Determine server liveness purely from server_stats.json file age.

    The server heartbeat writes this file every 5 s while running.
    No subprocess / sc.exe is spawned during normal polling.
    """
    try:
        age = time.time() - os.path.getmtime(STATS_FILE)
        return "running" if age <= STATS_MAX_AGE_S else "stopped"
    except FileNotFoundError:
        return "not_installed"
    except Exception:
        return "unknown"


def _run_admin_cmd(cmd_str: str) -> bool:
    r = subprocess.run(cmd_str, capture_output=True, shell=True)
    if r.returncode == 0:
        return True
    # Try elevated, pause on error so user can see why it failed
    elevated_cmd = f"/c {cmd_str} || pause"
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", elevated_cmd, None, 0)
    return ret > 32


def _read_stats() -> dict:
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _fmt_stats(stats: dict, service_status: str) -> tuple:
    """Return (text, colour) for the stats row."""
    if not stats:
        return ("no data yet", _COL_STALE)

    active  = stats.get("active_clients",    0)
    total   = stats.get("total_connections", 0)
    fails   = stats.get("auth_failures",     0)
    last_ip = stats.get("last_ip",           "")

    parts = [f"{active} online", f"{total} served", f"{fails} fails"]
    if active > 0 and last_ip:
        parts.append(f"({last_ip})")
    text = "  ·  ".join(parts[:3])
    if active > 0 and last_ip:
        text += f"  ({last_ip})"

    if service_status != "running":
        col = _COL_STALE
    elif active > 0:
        col = _COL_ACTIVE
    else:
        col = _COL_IDLE

    return (text, col)


# ---------------------------------------------------------------------------
# Watermark window
# ---------------------------------------------------------------------------

class Watermark:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.attributes("-alpha", 0.90)
        self.root.configure(bg=BG_COL)
        self.root.resizable(False, False)

        self.cv = tk.Canvas(
            self.root, width=W, height=H,
            bg=BG_COL,
            highlightthickness=1, highlightbackground=BDR_COL,
        )
        self.cv.pack()

        # ── Row 1: status dot + label ──────────────────────────────────
        self.dot_id  = self.cv.create_oval(8, 6, 18, 16, fill="#2dba4e", outline="")
        self.text_id = self.cv.create_text(
            26, 11, anchor="w",
            text="RC Server   Running",
            fill="#e6edf3",
            font=("Segoe UI", 8),
        )

        # ── Separator ──────────────────────────────────────────────────
        self.cv.create_line(6, 22, W - 6, 22, fill=SEP_COL, width=1)

        # ── Row 2: live stats ──────────────────────────────────────────
        self.stats_id = self.cv.create_text(
            12, 33, anchor="w",
            text="",
            fill=_COL_IDLE,
            font=("Segoe UI", 7),
        )

        # ── Context menu ───────────────────────────────────────────────
        self.menu = tk.Menu(
            self.root, tearoff=0,
            bg="#161b22", fg="#e6edf3",
            activebackground="#1f6feb", activeforeground="#ffffff",
            font=("Segoe UI", 9),
        )
        self.menu.add_command(label="▶  Start Service",   command=self._start)
        self.menu.add_command(label="■  Stop Service",    command=self._stop)
        self.menu.add_command(label="↺  Restart Service", command=self._restart)
        self.menu.add_separator()
        self.menu.add_command(label="⏻  Shutdown All",    command=self._shutdown_all)
        self.menu.add_separator()
        self.menu.add_command(label="📄  View Logs",       command=self._logs)
        self.menu.add_separator()
        self.menu.add_command(label="✕  Close Indicator", command=self.root.destroy)

        # ── Bindings ───────────────────────────────────────────────────
        self.cv.bind("<ButtonPress-1>",   self._drag_start)
        self.cv.bind("<B1-Motion>",       self._drag_move)
        self.cv.bind("<Button-3>",        self._show_menu)
        self.cv.bind("<Double-Button-1>", self._logs)

        self.cmd_queue = queue.Queue()
        threading.Thread(target=self._cmd_worker, daemon=True).start()

        self._place_default()
        self._poll()
        self.root.mainloop()

    # ── Command queue worker ─────────────────────────────────────────

    def _cmd_worker(self):
        while True:
            cmd = self.cmd_queue.get()
            if cmd is None:
                break
            
            if cmd == "start":
                if not _run_admin_cmd(f"net start {SERVICE_NAME}"):
                    self.root.after(0, lambda: mb.showwarning("RC Server", "Could not start service.\nTry running as Administrator."))
            elif cmd == "stop":
                if not _run_admin_cmd(f"net stop {SERVICE_NAME}"):
                    self.root.after(0, lambda: mb.showwarning("RC Server", "Could not stop service.\nTry running as Administrator."))
    # ── Positioning ──────────────────────────────────────────────────

    def _place_default(self):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"{W}x{H}+{sw - W - 10}+{sh - H - 46}")

    # ── Polling ──────────────────────────────────────────────────────

    def _poll(self):
        status = _get_status()

        if status == "not_installed":
            self.root.destroy()
            return

        cfg = _STATUS_CFG.get(status)
        if cfg is None:
            self.root.after(POLL_MS, self._poll)
            return

        dot_col, txt_col, label = cfg
        self.cv.itemconfig(self.dot_id,  fill=dot_col)
        self.cv.itemconfig(self.text_id, fill=txt_col, text=label)

        stats_text, stats_col = _fmt_stats(_read_stats(), status)
        self.cv.itemconfig(self.stats_id, text=stats_text, fill=stats_col)

        self.root.deiconify()
        self.root.after(POLL_MS, self._poll)

    # ── Drag ─────────────────────────────────────────────────────────

    def _drag_start(self, event):
        self._dx, self._dy = event.x, event.y

    def _drag_move(self, event):
        x = self.root.winfo_x() + event.x - self._dx
        y = self.root.winfo_y() + event.y - self._dy
        self.root.geometry(f"+{x}+{y}")

    # ── Context menu ─────────────────────────────────────────────────

    def _show_menu(self, event):
        self.menu.tk_popup(event.x_root, event.y_root)

    def _start(self):
        self.cmd_queue.put("start")

    def _stop(self):
        self.cmd_queue.put("stop")

    def _restart(self):
        self.cmd_queue.put("stop")
        self.cmd_queue.put("start")

    def _shutdown_all(self):
        self._stop()
        self.root.destroy()

    def _logs(self, _event=None):
        if os.path.exists(LOG_FILE):
            subprocess.Popen(["notepad", LOG_FILE])
        else:
            mb.showinfo("RC Server", f"Log file not found:\n{LOG_FILE}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    Watermark()
