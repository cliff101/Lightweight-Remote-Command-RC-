"""
IP Security Manager
-------------------
Tracks failed authentication attempts per IP and enforces blocking rules:

  - 5 consecutive wrong passwords  →  temporary block for 1 minute
  - This cycle can repeat up to 3 times (3 × 5 = 15 total failures)
  - After the 3rd temporary block  →  IP is permanently blacklisted

Permanent blacklist is persisted to disk; temporary state lives in memory
and resets on server restart.
"""

import json
import os
import time
import threading
import logging

FAILURES_PER_ROUND  = 5    # wrong attempts before a temp block
TEMP_BLOCK_SECONDS  = 60   # how long a temp block lasts (seconds)
MAX_TEMP_BLOCKS     = 3    # temp-block cycles before permanent ban

logger = logging.getLogger("RemoteCommandServer")


class SecurityManager:
    def __init__(self, blacklist_file: str = "blacklist.json"):
        self.blacklist_file = blacklist_file
        self._lock = threading.Lock()

        # In-memory per-IP state (resets on server restart)
        self._failures:     dict = {}   # ip -> failures in current round
        self._block_count:  dict = {}   # ip -> number of temp blocks served
        self._blocked_until: dict = {}  # ip -> epoch timestamp when block expires

        # Persistent permanent blacklist
        self._permanent: set = set()
        self._load_blacklist()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_blocked(self, ip: str):
        """Return (True, reason_str) if the IP should be denied, else (False, None)."""
        with self._lock:
            if ip in self._permanent:
                return True, "IP is permanently blacklisted"

            until = self._blocked_until.get(ip)
            if until:
                remaining = until - time.time()
                if remaining > 0:
                    return True, f"IP temporarily blocked for {int(remaining)+1}s"
                else:
                    del self._blocked_until[ip]

            return False, None

    def record_failure(self, ip: str) -> str:
        """
        Register one failed authentication for an IP.

        Returns one of:
          "failed"        – recorded, not yet blocked
          "temp_blocked"  – 5th failure in round, now temp-blocked
          "permanent"     – 3rd temp-block reached, now permanent ban
        """
        with self._lock:
            self._failures.setdefault(ip, 0)
            self._block_count.setdefault(ip, 0)

            self._failures[ip] += 1

            if self._failures[ip] >= FAILURES_PER_ROUND:
                self._failures[ip] = 0          # reset round counter
                self._block_count[ip] += 1

                if self._block_count[ip] >= MAX_TEMP_BLOCKS:
                    self._permanent.add(ip)
                    self._save_blacklist()
                    logger.warning(f"[SECURITY] {ip} permanently blacklisted "
                                   f"after {MAX_TEMP_BLOCKS} temp-block cycles.")
                    return "permanent"
                else:
                    self._blocked_until[ip] = time.time() + TEMP_BLOCK_SECONDS
                    logger.warning(
                        f"[SECURITY] {ip} temp-blocked for {TEMP_BLOCK_SECONDS}s "
                        f"(cycle {self._block_count[ip]}/{MAX_TEMP_BLOCKS})."
                    )
                    return "temp_blocked"

            return "failed"

    def record_success(self, ip: str):
        """Reset per-round failure counter and block-cycle count on successful authentication."""
        with self._lock:
            self._failures.pop(ip, None)
            self._block_count.pop(ip, None)

    def get_failures(self, ip: str) -> int:
        """Current round failure count (0-4)."""
        with self._lock:
            return self._failures.get(ip, 0)

    def get_block_count(self, ip: str) -> int:
        """How many temp-block cycles this IP has accumulated."""
        with self._lock:
            return self._block_count.get(ip, 0)

    def remove_from_blacklist(self, ip: str) -> bool:
        """Manually remove an IP from the permanent blacklist. Returns True if it was there."""
        with self._lock:
            if ip in self._permanent:
                self._permanent.discard(ip)
                self._block_count.pop(ip, None)
                self._failures.pop(ip, None)
                self._blocked_until.pop(ip, None)
                self._save_blacklist()
                return True
            return False

    def list_blacklist(self) -> list:
        with self._lock:
            return sorted(self._permanent)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load_blacklist(self):
        if not os.path.exists(self.blacklist_file):
            return
        try:
            with open(self.blacklist_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._permanent = set(data.get("blacklist", []))
            logger.info(f"[SECURITY] Loaded {len(self._permanent)} permanently blacklisted IPs.")
        except Exception as e:
            logger.error(f"[SECURITY] Failed to load blacklist: {e}")
            self._permanent = set()

    def _save_blacklist(self):
        try:
            with open(self.blacklist_file, "w", encoding="utf-8") as f:
                json.dump({"blacklist": sorted(self._permanent)}, f, indent=2)
        except Exception as e:
            logger.error(f"[SECURITY] Failed to save blacklist: {e}")
