"""
Password Setup Utility
-----------------------
Interactively sets (or changes) the server authentication password.
Stores a PBKDF2-HMAC-SHA256 hash + salt in config.json – the plaintext
password is never written to disk.

Usage:
    python setup_password.py
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str):
    """Return (hash_b64, salt_b64) using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               PBKDF2_ITERATIONS)
    return base64.b64encode(dk).decode(), base64.b64encode(salt).decode()


def verify_password(password: str, stored_hash: str, salt_b64: str) -> bool:
    salt     = base64.b64decode(salt_b64)
    dk       = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                   PBKDF2_ITERATIONS)
    computed = base64.b64encode(dk).decode()
    return hmac.compare_digest(computed, stored_hash)


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"[ERROR] config.json not found at: {CONFIG_FILE}")
        sys.exit(1)
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--install", action="store_true",
                    help="Install mode: keep existing password if user presses Enter")
    args, _ = ap.parse_known_args()

    print("=" * 50)
    print("  Remote Command Server – Password Setup")
    print("=" * 50)
    print()

    cfg = load_config()

    if cfg.get("password_hash"):
        if args.install:
            # ── Install mode: let user skip by pressing Enter ──────────────
            print("  A password is already configured.")
            try:
                answer = input("  Press Enter to keep it, or type 'change' to set a new one: ").strip().lower()
            except KeyboardInterrupt:
                print("\n  Keeping existing password.")
                sys.exit(0)
            if answer != "change":
                print("[OK] Keeping existing password.")
                sys.exit(0)
            print()
        else:
            # ── Normal mode: require current password before changing ──────
            print("A password is already configured.")
            try:
                current = getpass.getpass("Enter current password to confirm change: ")
            except KeyboardInterrupt:
                print("\nCancelled.")
                sys.exit(0)
            if not verify_password(current, cfg["password_hash"], cfg["password_salt"]):
                print("[ERROR] Incorrect current password. Aborting.")
                sys.exit(1)
            print("[OK] Current password verified.")
            print()

    while True:
        try:
            new_pw  = getpass.getpass("Enter new password (min 10 chars): ")
            confirm = getpass.getpass("Confirm new password               : ")
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)

        if new_pw != confirm:
            print("[!] Passwords do not match. Try again.\n")
            continue
        if len(new_pw) < 10:
            print("[!] Password must be at least 10 characters.\n")
            continue
        break

    pwd_hash, pwd_salt = hash_password(new_pw)
    cfg["password_hash"] = pwd_hash
    cfg["password_salt"] = pwd_salt
    save_config(cfg)

    print()
    print("[OK] Password updated successfully.")
    print("     Start (or restart) the server for the new password to take effect.")


if __name__ == "__main__":
    main()
