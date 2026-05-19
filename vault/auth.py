"""
auth.py
-------
Handles master password setup, verification, and in-memory session.

The master key is NEVER written to disk.
It lives only in the Session object for the duration of the process.
"""

import getpass

from vault.crypto import (
    generate_salt,
    derive_master_key,
    hash_master_password,
)
from vault.storage import (
    is_vault_initialized,
    save_master_config,
    load_master_config,
)


# ── Session (in-memory only) ───────────────────────────────────────────────────

class Session:
    """Holds the derived master key for the current run. Never persisted."""

    def __init__(self):
        self._master_key: bytes | None = None

    def set_key(self, key: bytes):
        self._master_key = key

    def get_key(self) -> bytes:
        if self._master_key is None:
            raise RuntimeError("Not authenticated. Please log in first.")
        return self._master_key

    def is_authenticated(self) -> bool:
        return self._master_key is not None

    def clear(self):
        self._master_key = None


# Module-level singleton
session = Session()


# ── Setup ──────────────────────────────────────────────────────────────────────

def setup_master_password() -> bool:
    """
    First-time vault setup: prompt the user to choose a master password.
    Derives and stores the salt + verifier. Returns True on success.
    """
    print("\n  ┌─────────────────────────────────────┐")
    print("  │   🔐  Create your Master Password   │")
    print("  └─────────────────────────────────────┘")
    print("  This password encrypts every note. It cannot be recovered if lost.\n")

    while True:
        password = getpass.getpass("  Choose a master password: ").strip()
        if len(password) < 8:
            print("  ⚠  Password must be at least 8 characters. Try again.\n")
            continue
        confirm = getpass.getpass("  Confirm master password:  ").strip()
        if password != confirm:
            print("  ⚠  Passwords do not match. Try again.\n")
            continue
        break

    print("\n  ⏳  Deriving key (this takes a moment for security)…", end="", flush=True)
    master_salt     = generate_salt()
    master_verifier = hash_master_password(password, master_salt)
    master_key      = derive_master_key(password, master_salt)
    save_master_config(master_salt, master_verifier)
    session.set_key(master_key)
    print(" done.\n")
    print("  ✅  Vault created successfully!\n")
    return True


# ── Login ──────────────────────────────────────────────────────────────────────

def login(max_attempts: int = 3) -> bool:
    """
    Prompt for the master password, verify it, and populate the session.
    Returns True on success, False after max_attempts failures.
    """
    cfg = load_master_config()

    print("\n  ┌────────────────────────────────┐")
    print("  │   🔐  Secret Vault — Login     │")
    print("  └────────────────────────────────┘\n")

    for attempt in range(1, max_attempts + 1):
        password = getpass.getpass("  Master password: ").strip()

        print("  ⏳  Verifying…", end="", flush=True)
        candidate_verifier = hash_master_password(password, cfg["master_salt"])
        print(" done.")

        if candidate_verifier == cfg["master_verifier"]:
            master_key = derive_master_key(password, cfg["master_salt"])
            session.set_key(master_key)
            print("  ✅  Access granted.\n")
            return True
        else:
            remaining = max_attempts - attempt
            if remaining > 0:
                print(f"  ❌  Wrong password. {remaining} attempt(s) remaining.\n")
            else:
                print("  ❌  Too many failed attempts. Exiting.\n")

    return False


# ── Entry point helper ─────────────────────────────────────────────────────────

def authenticate() -> bool:
    """
    Called once at startup.
    Sets up the vault on first run, or logs in on subsequent runs.
    Returns True if the user is authenticated.
    """
    if not is_vault_initialized():
        return setup_master_password()
    else:
        return login()