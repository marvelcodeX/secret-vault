"""
storage.py
----------
Handles all disk I/O for Secret Vault.

Vault file layout (vault_data.json):
{
    "config": {
        "master_salt":     "<hex>",   # salt used to derive/verify master key
        "master_verifier": "<hex>"    # SHA-256(master_key) for login check
    },
    "notes": {
        "<note_id>": {
            "title":     "<plaintext title>",
            "salt":      "<hex>",     # per-note salt
            "nonce":     "<hex>",
            "tag":       "<hex>",
            "cipher":    "<hex>",
            "created_at": "<ISO timestamp>",
            "updated_at": "<ISO timestamp>"
        },
        ...
    }
}
"""

import json
import os
from datetime import datetime

VAULT_DIR  = os.path.join(os.path.expanduser("~"), ".secret_vault")
VAULT_FILE = os.path.join(VAULT_DIR, "vault_data.json")


# ── Internal helpers ───────────────────────────────────────────────────────────

def _ensure_vault_dir():
    os.makedirs(VAULT_DIR, exist_ok=True)


def _load_raw() -> dict:
    """Load the raw vault JSON from disk. Returns empty structure if not found."""
    if not os.path.exists(VAULT_FILE):
        return {"config": {}, "notes": {}}
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_raw(data: dict):
    """Write the full vault dict to disk atomically (write-then-rename)."""
    _ensure_vault_dir()
    tmp_path = VAULT_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, VAULT_FILE)


def _now_iso() -> str:
    return datetime.now().isoformat(sep=" ", timespec="seconds")


# ── Config (master password setup) ────────────────────────────────────────────

def is_vault_initialized() -> bool:
    data = _load_raw()
    return bool(data["config"].get("master_salt"))


def save_master_config(master_salt: bytes, master_verifier: str):
    data = _load_raw()
    data["config"]["master_salt"]     = master_salt.hex()
    data["config"]["master_verifier"] = master_verifier
    _save_raw(data)


def load_master_config() -> dict:
    """
    Returns {"master_salt": bytes, "master_verifier": str}
    or raises RuntimeError if vault is not initialized.
    """
    data = _load_raw()
    cfg  = data.get("config", {})
    if not cfg.get("master_salt"):
        raise RuntimeError("Vault not initialized. Run the app and set a master password.")
    return {
        "master_salt":     bytes.fromhex(cfg["master_salt"]),
        "master_verifier": cfg["master_verifier"],
    }


# ── Notes CRUD ─────────────────────────────────────────────────────────────────

def save_note(note_id: str, title: str, crypto_blob: dict):
    """
    Write or overwrite a note entry.
    crypto_blob must contain: salt, nonce, tag, cipher (all hex strings).
    """
    data = _load_raw()
    now  = _now_iso()

    existing = data["notes"].get(note_id, {})
    data["notes"][note_id] = {
        "title":      title,
        "salt":       crypto_blob["salt"],
        "nonce":      crypto_blob["nonce"],
        "tag":        crypto_blob["tag"],
        "cipher":     crypto_blob["cipher"],
        "created_at": existing.get("created_at", now),
        "updated_at": now,
    }
    _save_raw(data)


def load_note(note_id: str) -> dict:
    """
    Return the full note record for note_id.
    Raises KeyError if not found.
    """
    data = _load_raw()
    if note_id not in data["notes"]:
        raise KeyError(f"Note '{note_id}' not found.")
    return data["notes"][note_id]


def list_notes() -> list[dict]:
    """
    Return a list of note summaries (id, title, created_at, updated_at).
    Sorted by creation time ascending.
    """
    data = _load_raw()
    summaries = []
    for note_id, note in data["notes"].items():
        summaries.append({
            "id":         note_id,
            "title":      note["title"],
            "created_at": note.get("created_at", "—"),
            "updated_at": note.get("updated_at", "—"),
        })
    return sorted(summaries, key=lambda n: n["created_at"])


def delete_note(note_id: str):
    """Remove a note by ID. Raises KeyError if not found."""
    data = _load_raw()
    if note_id not in data["notes"]:
        raise KeyError(f"Note '{note_id}' not found.")
    del data["notes"][note_id]
    _save_raw(data)


def note_exists(note_id: str) -> bool:
    data = _load_raw()
    return note_id in data["notes"]


def get_vault_path() -> str:
    return VAULT_FILE