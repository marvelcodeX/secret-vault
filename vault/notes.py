"""
notes.py
--------
High-level note operations.
Sits between the CLI and the crypto/storage layers.
"""

import uuid

from vault.crypto import (
    generate_salt,
    derive_note_key,
    encrypt_note,
    decrypt_note,
)
from vault.storage import (
    save_note,
    load_note,
    list_notes,
    delete_note,
    note_exists,
)
from vault.auth import session


def _new_id() -> str:
    """Generate a short unique note ID (first 8 chars of a UUID4)."""
    return uuid.uuid4().hex[:8]


# ── Create ─────────────────────────────────────────────────────────────────────

def add_note(title: str, body: str) -> str:
    """
    Encrypt and persist a new note.
    Returns the generated note ID.
    """
    master_key = session.get_key()
    note_salt  = generate_salt()
    note_key   = derive_note_key(master_key, note_salt)

    blob       = encrypt_note(body, note_key)
    blob["salt"] = note_salt.hex()      # attach salt so we can re-derive the key later

    note_id = _new_id()
    save_note(note_id, title, blob)
    return note_id


# ── Read ───────────────────────────────────────────────────────────────────────

def read_note(note_id: str) -> dict:
    """
    Decrypt and return a note as {"title": ..., "body": ..., "created_at": ..., "updated_at": ...}.
    Raises KeyError if the note doesn't exist.
    Raises ValueError on decryption failure.
    """
    master_key = session.get_key()
    record     = load_note(note_id)

    note_salt  = bytes.fromhex(record["salt"])
    note_key   = derive_note_key(master_key, note_salt)

    body = decrypt_note(
        {"nonce": record["nonce"], "tag": record["tag"], "cipher": record["cipher"]},
        note_key,
    )

    return {
        "title":      record["title"],
        "body":       body,
        "created_at": record.get("created_at", "—"),
        "updated_at": record.get("updated_at", "—"),
    }


# ── Update ─────────────────────────────────────────────────────────────────────

def update_note(note_id: str, new_title: str | None, new_body: str | None):
    """
    Update the title and/or body of an existing note.
    Re-encrypts with a fresh salt + nonce (forward secrecy for notes).
    """
    if not note_exists(note_id):
        raise KeyError(f"Note '{note_id}' not found.")

    # Decrypt existing note so we can merge changes
    existing = read_note(note_id)
    title    = new_title if new_title is not None else existing["title"]
    body     = new_body  if new_body  is not None else existing["body"]

    master_key = session.get_key()
    note_salt  = generate_salt()           # fresh salt on every update
    note_key   = derive_note_key(master_key, note_salt)

    blob           = encrypt_note(body, note_key)
    blob["salt"]   = note_salt.hex()

    save_note(note_id, title, blob)


# ── Delete ─────────────────────────────────────────────────────────────────────

def remove_note(note_id: str):
    """Delete a note permanently. Raises KeyError if not found."""
    delete_note(note_id)


# ── List ───────────────────────────────────────────────────────────────────────

def get_all_notes() -> list[dict]:
    """Return a list of note summaries (id, title, created_at, updated_at)."""
    return list_notes()