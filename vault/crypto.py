"""
crypto.py
---------
All cryptographic operations for Secret Vault.

Design:
  - Master password  →  PBKDF2-HMAC-SHA256  →  master key (32 bytes)
  - Each note gets its own random 16-byte salt  →  PBKDF2  →  note key (32 bytes)
  - Notes are encrypted with AES-256 in GCM mode (authenticated encryption).
  - GCM produces a 16-byte authentication tag that detects tampering.

Stored per note:
  {
      "salt":   <hex>,   # 16-byte random salt for this note's key
      "nonce":  <hex>,   # 12-byte GCM nonce (random per encryption)
      "tag":    <hex>,   # 16-byte GCM authentication tag
      "cipher": <hex>    # encrypted note body
  }
"""

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ──────────────────────────────────────────────────────────────────
PBKDF2_ITERATIONS = 600_000   # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
KEY_LENGTH        = 32        # 256-bit AES key
SALT_LENGTH       = 16        # bytes
NONCE_LENGTH      = 12        # bytes (96-bit GCM nonce)


# ── Key Derivation ─────────────────────────────────────────────────────────────

def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit master key from the user's password using PBKDF2-HMAC-SHA256.
    The salt is stored in the vault config and is unique per vault installation.
    """
    return hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = password.encode("utf-8"),
        salt        = salt,
        iterations  = PBKDF2_ITERATIONS,
        dklen       = KEY_LENGTH,
    )


def derive_note_key(master_key: bytes, note_salt: bytes) -> bytes:
    """
    Derive a per-note 256-bit key by running one more round of PBKDF2
    with the master key as the 'password' and the note's unique salt.
    This means even if one note key leaks, the master key is not exposed.
    """
    return hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = master_key,          # master key feeds into note KDF
        salt        = note_salt,
        iterations  = 100_000,
        dklen       = KEY_LENGTH,
    )


def generate_salt() -> bytes:
    """Return a cryptographically random 16-byte salt."""
    return os.urandom(SALT_LENGTH)


def generate_nonce() -> bytes:
    """Return a cryptographically random 12-byte GCM nonce."""
    return os.urandom(NONCE_LENGTH)


# ── AES-GCM Encrypt / Decrypt ──────────────────────────────────────────────────

def encrypt_note(plaintext: str, note_key: bytes) -> dict:
    """
    Encrypt a note string with AES-256-GCM.

    Returns a dict with hex-encoded fields:
        nonce, tag, cipher
    (salt is managed by the caller and stored separately)
    """
    nonce     = generate_nonce()
    aesgcm    = AESGCM(note_key)
    # AESGCM.encrypt returns ciphertext + 16-byte tag appended
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Split ciphertext and tag (tag is last 16 bytes)
    ciphertext = ct_with_tag[:-16]
    tag        = ct_with_tag[-16:]

    return {
        "nonce":  nonce.hex(),
        "tag":    tag.hex(),
        "cipher": ciphertext.hex(),
    }


def decrypt_note(crypto_blob: dict, note_key: bytes) -> str:
    """
    Decrypt a note from its stored crypto blob.
    Raises ValueError if authentication fails (tampered data or wrong key).
    """
    nonce      = bytes.fromhex(crypto_blob["nonce"])
    tag        = bytes.fromhex(crypto_blob["tag"])
    ciphertext = bytes.fromhex(crypto_blob["cipher"])

    aesgcm = AESGCM(note_key)
    # Re-join ciphertext + tag for AESGCM.decrypt
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password or data is corrupted/tampered.")

    return plaintext.decode("utf-8")


# ── Password Hashing (for master password verification) ────────────────────────

def hash_master_password(password: str, salt: bytes) -> str:
    """
    Produce a hex digest to store as the master password verifier.
    We don't store the password itself — just enough to verify it on login.
    """
    key = derive_master_key(password, salt)
    return hashlib.sha256(key).hexdigest()