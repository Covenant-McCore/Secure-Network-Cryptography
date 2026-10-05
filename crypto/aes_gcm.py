"""
crypto/aes_gcm.py
-----------------
AES-256-GCM authenticated symmetric encryption.

PURPOSE
-------
Provide confidentiality and integrity for arbitrary-length payloads.

  - Confidentiality: the ciphertext reveals nothing about the plaintext.
  - Integrity: the 16-byte GCM tag detects any modification of ciphertext,
    associated data, nonce, or tag.
  - Authenticity (weak): the tag also proves the sender knew the key.
    For non-repudiation, combine with a digital signature.

WHY GCM
-------
- AEAD (Authenticated Encryption with Associated Data) — one primitive
  gives both confidentiality and integrity.
- Standardised (NIST SP 800-38D).
- Hardware-accelerated on modern CPUs (AES-NI), so very fast.

CRITICAL RULES
--------------
1. NEVER reuse a (key, nonce) pair. We generate a fresh 12-byte random
   nonce for every encryption; the birthday bound for 96-bit nonces under
   a single key is about 2^32 messages, which is far beyond our use.
2. NEVER truncate or ignore the authentication tag. If decryption fails
   the tag check, treat the ciphertext as hostile.
3. Associated Data (AAD) is authenticated but not encrypted. Use it for
   metadata you want bound to the ciphertext, e.g. sender_id, recipient_id,
   message_id.
"""

import os
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_BYTES = 32      # AES-256
NONCE_BYTES = 12    # 96-bit GCM nonce (NIST recommended)
TAG_BYTES = 16      # 128-bit GCM tag

ALGORITHM_LABEL = "AES-256-GCM"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class DecryptionError(ValueError):
    """Raised when AES-GCM decryption fails (tampered or wrong key)."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """Generate a fresh AES-256 key."""
    return get_random_bytes(KEY_BYTES)


def encrypt(plaintext: bytes, key: bytes,
            associated_data: Optional[bytes] = None) -> dict:
    """
    Encrypt a byte string with AES-256-GCM.

    Parameters
    ----------
    plaintext : bytes
    key : bytes
        Exactly 32 bytes.
    associated_data : bytes, optional
        Additional data to authenticate but not encrypt. Use for metadata
        such as sender/recipient identifiers.

    Returns
    -------
    dict with base64-encodable byte fields:
        {
            "ciphertext": bytes,
            "nonce":      bytes (12),
            "tag":        bytes (16),
            "algorithm":  "AES-256-GCM",
        }
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"AES-256 key must be {KEY_BYTES} bytes.")

    cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(NONCE_BYTES))
    if associated_data:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "ciphertext": ciphertext,
        "nonce": cipher.nonce,
        "tag": tag,
        "algorithm": ALGORITHM_LABEL,
    }


def decrypt(payload: dict, key: bytes,
            associated_data: Optional[bytes] = None) -> bytes:
    """
    Reverse of encrypt().

    Raises
    ------
    DecryptionError
        If the tag does not verify. This means the ciphertext, nonce, tag,
        associated data, or key is wrong. We do not distinguish these cases
        in the error message to avoid leaking information.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"AES-256 key must be {KEY_BYTES} bytes.")

    nonce = payload["nonce"]
    tag = payload["tag"]
    ciphertext = payload["ciphertext"]

    if len(nonce) != NONCE_BYTES:
        raise DecryptionError("Malformed nonce.")
    if len(tag) != TAG_BYTES:
        raise DecryptionError("Malformed authentication tag.")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if associated_data:
        cipher.update(associated_data)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        # pycryptodome raises ValueError("MAC check failed")
        raise DecryptionError("AES-GCM authentication failed.") from exc

