"""
crypto/kdf.py
-------------
HKDF-SHA-256 key derivation.

PURPOSE
-------
Turn a high-entropy shared secret (e.g. the output of ML-KEM-768
encapsulation) into one or more cryptographically independent session keys.

WHY IT'S NEEDED
---------------
A raw KEM shared secret is a uniform random byte string. If you use it
directly as an AES key, you lose the ability to:

  - derive multiple independent keys from the same secret (e.g. one for
    encryption, one for authentication, one for file transfer);
  - bind the key to a context string (e.g. "sender-abc/recipient-xyz/session-1")
    so that a key derived for one context cannot be reused in another;
  - produce keys of arbitrary length (KEM outputs are fixed-length).

HKDF solves all three.

CONSTRUCTION
------------
HKDF = HKDF-Extract || HKDF-Expand, per RFC 5869.

Extract:  PRK = HMAC-SHA-256(salt, IKM)
Expand:   OKM = HMAC-SHA-256(PRK, info || counter) iterated to fill the output.

We use it with a random salt and a caller-supplied context ("info") string.
"""

import os
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class KDFError(ValueError):
    """Raised when key derivation inputs are invalid."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def derive_key(
    shared_secret: bytes,
    length: int = 32,
    salt: Optional[bytes] = None,
    info: bytes | str = b"",
) -> bytes:
    """
    Derive a key of `length` bytes from a shared secret.

    Parameters
    ----------
    shared_secret : bytes
        High-entropy input keying material (e.g. KEM output).
    length : int
        Desired output length in bytes. Default 32 (AES-256).
    salt : bytes, optional
        Random per-session salt. If omitted, a fresh random 32-byte salt
        is generated. The caller MUST store the salt alongside the ciphertext
        if omitted, so the recipient can re-derive the same key.
    info : bytes or str
        Context string binding the key to its purpose. E.g.
        b"crypto-net/message/v1" or b"crypto-net/file/v1/session-42".

    Returns
    -------
    bytes of length `length`.
    """
    if not isinstance(shared_secret, (bytes, bytearray)) or len(shared_secret) < 16:
        raise KDFError("shared_secret must be at least 16 bytes.")
    if not (1 <= length <= 8160):  # RFC 5869 upper bound for SHA-256
        raise KDFError("length must be between 1 and 8160 bytes.")

    if isinstance(info, str):
        info = info.encode("utf-8")
    if salt is None:
        salt = os.urandom(32)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise KDFError("salt must be at least 8 bytes.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def derive_keys(
    shared_secret: bytes,
    purposes: dict[str, int],
    salt: Optional[bytes] = None,
) -> dict[str, bytes]:
    """
    Derive multiple keys with one call, each for a different purpose.

    Parameters
    ----------
    shared_secret : bytes
    purposes : dict[str, int]
        Mapping of purpose name -> desired key length in bytes.
        Example: {"encryption": 32, "authentication": 32}
    salt : bytes, optional

    Returns
    -------
    dict[str, bytes] mapping each purpose name to its derived key.

    Notes
    -----
    Each derived key is independent because HKDF-Expand includes the purpose
    name in its `info` parameter, domain-separating the outputs.
    """
    if salt is None:
        salt = os.urandom(32)
    return {
        name: derive_key(shared_secret, length=length, salt=salt, info=name.encode())
        for name, length in purposes.items()
    }


def new_salt(length: int = 32) -> bytes:
    """Generate a fresh random HKDF salt."""
    return os.urandom(length)

