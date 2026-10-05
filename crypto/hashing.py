"""
crypto/hashing.py
-----------------
SHA-256 and HMAC-SHA-256 helpers.

PURPOSE
-------
- SHA-256 produces a deterministic 32-byte fingerprint of a message or file.
  It is used for integrity verification: a receiver recomputes the hash and
  compares against the stored/transmitted value. Any single-bit change to
  the input produces a completely different digest.

- HMAC-SHA-256 is used when we need keyed authentication of a message,
  e.g. to bind a message to a shared secret.

WHAT THIS IS NOT
----------------
- SHA-256 is NOT encryption. It cannot be reversed.
- SHA-256 alone does NOT provide authenticity. Anyone can compute a hash of
  a modified message. For authenticity, use signatures.py or HMAC with a
  secret key.

SECURITY NOTES
--------------
- SHA-256 is collision-resistant for current practice (NIST still approves
  it for most uses). For post-quantum resistance of the hash itself, SHA-256
  with 256-bit output is currently considered adequate.
- Always compare digests in constant time using hmac.compare_digest to
  avoid timing side-channels.
"""

import hashlib
import hmac
from pathlib import Path


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class IntegrityError(ValueError):
    """Raised when a stored digest does not match a recomputed digest."""


# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of a byte string."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("sha256_hex expects bytes.")
    return hashlib.sha256(data).hexdigest()


def sha256_file_hex(path: str | Path, chunk_size: int = 65536) -> str:
    """
    Compute SHA-256 of a file without loading it fully into memory.

    Parameters
    ----------
    path : str or Path
    chunk_size : int
        Read size in bytes. 64 KiB is a good default.

    Returns
    -------
    Lowercase hex digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(data: bytes, expected_hex: str) -> bool:
    """
    Constant-time comparison of a recomputed digest against an expected one.

    Returns True if they match, False otherwise.
    """
    actual = sha256_hex(data)
    return hmac.compare_digest(actual, expected_hex.lower())


def assert_sha256(data: bytes, expected_hex: str) -> None:
    """
    Like verify_sha256 but raises IntegrityError on mismatch.
    """
    if not verify_sha256(data, expected_hex):
        raise IntegrityError("SHA-256 integrity check failed.")


# ---------------------------------------------------------------------------
# HMAC-SHA-256
# ---------------------------------------------------------------------------

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Return the raw HMAC-SHA-256 tag of a message under a key.

    Use for keyed integrity — only someone with the key can produce a
    valid tag. This is faster than a digital signature but requires
    both parties to share the key.
    """
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise ValueError("HMAC key must be non-empty bytes.")
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac_sha256(key: bytes, message: bytes, tag: bytes) -> bool:
    """Constant-time verification of an HMAC tag."""
    expected = hmac_sha256(key, message)
    return hmac.compare_digest(expected, tag)


