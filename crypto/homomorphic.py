"""
crypto/homomorphic.py
---------------------
Privacy-preserving analytics with TenSEAL BFV homomorphic encryption.

PURPOSE
-------
Allow a server to perform arithmetic on encrypted integers without ever
seeing the plaintext values. In this project it supports a supplementary
analytics use case: an untrusted compute node can sum encrypted metrics
from multiple sources and return the encrypted result, which only the
data owner can decrypt.

WHAT THIS IS NOT
----------------
- Homomorphic encryption is NOT a replacement for AES-GCM for messaging.
  It is orders of magnitude slower and only supports specific arithmetic
  operations. It is used here for a narrowly scoped demonstration.
- The BFV scheme in TenSEAL supports integer addition and multiplication
  (with depth limits). It does not support arbitrary computation.

PARAMETERS
----------
poly_modulus_degree = 4096
plain_modulus       = 1032193  (a prime, supports batching up to 4096 slots)

These are lightweight parameters suitable for a demonstration on modest
hardware. They provide limited multiplicative depth (~2-3 levels). Do not
change without re-running the benchmarks.
"""

import base64

import tenseal as ts

from config import Config


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_LABEL = "BFV (TenSEAL)"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class HomomorphicError(ValueError):
    """Raised when homomorphic operations fail."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def new_context() -> ts.Context:
    """
    Build a fresh BFV context.

    In production, the context (specifically the secret key) should be held
    only by the data owner. Here it is used within a single process, which
    is acceptable for demonstration.
    """
    ctx = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=Config.HE_POLY_MODULUS_DEGREE,
        plain_modulus=Config.HE_PLAIN_MODULUS,
    )
    ctx.generate_galois_keys()
    return ctx


def encrypt_vector(context: ts.Context, values: list[int]) -> bytes:
    """Encrypt a list of integers into a BFV vector. Returns serialized bytes."""
    if not all(isinstance(v, int) for v in values):
        raise HomomorphicError("BFV vector values must all be integers.")
    vec = ts.bfv_vector(context, values)
    return vec.serialize()


def add_encrypted(context: ts.Context, a_bytes: bytes, b_bytes: bytes) -> bytes:
    """
    Add two encrypted vectors without decrypting either one.

    The result is a ciphertext that, when decrypted by the owner of the
    context's secret key, yields the element-wise sum of the two plaintexts.
    """
    a = ts.bfv_vector_from(context, a_bytes)
    b = ts.bfv_vector_from(context, b_bytes)
    return (a + b).serialize()


def decrypt_vector(context: ts.Context, ciphertext_bytes: bytes) -> list[int]:
    """Decrypt a serialized BFV vector. Only the secret-key holder can do this."""
    vec = ts.bfv_vector_from(context, ciphertext_bytes)
    return vec.decrypt()


def serialize_for_storage(ciphertext_bytes: bytes) -> str:
    """Base64-encode a ciphertext for Firestore storage."""
    return base64.b64encode(ciphertext_bytes).decode("ascii")


def deserialize_from_storage(blob: str) -> bytes:
    """Reverse of serialize_for_storage."""
    return base64.b64decode(blob)
