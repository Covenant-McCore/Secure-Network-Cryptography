"""
crypto/signatures.py
--------------------
Digital signatures for authenticity and non-repudiation.

SCHEME USED
-----------
Ed25519 — an Edwards-curve Digital Signature Algorithm defined in RFC 8032.
- 128-bit classical security.
- Deterministic signatures (no RNG at signing time).
- Fast, compact: 32-byte public keys, 64-byte signatures.

WHY NOT ML-DSA (Dilithium) HERE
-------------------------------
The thesis targets post-quantum signatures via ML-DSA (FIPS 204). A
standards-compliant ML-DSA implementation is available via the `pqcrypto`
or `liboqs-python` packages, but both require native compilation of the
liboqs C library, which is not available on the Railway buildpack and
adds significant local complexity.

Decision (recorded in the thesis, Chapter 5 — Limitations):
- The project implements ML-KEM-768 for post-quantum KEY ESTABLISHMENT
  (see ml_kem.py), which is the more security-critical primitive for
  protecting future communications.
- For DIGITAL SIGNATURES, the project uses Ed25519 as a reliable,
  standards-based classical signature. ML-DSA is documented as future
  work.
- The signature module is written against an abstract interface so that
  swapping Ed25519 for ML-DSA later requires changing only this file.

WHAT SIGNATURES PROVIDE
-----------------------
- Authenticity: only the holder of the private key could have produced
  the signature.
- Integrity: any modification invalidates the signature.
- Non-repudiation: the signer cannot later deny having signed, provided
  the private key was not compromised.

WHAT SIGNATURES DO NOT PROVIDE
------------------------------
- Confidentiality. A signature does not hide the message.
"""

from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_LABEL = "Ed25519"
POST_QUANTUM = False  # Honest label: Ed25519 is classical.

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SignatureError(ValueError):
    """Raised when signature verification fails or inputs are malformed."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an Ed25519 keypair.

    Returns
    -------
    (private_key_bytes, public_key_bytes)
        private_key: 32 raw bytes
        public_key:  32 raw bytes

    The private key is returned in raw form so the caller (key service) can
    apply its own persistence policy. Never store this in Firestore.
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def sign(message: bytes, private_key_bytes: bytes) -> bytes:
    """
    Produce a 64-byte signature over a message.

    Parameters
    ----------
    message : bytes
    private_key_bytes : bytes
        Raw 32-byte Ed25519 private key.

    Returns
    -------
    signature : bytes (64)
    """
    if len(private_key_bytes) != 32:
        raise SignatureError("Ed25519 private key must be 32 bytes.")
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def verify(message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify a signature. Returns True if valid, False otherwise.

    Never raises on invalid signatures — only on malformed inputs.
    """
    if len(public_key_bytes) != PUBLIC_KEY_BYTES:
        raise SignatureError("Ed25519 public key must be 32 bytes.")
    if len(signature) != SIGNATURE_BYTES:
        raise SignatureError("Ed25519 signature must be 64 bytes.")

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def sign_detached(message: bytes, private_key_bytes: bytes) -> dict:
    """
    Convenience wrapper that returns metadata alongside the signature.
    Useful for storage in Firestore and audit logging.
    """
    return {
        "signature": sign(message, private_key_bytes),
        "algorithm": ALGORITHM_LABEL,
        "post_quantum": POST_QUANTUM,
    }
