"""
crypto
------
Cryptographic primitives for CRYPTO-NET.

Every module in this package is a thin, well-documented wrapper around a
proven library. No cryptographic primitive is implemented from scratch.

Module map
----------
hashing.py      SHA-256 integrity fingerprinting; HMAC helpers.
kdf.py          HKDF-SHA-256 session key derivation from shared secrets.
aes_gcm.py      AES-256-GCM authenticated encryption for payloads.
ml_kem.py       ML-KEM-768 post-quantum key establishment (KEM).
signatures.py   Ed25519 digital signatures (classical, not post-quantum).
homomorphic.py  TenSEAL BFV privacy-preserving analytics.
cpabe.py        Bethencourt-Sahai-Waters CP-ABE (local demonstration only).
access_control.py  Policy-Based Access Control (PBAC) for deployment.

Design rules
------------
- No hardcoded secrets.
- No homemade cryptography.
- Every module exposes a narrow, well-typed public API.
- Every module raises specific exceptions, never bare Exception.
"""

__all__ = [
    "hashing",
    "kdf",
    "aes_gcm",
    "ml_kem",
    "signatures",
    "homomorphic",
]
