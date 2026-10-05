"""
Sanity tests for the crypto/ package primitives.

Run with:  pytest tests/test_crypto_primitives.py -v

These are not exhaustive; they verify that each primitive does what its
docstring claims. Integration tests (multi-primitive workflows) come in
later phases.
"""

import os

import pytest

from crypto import aes_gcm, hashing, homomorphic, kdf, ml_kem, signatures


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------

def test_sha256_known_vector():
    # FIPS 180-4 test vector: SHA-256 of "abc"
    digest = hashing.sha256_hex(b"abc")
    assert digest == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_integrity_detects_tampering():
    original = b"transfer 100 NGN to account X"
    tampered = b"transfer 999 NGN to account X"
    h1 = hashing.sha256_hex(original)
    h2 = hashing.sha256_hex(tampered)
    assert h1 != h2
    assert hashing.verify_sha256(original, h1) is True
    assert hashing.verify_sha256(tampered, h1) is False


def test_hmac_roundtrip():
    key = b"shared-secret-key"
    msg = b"payload"
    tag = hashing.hmac_sha256(key, msg)
    assert hashing.verify_hmac_sha256(key, msg, tag)
    assert not hashing.verify_hmac_sha256(key, b"other", tag)


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

def test_hkdf_deterministic_with_same_salt():
    secret = os.urandom(32)
    salt = kdf.new_salt()
    k1 = kdf.derive_key(secret, salt=salt, info=b"purpose-1")
    k2 = kdf.derive_key(secret, salt=salt, info=b"purpose-1")
    assert k1 == k2
    assert len(k1) == 32


def test_hkdf_different_info_gives_different_keys():
    secret = os.urandom(32)
    salt = kdf.new_salt()
    k1 = kdf.derive_key(secret, salt=salt, info=b"encryption")
    k2 = kdf.derive_key(secret, salt=salt, info=b"authentication")
    assert k1 != k2


def test_hkdf_rejects_short_secret():
    with pytest.raises(kdf.KDFError):
        kdf.derive_key(b"short", length=32)


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

def test_aes_gcm_roundtrip():
    key = aes_gcm.generate_key()
    plaintext = b"Organizational secret."
    aad = b"sender=doctor001|recipient=lab001"

    payload = aes_gcm.encrypt(plaintext, key, associated_data=aad)
    recovered = aes_gcm.decrypt(payload, key, associated_data=aad)
