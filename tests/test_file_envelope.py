"""Unit tests for file_envelope. No Firestore involvement."""

import pytest

from crypto import ml_kem, signatures
from crypto.file_envelope import (
    FileDecryptionError,
    FileSignatureError,
    open_file_envelope,
    seal_file,
)


@pytest.fixture
def keys():
    ed_priv, ed_pub = signatures.generate_keypair()
    kem_pub, kem_priv = ml_kem.keygen()
    return {
        "ed_priv": ed_priv, "ed_pub": ed_pub,
        "kem_pub": kem_pub, "kem_priv": kem_priv,
    }


def test_file_roundtrip(keys):
    content = b"CSV,header\n1,2,3\n"
    env = seal_file(
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_public_key=keys["kem_pub"],
        sender_ed25519_private_key=keys["ed_priv"],
        filename="results.csv",
        mimetype="text/csv",
        content=content,
    )
    assert env["fileSize"] == len(content)
    assert env["kemAlgorithm"] == "ML-KEM-768"

    out = open_file_envelope(
        env,
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_private_key=keys["kem_priv"],
        sender_ed25519_public_key=keys["ed_pub"],
    )
    assert out["filename"] == "results.csv"
    assert out["mimetype"] == "text/csv"
    assert out["content"] == content
    assert out["signature_verified"] is True
    assert out["hash_matches"] is True


def test_tampered_content_fails_signature(keys):
    env = seal_file(
        sender_id="d", recipient_id="l",
        recipient_mlkem_public_key=keys["kem_pub"],
        sender_ed25519_private_key=keys["ed_priv"],
        filename="a.txt", mimetype="text/plain",
        content=b"original",
    )
    # Flip a byte in the ciphertext (base64-encoded)
    c = env["contentCiphertext"]
    env["contentCiphertext"] = ("A" if c[0] != "A" else "B") + c[1:]
    with pytest.raises(FileSignatureError):
        open_file_envelope(
            env,
            sender_id="d", recipient_id="l",
            recipient_mlkem_private_key=keys["kem_priv"],
            sender_ed25519_public_key=keys["ed_pub"],
        )


def test_tampered_content_fails_gcm_when_signature_skipped(keys):
    env = seal_file(
        sender_id="d", recipient_id="l",
        recipient_mlkem_public_key=keys["kem_pub"],
        sender_ed25519_private_key=keys["ed_priv"],
        filename="a.txt", mimetype="text/plain",
        content=b"original",
    )
    c = env["contentCiphertext"]
    env["contentCiphertext"] = ("A" if c[0] != "A" else "B") + c[1:]
    with pytest.raises(FileDecryptionError):
        open_file_envelope(
            env,
            sender_id="d", recipient_id="l",
            recipient_mlkem_private_key=keys["kem_priv"],
            sender_ed25519_public_key=keys["ed_pub"],
            verify_signature_first=False,
        )
