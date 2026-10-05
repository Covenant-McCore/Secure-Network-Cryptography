"""
Unit tests for the message envelope. No Firestore involvement.
"""

import pytest

from crypto import ml_kem, signatures
from crypto.message_envelope import (
    DecryptionFailure,
    SignatureVerificationError,
    open_envelope,
    seal,
)


@pytest.fixture
def keypairs():
    # Sender: Ed25519 signing keypair
    sender_ed_priv, sender_ed_pub = signatures.generate_keypair()
    # Recipient: ML-KEM keypair
    recipient_kem_pub, recipient_kem_priv = ml_kem.keygen()
    return {
        "sender_ed_priv": sender_ed_priv,
        "sender_ed_pub": sender_ed_pub,
        "recipient_kem_pub": recipient_kem_pub,
        "recipient_kem_priv": recipient_kem_priv,
    }


def test_seal_and_open_roundtrip(keypairs):
    env = seal(
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_public_key=keypairs["recipient_kem_pub"],
        sender_ed25519_private_key=keypairs["sender_ed_priv"],
        subject="Test subject",
        body="Confidential lab results.",
    )
    assert "kemCiphertext" in env
    assert env["kemAlgorithm"] == "ML-KEM-768"

    result = open_envelope(
        env,
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_private_key=keypairs["recipient_kem_priv"],
        sender_ed25519_public_key=keypairs["sender_ed_pub"],
    )
    assert result["subject"] == "Test subject"
    assert result["body"] == "Confidential lab results."
    assert result["signature_verified"] is True
    assert result["message_hash_matches"] is True


def test_tampered_body_is_rejected(keypairs):
    env = seal(
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_public_key=keypairs["recipient_kem_pub"],
        sender_ed25519_private_key=keypairs["sender_ed_priv"],
        subject="S",
        body="B",
    )
    # Flip a byte in the body ciphertext
    original = env["bodyCiphertext"]
    tampered = ("A" if original[0] != "A" else "B") + original[1:]
    env["bodyCiphertext"] = tampered

    # Signature check must fail first
    with pytest.raises(SignatureVerificationError):
        open_envelope(
            env,
            sender_id="doctor001",
            recipient_id="lab001",
            recipient_mlkem_private_key=keypairs["recipient_kem_priv"],
            sender_ed25519_public_key=keypairs["sender_ed_pub"],
        )


def test_tampered_body_with_signature_disabled_fails_gcm(keypairs):
    env = seal(
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_public_key=keypairs["recipient_kem_pub"],
        sender_ed25519_private_key=keypairs["sender_ed_priv"],
        subject="S",
        body="B",
    )
    original = env["bodyCiphertext"]
    tampered = ("A" if original[0] != "A" else "B") + original[1:]
    env["bodyCiphertext"] = tampered

    with pytest.raises(DecryptionFailure):
        open_envelope(
            env,
            sender_id="doctor001",
            recipient_id="lab001",
            recipient_mlkem_private_key=keypairs["recipient_kem_priv"],
            sender_ed25519_public_key=keypairs["sender_ed_pub"],
            verify_signature_first=False,
        )


def test_wrong_sender_key_fails_signature(keypairs):
    env = seal(
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_public_key=keypairs["recipient_kem_pub"],
        sender_ed25519_private_key=keypairs["sender_ed_priv"],
        subject="S",
        body="B",
    )
    other_priv, other_pub = signatures.generate_keypair()
    with pytest.raises(SignatureVerificationError):
        open_envelope(
            env,
            sender_id="doctor001",
            recipient_id="lab001",
            recipient_mlkem_private_key=keypairs["recipient_kem_priv"],
            sender_ed25519_public_key=other_pub,
        )


def test_wrong_recipient_kem_key_fails_decryption(keypairs):
    env = seal(
        sender_id="doctor001",
        recipient_id="lab001",
        recipient_mlkem_public_key=keypairs["recipient_kem_pub"],
        sender_ed25519_private_key=keypairs["sender_ed_priv"],
        subject="S",
        body="B",
    )
    # Different recipient's KEM private key
    _, other_kem_priv = ml_kem.keygen()
    with pytest.raises(DecryptionFailure):
        open_envelope(
            env,
            sender_id="doctor001",
            recipient_id="lab001",
            recipient_mlkem_private_key=other_kem_priv,
            sender_ed25519_public_key=keypairs["sender_ed_pub"],
            verify_signature_first=False,
        )
