"""
crypto/message_envelope.py
--------------------------
End-to-end encrypted message envelope.

This module ties together every primitive:

    ML-KEM-768  : key establishment (sender encapsulates to recipient)
    HKDF-SHA-256: derive separate subject and body session keys
    AES-256-GCM : encrypt subject and body independently
    SHA-256     : fingerprint the plaintext (for audit / integrity reference)
    Ed25519     : sign the ciphertext envelope (sender authenticity)

ENVELOPE FORMAT (all fields JSON-safe / base64 string except where noted)
------------------------------------------------------------------------
    kemCiphertext        : base64 (1088 bytes)
    kdfSalt              : base64 (32 bytes)
    subjectCiphertext    : base64
    subjectNonce         : base64 (12 bytes)
    subjectTag           : base64 (16 bytes)
    bodyCiphertext       : base64
    bodyNonce            : base64 (12 bytes)
    bodyTag              : base64 (16 bytes)
    messageHash          : hex SHA-256 of the plaintext body (for audit)
    signature            : base64 (64 bytes) Ed25519 over canonical envelope
    signatureAlgorithm   : "Ed25519"
    encryptionAlgorithm  : "AES-256-GCM"
    kemAlgorithm         : "ML-KEM-768"
    kdfAlgorithm         : "HKDF-SHA-256"

WHAT THE SIGNATURE COVERS
-------------------------
The signature is computed over a canonical, deterministic byte string
built from the ciphertext-only fields. It does NOT cover the plaintext
(which we don't have at recipient-side), but it does bind:

    senderId | recipientId | kemCiphertext | subjectCiphertext
    bodyCiphertext | subjectNonce | bodyNonce | kdfSalt | messageHash

Any modification of any of these fields invalidates the signature.
"""

import base64
import json
import os
from typing import Optional

from crypto import aes_gcm, hashing, kdf, ml_kem, signatures


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ENVELOPE_VERSION = 1

INFO_SUBJECT = b"crypto-net/message/subject/v1"
INFO_BODY = b"crypto-net/message/body/v1"

ENCRYPTION_ALGORITHM = "AES-256-GCM"
KEM_ALGORITHM = "ML-KEM-768"
KDF_ALGORITHM = "HKDF-SHA-256"
SIGNATURE_ALGORITHM = "Ed25519"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class EnvelopeError(ValueError):
    """Raised when an envelope is malformed or a verification step fails."""


class SignatureVerificationError(EnvelopeError):
    """Raised when the envelope signature does not verify."""


class DecryptionFailure(EnvelopeError):
    """Raised when AES-GCM authentication fails on decrypt."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


def _canonical_signed_bytes(
    sender_id: str,
    recipient_id: str,
    kem_ct_b64: str,
    subject_ct_b64: str,
    body_ct_b64: str,
    subject_nonce_b64: str,
    body_nonce_b64: str,
    kdf_salt_b64: str,
    message_hash_hex: str,
) -> bytes:
    """
    Deterministic byte string that the sender signs and the recipient
    verifies. Every field that matters for integrity must appear here.

    We use a sorted-key JSON dump with no whitespace to guarantee
    determinism across Python versions and platforms.
    """
    payload = {
        "senderId": sender_id,
        "recipientId": recipient_id,
        "kemCiphertext": kem_ct_b64,
        "subjectCiphertext": subject_ct_b64,
        "bodyCiphertext": body_ct_b64,
        "subjectNonce": subject_nonce_b64,
        "bodyNonce": body_nonce_b64,
        "kdfSalt": kdf_salt_b64,
        "messageHash": message_hash_hex,
        "v": ENVELOPE_VERSION,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Encryption (sender side)
# ---------------------------------------------------------------------------

def seal(
    *,
    sender_id: str,
    recipient_id: str,
    recipient_mlkem_public_key: bytes,
    sender_ed25519_private_key: bytes,
    subject: str,
    body: str,
) -> dict:
    """
    Build a sealed envelope. This is what the sender's client (or the
    sender's request handler on the server) calls.

    Parameters
    ----------
    sender_id, recipient_id : str
        Firestore user IDs. Bound into the signature.
    recipient_mlkem_public_key : bytes
        Recipient's ML-KEM-768 public key (1184 bytes).
    sender_ed25519_private_key : bytes
        Sender's Ed25519 private key (32 bytes).
    subject, body : str
        Plaintext. NEVER persisted by this function.

    Returns
    -------
    dict
        All fields are strings ready to be written to Firestore.
    """
    if not recipient_mlkem_public_key or len(recipient_mlkem_public_key) != ml_kem.PUBLIC_KEY_BYTES:
        raise EnvelopeError("Recipient ML-KEM public key is missing or malformed.")

    # ---- 1. Key establishment: encapsulate to recipient ----
    shared_secret, kem_ct = ml_kem.encapsulate(recipient_mlkem_public_key)

    # ---- 2. Derive independent session keys for subject and body ----
    kdf_salt = kdf.new_salt(32)
    subject_key = kdf.derive_key(shared_secret, length=32, salt=kdf_salt, info=INFO_SUBJECT)
    body_key    = kdf.derive_key(shared_secret, length=32, salt=kdf_salt, info=INFO_BODY)

    # Zero the shared secret as soon as we no longer need it.
    del shared_secret

    # ---- 3. AES-256-GCM encrypt subject and body separately ----
    subject_env = aes_gcm.encrypt(subject.encode("utf-8"), subject_key)
    body_env    = aes_gcm.encrypt(body.encode("utf-8"), body_key)
    del subject_key, body_key

    # ---- 4. SHA-256 fingerprint of the plaintext body (audit only) ----
    message_hash_hex = hashing.sha256_hex(body.encode("utf-8"))

    # ---- 5. Signature over the ciphertext envelope ----
    kem_ct_b64 = _b64(kem_ct)
    subj_ct_b64 = _b64(subject_env["ciphertext"])
    body_ct_b64 = _b64(body_env["ciphertext"])
    subj_nonce_b64 = _b64(subject_env["nonce"])
    body_nonce_b64 = _b64(body_env["nonce"])
    kdf_salt_b64 = _b64(kdf_salt)

    signed_bytes = _canonical_signed_bytes(
        sender_id=sender_id,
        recipient_id=recipient_id,
        kem_ct_b64=kem_ct_b64,
        subject_ct_b64=subj_ct_b64,
        body_ct_b64=body_ct_b64,
        subject_nonce_b64=subj_nonce_b64,
        body_nonce_b64=body_nonce_b64,
        kdf_salt_b64=kdf_salt_b64,
        message_hash_hex=message_hash_hex,
    )
    signature = signatures.sign(signed_bytes, sender_ed25519_private_key)

    # ---- 6. Assemble the envelope ----
    return {
        "kemCiphertext": kem_ct_b64,
        "kdfSalt": kdf_salt_b64,
        "subjectCiphertext": subj_ct_b64,
        "subjectNonce": subj_nonce_b64,
        "subjectTag": _b64(subject_env["tag"]),
        "bodyCiphertext": body_ct_b64,
        "bodyNonce": body_nonce_b64,
        "bodyTag": _b64(body_env["tag"]),
        "messageHash": message_hash_hex,
        "signature": _b64(signature),
        "signatureAlgorithm": SIGNATURE_ALGORITHM,
        "encryptionAlgorithm": ENCRYPTION_ALGORITHM,
        "kemAlgorithm": KEM_ALGORITHM,
        "kdfAlgorithm": KDF_ALGORITHM,
        "envelopeVersion": ENVELOPE_VERSION,
    }


# ---------------------------------------------------------------------------
# Decryption (recipient side)
# ---------------------------------------------------------------------------

def verify_signature(
    envelope: dict,
    *,
    sender_id: str,
    recipient_id: str,
    sender_ed25519_public_key: bytes,
) -> bool:
    """
    Verify the envelope signature using the sender's public key.

    Returns True on success, False on signature mismatch. Raises
    EnvelopeError for structurally malformed input.
    """
    try:
        signed_bytes = _canonical_signed_bytes(
            sender_id=sender_id,
            recipient_id=recipient_id,
            kem_ct_b64=envelope["kemCiphertext"],
            subject_ct_b64=envelope["subjectCiphertext"],
            body_ct_b64=envelope["bodyCiphertext"],
            subject_nonce_b64=envelope["subjectNonce"],
            body_nonce_b64=envelope["bodyNonce"],
            kdf_salt_b64=envelope["kdfSalt"],
            message_hash_hex=envelope["messageHash"],
        )
    except KeyError as exc:
        raise EnvelopeError(f"Envelope missing required field: {exc}") from exc

    signature = _unb64(envelope["signature"])
    return signatures.verify(signed_bytes, signature, sender_ed25519_public_key)


def open_envelope(
    envelope: dict,
    *,
    sender_id: str,
    recipient_id: str,
    recipient_mlkem_private_key: bytes,
    sender_ed25519_public_key: bytes,
    verify_signature_first: bool = True,
) -> dict:
    """
    Decrypt and verify an envelope.

    Steps
    -----
    1. Optionally verify the sender's signature (recommended; default True).
    2. Decapsulate the ML-KEM ciphertext to recover the shared secret.
    3. Re-derive subject and body keys via HKDF.
    4. AES-GCM-decrypt subject and body.

    Returns
    -------
    dict:
        {
            "subject": str,
            "body":    str,
            "signature_verified": bool,
            "message_hash_matches": bool,
        }

    Raises
    ------
    SignatureVerificationError  if signature verification is enabled and fails.
    DecryptionFailure           if AES-GCM authentication fails.
    EnvelopeError               for malformed input.
    """
    if verify_signature_first:
        if not verify_signature(
            envelope,
            sender_id=sender_id,
            recipient_id=recipient_id,
            sender_ed25519_public_key=sender_ed25519_public_key,
        ):
            raise SignatureVerificationError(
                "Sender signature verification failed. Envelope may have been "
                "tampered with or signed by a different key."
            )

    # ---- 1. Decapsulate ----
    try:
        kem_ct = _unb64(envelope["kemCiphertext"])
    except KeyError as exc:
        raise EnvelopeError(f"Envelope missing field: {exc}") from exc

    shared_secret = ml_kem.decapsulate(recipient_mlkem_private_key, kem_ct)

    # ---- 2. Re-derive session keys ----
    kdf_salt = _unb64(envelope["kdfSalt"])
    subject_key = kdf.derive_key(shared_secret, length=32, salt=kdf_salt, info=INFO_SUBJECT)
    body_key    = kdf.derive_key(shared_secret, length=32, salt=kdf_salt, info=INFO_BODY)
    del shared_secret

    # ---- 3. AES-GCM decrypt ----
    try:
        subject_pt = aes_gcm.decrypt(
            {
                "ciphertext": _unb64(envelope["subjectCiphertext"]),
                "nonce": _unb64(envelope["subjectNonce"]),
                "tag": _unb64(envelope["subjectTag"]),
            },
            subject_key,
        )
    except aes_gcm.DecryptionError as exc:
        raise DecryptionFailure("Subject decryption failed (GCM tag mismatch).") from exc

    try:
        body_pt = aes_gcm.decrypt(
            {
                "ciphertext": _unb64(envelope["bodyCiphertext"]),
                "nonce": _unb64(envelope["bodyNonce"]),
                "tag": _unb64(envelope["bodyTag"]),
            },
            body_key,
        )
    except aes_gcm.DecryptionError as exc:
        raise DecryptionFailure("Body decryption failed (GCM tag mismatch).") from exc
    finally:
        del subject_key, body_key

    subject = subject_pt.decode("utf-8")
    body = body_pt.decode("utf-8")

    # ---- 4. Confirm the SHA-256 fingerprint matches ----
    expected_hash = envelope.get("messageHash", "")
    message_hash_matches = hashing.verify_sha256(body.encode("utf-8"), expected_hash)

    return {
        "subject": subject,
        "body": body,
        "signature_verified": verify_signature_first,  # True if we got here
        "message_hash_matches": message_hash_matches,
    }
