"""
crypto/file_envelope.py
-----------------------
End-to-end encrypted file envelope.

Reuses the primitives established in message_envelope.py:

    ML-KEM-768    : key establishment (sender encapsulates to recipient)
    HKDF-SHA-256  : derive separate keys for filename, mime, and content
    AES-256-GCM   : encrypt filename, mime, and content independently
    SHA-256       : fingerprint the plaintext file (stored alongside)
    Ed25519       : sign the ciphertext envelope

DOMAIN SEPARATION
-----------------
Three keys are derived from one KEM shared secret, each with a distinct
HKDF `info` string:

    crypto-net/file/filename/v1
    crypto-net/file/mimetype/v1
    crypto-net/file/content/v1

This prevents cross-purpose key reuse.

SIZE CONSTRAINT
---------------
Files are capped at Config.MAX_FILE_BYTES so the base64-encoded sealed
envelope fits within Firestore's 1 MB document limit. Enforced by the
route layer via Flask's MAX_CONTENT_LENGTH.
"""

import base64
import json

from config import Config
from crypto import aes_gcm, hashing, kdf, ml_kem, signatures


ENVELOPE_VERSION = 1

INFO_FILENAME = b"crypto-net/file/filename/v1"
INFO_MIMETYPE = b"crypto-net/file/mimetype/v1"
INFO_CONTENT  = b"crypto-net/file/content/v1"

ENCRYPTION_ALGORITHM = "AES-256-GCM"
KEM_ALGORITHM = "ML-KEM-768"
KDF_ALGORITHM = "HKDF-SHA-256"
SIGNATURE_ALGORITHM = "Ed25519"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class FileEnvelopeError(ValueError):
    """Raised when a file envelope is malformed or a verification step fails."""


class FileTooLargeError(FileEnvelopeError):
    """Raised when the plaintext exceeds MAX_FILE_BYTES."""


class FileSignatureError(FileEnvelopeError):
    """Raised when the file envelope signature does not verify."""


class FileDecryptionError(FileEnvelopeError):
    """Raised when AES-GCM authentication fails during file decryption."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


def _canonical_signed_bytes(
    sender_id: str,
    recipient_id: str,
    kem_ct_b64: str,
    filename_ct_b64: str,
    mimetype_ct_b64: str,
    content_ct_b64: str,
    filename_nonce_b64: str,
    mimetype_nonce_b64: str,
    content_nonce_b64: str,
    kdf_salt_b64: str,
    file_hash_hex: str,
) -> bytes:
    """Deterministic canonical byte string the sender signs."""
    payload = {
        "senderId": sender_id,
        "recipientId": recipient_id,
        "kemCiphertext": kem_ct_b64,
        "filenameCiphertext": filename_ct_b64,
        "mimetypeCiphertext": mimetype_ct_b64,
        "contentCiphertext": content_ct_b64,
        "filenameNonce": filename_nonce_b64,
        "mimetypeNonce": mimetype_nonce_b64,
        "contentNonce": content_nonce_b64,
        "kdfSalt": kdf_salt_b64,
        "fileHash": file_hash_hex,
        "v": ENVELOPE_VERSION,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Seal
# ---------------------------------------------------------------------------

def seal_file(
    *,
    sender_id: str,
    recipient_id: str,
    recipient_mlkem_public_key: bytes,
    sender_ed25519_private_key: bytes,
    filename: str,
    mimetype: str,
    content: bytes,
) -> dict:
    """
    Seal a file into a Firestore-ready envelope.

    Plaintext is confined to local scope; never returned or logged.
    """
    if len(content) > Config.MAX_FILE_BYTES:
        raise FileTooLargeError(
            f"File exceeds {Config.MAX_FILE_BYTES} bytes."
        )

    if not recipient_mlkem_public_key or len(recipient_mlkem_public_key) != ml_kem.PUBLIC_KEY_BYTES:
        raise FileEnvelopeError("Recipient ML-KEM public key is missing or malformed.")

    # ---- 1. Key establishment ----
    shared_secret, kem_ct = ml_kem.encapsulate(recipient_mlkem_public_key)

    # ---- 2. Three independent keys via HKDF ----
    kdf_salt = kdf.new_salt(32)
    filename_key = kdf.derive_key(shared_secret, 32, kdf_salt, INFO_FILENAME)
    mimetype_key = kdf.derive_key(shared_secret, 32, kdf_salt, INFO_MIMETYPE)
    content_key  = kdf.derive_key(shared_secret, 32, kdf_salt, INFO_CONTENT)
    del shared_secret

    # ---- 3. AES-GCM each component separately ----
    filename_env = aes_gcm.encrypt(filename.encode("utf-8"), filename_key)
    mimetype_env = aes_gcm.encrypt(mimetype.encode("utf-8"), mimetype_key)
    content_env  = aes_gcm.encrypt(content, content_key)
    del filename_key, mimetype_key, content_key

    # ---- 4. SHA-256 of the plaintext file ----
    file_hash_hex = hashing.sha256_hex(content)

    # ---- 5. Sign canonical envelope ----
    kem_ct_b64 = _b64(kem_ct)
    fn_ct_b64 = _b64(filename_env["ciphertext"])
    mt_ct_b64 = _b64(mimetype_env["ciphertext"])
    ct_ct_b64 = _b64(content_env["ciphertext"])
    fn_nonce_b64 = _b64(filename_env["nonce"])
    mt_nonce_b64 = _b64(mimetype_env["nonce"])
    ct_nonce_b64 = _b64(content_env["nonce"])
    kdf_salt_b64 = _b64(kdf_salt)

    signed_bytes = _canonical_signed_bytes(
        sender_id=sender_id,
        recipient_id=recipient_id,
        kem_ct_b64=kem_ct_b64,
        filename_ct_b64=fn_ct_b64,
        mimetype_ct_b64=mt_ct_b64,
        content_ct_b64=ct_ct_b64,
        filename_nonce_b64=fn_nonce_b64,
        mimetype_nonce_b64=mt_nonce_b64,
        content_nonce_b64=ct_nonce_b64,
        kdf_salt_b64=kdf_salt_b64,
        file_hash_hex=file_hash_hex,
    )
    signature = signatures.sign(signed_bytes, sender_ed25519_private_key)

    # ---- 6. Assemble ----
    return {
        "kemCiphertext": kem_ct_b64,
        "kdfSalt": kdf_salt_b64,
        "filenameCiphertext": fn_ct_b64,
        "filenameNonce": fn_nonce_b64,
        "filenameTag": _b64(filename_env["tag"]),
        "mimetypeCiphertext": mt_ct_b64,
        "mimetypeNonce": mt_nonce_b64,
        "mimetypeTag": _b64(mimetype_env["tag"]),
        "contentCiphertext": ct_ct_b64,
        "contentNonce": ct_nonce_b64,
        "contentTag": _b64(content_env["tag"]),
        "fileHash": file_hash_hex,
        "fileSize": len(content),
        "signature": _b64(signature),
        "signatureAlgorithm": SIGNATURE_ALGORITHM,
        "encryptionAlgorithm": ENCRYPTION_ALGORITHM,
        "kemAlgorithm": KEM_ALGORITHM,
        "kdfAlgorithm": KDF_ALGORITHM,
        "envelopeVersion": ENVELOPE_VERSION,
    }


# ---------------------------------------------------------------------------
# Open
# ---------------------------------------------------------------------------

def open_file_envelope(
    envelope: dict,
    *,
    sender_id: str,
    recipient_id: str,
    recipient_mlkem_private_key: bytes,
    sender_ed25519_public_key: bytes,
    verify_signature_first: bool = True,
) -> dict:
    """
    Verify and decrypt a file envelope.

    Returns
    -------
    dict:
        {
            "filename": str,
            "mimetype": str,
            "content": bytes,
            "signature_verified": bool,
            "hash_matches": bool,
        }
    """
    # ---- 1. Signature ----
    if verify_signature_first:
        try:
            signed_bytes = _canonical_signed_bytes(
                sender_id=sender_id,
                recipient_id=recipient_id,
                kem_ct_b64=envelope["kemCiphertext"],
                filename_ct_b64=envelope["filenameCiphertext"],
                mimetype_ct_b64=envelope["mimetypeCiphertext"],
                content_ct_b64=envelope["contentCiphertext"],
                filename_nonce_b64=envelope["filenameNonce"],
                mimetype_nonce_b64=envelope["mimetypeNonce"],
                content_nonce_b64=envelope["contentNonce"],
                kdf_salt_b64=envelope["kdfSalt"],
                file_hash_hex=envelope["fileHash"],
            )
        except KeyError as exc:
            raise FileEnvelopeError(f"Envelope missing field: {exc}") from exc

        if not signatures.verify(
            signed_bytes, _unb64(envelope["signature"]), sender_ed25519_public_key
        ):
            raise FileSignatureError(
                "File envelope signature verification failed."
            )

    # ---- 2. Decapsulate ----
    try:
        kem_ct = _unb64(envelope["kemCiphertext"])
    except KeyError as exc:
        raise FileEnvelopeError(f"Envelope missing field: {exc}") from exc

    shared_secret = ml_kem.decapsulate(recipient_mlkem_private_key, kem_ct)

    # ---- 3. Re-derive keys ----
    kdf_salt = _unb64(envelope["kdfSalt"])
    filename_key = kdf.derive_key(shared_secret, 32, kdf_salt, INFO_FILENAME)
    mimetype_key = kdf.derive_key(shared_secret, 32, kdf_salt, INFO_MIMETYPE)
    content_key  = kdf.derive_key(shared_secret, 32, kdf_salt, INFO_CONTENT)
    del shared_secret

    # ---- 4. AES-GCM decrypt each component ----
    try:
        filename_pt = aes_gcm.decrypt(
            {
                "ciphertext": _unb64(envelope["filenameCiphertext"]),
                "nonce": _unb64(envelope["filenameNonce"]),
                "tag": _unb64(envelope["filenameTag"]),
            },
            filename_key,
        )
        mimetype_pt = aes_gcm.decrypt(
            {
                "ciphertext": _unb64(envelope["mimetypeCiphertext"]),
                "nonce": _unb64(envelope["mimetypeNonce"]),
                "tag": _unb64(envelope["mimetypeTag"]),
            },
            mimetype_key,
        )
        content_pt = aes_gcm.decrypt(
            {
                "ciphertext": _unb64(envelope["contentCiphertext"]),
                "nonce": _unb64(envelope["contentNonce"]),
                "tag": _unb64(envelope["contentTag"]),
            },
            content_key,
        )
    except aes_gcm.DecryptionError as exc:
        raise FileDecryptionError(
            "File decryption failed (AES-GCM authentication)."
        ) from exc
    finally:
        del filename_key, mimetype_key, content_key

    # ---- 5. Verify SHA-256 fingerprint ----
    hash_matches = hashing.verify_sha256(content_pt, envelope.get("fileHash", ""))

    return {
        "filename": filename_pt.decode("utf-8"),
        "mimetype": mimetype_pt.decode("utf-8"),
        "content": content_pt,
        "signature_verified": verify_signature_first,
        "hash_matches": hash_matches,
    }
