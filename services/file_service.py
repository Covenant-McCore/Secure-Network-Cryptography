"""
services/file_service.py
------------------------
Persistence and orchestration for secure file transfer.

Metadata (sender, recipient, size, hash, algorithms, timestamp) is stored
in Firestore in plaintext. The file content, filename, and MIME type live
ONLY inside the sealed envelope. This is intentional: it lets the inbox
view render useful columns without exposing anything sensitive.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import extensions
from config import Config
from crypto.file_envelope import (
    FileDecryptionError,
    FileEnvelopeError,
    FileSignatureError,
    FileTooLargeError,
    open_file_envelope,
    seal_file,
)
from services import audit_service, key_service


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class FileServiceError(RuntimeError):
    """Base class for file service failures."""


class FileNotAuthorized(FileServiceError):
    """Raised when a user attempts to access a file they don't own."""


class FileNotFoundInStore(FileServiceError):
    """Raised when a file ID does not resolve."""


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

def upload_file(
    *,
    sender_id: str,
    recipient_id: str,
    organization_id: str,
    filename: str,
    mimetype: str,
    content: bytes,
    classification: str = "INTERNAL",
) -> str:
    """
    Seal and persist a file. Returns the new fileId.
    """
    if extensions.db is None:
        raise FileServiceError("Firestore is not initialised.")

    if sender_id == recipient_id:
        raise FileServiceError("Cannot send a file to yourself.")

    if len(content) > Config.MAX_FILE_BYTES:
        raise FileTooLargeError(
            f"File exceeds {Config.MAX_FILE_BYTES} bytes."
        )

    if mimetype not in Config.ALLOWED_FILE_MIME_TYPES:
        raise FileServiceError(f"MIME type not allowed: {mimetype}")

    # ---- Sender private key ----
    sender_keys = key_service.get_user_private_material(sender_id)
    if not sender_keys or not sender_keys.get("ed25519PrivateKey"):
        raise FileServiceError("Sender key material is unavailable.")

    # ---- Recipient public key ----
    recipient_pub = key_service.get_user_public_keys(recipient_id)
    if not recipient_pub:
        raise FileServiceError(f"No key material for recipient {recipient_id}.")
    if recipient_pub.get("status") == "revoked":
        raise FileServiceError("Recipient's keys are revoked.")

    recipient_mlkem_pk = _coerce_bytes(recipient_pub.get("mlKem768PublicKey"))
    if not recipient_mlkem_pk:
        raise FileServiceError("Recipient has no ML-KEM public key.")
    sender_ed_sk = _coerce_bytes(sender_keys["ed25519PrivateKey"])

    # ---- Seal ----
    envelope = seal_file(
        sender_id=sender_id,
        recipient_id=recipient_id,
        recipient_mlkem_public_key=recipient_mlkem_pk,
        sender_ed25519_private_key=sender_ed_sk,
        filename=filename,
        mimetype=mimetype,
        content=content,
    )

    # ---- Persist ----
    now = datetime.now(timezone.utc)
    doc = {
        "senderId": sender_id,
        "recipientId": recipient_id,
        "organizationId": organization_id,
        "classification": classification,
        "fileSize": envelope["fileSize"],
        "fileHash": envelope["fileHash"],          # SHA-256 of plaintext
        "fileExtension": _safe_extension(filename),
        "envelope": envelope,
        "status": "unread",
        "createdAt": now,
        "downloadedAt": None,
    }
    ref = extensions.db.collection(Config.COLLECTION_FILES).document()
    ref.set(doc)

    audit_service.log_event(
        "FILE_ENCRYPTED",
        user_id=sender_id,
        organization_id=organization_id,
        resource=f"file/{ref.id}",
        result="SUCCESS",
        details={
            "recipientId": recipient_id,
            "fileSize": envelope["fileSize"],
            "classification": classification,
            "kemAlgorithm": envelope["kemAlgorithm"],
            "encryptionAlgorithm": envelope["encryptionAlgorithm"],
        },
    )
    return ref.id


# ---------------------------------------------------------------------------
# Listing / retrieval
# ---------------------------------------------------------------------------

def list_inbox(user_id: str, limit: int = 100) -> list[dict]:
    return _list(field="recipientId", user_id=user_id, limit=limit)


def list_sent(user_id: str, limit: int = 100) -> list[dict]:
    return _list(field="senderId", user_id=user_id, limit=limit)


def _list(*, field: str, user_id: str, limit: int) -> list[dict]:
    if extensions.db is None:
        raise FileServiceError("Firestore is not initialised.")

    query = (
        extensions.db.collection(Config.COLLECTION_FILES)
        .where(field, "==", user_id)
        .order_by("createdAt", direction="DESCENDING")
        .limit(limit)
    )
    rows = []
    for doc in query.stream():
        data = doc.to_dict() or {}
        data["fileId"] = doc.id
        data.pop("envelope", None)  # don't send ciphertext to list view
        rows.append(data)
    return rows


def get_file(file_id: str) -> Optional[dict]:
    """Full document, including the envelope. Callers must authorize."""
    if extensions.db is None:
        raise FileServiceError("Firestore is not initialised.")
    doc = extensions.db.collection(Config.COLLECTION_FILES).document(file_id).get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    data["fileId"] = doc.id
    return data


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def download_file(file_id: str, recipient_user: dict) -> dict:
    """
    Decrypt a file as its recipient. Returns the decrypted dict.

    Raises
    ------
    FileNotFoundInStore, FileNotAuthorized, FileSignatureError,
    FileDecryptionError, FileServiceError
    """
    if extensions.db is None:
        raise FileServiceError("Firestore is not initialised.")

    recipient_id = recipient_user["userId"]
    doc = get_file(file_id)
    if doc is None:
        raise FileNotFoundInStore(f"File {file_id} not found.")

    if doc.get("recipientId") != recipient_id:
        audit_service.access_denied(
            user_id=recipient_id,
            resource=f"file/{file_id}",
            reason="not the recipient",
        )
        raise FileNotAuthorized("You are not the recipient of this file.")

    sender_id = doc["senderId"]
    sender_pub = key_service.get_user_public_keys(sender_id)
    recipient_priv = key_service.get_user_private_material(recipient_id)

    if not sender_pub or not sender_pub.get("ed25519PublicKey"):
        raise FileServiceError("Sender's public key is unavailable.")
    if not recipient_priv or not recipient_priv.get("mlKem768PrivateKey"):
        raise FileServiceError("Recipient's ML-KEM private key is unavailable.")

    sender_ed_pk = _coerce_bytes(sender_pub["ed25519PublicKey"])
    recipient_mlkem_sk = _coerce_bytes(recipient_priv["mlKem768PrivateKey"])

    try:
        result = open_file_envelope(
            doc["envelope"],
            sender_id=sender_id,
            recipient_id=recipient_id,
            recipient_mlkem_private_key=recipient_mlkem_sk,
            sender_ed25519_public_key=sender_ed_pk,
            verify_signature_first=True,
        )
    except FileSignatureError as exc:
        audit_service.log_event(
            "SIGNATURE_FAILED",
            user_id=recipient_id,
            resource=f"file/{file_id}",
            result="FAILURE",
            severity=audit_service.SEVERITY_CRITICAL,
            details={"reason": str(exc)},
        )
        raise
    except FileDecryptionError as exc:
        audit_service.log_event(
            "FILE_INTEGRITY_FAILED",
            user_id=recipient_id,
            resource=f"file/{file_id}",
            result="FAILURE",
            severity=audit_service.SEVERITY_WARNING,
            details={"reason": str(exc)},
        )
        raise

    # If the SHA-256 doesn't match, treat it as a critical integrity failure.
    if not result["hash_matches"]:
        audit_service.log_event(
            "INTEGRITY_FAILED",
            user_id=recipient_id,
            resource=f"file/{file_id}",
            result="FAILURE",
            severity=audit_service.SEVERITY_CRITICAL,
            details={"expected": doc.get("fileHash")},
        )
        raise FileServiceError("SHA-256 fingerprint mismatch after decryption.")

    extensions.db.collection(Config.COLLECTION_FILES).document(file_id).update({
        "status": "downloaded",
        "downloadedAt": datetime.now(timezone.utc),
    })

    audit_service.log_event(
        "FILE_DECRYPTED",
        user_id=recipient_id,
        resource=f"file/{file_id}",
        result="SUCCESS",
        details={
            "senderId": sender_id,
            "signatureVerified": result["signature_verified"],
            "hashMatched": result["hash_matches"],
        },
    )
    return result


def list_eligible_recipients(exclude_user_id: str) -> list[dict]:
    """Same as message_service.list_eligible_recipients — duplicated for clarity."""
    if extensions.db is None:
        raise FileServiceError("Firestore is not initialised.")
    rows = []
    for doc in extensions.db.collection(Config.COLLECTION_USERS).stream():
        data = doc.to_dict() or {}
        if doc.id == exclude_user_id:
            continue
        if data.get("status", "active") != "active":
            continue
        rows.append({
            "userId": doc.id,
            "fullName": data.get("fullName", ""),
            "role": data.get("role", ""),
            "department": data.get("department", ""),
        })
    rows.sort(key=lambda r: (r["role"], r["fullName"]))
    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_bytes(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    try:
        return bytes(value)
    except TypeError as exc:
        raise FileServiceError(f"Cannot coerce {type(value)} to bytes.") from exc


def _safe_extension(filename: str) -> str:
    """Return the extension (without dot) or '' if none, lowercased."""
    if "." not in filename:
        return ""
    ext = filename.rsplit(".", 1)[-1].strip().lower()
    # Only keep alphanumerics; prevents stored XSS if rendered unchecked.
    return "".join(c for c in ext if c.isalnum())[:10]
