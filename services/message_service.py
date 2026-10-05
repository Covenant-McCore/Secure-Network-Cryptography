"""
services/message_service.py
---------------------------
Persistence and orchestration for secure messages.

Every function that touches a message emits an audit event. No function
in this module ever logs or returns plaintext.
"""

import logging
from datetime import datetime, timezone
from typing import Iterable, Optional

import extensions
from config import Config
from crypto.message_envelope import (
    DecryptionFailure,
    EnvelopeError,
    SignatureVerificationError,
    open_envelope,
    seal,
)
from services import audit_service, key_service


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class MessageServiceError(RuntimeError):
    """Base class for message service failures."""


class RecipientNotFound(MessageServiceError):
    """Raised when a recipient ID does not resolve to an active user."""


class RecipientKeyMissing(MessageServiceError):
    """Raised when the recipient has no ML-KEM public key."""


class NotAuthorizedToRead(MessageServiceError):
    """Raised when a user attempts to read a message they don't own."""


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------

def send_message(
    *,
    sender_id: str,
    sender_attributes: list[str],
    recipient_id: str,
    organization_id: str,
    subject: str,
    body: str,
) -> str:
    """
    Seal and persist a message. Returns the new messageId.

    All plaintext is confined to this function's local scope. It is never
    written to Firestore, never logged, and never returned.
    """
    if extensions.db is None:
        raise MessageServiceError("Firestore is not initialised.")

    if sender_id == recipient_id:
        raise MessageServiceError("Cannot send a message to yourself.")

    if not subject or not body:
        raise MessageServiceError("Subject and body must both be non-empty.")

    # ---- 1. Look up sender's private key material ----
    sender_keys = key_service.get_user_private_material(sender_id)
    if not sender_keys or not sender_keys.get("ed25519PrivateKey"):
        raise MessageServiceError("Sender key material is unavailable.")

    # ---- 2. Look up recipient public key material ----
    recipient_pub = key_service.get_user_public_keys(recipient_id)
    if not recipient_pub:
        raise RecipientNotFound(f"No key material for recipient {recipient_id}.")
    if recipient_pub.get("status") == "revoked":
        raise RecipientKeyMissing("Recipient's keys are revoked.")

    recipient_mlkem_pk = recipient_pub.get("mlKem768PublicKey")
    if not recipient_mlkem_pk:
        raise RecipientKeyMissing("Recipient has no ML-KEM public key.")

    # Firestore may return Blob for bytes fields; coerce.
    recipient_mlkem_pk = _coerce_bytes(recipient_mlkem_pk)
    sender_ed_sk = _coerce_bytes(sender_keys["ed25519PrivateKey"])

    # ---- 3. Seal the envelope ----
    envelope = seal(
        sender_id=sender_id,
        recipient_id=recipient_id,
        recipient_mlkem_public_key=recipient_mlkem_pk,
        sender_ed25519_private_key=sender_ed_sk,
        subject=subject,
        body=body,
    )

    # ---- 4. Persist ----
    now = datetime.now(timezone.utc)
    doc = {
        "senderId": sender_id,
        "recipientId": recipient_id,
        "organizationId": organization_id,
        "envelope": envelope,
        "status": "unread",
        "createdAt": now,
        "readAt": None,
    }

    ref = extensions.db.collection(Config.COLLECTION_MESSAGES).document()
    ref.set(doc)

    audit_service.log_event(
        "MESSAGE_SENT",
        user_id=sender_id,
        organization_id=organization_id,
        resource=f"message/{ref.id}",
        result="SUCCESS",
        details={
            "recipientId": recipient_id,
            "kemAlgorithm": envelope["kemAlgorithm"],
            "encryptionAlgorithm": envelope["encryptionAlgorithm"],
            "signatureAlgorithm": envelope["signatureAlgorithm"],
        },
    )

    return ref.id


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def list_inbox(user_id: str, limit: int = 100) -> list[dict]:
    """Return the recipient's messages, newest first, WITHOUT plaintext."""
    return _list_messages(field="recipientId", user_id=user_id, limit=limit)


def list_sent(user_id: str, limit: int = 100) -> list[dict]:
    """Return messages the user sent, newest first, WITHOUT plaintext."""
    return _list_messages(field="senderId", user_id=user_id, limit=limit)


def _list_messages(*, field: str, user_id: str, limit: int) -> list[dict]:
    if extensions.db is None:
        raise MessageServiceError("Firestore is not initialised.")

    query = (
        extensions.db.collection(Config.COLLECTION_MESSAGES)
        .where(field, "==", user_id)
        .order_by("createdAt", direction="DESCENDING")
        .limit(limit)
    )
    rows = []
    for doc in query.stream():
        data = doc.to_dict() or {}
        data["messageId"] = doc.id
        # Strip the full envelope from list views — the view pages will
        # fetch it on demand. This avoids rendering huge blobs in tables.
        env = data.pop("envelope", {}) or {}
        data["kemAlgorithm"] = env.get("kemAlgorithm")
        data["encryptionAlgorithm"] = env.get("encryptionAlgorithm")
        data["signatureAlgorithm"] = env.get("signatureAlgorithm")
        rows.append(data)
    return rows


def get_message(message_id: str) -> Optional[dict]:
    """
    Fetch a message including its envelope. Callers must authorize before
    rendering anything from the envelope.
    """
    if extensions.db is None:
        raise MessageServiceError("Firestore is not initialised.")

    doc = extensions.db.collection(Config.COLLECTION_MESSAGES).document(message_id).get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    data["messageId"] = doc.id
    return data


def mark_read(message_id: str, user_id: str) -> None:
    if extensions.db is None:
        raise MessageServiceError("Firestore is not initialised.")
    extensions.db.collection(Config.COLLECTION_MESSAGES).document(message_id).update({
        "status": "read",
        "readAt": datetime.now(timezone.utc),
    })


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def decrypt_message(message_id: str, recipient_user: dict) -> dict:
    """
    Decrypt a message as its recipient. Emits audit events.

    Parameters
    ----------
    message_id : str
    recipient_user : dict
        Must contain 'userId'. The caller (route) is responsible for
        confirming this is the actual recipient.

    Returns
    -------
    dict:
        {
            "subject": str,
            "body": str,
            "signature_verified": bool,
            "message_hash_matches": bool,
        }

    Raises
    ------
    NotAuthorizedToRead
    EnvelopeError subclasses (SignatureVerificationError, DecryptionFailure)
    """
    if extensions.db is None:
        raise MessageServiceError("Firestore is not initialised.")

    recipient_id = recipient_user["userId"]
    msg = get_message(message_id)
    if msg is None:
        raise MessageServiceError("Message not found.")

    if msg.get("recipientId") != recipient_id:
        audit_service.access_denied(
            user_id=recipient_id,
            resource=f"message/{message_id}",
            reason="not the recipient",
        )
        raise NotAuthorizedToRead("You are not the recipient of this message.")

    # ---- Load key material ----
    sender_id = msg["senderId"]
    sender_pub = key_service.get_user_public_keys(sender_id)
    recipient_priv = key_service.get_user_private_material(recipient_id)

    if not sender_pub or not sender_pub.get("ed25519PublicKey"):
        raise MessageServiceError("Sender's public key is unavailable.")
    if not recipient_priv or not recipient_priv.get("mlKem768PrivateKey"):
        raise MessageServiceError("Recipient's ML-KEM private key is unavailable.")

    sender_ed_pk = _coerce_bytes(sender_pub["ed25519PublicKey"])
    recipient_mlkem_sk = _coerce_bytes(recipient_priv["mlKem768PrivateKey"])

    # ---- Decrypt ----
    try:
        result = open_envelope(
            msg["envelope"],
            sender_id=sender_id,
            recipient_id=recipient_id,
            recipient_mlkem_private_key=recipient_mlkem_sk,
            sender_ed25519_public_key=sender_ed_pk,
            verify_signature_first=True,
        )
    except SignatureVerificationError as exc:
        audit_service.log_event(
            "SIGNATURE_FAILED",
            user_id=recipient_id,
            resource=f"message/{message_id}",
            result="FAILURE",
            severity=audit_service.SEVERITY_CRITICAL,
            details={"reason": str(exc)},
        )
        raise
    except DecryptionFailure as exc:
        audit_service.log_event(
            "MESSAGE_DECRYPT_FAILED",
            user_id=recipient_id,
            resource=f"message/{message_id}",
            result="FAILURE",
            severity=audit_service.SEVERITY_WARNING,
            details={"reason": str(exc)},
        )
        raise

    # ---- Update status, audit ----
    mark_read(message_id, recipient_id)
    audit_service.log_event(
        "MESSAGE_DECRYPTED",
        user_id=recipient_id,
        resource=f"message/{message_id}",
        result="SUCCESS",
        details={
            "senderId": sender_id,
            "signatureVerified": result["signature_verified"],
            "hashMatched": result["message_hash_matches"],
        },
    )
    return result


# ---------------------------------------------------------------------------
# Recipient list for compose form
# ---------------------------------------------------------------------------

def list_eligible_recipients(exclude_user_id: str) -> list[dict]:
    """
    Return a list of (userId, fullName, role, department) for all active
    users other than the caller. This is intentionally not filtered by
    role — the RBAC model in this project allows any authenticated user
    to initiate a secure message with any other user. Policy-based
    restrictions on content are enforced at the CP-ABE layer for files,
    and by policy for messages in later phases.
    """
    if extensions.db is None:
        raise MessageServiceError("Firestore is not initialised.")

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
    """
    Coerce a Firestore-returned value (which may be Blob, bytes, or
    bytearray) into plain bytes.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    # firebase_admin.firestore.Blob
    try:
        return bytes(value)
    except TypeError as exc:
        raise MessageServiceError(f"Cannot coerce {type(value)} to bytes.") from exc
