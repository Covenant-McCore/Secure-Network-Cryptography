"""
services/auth_service.py
------------------------
User lookup, password verification, and account-status handling.

This module is the ONLY place that reads password hashes. Routes never
touch `passwordHash`.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import extensions
from config import Config
from crypto import password as pw


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Base class for authentication failures."""


class UserNotFound(AuthError):
    """Raised when no user matches the supplied email."""


class InvalidCredentials(AuthError):
    """Raised when the password is wrong."""


class AccountDisabled(AuthError):
    """Raised when the account status is not 'active'."""


# ---------------------------------------------------------------------------
# User lookup
# ---------------------------------------------------------------------------

def find_user_by_email(email: str) -> Optional[dict]:
    """
    Look up a user document by email. Email is stored lowercase.

    Returns the user dict including its 'userId' field, or None if absent.
    """
    if extensions.db is None:
        raise RuntimeError("Firestore is not initialised.")

    email = email.strip().lower()
    query = (
        extensions.db.collection(Config.COLLECTION_USERS)
        .where("email", "==", email)
        .limit(1)
        .stream()
    )
    for doc in query:
        data = doc.to_dict() or {}
        data["userId"] = doc.id
        return data
    return None


def get_user(user_id: str) -> Optional[dict]:
    """Fetch a user by ID. Returns dict with 'userId' populated."""
    if extensions.db is None:
        raise RuntimeError("Firestore is not initialised.")

    doc = extensions.db.collection(Config.COLLECTION_USERS).document(user_id).get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    data["userId"] = doc.id
    return data


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def authenticate(email: str, candidate_password: str) -> dict:
    """
    Verify credentials and return the authenticated user dict.

    Raises
    ------
    UserNotFound, InvalidCredentials, AccountDisabled
        All three are caught by the login route and converted into a single
        generic "invalid credentials" response to the browser (to prevent
        user enumeration).
    """
    user = find_user_by_email(email)
    if user is None:
        raise UserNotFound()

    stored_hash = user.get("passwordHash")
    if not stored_hash:
        # Defensive: a user document must always have a passwordHash.
        logger.error("User %s has no passwordHash field.", user.get("userId"))
        raise InvalidCredentials()

    if not pw.verify_password(stored_hash, candidate_password):
        raise InvalidCredentials()

    if user.get("status", "active").lower() != "active":
        raise AccountDisabled()

    # Opportunistic rehash if Argon2 parameters have improved.
    if pw.needs_rehash(stored_hash):
        _update_password_hash(user["userId"], candidate_password)

    _touch_last_login(user["userId"])
    return user


def _touch_last_login(user_id: str) -> None:
    try:
        extensions.db.collection(Config.COLLECTION_USERS).document(user_id).update({
            "lastLogin": datetime.now(timezone.utc),
        })
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not update lastLogin for %s: %s", user_id, exc)


def _update_password_hash(user_id: str, plaintext_password: str) -> None:
    try:
        new_hash = pw.hash_password(plaintext_password)
        extensions.db.collection(Config.COLLECTION_USERS).document(user_id).update({
            "passwordHash": new_hash,
        })
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not rehash password for %s: %s", user_id, exc)


# ---------------------------------------------------------------------------
# User lifecycle (used by admin routes and seed script)
# ---------------------------------------------------------------------------

def create_user(
    *,
    email: str,
    full_name: str,
    password: str,
    role: str,
    department: str,
    organization_id: str,
    clearance: str = "INTERNAL",
) -> str:
    """
    Create a new user. Returns the new userId.

    Validates role and clearance against Config. Does NOT create key
    material — that is the key service's job (call it after this returns).
    """
    if role not in Config.ROLES:
        raise AuthError(f"Unknown role: {role}")
    if clearance not in Config.CLEARANCE_LEVELS:
        raise AuthError(f"Unknown clearance: {clearance}")

    email = email.strip().lower()
    if find_user_by_email(email) is not None:
        raise AuthError(f"User with email {email} already exists.")

    doc = {
        "email": email,
        "fullName": full_name,
        "passwordHash": pw.hash_password(password),
        "role": role,
        "department": department,
        "organizationId": organization_id,
        "clearanceLevel": clearance,
        "status": "active",
        "createdAt": datetime.now(timezone.utc),
        "lastLogin": None,
        "publicKeyId": None,  # populated by key_service
    }
    ref = extensions.db.collection(Config.COLLECTION_USERS).document()
    ref.set(doc)
    return ref.id


def set_status(user_id: str, status: str) -> None:
    if status not in {"active", "disabled"}:
        raise AuthError("Status must be 'active' or 'disabled'.")
    extensions.db.collection(Config.COLLECTION_USERS).document(user_id).update({
        "status": status,
    })
