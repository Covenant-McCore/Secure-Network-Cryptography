"""
services/audit_service.py
-------------------------
Security event logging.

Every security-relevant action in CRYPTO-NET emits an audit event. Events
are stored in the `security_events` Firestore collection and are shown in
the Security Monitor and Audit Log pages.

The audit service NEVER raises into the caller's request path. If the
Firestore write fails, we log to stdout and continue. Losing an audit
record must never break a legitimate user action — that would be an
availability vulnerability. (The inverse trade-off — blocking on audit
write — would be correct for a regulated environment, and is documented
as a limitation.)

EVENT TYPES (canonical list — extend carefully)
-----------------------------------------------
Authentication:   LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT,
                  SESSION_EXPIRED, PASSWORD_CHANGED, PASSWORD_REJECTED_BREACHED
Authorization:    ACCESS_GRANTED, ACCESS_DENIED
Keys:             KEY_GENERATED, KEY_ROTATED, KEY_REVOKED, ABE_KEY_ISSUED
Messages:         MESSAGE_SENT, MESSAGE_DECRYPTED, MESSAGE_DECRYPT_FAILED
Files:            FILE_ENCRYPTED, FILE_DECRYPTED, FILE_INTEGRITY_FAILED
Integrity:        INTEGRITY_OK, INTEGRITY_FAILED
Signatures:       SIGNATURE_OK, SIGNATURE_FAILED
Threats:          REPLAY_DETECTED, TAMPER_DETECTED
External APIs:    SECURITY_API_OK, SECURITY_API_ALERT, SECURITY_API_UNAVAILABLE
Admin:            USER_CREATED, USER_DISABLED, ROLE_CHANGED
"""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from flask import request

import extensions
from config import Config


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def log_event(
    event_type: str,
    *,
    user_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    result: str = "SUCCESS",
    severity: str = SEVERITY_INFO,
    resource: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> Optional[str]:
    """
    Write a security event to Firestore.

    Returns the event ID on success, None on failure. Never raises.
    """
    event = _build_event(
        event_type=event_type,
        user_id=user_id,
        organization_id=organization_id,
        result=result,
        severity=severity,
        resource=resource,
        details=details,
    )

    if extensions.db is None:
        logger.warning("Audit event dropped (Firestore unavailable): %s", event)
        return None

    try:
        ref = extensions.db.collection(Config.COLLECTION_SECURITY_EVENTS).document()
        ref.set(event)
        return ref.id
    except Exception as exc:  # noqa: BLE001 — audit must never crash the request
        logger.exception("Failed to write audit event: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _build_event(
    *,
    event_type: str,
    user_id: Optional[str],
    organization_id: Optional[str],
    result: str,
    severity: str,
    resource: Optional[str],
    details: Optional[dict[str, Any]],
) -> dict:
    """Assemble the Firestore document. Also captures request context."""
    ip, user_agent = _request_context()
    return {
        "eventType": event_type,
        "userId": user_id,
        "organizationId": organization_id,
        "resource": resource,
        "result": result,
        "severity": severity,
        "sourceIp": ip,
        "userAgent": user_agent,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc),
    }


def _request_context() -> tuple[Optional[str], Optional[str]]:
    """
    Best-effort extraction of client IP and user agent.

    Behind Railway's proxy, request.remote_addr is the proxy IP. We prefer
    X-Forwarded-For (which Railway sets) but treat it as untrusted — it is
    stored for correlation, not for security decisions.
    """
    if request is None or not request:
        return None, None
    try:
        forwarded = request.headers.get("X-Forwarded-For", "")
        ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
        return ip, request.headers.get("User-Agent")
    except RuntimeError:
        # Outside request context (e.g. called from a script)
        return None, None


# ---------------------------------------------------------------------------
# Convenience wrappers (used widely)
# ---------------------------------------------------------------------------

def login_success(user_id: str) -> None:
    log_event("LOGIN_SUCCESS", user_id=user_id, severity=SEVERITY_INFO)


def login_failed(email: str) -> None:
    # Do NOT include the attempted email in the event type — we store it in
    # details, but strip it from any user-facing output.
    log_event(
        "LOGIN_FAILED",
        user_id=None,
        result="FAILURE",
        severity=SEVERITY_WARNING,
        details={"attemptedEmail": email},
    )


def access_denied(user_id: Optional[str], resource: str, reason: str) -> None:
    log_event(
        "ACCESS_DENIED",
        user_id=user_id,
        resource=resource,
        result="DENIED",
        severity=SEVERITY_WARNING,
        details={"reason": reason},
    )
