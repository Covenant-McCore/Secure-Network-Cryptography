"""
services/aggregation_service.py
-------------------------------
Firestore aggregation queries for dashboards, monitoring, and reports.

All metrics are computed from `security_events` and the resource
collections. No in-memory counters. No estimates.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import extensions
from config import Config


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dashboard metrics
# ---------------------------------------------------------------------------

def dashboard_metrics() -> dict:
    """
    Return the metric set shown on the main dashboard.

    Counts are limited to the last 30 days to keep queries fast.
    """
    if extensions.db is None:
        return _empty_dashboard()

    since = datetime.now(timezone.utc) - timedelta(days=30)
    events = _query_events(since=since)

    return {
        "total_users": _count_collection(Config.COLLECTION_USERS),
        "active_users": _count_users_by_status("active"),
        "secure_sessions": _count_events(events, "LOGIN_SUCCESS"),
        "encrypted_messages": _count_collection(Config.COLLECTION_MESSAGES),
        "secure_files": _count_collection(Config.COLLECTION_FILES),
        "failed_logins": _count_events(events, "LOGIN_FAILED"),
        "unauthorized_attempts": _count_events(events, "ACCESS_DENIED"),
        "integrity_failures": _count_events(events, "INTEGRITY_FAILED"),
        "signature_failures": _count_events(events, "SIGNATURE_FAILED"),
        "crypto_operations": _count_events(events, "MESSAGE_SENT")
                            + _count_events(events, "FILE_ENCRYPTED")
                            + _count_events(events, "LAB_PQC_RUN")
                            + _count_events(events, "LAB_SIGNATURE_RUN")
                            + _count_events(events, "LAB_INTEGRITY_RUN"),
        "since": since.isoformat(),
    }


def _empty_dashboard() -> dict:
    return {
        "total_users": 0, "active_users": 0, "secure_sessions": 0,
        "encrypted_messages": 0, "secure_files": 0, "failed_logins": 0,
        "unauthorized_attempts": 0, "integrity_failures": 0,
        "signature_failures": 0, "crypto_operations": 0,
        "since": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Event queries
# ---------------------------------------------------------------------------

def recent_events(limit: int = 100, event_type: Optional[str] = None,
                  user_id: Optional[str] = None) -> list[dict]:
    """Fetch recent security events, newest first."""
    if extensions.db is None:
        return []

    query = extensions.db.collection(Config.COLLECTION_SECURITY_EVENTS)
    if event_type:
        query = query.where("eventType", "==", event_type)
    if user_id:
        query = query.where("userId", "==", user_id)
    query = query.order_by("timestamp", direction="DESCENDING").limit(limit)

    rows = []
    for doc in query.stream():
        data = doc.to_dict() or {}
        data["eventId"] = doc.id
        rows.append(data)
    return rows


def _query_events(since: datetime) -> list[dict]:
    """Fetch events since a timestamp. Used by dashboard aggregations."""
    if extensions.db is None:
        return []
    query = (
        extensions.db.collection(Config.COLLECTION_SECURITY_EVENTS)
        .where("timestamp", ">=", since)
        .stream()
    )
    return [doc.to_dict() or {} for doc in query]


def _count_events(events: list[dict], event_type: str) -> int:
    return sum(1 for e in events if e.get("eventType") == event_type)


# ---------------------------------------------------------------------------
# Collection counts
# ---------------------------------------------------------------------------

def _count_collection(name: str) -> int:
    if extensions.db is None:
        return 0
    try:
        return len(list(extensions.db.collection(name).limit(1000).stream()))
    except Exception as exc:  # noqa: BLE001
        logger.warning("count_collection(%s) failed: %s", name, exc)
        return 0


def _count_users_by_status(status: str) -> int:
    if extensions.db is None:
        return 0
    try:
        query = extensions.db.collection(Config.COLLECTION_USERS).where("status", "==", status)
        return len(list(query.limit(1000).stream()))
    except Exception as exc:  # noqa: BLE001
        logger.warning("count_users_by_status(%s) failed: %s", status, exc)
        return 0


# ---------------------------------------------------------------------------
# Chart data
# ---------------------------------------------------------------------------

def event_timeline(days: int = 14) -> dict:
    """
    Return daily counts of key event types for the last N days.

    Used by the monitoring dashboard charts.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    events = _query_events(since=since)

    buckets = {}
    for i in range(days):
        day = (since + timedelta(days=i)).strftime("%Y-%m-%d")
        buckets[day] = {"logins": 0, "failures": 0, "crypto": 0}

    for e in events:
        ts = e.get("timestamp")
        if not ts:
            continue
        if hasattr(ts, "strftime"):
            day = ts.strftime("%Y-%m-%d")
        else:
            day = str(ts)[:10]
        if day not in buckets:
            continue
        et = e.get("eventType", "")
        if et == "LOGIN_SUCCESS":
            buckets[day]["logins"] += 1
        elif et in ("LOGIN_FAILED", "ACCESS_DENIED"):
            buckets[day]["failures"] += 1
        elif et.startswith("MESSAGE_") or et.startswith("FILE_") or et.startswith("LAB_"):
            buckets[day]["crypto"] += 1

    labels = sorted(buckets.keys())
    return {
        "labels": labels,
        "logins": [buckets[d]["logins"] for d in labels],
        "failures": [buckets[d]["failures"] for d in labels],
        "crypto": [buckets[d]["crypto"] for d in labels],
    }


def event_type_distribution() -> dict:
    """Return a label/count pair list for the event-type pie chart."""
    events = _query_events(
        since=datetime.now(timezone.utc) - timedelta(days=7)
    )
    counts = {}
    for e in events:
        et = e.get("eventType", "UNKNOWN")
        counts[et] = counts.get(et, 0) + 1
    # Sort descending, take top 10
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return {"labels": [k for k, _ in top], "counts": [v for _, v in top]}
