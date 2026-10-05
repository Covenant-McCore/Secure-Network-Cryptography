"""
routes/reports.py
-----------------
/reports — summary reports and CSV export.
"""

import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, render_template, request
from flask_login import login_required

import extensions
from config import Config
from services import aggregation_service


reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    return render_template("reports.html")


@reports_bp.route("/summary")
@login_required
def summary():
    metrics = aggregation_service.dashboard_metrics()
    recent = aggregation_service.recent_events(limit=20)
    return render_template("report_summary.html", metrics=metrics, recent=recent)


@reports_bp.route("/export/events.csv")
@login_required
def export_events_csv():
    """Export the last 30 days of security events as CSV."""
    events = aggregation_service.recent_events(limit=1000)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "eventId", "eventType", "userId", "resource", "result",
        "severity", "sourceIp", "timestamp",
    ])
    for e in events:
        writer.writerow([
            e.get("eventId", ""),
            e.get("eventType", ""),
            e.get("userId", ""),
            e.get("resource", ""),
            e.get("result", ""),
            e.get("severity", ""),
            e.get("sourceIp", ""),
            e.get("timestamp", ""),
        ])
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cryptonet_events.csv"},
    )


@reports_bp.route("/export/benchmarks.csv")
@login_required
def export_benchmarks_csv():
    """Export the persisted benchmark results as CSV."""
    if extensions.db is None:
        return Response("Firestore unavailable", status=503)
    query = (
        extensions.db.collection(Config.COLLECTION_PERFORMANCE_TESTS)
        .order_by("timestamp", direction="DESCENDING")
        .limit(500)
    )
    rows = [doc.to_dict() for doc in query.stream()]

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["algorithm", "operation", "trials", "timestamp",
                     "min_ms", "max_ms", "avg_ms", "stddev_ms"])
    for r in rows:
        payload = r.get("payload", {}) or {}
        # Flatten the first timing block we find
        timing = None
        for key in ("encrypt_ms", "keygen_ms", "derive_ms", "sign_ms"):
            if key in payload:
                timing = payload[key]
                break
        writer.writerow([
            r.get("algorithm", ""),
            r.get("operation", ""),
            r.get("trials", ""),
            r.get("timestamp", ""),
            timing.get("min") if timing else "",
            timing.get("max") if timing else "",
            timing.get("avg") if timing else "",
            timing.get("stddev") if timing else "",
        ])
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cryptonet_benchmarks.csv"},
    )
