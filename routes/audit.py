"""
routes/audit.py
---------------
/audit — filterable audit log viewer.
"""

from flask import Blueprint, render_template, request
from flask_login import login_required

from services import aggregation_service


audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("/")
@login_required
def index():
    event_type = (request.args.get("type") or "").strip() or None
    user_id = (request.args.get("user") or "").strip() or None
    limit = min(int(request.args.get("limit", 100)), 500)

    events = aggregation_service.recent_events(
        limit=limit, event_type=event_type, user_id=user_id
    )
    # Distinct event types present in the system (for the filter dropdown)
    all_types = sorted({e.get("eventType", "") for e in aggregation_service.recent_events(limit=500)})

    return render_template(
        "audit_log.html",
        events=events,
        selected_type=event_type or "",
        selected_user=user_id or "",
        all_types=all_types,
    )
