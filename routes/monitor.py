"""
routes/monitor.py
-----------------
/security/monitor — live security dashboard.
"""

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from services import aggregation_service


monitor_bp = Blueprint("monitor", __name__, url_prefix="/security/monitor")


@monitor_bp.route("/")
@login_required
def index():
    return render_template("security_monitor.html")


@monitor_bp.route("/data")
@login_required
def data():
    return jsonify({
        "metrics": aggregation_service.dashboard_metrics(),
        "timeline": aggregation_service.event_timeline(days=14),
        "distribution": aggregation_service.event_type_distribution(),
    }), 200
