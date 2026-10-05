"""
routes/dashboard.py
-------------------
Public landing, about, and the authenticated security dashboard.

Dashboard metrics are sourced from real Firestore aggregations.
"""

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from config import Config
from services import aggregation_service


dashboard_bp = Blueprint("dashboard", __name__)


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@dashboard_bp.route("/")
def landing():
    return render_template("landing.html")


@dashboard_bp.route("/about")
def about():
    return render_template("about.html")


# ---------------------------------------------------------------------------
# Authenticated dashboard
# ---------------------------------------------------------------------------

@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    # Pull real metrics from Firestore through the aggregation service.
    metrics = aggregation_service.dashboard_metrics()

    return render_template(
        "dashboard.html",
        metrics=metrics,
        system_status="PROTECTED",
        role=current_user.role,
    )
