"""
routes/auth.py
--------------
Login, logout, and post-login redirect handling.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from services import audit_service, auth_service
from services.user_model import CryptoNetUser


auth_bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Email and password are required.", "warning")
            return render_template("login.html"), 400

        try:
            user_data = auth_service.authenticate(email, password)
        except auth_service.UserNotFound:
            audit_service.login_failed(email)
            flash("Invalid credentials.", "danger")
            return render_template("login.html"), 401
        except auth_service.InvalidCredentials:
            audit_service.login_failed(email)
            flash("Invalid credentials.", "danger")
            return render_template("login.html"), 401
        except auth_service.AccountDisabled:
            audit_service.login_failed(email)
            # Same generic message — do not reveal account status.
            flash("Invalid credentials.", "danger")
            return render_template("login.html"), 401

        # Authenticate
        user = CryptoNetUser(user_data)
        login_user(user)
        audit_service.login_success(user.id)

        # Redirect safely — never trust a raw `next` parameter.
        next_url = request.args.get("next") or ""
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = url_for("dashboard.dashboard")
        return redirect(next_url)

    return render_template("login.html")


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    audit_service.log_event("LOGOUT", user_id=user_id)
    flash("You have been signed out.", "info")
    return redirect(url_for("dashboard.landing"))
