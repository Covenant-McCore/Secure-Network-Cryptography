"""
app.py
------
CRYPTO-NET
Advanced Cryptographic Network Security Platform

Application factory. Creates and configures the Flask app, wires up
extensions, registers blueprints, and installs error handlers.

Blueprint registration lines are commented out for phases that haven't
been delivered yet. Uncomment as each phase lands.
"""

import logging
from logging.config import dictConfig

from flask import Flask, jsonify, render_template

from config import Config, ConfigError, get_config
import extensions

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        },
    },
    "handlers": {
        "wsgi": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "default",
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["wsgi"],
    },
})

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Build and return the configured Flask application."""
    app = Flask(__name__)

    try:
        app.config.from_object(get_config())
    except ConfigError as exc:
        logger.critical("Configuration error: %s", exc)
        raise

    # ---------- Extensions ----------
    extensions.db = extensions.init_firebase()
    extensions.he_context = extensions.build_he_context()

    # Flask-Login setup
    extensions.login_manager.init_app(app)

    # Flask-Limiter setup
    extensions.limiter.init_app(app)

    @extensions.login_manager.user_loader
    def load_user(user_id: str):
        from services.user_model import CryptoNetUser
        return CryptoNetUser.from_id(user_id)

    # ---------- Blueprints ----------
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.messages import messages_bp
    from routes.files import files_bp
    from routes.crypto_lab import crypto_lab_bp
    from routes.security import security_bp
    from routes.analytics import analytics_bp
    from routes.audit import audit_bp
    from routes.monitor import monitor_bp
    from routes.evaluation import evaluation_bp
    from routes.reports import reports_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(crypto_lab_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(monitor_bp)
    app.register_blueprint(evaluation_bp)
    app.register_blueprint(reports_bp)
    # (later phases will register additional blueprints here)

    # ---------- Health ----------
    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "firebase": extensions.db is not None,
            "he_context": extensions.he_context is not None,
        }), 200

    # ---------- Error handlers ----------
    @app.errorhandler(401)
    def unauthorized(_e):
        # Flask-Login handles redirect for HTML; this covers API calls.
        from flask import request, redirect, url_for
        if request.path.startswith("/api/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("auth.login", next=request.path))

    @app.errorhandler(403)
    def forbidden(_e):
        return jsonify({"error": "forbidden"}), 403

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.exception("Internal server error: %s", e)
        return jsonify({"error": "internal_error"}), 500

    logger.info("CRYPTO-NET application created.")
    return app


# ---------------------------------------------------------------------------
# WSGI entry point (used by gunicorn: `gunicorn app:app`)
# ---------------------------------------------------------------------------

app = create_app()


if __name__ == "__main__":
    # Development only. Never used in production (Procfile runs gunicorn).
    app.run(debug=True, host="127.0.0.1", port=5000)

