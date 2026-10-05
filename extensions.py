"""
extensions.py
-------------
Initialises long-lived objects shared across the Flask app:

  - Firebase Admin SDK + Firestore client
  - TenSEAL BFV homomorphic encryption context
  - Flask-Login manager

Kept separate from app.py so tests can import them without booting Flask.
"""

import logging

import firebase_admin
import tenseal as ts
from firebase_admin import credentials, firestore
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config


logger = logging.getLogger(__name__)


# key_func will be overridden per-route when needed
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=[],
)

# ---------------------------------------------------------------------------
# Firebase
# ---------------------------------------------------------------------------

def init_firebase() -> firestore.Client:
    """Initialise Firebase Admin SDK once, return Firestore client."""
    try:
        firebase_admin.get_app()
        logger.info("Firebase Admin SDK already initialised.")
    except ValueError:
        cred = credentials.Certificate(Config.FIREBASE_CONFIG)
        firebase_admin.initialize_app(cred)
        logger.info(
            "Firebase Admin SDK initialised for project %s",
            Config.FIREBASE_CONFIG.get("project_id"),
        )
    return firestore.client()


# ---------------------------------------------------------------------------
# Homomorphic encryption context
# ---------------------------------------------------------------------------

def build_he_context() -> ts.Context:
    """Build the BFV context used by the privacy-preserving analytics module."""
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=Config.HE_POLY_MODULUS_DEGREE,
        plain_modulus=Config.HE_PLAIN_MODULUS,
    )
    context.generate_galois_keys()
    logger.info(
        "TenSEAL BFV context built (poly_modulus_degree=%d, plain_modulus=%d)",
        Config.HE_POLY_MODULUS_DEGREE,
        Config.HE_PLAIN_MODULUS,
    )
    return context


# ---------------------------------------------------------------------------
# Flask-Login
# ---------------------------------------------------------------------------

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to access this page."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


# ---------------------------------------------------------------------------
# Module-level singletons (populated by app.py)
# ---------------------------------------------------------------------------

db: firestore.Client | None = None
he_context: ts.Context | None = None
