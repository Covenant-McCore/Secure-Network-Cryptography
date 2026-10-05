"""
config.py
---------
Centralised configuration for CRYPTO-NET.

Loads environment variables, validates required ones, and exposes a Config
class consumable by the Flask application factory.

Never hardcode secrets here.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env in development. In production (Railway), env vars come from the
# platform, and .env is not present — load_dotenv() is a no-op in that case.
load_dotenv()


class ConfigError(RuntimeError):
    """Raised when a required environment variable is missing or malformed."""


def _require(name: str) -> str:
    """Fetch a required environment variable or raise ConfigError."""
    value = os.environ.get(name)
    if not value:
        raise ConfigError(
            f"Missing required environment variable: {name}. "
            f"See .env.example for the full list."
        )
    return value


def _optional(name: str, default: str = "") -> str:
    """Fetch an optional environment variable."""
    return os.environ.get(name, default)


class Config:
    """Base configuration shared by all environments."""

    # ---------- Flask core ----------
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-only-insecure-key")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    # ---------- Session ----------
    SESSION_COOKIE_NAME = "cryptonet_session"
    REMEMBER_COOKIE_DURATION = 3600 * 8  # 8 hours
    # ---------- External security API behaviour ----------
    EXTERNAL_API_TIMEOUT = (5, 5)     # (connect, read) seconds
    EXTERNAL_API_MAX_RETRIES = 2
    EXTERNAL_API_BACKOFF_BASE = 0.5   # seconds; doubles each retry
    EXTERNAL_API_USER_AGENT = "CRYPTO-NET/1.0 (Final-Year Project)"

    # AbuseIPDB options
    ABUSEIPDB_MAX_AGE_DAYS = 90
    ABUSEIPDB_HIGH_RISK_SCORE = 50    # >= 50 => "suspicious"

    # Rate limits
    RATE_LIMIT_IP_REPUTATION = "30 per hour"
    RATE_LIMIT_HIBP_CHECK = "20 per hour"
    # ---------- Firebase Admin SDK ----------
    FIREBASE_CONFIG = {
        "type": "service_account",
        "project_id": _require("FIREBASE_PROJECT_ID"),
        "private_key_id": _optional("FIREBASE_PRIVATE_KEY_ID"),
        "private_key": _require("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
        "client_email": _require("FIREBASE_CLIENT_EMAIL"),
        "client_id": _optional("FIREBASE_CLIENT_ID"),
        "auth_uri": _optional("FIREBASE_AUTH_URI", "https://accounts.google.com/o/oauth2/auth"),
        "token_uri": _optional("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
        "auth_provider_x509_cert_url": _optional(
            "FIREBASE_AUTH_PROVIDER_CERT_URL",
            "https://www.googleapis.com/oauth2/v1/certs",
        ),
        "client_x509_cert_url": _optional("FIREBASE_CLIENT_CERT_URL"),
        "universe_domain": _optional("FIREBASE_UNIVERSE_DOMAIN", "googleapis.com"),
    }
    # ---------- RBAC ----------
    ROLES = frozenset({
        "ADMINISTRATOR",
        "SECURITY_OFFICER",
        "DOCTOR",
        "RECORDS_OFFICER",
        "LABORATORY_OFFICER",
    })
    CLEARANCE_LEVELS = {
        "PUBLIC": 0,
        "INTERNAL": 1,
        "CONFIDENTIAL": 2,
        "SECRET": 3,
        "TOP_SECRET": 4,
    }

    # ---------- Cryptographic configuration ----------
    # Master secret for PolicyBasedAccessControl seed derivation.
    # MUST be rotated from the previous hardcoded value.
    PBAC_MASTER_SECRET = _require("PBAC_MASTER_SECRET").encode("utf-8")

    # Homomorphic encryption context parameters (TenSEAL / BFV)
    HE_POLY_MODULUS_DEGREE = 4096
    HE_PLAIN_MODULUS = 1032193

    # ---------- External security intelligence APIs ----------
    ABUSEIPDB_API_KEY = _optional("ABUSEIPDB_API_KEY")
    IPINFO_TOKEN = _optional("IPINFO_TOKEN")

    # ---------- Rate limiting ----------
    RATE_LIMIT_LOGIN = _optional("RATE_LIMIT_LOGIN", "10 per minute")
    RATE_LIMIT_DEFAULT = _optional("RATE_LIMIT_DEFAULT", "200 per day")

    # ---------- Uploads ----------
    MAX_CONTENT_LENGTH = 700 * 1024
    UPLOAD_FOLDER = Path("secure_uploads")
    UPLOAD_FOLDER.mkdir(exist_ok=True)

    # ---------- File transfer ----------
    # Firestore enforces a 1 MB document limit. Base64 encoding inflates
    # payloads by ~33%. This cap keeps the sealed envelope comfortably
    # under the limit. Documented in thesis as a hard constraint.
    MAX_FILE_BYTES = 700 * 1024  # 700 KiB

    ALLOWED_FILE_MIME_TYPES = frozenset({
        "text/plain",
        "application/pdf",
        "image/png",
        "image/jpeg",
        "application/json",
        "text/csv",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    })


    # ---------- Firestore collection names ----------
    # Centralised so we never typo a collection name.
    COLLECTION_ORGANIZATIONS = "organizations"
    COLLECTION_USERS = "users"
    COLLECTION_KEYS = "cryptographic_keys"
    COLLECTION_MESSAGES = "secure_messages"
    COLLECTION_FILES = "secure_files"
    COLLECTION_SECURITY_EVENTS = "security_events"
    COLLECTION_ACCESS_POLICIES = "access_policies"
    COLLECTION_SESSIONS = "secure_sessions"
    COLLECTION_ANALYTICS = "analytics"
    COLLECTION_PERFORMANCE_TESTS = "performance_tests"
    COLLECTION_ABE_MASTER = "abe_master_keys"


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


def get_config() -> type[Config]:
    """Return the appropriate Config subclass for the current FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development").lower()
    if env == "production":
        return ProductionConfig
    return DevelopmentConfig

