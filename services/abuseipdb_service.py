"""
services/abuseipdb_service.py
-----------------------------
IP reputation lookups via AbuseIPDB.

API: https://api.abuseipdb.com/api/v2/check?ipAddress=<IP>&maxAgeInDays=90
Auth: "Key: <API_KEY>" header.
Response: {"data": {"abuseConfidenceScore": int, "totalReports": int,
                    "countryCode": str, "isp": str, ...}} [citation:1][citation:13][citation:18]

WHAT THIS PROVIDES
------------------
AbuseIPDB is a crowdsourced IP reputation database. A high
abuseConfidenceScore (>= 50) suggests the address has been reported for
brute-forcing, scanning, or spam [citation:13].

WHAT THIS IS NOT
----------------
This service does NOT block IPs and does NOT feed into cryptographic
decisions. It is supporting security-intelligence data, shown to the
Security Officer for situational awareness. Documented in Chapter 5.
"""

import logging

from config import Config
from services.external_api_utils import ExternalAPIError, get_json


logger = logging.getLogger(__name__)

SERVICE_NAME = "AbuseIPDB"
API_URL = "https://api.abuseipdb.com/api/v2/check"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(ip_address: str) -> dict:
    """
    Look up an IP address in AbuseIPDB.

    Returns
    -------
    dict with keys:
        status            : "ok" | "not_configured" | "unavailable"
        ip                : str (echoed back)
        abuse_score       : int (0-100) or None
        total_reports     : int or None
        country_code      : str or None
        isp               : str or None
        risk_level        : "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN"
        raw_source        : "AbuseIPDB"
        error             : str (only when status != "ok")
    """
    if not Config.ABUSEIPDB_API_KEY:
        return {
            "status": "not_configured",
            "ip": ip_address,
            "raw_source": SERVICE_NAME,
            "error": "ABUSEIPDB_API_KEY is not set.",
        }

    try:
        body = get_json(
            service=SERVICE_NAME,
            url=API_URL,
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": Config.ABUSEIPDB_MAX_AGE_DAYS,
            },
            headers={"Key": Config.ABUSEIPDB_API_KEY},
        )
    except ExternalAPIError as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip_address, exc.reason)
        return {
            "status": "unavailable",
            "ip": ip_address,
            "raw_source": SERVICE_NAME,
            "error": exc.reason,
        }

    data = (body or {}).get("data") or {}
    score = data.get("abuseConfidenceScore")

    if score is None:
        risk = "UNKNOWN"
    elif score >= Config.ABUSEIPDB_HIGH_RISK_SCORE:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "status": "ok",
        "ip": data.get("ipAddress", ip_address),
        "abuse_score": score,
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "is_public": data.get("isPublic"),
        "is_tor": data.get("isTor"),
        "last_reported_at": data.get("lastReportedAt"),
        "risk_level": risk,
        "raw_source": SERVICE_NAME,
    }
