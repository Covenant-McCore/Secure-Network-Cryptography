"""
services/ipinfo_service.py
--------------------------
IP context enrichment via IPinfo Lite.

API: https://api.ipinfo.io/lite/<IP>?token=<TOKEN>
Auth: token query parameter (or Basic/Bearer).
Response: {"ip", "asn", "as_name", "as_domain", "country",
           "country_code", "continent", "continent_code"} [citation:2][citation:8][citation:19]

NOTE ON IPinfo Lite
-------------------
IPinfo Lite is the current free tier. It is NOT a drop-in replacement for
the Legacy Free API: it returns country and ASN only, with no city, region,
coordinates, hostname, or timezone [citation:2]. We use Lite because it has
no request cap and permits commercial use with attribution.
"""

import logging

from config import Config
from services.external_api_utils import ExternalAPIError, get_json


logger = logging.getLogger(__name__)

SERVICE_NAME = "IPinfo"
API_URL_TEMPLATE = "https://api.ipinfo.io/lite/{ip}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(ip_address: str) -> dict:
    """
    Look up ASN and country for an IP via IPinfo Lite.

    Returns
    -------
    dict with keys:
        status          : "ok" | "not_configured" | "unavailable"
        ip              : str
        country         : str or None
        country_code    : str or None
        asn             : str or None
        as_name         : str or None
        continent       : str or None
        raw_source      : "IPinfo Lite"
        error           : str (only when status != "ok")
    """
    if not Config.IPINFO_TOKEN:
        return {
            "status": "not_configured",
            "ip": ip_address,
            "raw_source": SERVICE_NAME,
            "error": "IPINFO_TOKEN is not set.",
        }

    url = API_URL_TEMPLATE.format(ip=ip_address)

    try:
        body = get_json(
            service=SERVICE_NAME,
            url=url,
            params={"token": Config.IPINFO_TOKEN},
        )
    except ExternalAPIError as exc:
        logger.warning("IPinfo lookup failed for %s: %s", ip_address, exc.reason)
        return {
            "status": "unavailable",
            "ip": ip_address,
            "raw_source": SERVICE_NAME,
            "error": exc.reason,
        }

    return {
        "status": "ok",
        "ip": body.get("ip", ip_address),
        "country": body.get("country"),
        "country_code": body.get("country_code"),
        "asn": body.get("asn"),
        "as_name": body.get("as_name"),
        "continent": body.get("continent"),
        "continent_code": body.get("continent_code"),
        "raw_source": SERVICE_NAME,
    }
