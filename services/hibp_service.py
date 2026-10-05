"""
services/hibp_service.py
------------------------
Pwned password screening via Have I Been Pwned (k-anonymity range API).

ENDPOINT
--------
GET https://api.pwnedpasswords.com/range/{first-5-chars-of-SHA1}
Response: text/plain, one line per suffix: "<35-char-suffix>:<count>"

PROTOCOL (k-anonymity)
----------------------
1. SHA-1 the candidate password locally.
2. Send ONLY the first 5 hex characters of the hash to the API.
3. Receive a list of ~800 hash suffixes that share that prefix.
4. Locally check whether our password's suffix appears in the list.
5. Report the breach count.

The plaintext password never leaves the process. The full hash never
leaves the process. Only 5 characters of a SHA-1 hash are sent — a value
that maps to roughly 800 distinct candidate passwords. [citation:3][citation:9][citation:15]

USAGE
-----
This service is called ONLY at account creation and password change.
It is not called at login. See docstring in service module for rationale.
"""

import hashlib
import logging

from config import Config
from services.external_api_utils import ExternalAPIError, get_json


logger = logging.getLogger(__name__)

SERVICE_NAME = "HIBP Pwned Passwords"
API_URL = "https://api.pwnedpasswords.com/range/{prefix}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_password(candidate_password: str) -> dict:
    """
    Check whether a password appears in the Pwned Passwords corpus.

    Returns
    -------
    dict with keys:
        status          : "ok" | "unavailable"
        breached        : bool or None
        count           : int or None (number of breach occurrences)
        message         : human-readable explanation
        raw_source      : "HIBP Pwned Passwords"
        error           : str (only when status == "unavailable")
    """
    if not candidate_password:
        return {
            "status": "ok",
            "breached": False,
            "count": 0,
            "message": "Empty password (rejected by policy elsewhere).",
            "raw_source": SERVICE_NAME,
        }

    # ---- 1. SHA-1 the password locally ----
    sha1 = hashlib.sha1(candidate_password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    # ---- 2. Query only the prefix ----
    try:
        # The range API returns text/plain; our shared get_json would fail.
        # We use a thin wrapper that returns the raw text.
        text = _get_text(API_URL.format(prefix=prefix))
    except ExternalAPIError as exc:
        logger.warning("HIBP lookup failed: %s", exc.reason)
        return {
            "status": "unavailable",
            "breached": None,
            "count": None,
            "message": "External security intelligence temporarily unavailable.",
            "raw_source": SERVICE_NAME,
            "error": exc.reason,
        }

    # ---- 3. Search the returned lines for our suffix ----
    count = 0
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        if parts[0].upper() == suffix:
            try:
                count = int(parts[1])
            except ValueError:
                count = 1
            break

    breached = count > 0
    if breached:
        message = (
            f"Password appears in known breach data ({count} occurrences). "
            f"Choose a different password."
        )
    else:
        message = "Password not found in the known Pwned Passwords dataset."

    return {
        "status": "ok",
        "breached": breached,
        "count": count,
        "message": message,
        "raw_source": SERVICE_NAME,
    }


# ---------------------------------------------------------------------------
# Text-response variant
# ---------------------------------------------------------------------------

def _get_text(url: str) -> str:
    """
    Like external_api_utils.get_json but for text/plain responses.

    Kept local to this module because the HIBP range endpoint is the only
    text-returning API in the project.
    """
    import requests

    last_reason = "unknown"
    attempts = Config.EXTERNAL_API_MAX_RETRIES + 1

    for attempt in range(1, attempts + 1):
        try:
            resp = requests.get(
                url,
                headers={
                    "User-Agent": Config.EXTERNAL_API_USER_AGENT,
                    "Accept": "text/plain",
                },
                timeout=Config.EXTERNAL_API_TIMEOUT,
            )
            if 400 <= resp.status_code < 500:
                raise ExternalAPIError(SERVICE_NAME, f"http_{resp.status_code}")
            if resp.status_code >= 500:
                last_reason = f"http_{resp.status_code}"
                if attempt < attempts:
                    _sleep(attempt)
                    continue
                raise ExternalAPIError(SERVICE_NAME, last_reason)
            return resp.text
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_reason = "timeout" if isinstance(exc, requests.Timeout) else "connection_error"
            if attempt < attempts:
                _sleep(attempt)
                continue
            raise ExternalAPIError(SERVICE_NAME, last_reason) from exc

    raise ExternalAPIError(SERVICE_NAME, last_reason)


def _sleep(attempt: int) -> None:
    import random, time
    delay = Config.EXTERNAL_API_BACKOFF_BASE * (2 ** (attempt - 1))
    delay += random.uniform(0, 0.2)
    time.sleep(delay)
