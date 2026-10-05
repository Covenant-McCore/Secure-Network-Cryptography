"""
services/external_api_utils.py
------------------------------
Shared HTTP client for all external security-intelligence calls.

WHY A SHARED CLIENT
-------------------
Every external call in CRYPTO-NET must have:

  1. A hard timeout. Without one, a stalled upstream can pin a Flask
     worker indefinitely [citation:5].
  2. A small, bounded retry budget with exponential backoff. Retrying
     on network failures and 5xx is safe for idempotent GET lookups.
     We do NOT retry on 4xx — a bad request will stay bad [citation:12].
  3. A uniform error surface, so services can decide to degrade
     gracefully without each writing its own try/except.

All three behaviours are implemented here, once.
"""

import logging
import time
from typing import Any, Optional

import requests

from config import Config


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ExternalAPIError(RuntimeError):
    """
    Raised when an external API call cannot be completed after retries.

    Attributes
    ----------
    service : str
        Name of the upstream service, e.g. "AbuseIPDB".
    reason : str
        Short, safe-to-display description, e.g. "timeout", "http_503".
    """

    def __init__(self, service: str, reason: str):
        super().__init__(f"{service} error: {reason}")
        self.service = service
        self.reason = reason


# ---------------------------------------------------------------------------
# Core request helper
# ---------------------------------------------------------------------------

def get_json(
    *,
    service: str,
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: Optional[tuple[int, int]] = None,
) -> dict:
    """
    Perform a GET with retries, exponential backoff, and a hard timeout.

    Parameters
    ----------
    service : str
        Upstream name for error messages (e.g. "AbuseIPDB").
    url : str
        Full URL.
    params : dict, optional
        Query parameters.
    headers : dict, optional
        HTTP headers (API key, Accept, User-Agent).
    timeout : tuple, optional
        Overrides Config.EXTERNAL_API_TIMEOUT.

    Returns
    -------
    dict : parsed JSON body.

    Raises
    ------
    ExternalAPIError
        On timeout, network failure, retry exhaustion, or non-2xx response
        (excluding 4xx which are not retried).
    """
    timeout = timeout or Config.EXTERNAL_API_TIMEOUT
    headers = {
        "Accept": "application/json",
        "User-Agent": Config.EXTERNAL_API_USER_AGENT,
        **(headers or {}),
    }

    last_reason = "unknown"
    attempts = Config.EXTERNAL_API_MAX_RETRIES + 1

    for attempt in range(1, attempts + 1):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=timeout)

            # 4xx: do not retry — the request itself is wrong.
            if 400 <= resp.status_code < 500:
                raise ExternalAPIError(service, f"http_{resp.status_code}")

            # 5xx: retry.
            if resp.status_code >= 500:
                last_reason = f"http_{resp.status_code}"
                logger.warning("%s attempt %d returned %s", service, attempt, resp.status_code)
                if attempt < attempts:
                    _sleep_backoff(attempt)
                    continue
                raise ExternalAPIError(service, last_reason)

            # 2xx
            try:
                return resp.json()
            except ValueError as exc:
                raise ExternalAPIError(service, "invalid_json") from exc

        except (requests.Timeout, requests.ConnectionError) as exc:
            last_reason = "timeout" if isinstance(exc, requests.Timeout) else "connection_error"
            logger.warning("%s attempt %d failed: %s", service, attempt, last_reason)
            if attempt < attempts:
                _sleep_backoff(attempt)
                continue
            raise ExternalAPIError(service, last_reason) from exc

    # Unreachable, but satisfies type checkers.
    raise ExternalAPIError(service, last_reason)


def _sleep_backoff(attempt: int) -> None:
    """Exponential backoff with mild jitter."""
    import random
    delay = Config.EXTERNAL_API_BACKOFF_BASE * (2 ** (attempt - 1))
    delay += random.uniform(0, 0.2)
    time.sleep(delay)
