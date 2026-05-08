"""HaveIBeenPwned API v3 — breach check for individual email addresses."""

from __future__ import annotations

import time

import requests

_BASE = "https://haveibeenpwned.com/api/v3"
_TIMEOUT = 15
_DELAY = 1.5  # HIBP recommends >= 1.5s between requests on paid tier


def check_email_breaches(api_key: str, email: str) -> list[str]:
    """Return list of breach names for a single email address.

    Returns [] if email is clean (404) or on non-fatal network errors.
    Raises ValueError on invalid API key (401).
    """
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "OSINT-Research/1.0",
    }
    params = {"truncateResponse": "false"}

    try:
        r = requests.get(
            f"{_BASE}/breachedaccount/{email}",
            headers=headers,
            params=params,
            timeout=_TIMEOUT,
        )
    except requests.RequestException:
        return []

    if r.status_code == 401:
        raise ValueError("HIBP: API key non valida (401)")
    if r.status_code == 404:
        return []
    if r.status_code == 429:
        time.sleep(5.0)
        return []
    if r.status_code != 200:
        return []

    return [b["Name"] for b in r.json() if b.get("Name")]


def check_emails_batch(api_key: str, emails: list[str]) -> dict[str, list[str]]:
    """Check multiple emails against HIBP, respecting rate limits.

    Returns dict mapping each email to its list of breach names.
    """
    results: dict[str, list[str]] = {}
    for i, email in enumerate(emails):
        if i > 0:
            time.sleep(_DELAY)
        results[email] = check_email_breaches(api_key, email)
    return results
