"""VirusTotal API v3 — passive subdomain enumeration."""

from __future__ import annotations

import time

import requests

_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15
_PAGE_DELAY = 1.0  # Free tier: 4 req/min — 1s between pages stays within quota


def fetch_vt_subdomains(api_key: str, domain: str, max_pages: int = 5) -> list[str]:
    """Fetch subdomains from VirusTotal passive DNS data.

    Returns sorted list of unique subdomain strings.
    Raises ValueError on invalid API key (401).
    Silently stops on quota exhaustion (429).
    """
    headers = {"x-apikey": api_key}
    url = f"{_BASE}/domains/{domain}/subdomains"
    params: dict = {"limit": 40}
    subdomains: set[str] = set()

    for page_num in range(max_pages):
        if page_num > 0:
            time.sleep(_PAGE_DELAY)
        try:
            r = requests.get(url, headers=headers, params=params, timeout=_TIMEOUT)
        except requests.RequestException:
            break

        if r.status_code == 401:
            raise ValueError("VirusTotal: API key non valida (401)")
        if r.status_code in (429, 204):
            break
        if r.status_code != 200:
            break

        data = r.json()
        for item in data.get("data", []):
            subdomains.add(item["id"])

        cursor = data.get("meta", {}).get("cursor")
        if not cursor:
            break
        params = {"limit": 40, "cursor": cursor}

    return sorted(subdomains)
