"""inipec.gov.it — official Italian PEC email registry lookup."""

from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

_BASE = "https://www.inipec.gov.it/cerca-pec/-/pec/ricerca"
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "it-IT,it;q=0.9",
    "Referer": "https://www.inipec.gov.it/",
}
_PEC_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.pec\.[a-zA-Z]{2,}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)


def _parse_pec_from_html(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    found: list[str] = []

    # Try table cells first
    for cell in soup.find_all(["td", "span", "div", "p"]):
        text = cell.get_text(strip=True)
        for m in _PEC_RE.finditer(text):
            addr = m.group(0).lower()
            if addr not in found:
                found.append(addr)
        if not found:
            for m in _EMAIL_RE.finditer(text):
                addr = m.group(0).lower()
                if "pec" in addr and addr not in found:
                    found.append(addr)

    # Fallback: scan raw HTML for PEC patterns
    if not found:
        for m in _PEC_RE.finditer(html):
            addr = m.group(0).lower()
            if addr not in found:
                found.append(addr)

    return found


def fetch_pec_by_company(company_name: str, city: str = "") -> list[str]:
    """Search inipec.gov.it for PEC email by company name (denominazione).

    Returns list of PEC addresses found, [] on any failure.
    """
    if not company_name:
        return []
    try:
        params: dict = {"denominazione": company_name}
        if city:
            params["comune"] = city
        resp = requests.get(_BASE, params=params, headers=_HEADERS, timeout=15)
        if resp.status_code != 200:
            return []
        return _parse_pec_from_html(resp.text)
    except Exception:
        return []


def fetch_pec_by_person(first_name: str, last_name: str) -> list[str]:
    """Search inipec.gov.it for PEC email of a person as legale rappresentante.

    Returns list of PEC addresses found, [] on any failure.
    """
    if not first_name or not last_name:
        return []
    try:
        params = {"nome": first_name, "cognome": last_name}
        resp = requests.get(_BASE, params=params, headers=_HEADERS, timeout=15)
        if resp.status_code != 200:
            return []
        return _parse_pec_from_html(resp.text)
    except Exception:
        return []
