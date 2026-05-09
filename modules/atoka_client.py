"""Atoka.io API — Italian company enrichment (ATECO, sede, soci, PEC, fatturato)."""

from __future__ import annotations

import requests

_API_BASE = "https://atoka.io/api"
_SEARCH_URL = f"{_API_BASE}/companies/"


def search_company(
    company_name: str,
    city: str = "",
    piva: str = "",
    api_key: str = "",
) -> dict:
    """Search Atoka.io for an Italian company.

    Returns a normalised dict with keys:
        name, piva, cf, ateco, ateco_desc, sede, pec, email, phone,
        officers (list[dict]), fatturato, dipendenti, founded_year, url
    Returns {} if api_key is empty or on any failure.
    """
    if not api_key:
        return {}
    if not company_name:
        return {}

    headers = {
        "Authorization": f"Token {api_key}",
        "Accept": "application/json",
    }
    params: dict = {
        "name": company_name,
        "active": "true",
        "limit": 5,
    }
    if piva:
        params["taxId"] = piva
    if city:
        params["city"] = city

    try:
        resp = requests.get(_SEARCH_URL, params=params, headers=headers, timeout=15)
        if resp.status_code == 401:
            raise ValueError("Atoka API key non valida (401)")
        if resp.status_code == 429:
            return {}
        if resp.status_code != 200:
            return {}
        data = resp.json()
        items = data.get("items") or data.get("results") or []
        if not items:
            return {}
        # Pick first result — caller should verify relevance
        return _normalise(items[0])
    except ValueError:
        raise
    except Exception:
        return {}


def _normalise(raw: dict) -> dict:
    """Flatten Atoka response to a consistent schema."""
    officers = []
    for person in raw.get("people", []):
        officers.append({
            "name": person.get("fullName") or f"{person.get('firstName','')} {person.get('lastName','')}".strip(),
            "role": person.get("role", ""),
            "current": person.get("active", True),
            "start_date": person.get("startDate", ""),
        })

    address = raw.get("registeredAddress") or raw.get("address") or {}
    sede = ", ".join(filter(None, [
        address.get("streetName", ""),
        address.get("city", ""),
        address.get("province", ""),
        address.get("zip", ""),
    ]))

    return {
        "name": raw.get("name", ""),
        "piva": raw.get("taxId", ""),
        "cf": raw.get("fiscalCode", ""),
        "ateco": raw.get("atecoCode", ""),
        "ateco_desc": raw.get("atecoDesc") or raw.get("atecoDescription", ""),
        "sede": sede,
        "pec": raw.get("pec", ""),
        "email": raw.get("email", ""),
        "phone": raw.get("phone", ""),
        "officers": officers,
        "fatturato": raw.get("revenues") or raw.get("revenue", ""),
        "dipendenti": raw.get("employees", ""),
        "founded_year": raw.get("foundedYear") or raw.get("incorporationYear", ""),
        "url": raw.get("url", ""),
    }
