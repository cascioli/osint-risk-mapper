"""OpenCorporates REST API — Italian company officers and directors.

Requires an API token (OPENCORPORATES_API_KEY in .env/.streamlit/secrets.toml).
Without a token, requests return 401 and the module returns [] gracefully.

Free-tier tokens available at https://opencorporates.com/users/sign_up
"""

from __future__ import annotations

import re

import requests

_BASE = "https://api.opencorporates.com/v0.4"
_TIMEOUT = 15

# Strip common Italian legal-form suffixes before search — improves match rate
_LEGAL_SUFFIX_RE = re.compile(
    r"\s*\b(S\.?\s*r\.?\s*l\.?|SRL|S\.?\s*p\.?\s*A\.?|SPA|S\.?\s*n\.?\s*c\.?|SNC"
    r"|S\.?\s*a\.?\s*s\.?|SAS|S\.?\s*a\.?\s*p\.?\s*a\.?|SAPA|S\.?\s*s\.?|SS"
    r"|S\.?\s*c\.?\s*r\.?\s*l\.?|SCRL|S\.?\s*c\.?\s*a\.?\s*r\.?\s*l\.?|SCARL"
    r"|Onlus|ASD|APS)\b\.?",
    re.IGNORECASE,
)


def _clean_company_name(name: str) -> str:
    return _LEGAL_SUFFIX_RE.sub("", name).strip().strip(".,")


def _title(s: str) -> str:
    """Title-case a string — Italian names in OpenCorporates are ALL CAPS."""
    return s.title() if s else s


def search_company_it(company_name: str, api_token: str = "", per_page: int = 5) -> list[dict]:
    """Search for Italian companies by name.

    Returns a list of company dicts with keys:
        name, number, jurisdiction_code, address, status, opencorporates_url
    Returns [] without an api_token (API returns 401).
    """
    if not company_name or not api_token:
        return []

    query = _clean_company_name(company_name)
    params = {
        "q": query,
        "jurisdiction_code": "it",
        "format": "json",
        "per_page": per_page,
        "api_token": api_token,
    }
    try:
        r = requests.get(f"{_BASE}/companies/search", params=params, timeout=_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException:
        return []

    raw_companies = r.json().get("results", {}).get("companies", [])
    results = []
    for item in raw_companies:
        c = item.get("company", {})
        if not c:
            continue
        addr = c.get("registered_address") or {}
        results.append({
            "name": _title(c.get("name", "")),
            "number": c.get("company_number", ""),
            "jurisdiction_code": c.get("jurisdiction_code", "it"),
            "address": _title(addr.get("street_address", "") or ""),
            "city": _title(addr.get("locality", "") or ""),
            "status": c.get("current_status", ""),
            "opencorporates_url": c.get("opencorporates_url", ""),
        })
    return results


def fetch_officers(jurisdiction_code: str, company_number: str, api_token: str = "") -> list[dict]:
    """Fetch current and past officers for a specific company.

    Returns list of dicts with keys: name, role, start_date, end_date, current
    """
    if not jurisdiction_code or not company_number or not api_token:
        return []

    url = f"{_BASE}/companies/{jurisdiction_code}/{company_number}/officers"
    params: dict = {"format": "json", "api_token": api_token}
    try:
        r = requests.get(url, params=params, timeout=_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException:
        return []

    raw = r.json().get("results", {}).get("officers", [])
    officers = []
    for item in raw:
        o = item.get("officer", {})
        if not o or not o.get("name"):
            continue
        officers.append({
            "name": _title(o.get("name", "")),
            "role": o.get("role", ""),
            "start_date": o.get("start_date"),
            "end_date": o.get("end_date"),
            "current": o.get("end_date") is None,
        })
    return officers


def find_company_officers(company_name: str, city: str = "", api_token: str = "") -> list[dict]:
    """High-level: search for an Italian company and return its officers/directors.

    Requires api_token. Returns [] without one.
    Applies city-based matching when available to select the right company.

    Returns list of dicts:
        name, role, current, start_date, company_name, company_url
    """
    if not company_name or not api_token:
        return []

    companies = search_company_it(company_name, api_token=api_token)
    if not companies:
        return []

    target = companies[0]
    if city:
        city_lower = city.lower()
        for c in companies:
            if city_lower in (c.get("city") or "").lower() or city_lower in (c.get("address") or "").lower():
                target = c
                break

    officers = fetch_officers(target["jurisdiction_code"], target["number"], api_token=api_token)
    return [
        {
            "name": o["name"],
            "role": o["role"],
            "current": o["current"],
            "start_date": o.get("start_date"),
            "company_name": target["name"],
            "company_url": target.get("opencorporates_url", ""),
        }
        for o in officers
        if o.get("name")
    ]
