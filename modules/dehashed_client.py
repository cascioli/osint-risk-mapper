"""DeHashed API — breach lookup by username, email, name, or phone."""

from __future__ import annotations

import requests

_SEARCH_URL = "https://api.dehashed.com/search"
_VALID_TYPES = {"username", "email", "name", "phone", "address", "ip_address", "vin", "free"}


def search(
    query: str,
    query_type: str,
    email: str,
    api_key: str,
    max_results: int = 50,
) -> list[dict]:
    """Search DeHashed for breach records matching query.

    Args:
        query: The value to search for (e.g. "sfontana", "samantha.fontana@gmail.com")
        query_type: Field to search — "username"|"email"|"name"|"phone"|"address"
        email: DeHashed account email (used as Basic auth username)
        api_key: DeHashed API key (used as Basic auth password)
        max_results: Max entries to return (DeHashed pages at 10000 per page)

    Returns list of dicts with keys: email, username, password, hashed_password,
        name, vin, address, phone, database_name, id
    Returns [] on 429 or non-fatal errors. Raises ValueError on 401.
    """
    if not api_key or not email:
        return []
    if not query:
        return []

    qt = query_type.lower()
    if qt not in _VALID_TYPES:
        qt = "username"

    if qt == "free":
        dork = query
    else:
        dork = f"{qt}:{query}"

    params = {
        "query": dork,
        "size": min(max_results, 10000),
    }

    try:
        resp = requests.get(
            _SEARCH_URL,
            params=params,
            auth=(email, api_key),
            headers={"Accept": "application/json"},
            timeout=20,
        )
        if resp.status_code == 401:
            raise ValueError("DeHashed credenziali non valide (401)")
        if resp.status_code == 429:
            return []
        if resp.status_code == 400:
            return []
        if resp.status_code != 200:
            return []
        data = resp.json()
        entries = data.get("entries") or []
        return [_normalise(e) for e in entries[:max_results]]
    except ValueError:
        raise
    except Exception:
        return []


def _normalise(raw: dict) -> dict:
    return {
        "email": raw.get("email", ""),
        "username": raw.get("username", ""),
        "password": raw.get("password", ""),
        "hashed_password": raw.get("hashed_password", ""),
        "name": raw.get("name", ""),
        "phone": raw.get("phone", ""),
        "address": raw.get("address", ""),
        "database_name": raw.get("database_name", ""),
        "id": raw.get("id", ""),
    }
