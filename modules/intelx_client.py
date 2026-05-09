"""IntelX API — intelligence lookup for email, username, domain, phone."""

from __future__ import annotations

import time

import requests

_BASE = "https://2.intelx.io"
_SEARCH_URL = f"{_BASE}/intelligent/search"
_RESULT_URL = f"{_BASE}/intelligent/search/result"

# IntelX media type IDs for text-like leaks
_TEXT_TYPES = {1, 2, 8, 13, 14, 15, 17, 21}


def search(query: str, api_key: str, max_results: int = 20) -> list[dict]:
    """Search IntelX for leaked records matching query.

    Two-step: POST to create search → GET results after brief wait.
    Returns list of {type, name, value, bucket, date, storageid}.
    Returns [] on non-fatal errors. Raises ValueError on 401.
    """
    if not api_key or not query:
        return []

    headers = {
        "x-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Step 1: create search
    payload = {
        "term": query,
        "buckets": [],
        "lookuplevel": 0,
        "maxresults": max_results,
        "timeout": 20,
        "datefrom": "",
        "dateto": "",
        "sort": 4,       # date desc
        "media": 0,      # all media
        "terminate": [],
    }

    try:
        r = requests.post(_SEARCH_URL, json=payload, headers=headers, timeout=20)
        if r.status_code == 401:
            raise ValueError("IntelX API key non valida (401)")
        if r.status_code == 402:
            raise ValueError("IntelX quota esaurita (402)")
        if r.status_code != 200:
            return []
        search_id = r.json().get("id", "")
        if not search_id:
            return []
    except ValueError:
        raise
    except Exception:
        return []

    # Step 2: retrieve results (wait for indexing)
    time.sleep(3)
    try:
        r2 = requests.get(
            _RESULT_URL,
            params={"id": search_id, "limit": max_results, "offset": 0},
            headers=headers,
            timeout=20,
        )
        if r2.status_code != 200:
            return []
        data = r2.json()
        records = data.get("records") or []
        return [_normalise(rec) for rec in records[:max_results]]
    except Exception:
        return []


def _normalise(raw: dict) -> dict:
    meta = raw.get("systemid", {}) if isinstance(raw.get("systemid"), dict) else {}
    return {
        "name": raw.get("name", ""),
        "bucket": raw.get("bucket", ""),
        "type": raw.get("type", 0),
        "date": raw.get("date", ""),
        "storageid": raw.get("storageid", ""),
        "value": raw.get("value") or raw.get("name", ""),
        "added": raw.get("added", ""),
    }
