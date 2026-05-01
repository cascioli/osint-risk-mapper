"""Google Dorking module via Custom Search JSON API.

Finds publicly indexed sensitive documents for a target domain.
Only metadata and URLs are extracted — file contents are never downloaded.
"""

import requests

_GOOGLE_CSE_ENDPOINT = "https://www.googleapis.com/customsearch/v1"

_SENSITIVE_EXTENSIONS = (
    "pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx "
    "OR ext:sql OR ext:env OR ext:bak OR ext:txt"
)


def search_by_query(
    query: str,
    api_key: str,
    cx_id: str,
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Execute a pre-built Google CSE query string.

    Returns list of dicts with keys "title" and "url".
    Returns empty list on quota/auth errors (caller handles warnings).
    """
    if not api_key or not cx_id or not query:
        return []

    params: dict[str, str | int] = {
        "key": api_key,
        "cx": cx_id,
        "q": query,
        "num": min(num_results, 10),
    }

    try:
        response = requests.get(_GOOGLE_CSE_ENDPOINT, params=params, timeout=15)
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        if status == 429:
            raise RuntimeError("Google CSE: limite giornaliero di ricerche superato (quota 429).") from exc
        if status == 403:
            raise RuntimeError("Google CSE: API Key non valida o accesso negato (403).") from exc
        raise RuntimeError(f"Google CSE HTTP error {status}: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Google CSE network error: {exc}") from exc

    items: list[dict] = response.json().get("items", [])
    return [
        {"title": item.get("title", "N/D"), "url": item.get("link", "")}
        for item in items
        if item.get("link")
    ]


def search_exposed_documents(
    domain: str,
    api_key: str,
    cx_id: str,
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Query Google Custom Search API for publicly indexed sensitive files.

    Args:
        domain:      Target domain (e.g. "example.com").
        api_key:     Google Custom Search JSON API key.
        cx_id:       Programmable Search Engine (CX) ID.
        num_results: Max results to request (1–10, API limit per call).

    Returns:
        List of dicts with keys "title" and "url".
        Empty list on no results, missing keys, or API errors.

    Raises:
        RuntimeError on quota/auth failures.
    """
    if not api_key or not cx_id:
        return []

    dork_query = f"site:{domain} ext:{_SENSITIVE_EXTENSIONS}"
    return search_by_query(dork_query, api_key, cx_id, num_results)
