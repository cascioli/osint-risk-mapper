"""Google Dorking via Serper.dev (primary) with SerpAPI fallback.

Finds publicly indexed sensitive documents for a target domain.
Only metadata and URLs are extracted — file contents are never downloaded.
"""

import requests

_SERPER_ENDPOINT = "https://google.serper.dev/search"
_SERPAPI_ENDPOINT = "https://serpapi.com/search"

_SENSITIVE_EXTENSIONS = (
    "pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx "
    "OR ext:sql OR ext:env OR ext:bak OR ext:txt"
)


def _search_serper(query: str, api_key: str, num_results: int) -> list[dict[str, str]]:
    headers = {
        "X-API-KEY": api_key,
        "Content-Type": "application/json",
    }
    payload = {"q": query, "num": min(num_results, 10)}

    try:
        response = requests.post(_SERPER_ENDPOINT, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        if status == 429:
            raise RuntimeError("Serper.dev: quota superata (429).") from exc
        if status == 401:
            raise RuntimeError("Serper.dev: API Key non valida (401).") from exc
        raise RuntimeError(f"Serper.dev HTTP error {status}: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Serper.dev network error: {exc}") from exc

    items: list[dict] = response.json().get("organic", [])
    return [
        {"title": item.get("title", "N/D"), "url": item.get("link", "")}
        for item in items
        if item.get("link")
    ]


def _search_serpapi(query: str, api_key: str, num_results: int) -> list[dict[str, str]]:
    params = {
        "q": query,
        "api_key": api_key,
        "engine": "google",
        "num": min(num_results, 10),
    }

    try:
        response = requests.get(_SERPAPI_ENDPOINT, params=params, timeout=15)
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        if status == 429:
            raise RuntimeError("SerpAPI: quota superata (429).") from exc
        if status == 401:
            raise RuntimeError("SerpAPI: API Key non valida (401).") from exc
        raise RuntimeError(f"SerpAPI HTTP error {status}: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"SerpAPI network error: {exc}") from exc

    items: list[dict] = response.json().get("organic_results", [])
    return [
        {"title": item.get("title", "N/D"), "url": item.get("link", "")}
        for item in items
        if item.get("link")
    ]


def search_by_query(
    query: str,
    api_key: str,
    num_results: int = 10,
    fallback_key: str = "",
) -> list[dict[str, str]]:
    """Execute a dork query. Tries Serper.dev first, falls back to SerpAPI.

    Returns list of dicts with keys "title" and "url".
    """
    if not query:
        return []

    if api_key:
        try:
            return _search_serper(query, api_key, num_results)
        except RuntimeError:
            if not fallback_key:
                raise

    if fallback_key:
        return _search_serpapi(query, fallback_key, num_results)

    return []


def search_linkedin_profiles(
    name: str,
    company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 5,
) -> list[dict[str, str]]:
    """Search for LinkedIn profiles matching a person name and company."""
    if not name:
        return []
    query = f'site:linkedin.com "{name}"'
    if company:
        query += f' "{company}"'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_twitter_presence(
    company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 5,
) -> list[dict[str, str]]:
    """Search for Twitter/X presence for a company."""
    if not company:
        return []
    query = f'site:twitter.com "{company}" OR site:x.com "{company}"'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_github_mentions(
    domain: str,
    company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Search GitHub for leaked code, configs, or credentials mentioning this domain/company."""
    parts = []
    if domain:
        parts.append(f'"{domain}"')
    if company and company.lower() not in domain.lower():
        parts.append(f'"{company}"')
    if not parts:
        return []
    query = f"site:github.com {' OR '.join(parts)}"
    return search_by_query(query, api_key, num_results, fallback_key)


def search_pastebin_mentions(
    domain: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Search Pastebin for leaks mentioning this domain."""
    if not domain:
        return []
    query = f'site:pastebin.com "{domain}"'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_brand_documents(
    company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Search for publicly indexed documents mentioning the company name."""
    if not company:
        return []
    query = f'"{company}" filetype:pdf OR filetype:doc OR filetype:xls OR filetype:xlsx'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_exposed_documents(
    domain: str,
    api_key: str,
    num_results: int = 10,
    fallback_key: str = "",
) -> list[dict[str, str]]:
    """Query for publicly indexed sensitive files on a domain.

    Args:
        domain:       Target domain (e.g. "example.com").
        api_key:      Serper.dev API key (primary).
        num_results:  Max results to request (1–10).
        fallback_key: SerpAPI key used if Serper.dev fails or is absent.

    Returns:
        List of dicts with keys "title" and "url".

    Raises:
        RuntimeError on quota/auth failures with no fallback available.
    """
    if not api_key and not fallback_key:
        return []

    dork_query = f"site:{domain} ext:{_SENSITIVE_EXTENSIONS}"
    return search_by_query(dork_query, api_key, num_results, fallback_key)
