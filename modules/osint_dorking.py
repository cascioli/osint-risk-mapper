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
    city: str = "",
) -> list[dict[str, str]]:
    """Search for LinkedIn profiles matching a person name.

    Adds company and city to narrow results when available.
    Returns multiple candidates — caller must not assume they are the correct person.
    """
    if not name:
        return []
    query = f'site:linkedin.com "{name}"'
    if company:
        query += f' "{company}"'
    if city:
        query += f' "{city}"'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_twitter_presence(
    company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 5,
    city: str = "",
) -> list[dict[str, str]]:
    """Search for Twitter/X presence for a company or person name.

    Adds city context when available to reduce false positives.
    Results are candidates, not verified identities.
    """
    if not company:
        return []
    query = f'site:twitter.com "{company}" OR site:x.com "{company}"'
    if city:
        query += f' "{city}"'
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
    domain: str,
    company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Search for documents directly tied to this specific domain.

    Two targeted queries:
    1. Documents hosted ON the domain (site:domain filetype:...)
    2. External documents that reference the domain URL explicitly

    Deliberately avoids pure company-name searches — too many false positives
    when company names are common (e.g. "Farmacia Fontana" returns all Italian
    pharmacies with that name).
    """
    if not domain:
        return []

    results: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    def _add(items: list[dict]) -> None:
        for item in items:
            if item.get("url") not in seen_urls:
                seen_urls.add(item["url"])
                results.append(item)

    # 1. Documents hosted on the domain itself
    q1 = f"site:{domain} filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx"
    try:
        _add(search_by_query(q1, api_key, num_results, fallback_key))
    except RuntimeError:
        pass

    # 2. External documents that explicitly cite this domain URL
    q2 = f'"{domain}" filetype:pdf OR filetype:doc'
    try:
        _add(search_by_query(q2, api_key, num_results // 2, fallback_key))
    except RuntimeError:
        pass

    return results


def search_instagram_profiles(
    name: str,
    company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 5,
    city: str = "",
) -> list[dict[str, str]]:
    """Search Instagram for profiles matching a person or company name.

    Adds company and city context to reduce false positives.
    Returns multiple candidates — caller must not assume verified identity.
    """
    if not name and not company:
        return []
    query = f'site:instagram.com "{name or company}"'
    if name and company:
        query += f' "{company}"'
    if city:
        query += f' "{city}"'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_facebook_profiles(
    name_or_company: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 5,
    city: str = "",
) -> list[dict[str, str]]:
    """Search Facebook for pages or profiles matching a company or person name.

    Results are candidates — caller must verify relevance.
    """
    if not name_or_company:
        return []
    query = f'site:facebook.com "{name_or_company}"'
    if city:
        query += f' "{city}"'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_piva_mentions(
    piva: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Search for sites and documents mentioning a specific Italian VAT number (P.IVA).

    Finds related company properties, registrations, and external references.
    """
    if not piva:
        return []
    query = f'"{piva}"'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_email_pattern_external(
    domain: str,
    api_key: str,
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Search for email addresses at a domain mentioned on external sites.

    Finds employee emails in documents, forum posts, LinkedIn profiles, etc.
    Excludes the domain itself to focus on external references only.
    """
    if not domain:
        return []
    query = f'"@{domain}" -site:{domain}'
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


def search_pagine_bianche(
    name: str,
    city: str = "",
    api_key: str = "",
    fallback_key: str = "",
    num_results: int = 5,
) -> list[dict[str, str]]:
    """Search paginebianche.it and paginegialle.it for a person's phone and address.

    Effective for Italian PMI owners — most have a personal or business listing.
    """
    if not name:
        return []
    base = f'"{name}"'
    if city:
        base += f' "{city}"'
    query = f'{base} (site:paginebianche.it OR site:paginegialle.it OR site:tuttitalia.it)'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_username_leaks(
    username: str,
    api_key: str = "",
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Search for a username in Pastebin, GitHub, leak forums, and Telegram.

    Use username variations derived from a person's name (e.g. sfontana, samantha.fontana).
    """
    if not username:
        return []
    query = (
        f'"{username}" '
        f'(site:pastebin.com OR site:github.com OR site:raidforums.com '
        f'OR site:breached.to OR site:telegram.me OR intext:password)'
    )
    return search_by_query(query, api_key, num_results, fallback_key)


def search_registry_dork(
    company_name: str,
    piva: str = "",
    city: str = "",
    api_key: str = "",
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Dork Italian company registry sources for company data.

    Searches registroimprese.it, impresainungiorno.gov.it, codicefiscale.net
    and other public sources for P.IVA, sede, ATECO, and company officers.
    """
    if not company_name:
        return []
    base = f'"{company_name}"'
    if city:
        base += f' "{city}"'
    if piva:
        # P.IVA search is more precise when available
        query = f'"{piva}" (site:registroimprese.it OR site:codicefiscale.net OR site:impresainungiorno.gov.it OR site:ateco.camera.it)'
    else:
        query = f'{base} (site:registroimprese.it OR site:codicefiscale.net OR site:impresainungiorno.gov.it OR partita IVA OR codice fiscale)'
    return search_by_query(query, api_key, num_results, fallback_key)


def search_person_advanced(
    name: str,
    city: str = "",
    api_key: str = "",
    fallback_key: str = "",
    num_results: int = 10,
) -> list[dict[str, str]]:
    """Advanced dork for a person's email, phone, and address across all public sources.

    Searches for the person's name in combination with contact-revealing keywords.
    """
    if not name:
        return []
    base = f'"{name}"'
    if city:
        base += f' "{city}"'
    query = f'{base} (email OR telefono OR "tel:" OR "@" OR indirizzo OR contatti OR LinkedIn OR Facebook)'
    return search_by_query(query, api_key, num_results, fallback_key)
