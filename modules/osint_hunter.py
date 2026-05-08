"""Hunter.io API client — fetches email addresses associated with a domain."""

import requests


HUNTER_BASE_URL = "https://api.hunter.io/v2/domain-search"


def fetch_emails_for_domain(domain: str, api_key: str) -> list[str]:
    """Query Hunter.io and return all email addresses found for the domain.

    Args:
        domain: The target domain (e.g. "example.com").
        api_key: Hunter.io API key.

    Returns:
        A list of email address strings. Empty list on error or no results.

    Raises:
        ValueError: When the API key is rejected (401/403).
        RuntimeError: On non-auth HTTP errors or network failures.
    """
    params: dict[str, str | int] = {
        "domain": domain,
        "api_key": api_key,
        "limit": 100,
    }

    try:
        response = requests.get(HUNTER_BASE_URL, params=params, timeout=15)
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Hunter.io: network error — {exc}") from exc

    if response.status_code in (401, 403):
        raise ValueError("Hunter.io: API key non valida o non autorizzata.")

    if response.status_code == 400:
        # Domain not found or malformed — treat as no results, not a fatal error
        return []

    if response.status_code == 429:
        raise RuntimeError("Hunter.io: quota mensile esaurita (429).")

    if response.status_code != 200:
        raise RuntimeError(
            f"Hunter.io: risposta inattesa HTTP {response.status_code}"
        )

    payload: dict = response.json()
    emails_data: list[dict] = payload.get("data", {}).get("emails", [])
    return [entry["value"] for entry in emails_data if entry.get("value")]
