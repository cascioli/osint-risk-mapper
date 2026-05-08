"""PhoneBook.cz passive email discovery.

Attempts a plain HTTP GET against the public search page and extracts any
email addresses that appear in the initial HTML for the target domain.

PhoneBook.cz renders most results via JavaScript; plain requests will often
return an empty set. This module treats that as a graceful no-op — callers
get [] and pipeline continues. Never raises.
"""

from __future__ import annotations

import re

import requests

_TIMEOUT = 15
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)
_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico", ".woff")
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
    "Referer": "https://phonebook.cz/",
}


def fetch_emails_phonebook(domain: str) -> list[str]:
    """Scrape PhoneBook.cz for email addresses associated with a domain.

    Returns a list of email strings (may be empty if page is JS-rendered).
    Never raises — any failure returns [].
    """
    if not domain:
        return []

    url = f"https://phonebook.cz/?term={domain}&type=1&regionid=1"
    try:
        r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        html = r.text
    except requests.RequestException:
        return []

    emails: set[str] = set()
    for raw in _EMAIL_RE.findall(html):
        clean = raw.lower()
        if any(clean.endswith(s) for s in _SKIP_SUFFIXES):
            continue
        # Keep only addresses that belong to the target domain
        if f"@{domain}" in clean:
            emails.add(clean)

    return sorted(emails)
