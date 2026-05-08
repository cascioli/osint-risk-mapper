"""Passive subdomain enumeration — crt.sh (with retry) + HackerTarget fallback."""

import time

import requests


_CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
_MAX_RETRIES = 3


def _parse_crt(records: list[dict], domain: str) -> set[str]:
    seen: set[str] = set()
    for record in records:
        raw = record.get("name_value", "")
        for entry in raw.splitlines():
            entry = entry.strip().lstrip("*").lstrip(".").lower()
            if entry and "." in entry and entry.endswith(domain):
                seen.add(entry)
    return seen


def _fetch_crt(domain: str) -> set[str]:
    url = _CRT_URL.format(domain=domain)
    for attempt in range(_MAX_RETRIES):
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            records: list[dict] = r.json()
            return _parse_crt(records, domain)
        except (requests.exceptions.Timeout, requests.exceptions.RequestException):
            if attempt < _MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
        except (ValueError, KeyError):
            break
    raise RuntimeError("crt.sh non raggiungibile dopo 3 tentativi")


def _fetch_hackertarget(domain: str) -> set[str]:
    """HackerTarget hostsearch — free, no key, used as crt.sh fallback."""
    try:
        r = requests.get(_HACKERTARGET_URL.format(domain=domain), timeout=15)
        if r.status_code != 200 or not r.text:
            return set()
        text = r.text.strip()
        if "error" in text.lower() or "api count exceeded" in text.lower():
            return set()
        subs: set[str] = set()
        for line in text.splitlines():
            sub = line.split(",")[0].strip().lower()
            if sub and "." in sub and sub.endswith(domain):
                subs.add(sub)
        return subs
    except requests.RequestException:
        return set()


def get_subdomains(domain: str) -> list[str]:
    """Enumerate subdomains passively via crt.sh (with retry) + HackerTarget fallback.

    Returns sorted list of unique subdomains. Never raises — returns [] on total failure.
    """
    try:
        subs = _fetch_crt(domain)
    except RuntimeError:
        subs = _fetch_hackertarget(domain)

    # Always merge HackerTarget results (complementary data)
    subs |= _fetch_hackertarget(domain)

    return sorted(subs)
