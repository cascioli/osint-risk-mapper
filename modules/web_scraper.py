"""Passive web scraper — extracts contacts, social links, and tech hints from a domain."""

from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

_TIMEOUT = 10
_MAX_PAGES = 5
_KEY_PATHS = ["/", "/about", "/chi-siamo", "/team", "/contatti", "/contact", "/staff", "/azienda"]

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)
_PHONE_IT_RE = re.compile(
    r"(?:\+39[\s\.\-]?)?(?:0\d{1,4}[\s\.\-]?\d{3,4}[\s\.\-]?\d{3,4}|\d{3}[\s\.\-]?\d{3,4}[\s\.\-]?\d{3,4})",
)
_SOCIAL_DOMAINS = {
    "linkedin.com": "linkedin",
    "twitter.com": "twitter",
    "x.com": "twitter",
    "instagram.com": "instagram",
    "facebook.com": "facebook",
}
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OSINT-Research/1.0)",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
}
_SKIP_EMAIL_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".woff")


def _fetch_page(url: str) -> str | None:
    try:
        r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, allow_redirects=True)
        if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
            return r.text
    except requests.RequestException:
        pass
    return None


def _extract_social_links(soup: BeautifulSoup) -> list[dict[str, str]]:
    found = []
    for tag in soup.find_all("a", href=True):
        href: str = tag["href"]
        if not href.startswith("http"):
            continue
        for domain, platform in _SOCIAL_DOMAINS.items():
            if domain in href:
                found.append({"platform": platform, "url": href})
                break
    return found


def _extract_tech_hints(soup: BeautifulSoup, html: str) -> list[str]:
    hints = []
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        hints.append(gen["content"])
    html_lower = html.lower()
    if "/wp-content/" in html_lower and "WordPress" not in hints:
        hints.append("WordPress")
    if "joomla" in html_lower:
        hints.append("Joomla")
    if "drupal" in html_lower:
        hints.append("Drupal")
    return list(dict.fromkeys(hints))


def scrape_domain(domain: str) -> dict:
    """Scrape homepage + key contact/team pages for contacts, social links, and tech hints.

    Returns:
        Dict with keys: emails (list), phones (list), social_links (list of {platform, url}),
        tech_hints (list). All failures are silent — returns partial data.
    """
    emails: set[str] = set()
    phones: set[str] = set()
    social_links: list[dict[str, str]] = []
    tech_hints: list[str] = []
    seen_socials: set[str] = set()
    pages_tried = 0

    for path in _KEY_PATHS:
        if pages_tried >= _MAX_PAGES:
            break
        url = f"https://{domain}{path}" if path != "/" else f"https://{domain}"
        html = _fetch_page(url)
        if not html and path == "/":
            html = _fetch_page(f"http://{domain}")
        if not html:
            continue
        pages_tried += 1

        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ", strip=True)

        for email in _EMAIL_RE.findall(text):
            if not any(email.lower().endswith(s) for s in _SKIP_EMAIL_SUFFIXES):
                emails.add(email.lower())

        for phone in _PHONE_IT_RE.findall(text):
            clean = re.sub(r"\s+", " ", phone).strip()
            if len(re.sub(r"\D", "", clean)) >= 9:
                phones.add(clean)

        for slink in _extract_social_links(soup):
            if slink["url"] not in seen_socials:
                seen_socials.add(slink["url"])
                social_links.append(slink)

        if not tech_hints:
            tech_hints = _extract_tech_hints(soup, html)

    return {
        "emails": sorted(emails),
        "phones": sorted(phones)[:20],
        "social_links": social_links,
        "tech_hints": tech_hints,
    }
