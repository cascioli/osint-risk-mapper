"""Passive web scraper — extracts contacts, social links, and tech hints from a domain."""

from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

_TIMEOUT = 12
_MAX_PAGES = 5
_KEY_PATHS = [
    "/", "/about", "/chi-siamo", "/team", "/contatti", "/contact",
    "/staff", "/azienda", "/about-us", "/contacts",
]

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)
_PIVA_RE = re.compile(
    r"(?:P\.?\s*I\.?\s*V\.?\s*A\.?|Partita\s+IVA|P\.?\s*IVA|PIVA)\s*[:\s]*(\d{11})",
    re.IGNORECASE,
)
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
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
}
_SKIP_EMAIL_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".woff", ".ico")


def _fetch_page(url: str) -> tuple[str | None, str]:
    """Fetch a URL. Returns (html, final_url) or (None, url) on failure."""
    try:
        r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, allow_redirects=True)
        if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
            return r.text, r.url
    except requests.RequestException:
        pass
    return None, url


def _extract_emails(soup: BeautifulSoup, html: str) -> set[str]:
    """Extract emails from mailto: links (primary) and text content (secondary)."""
    emails: set[str] = set()

    # Primary: explicit mailto: links — most reliable
    for tag in soup.find_all("a", href=True):
        href: str = tag["href"]
        if href.lower().startswith("mailto:"):
            addr = href[7:].split("?")[0].strip().lower()
            if _EMAIL_RE.match(addr) and not any(addr.endswith(s) for s in _SKIP_EMAIL_SUFFIXES):
                emails.add(addr)

    # Secondary: regex on visible text
    text = soup.get_text(" ", strip=True)
    for email in _EMAIL_RE.findall(text):
        clean = email.lower()
        if not any(clean.endswith(s) for s in _SKIP_EMAIL_SUFFIXES):
            emails.add(clean)

    # Tertiary: regex on raw HTML (catches obfuscated spans)
    for email in _EMAIL_RE.findall(html):
        clean = email.lower()
        if not any(clean.endswith(s) for s in _SKIP_EMAIL_SUFFIXES):
            emails.add(clean)

    return emails


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
    if "shopify" in html_lower:
        hints.append("Shopify")
    if "prestashop" in html_lower:
        hints.append("PrestaShop")
    return list(dict.fromkeys(hints))


def scrape_domain(domain: str) -> dict:
    """Scrape homepage + key contact/team pages for contacts, social links, and tech hints.

    Returns:
        Dict with keys: emails (list), phones (list), social_links (list of {platform, url}),
        tech_hints (list), pages_scraped (int). All failures are silent — returns partial data.
    """
    emails: set[str] = set()
    phones: set[str] = set()
    social_links: list[dict[str, str]] = []
    tech_hints: list[str] = []
    seen_socials: set[str] = set()
    piva: str | None = None
    pages_tried = 0
    errors: list[str] = []

    # Try https first, then http for homepage
    base_urls = [f"https://{domain}", f"http://{domain}"]
    base_url = f"https://{domain}"

    # Determine working base URL from homepage
    for candidate in base_urls:
        html, final_url = _fetch_page(candidate)
        if html:
            base_url = final_url.rstrip("/")
            # Process homepage
            soup = BeautifulSoup(html, "html.parser")
            emails.update(_extract_emails(soup, html))
            for phone in _PHONE_IT_RE.findall(soup.get_text(" ", strip=True)):
                clean = re.sub(r"\s+", " ", phone).strip()
                if len(re.sub(r"\D", "", clean)) >= 9:
                    phones.add(clean)
            for slink in _extract_social_links(soup):
                if slink["url"] not in seen_socials:
                    seen_socials.add(slink["url"])
                    social_links.append(slink)
            if not tech_hints:
                tech_hints = _extract_tech_hints(soup, html)
            if not piva:
                m = _PIVA_RE.search(soup.get_text(" ", strip=True)) or _PIVA_RE.search(html)
                if m:
                    piva = m.group(1)
            pages_tried += 1
            break

    # Try additional key paths
    for path in _KEY_PATHS[1:]:  # skip "/" already tried
        if pages_tried >= _MAX_PAGES:
            break
        url = f"{base_url}{path}"
        html, _ = _fetch_page(url)
        if not html:
            continue
        pages_tried += 1

        soup = BeautifulSoup(html, "html.parser")
        emails.update(_extract_emails(soup, html))
        for phone in _PHONE_IT_RE.findall(soup.get_text(" ", strip=True)):
            clean = re.sub(r"\s+", " ", phone).strip()
            if len(re.sub(r"\D", "", clean)) >= 9:
                phones.add(clean)
        for slink in _extract_social_links(soup):
            if slink["url"] not in seen_socials:
                seen_socials.add(slink["url"])
                social_links.append(slink)
        if not tech_hints:
            tech_hints = _extract_tech_hints(soup, html)
        if not piva:
            m = _PIVA_RE.search(soup.get_text(" ", strip=True)) or _PIVA_RE.search(html)
            if m:
                piva = m.group(1)

    return {
        "emails": sorted(emails),
        "phones": sorted(phones)[:20],
        "social_links": social_links,
        "tech_hints": tech_hints,
        "pages_scraped": pages_tried,
        "piva": piva,
    }
