"""Scrape public Instagram and Facebook profiles for contact data in bio."""

from __future__ import annotations

import json
import re

import requests
from bs4 import BeautifulSoup

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)
_PHONE_IT_RE = re.compile(r"(?:\+39[\s\-]?)?(?:0\d{1,3}[\s\-]?\d{5,8}|\d{3}[\s\-]?\d{3,4}[\s\-]?\d{3,4})")
_WA_RE = re.compile(r"wa\.me/(\d+)", re.IGNORECASE)


def _extract_contact(text: str) -> dict:
    result: dict = {}
    emails = _EMAIL_RE.findall(text)
    if emails:
        result["email"] = emails[0]
    phones = _PHONE_IT_RE.findall(text)
    if phones:
        result["phone"] = phones[0].strip()
    wa = _WA_RE.search(text)
    if wa:
        result["whatsapp"] = wa.group(1)
    return result


def scrape_instagram_bio(username_or_url: str) -> dict:
    """Scrape a public Instagram profile page.

    Extracts: bio, email, phone, website, location from og: meta tags
    and JSON-LD data embedded in the page.
    Returns {} on any failure (blocks, login wall, etc.).
    """
    if not username_or_url:
        return {}

    username = (
        username_or_url
        .rstrip("/")
        .split("/")[-1]
        .lstrip("@")
    )
    if not username:
        return {}

    url = f"https://www.instagram.com/{username}/"
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=15, allow_redirects=True)
        if resp.status_code in (404, 410):
            return {}
        if resp.status_code != 200:
            return {}

        soup = BeautifulSoup(resp.text, "html.parser")
        result: dict = {"platform": "instagram", "url": url, "username": username}

        # og:description usually contains: "X Followers, Y Following, Z Posts — {bio}"
        og_desc = soup.find("meta", property="og:description")
        if og_desc:
            content = og_desc.get("content", "")
            result["bio"] = content
            result.update(_extract_contact(content))

        og_title = soup.find("meta", property="og:title")
        if og_title:
            result["display_name"] = og_title.get("content", "")

        # Try shared_data JSON embedded in page
        shared_data_match = re.search(r"window\._sharedData\s*=\s*(\{.*?\});</script>", resp.text, re.DOTALL)
        if shared_data_match:
            try:
                sd = json.loads(shared_data_match.group(1))
                user = (
                    sd.get("entry_data", {})
                    .get("ProfilePage", [{}])[0]
                    .get("graphql", {})
                    .get("user", {})
                )
                if user:
                    result["bio"] = user.get("biography", result.get("bio", ""))
                    result["website"] = user.get("external_url", "")
                    result["display_name"] = user.get("full_name", result.get("display_name", ""))
                    result["followers"] = user.get("edge_followed_by", {}).get("count", "")
                    if user.get("business_email"):
                        result["email"] = user["business_email"]
                    if user.get("business_phone_number"):
                        result["phone"] = user["business_phone_number"]
            except Exception:
                pass

        # Scan full page text for contact patterns as fallback
        page_text = soup.get_text(" ", strip=True)
        contact = _extract_contact(page_text)
        for k, v in contact.items():
            if k not in result:
                result[k] = v

        return {k: v for k, v in result.items() if v}
    except Exception:
        return {}


def scrape_facebook_bio(url: str) -> dict:
    """Scrape a public Facebook page/profile for contact info in the About section.

    Returns {} on any failure.
    """
    if not url:
        return {}
    if "facebook.com" not in url.lower():
        return {}

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=15, allow_redirects=True)
        if resp.status_code not in (200, 301, 302):
            return {}

        soup = BeautifulSoup(resp.text, "html.parser")
        result: dict = {"platform": "facebook", "url": url}

        og_title = soup.find("meta", property="og:title")
        if og_title:
            result["display_name"] = og_title.get("content", "")

        og_desc = soup.find("meta", property="og:description")
        if og_desc:
            result["bio"] = og_desc.get("content", "")

        # Scan all visible text for contact patterns
        page_text = soup.get_text(" ", strip=True)
        result.update(_extract_contact(page_text))

        # Try JSON-LD for structured data
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                ld = json.loads(script.string or "")
                if isinstance(ld, dict):
                    if ld.get("email"):
                        result["email"] = ld["email"]
                    if ld.get("telephone"):
                        result["phone"] = ld["telephone"]
                    if ld.get("address"):
                        addr = ld["address"]
                        if isinstance(addr, dict):
                            result["location"] = ", ".join(filter(None, [
                                addr.get("streetAddress", ""),
                                addr.get("addressLocality", ""),
                                addr.get("addressRegion", ""),
                            ]))
                        else:
                            result["location"] = str(addr)
                    if ld.get("url"):
                        result["website"] = ld["url"]
            except Exception:
                continue

        return {k: v for k, v in result.items() if v}
    except Exception:
        return {}
