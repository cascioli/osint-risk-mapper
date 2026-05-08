"""WHOIS lookup for registrant and domain registration data.

python-whois does not parse NIC.it (.it domains) structured fields — raw text
parsing is used as primary/fallback for Italian domains.
"""

from __future__ import annotations

import re


def _str(val) -> str | None:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return None
    return str(val).strip() or None


def _date(val) -> str | None:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return None
    try:
        return val.strftime("%Y-%m-%d")
    except AttributeError:
        s = str(val)[:10]
        return s if re.match(r"\d{4}-\d{2}-\d{2}", s) else None


def _parse_raw(text: str) -> dict:
    """Parse NIC.it style raw WHOIS text (and similar structured formats).

    NIC.it layout:
        Registrant
          Organization:  farmacia fontana
          Address:       VIA ...
        Admin Contact
          Name:          samantha fontana
          Organization:  farmacia fontana
        Registrar
          Organization:  Netsons S.r.l.
        Nameservers
          dns1.netsons.net
    """
    if not text:
        return {}

    def _section(header: str) -> str:
        """Extract indented block after a section header."""
        m = re.search(
            rf"^{re.escape(header)}\s*\n((?:[ \t]+.*\n?)*)",
            text,
            re.IGNORECASE | re.MULTILINE,
        )
        return m.group(1) if m else ""

    def _field(block: str, key: str) -> str | None:
        m = re.search(rf"^\s+{re.escape(key)}:\s*(.+)", block, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    def _first(pattern: str, flags: int = 0) -> str | None:
        m = re.search(pattern, text, flags)
        return m.group(1).strip() if m else None

    # --- Sections ---
    registrant_block = _section("Registrant")
    admin_block = _section("Admin Contact")
    registrar_block = _section("Registrar")

    # Person name: Admin Contact > Name  (Registrant often omits Name for .it)
    registrant_name = (
        _field(admin_block, "Name")
        or _field(_section("Technical Contacts"), "Name")
        or _field(registrant_block, "Name")
    )

    # Organization: Registrant > Organization
    registrant_org = (
        _field(registrant_block, "Organization")
        or _field(admin_block, "Organization")
    )

    # Address: first non-blank continuation line after "Address:"
    registrant_address = _field(registrant_block, "Address")

    # City: try to find Italian city pattern (CAP line or second address line)
    city = None
    if registrant_block:
        addr_match = re.search(r"Address:\s*.*\n\s+(.+)", registrant_block, re.IGNORECASE)
        if addr_match:
            city = addr_match.group(1).strip()

    # Dates (top-level, not inside sections)
    created = _first(r"^Created:\s*(\d{4}-\d{2}-\d{2})", re.MULTILINE)
    updated = _first(r"^Last Update:\s*(\d{4}-\d{2}-\d{2})", re.MULTILINE)
    expire = _first(r"^Expire Date:\s*(\d{4}-\d{2}-\d{2})", re.MULTILINE)

    # Name servers
    ns_raw = re.findall(r"^\s+([\w][\w\-\.]+\.[a-z]{2,})\s*$", text, re.IGNORECASE | re.MULTILINE)
    # Filter out lines that are clearly other values
    name_servers = sorted(set(
        ns.lower() for ns in ns_raw
        if re.search(r"\.(net|com|eu|it|org)$", ns, re.I)
        and "whois" not in ns.lower()
        and "nic" not in ns.lower()
    ))

    # Registrar
    registrar = _field(registrar_block, "Organization")

    result: dict = {}
    if registrant_name:
        result["registrant_name"] = registrant_name.title()
    if registrant_org:
        result["registrant_org"] = registrant_org.title()
    if registrant_address:
        result["registrant_address"] = registrant_address
    if city:
        result["registrant_city"] = city
    if created:
        result["creation_date"] = created
    if updated:
        result["updated_date"] = updated
    if expire:
        result["expire_date"] = expire
    if name_servers:
        result["name_servers"] = name_servers
    if registrar:
        result["registrar"] = registrar

    return result


def fetch_whois(domain: str) -> dict:
    """Return structured WHOIS data for a domain.

    Strategy:
    1. python-whois for structured parsing (works on most TLDs)
    2. Raw text parsing via _parse_raw() — primary for .it (NIC.it format)
    3. Merge results: raw text takes priority for fields python-whois missed

    Returns empty dict on total failure; all fields safe to .get().
    """
    raw_text = ""
    parsed: dict = {}

    try:
        import whois
        w = whois.whois(domain)
        raw_text = w.text or ""

        # Try structured fields from python-whois
        name_servers_raw = getattr(w, "name_servers", None)
        if isinstance(name_servers_raw, (list, set)):
            ns = sorted(str(n).lower() for n in name_servers_raw if n)
        else:
            ns = []

        registrant_name = _str(
            getattr(w, "name", None)
            or getattr(w, "registrant_name", None)
            or getattr(w, "registrant", None)
        )
        registrant_email = _str(getattr(w, "emails", None))

        parsed = {
            "registrant_name": registrant_name,
            "registrant_email": registrant_email,
            "registrant_org": _str(getattr(w, "org", None)),
            "registrant_address": _str(getattr(w, "address", None)),
            "creation_date": _date(getattr(w, "creation_date", None)),
            "updated_date": _date(getattr(w, "updated_date", None)),
            "name_servers": ns or None,
        }
        # Remove None values
        parsed = {k: v for k, v in parsed.items() if v}

    except Exception:
        pass

    # Raw text fallback — fills gaps left by python-whois (especially .it)
    raw_parsed = _parse_raw(raw_text)

    # Merge: raw_parsed fills missing keys from parsed
    merged = {**raw_parsed, **{k: v for k, v in parsed.items() if v}}

    # Raw text takes priority for name/org if python-whois gave nothing useful
    for key in ("registrant_name", "registrant_org", "registrant_address", "registrant_city",
                "creation_date", "updated_date", "expire_date", "name_servers", "registrar"):
        if raw_parsed.get(key) and not parsed.get(key):
            merged[key] = raw_parsed[key]

    return merged
