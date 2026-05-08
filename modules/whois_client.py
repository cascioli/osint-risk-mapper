"""WHOIS lookup for registrant and domain registration data."""

from __future__ import annotations


def fetch_whois(domain: str) -> dict:
    """Return structured WHOIS data for a domain.

    .it domains (NIC.it) often use privacy protection — registrant_name may be None.
    Returns empty dict on total failure; all fields are safe to access with .get().
    """
    try:
        import whois
        w = whois.whois(domain)
    except Exception:
        return {}

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
            return str(val)[:10]

    name_servers = getattr(w, "name_servers", None)
    if isinstance(name_servers, (list, set)):
        name_servers = sorted(str(n).lower() for n in name_servers if n)
    else:
        name_servers = []

    # python-whois uses different attribute names across TLDs
    registrant_name = _str(
        getattr(w, "name", None)
        or getattr(w, "registrant_name", None)
        or getattr(w, "registrant", None)
    )
    registrant_email = _str(getattr(w, "emails", None))

    return {
        "registrant_name": registrant_name,
        "registrant_email": registrant_email,
        "registrant_org": _str(getattr(w, "org", None)),
        "registrant_address": _str(getattr(w, "address", None)),
        "creation_date": _date(getattr(w, "creation_date", None)),
        "updated_date": _date(getattr(w, "updated_date", None)),
        "name_servers": name_servers,
    }
