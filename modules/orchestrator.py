"""Multi-round synergistic OSINT orchestrator — person+data focused.

Runs 3 rounds of data collection, each feeding into the next:
  Round 1 — discovery: web scrape, WHOIS, subdomains, emails, exposed docs
  Round 2 — enrichment: breach check, social dork, GitHub/Pastebin dork
  Round 3 — LLM-guided: suggests additional people + queries, executes follow-ups
  Final   — unified LLM report + connection graph
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime

from google import genai
from google.genai import types as genai_types

from modules.hibp_client import check_emails_batch
from modules.osint_dorking import (
    search_brand_documents,
    search_by_query,
    search_email_pattern_external,
    search_exposed_documents,
    search_facebook_profiles,
    search_github_mentions,
    search_instagram_profiles,
    search_linkedin_profiles,
    search_pastebin_mentions,
    search_piva_mentions,
    search_twitter_presence,
)
from modules.osint_hunter import fetch_emails_for_domain
from modules.osint_leaklookup import check_emails_for_breaches
from modules.osint_subdomains import get_subdomains
from modules.scan_context import BreachResult, PersonProfile, ScanContext, SocialProfile
from modules.vt_client import fetch_vt_subdomains
from modules.web_scraper import scrape_domain
from modules.whois_client import fetch_whois

LogFn = Callable[[str], None]
ProgressFn = Callable[[float], None]

_MAX_FOLLOW_UP = 5


def _noop_log(msg: str) -> None:
    pass


def _noop_progress(val: float) -> None:
    pass


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _get_company_name(ctx: ScanContext) -> str:
    """Derive company name — priority: user-provided > WHOIS org > domain label."""
    # 1. User-provided (most reliable)
    user_company = ctx.target_context.get("company_name", "").strip()
    if user_company:
        return user_company

    # 2. WHOIS org (exclude generic registrar strings)
    org = ctx.whois_data.get("registrant_org") or ""
    generic = ("register", "privacy", "whoisguard", "domains", "protection")
    if org and not any(g in org.lower() for g in generic):
        return org.strip()

    # 3. Domain label fallback
    label = ctx.domain.split(".")[0].replace("-", " ").title()
    return label


def _dedup_dork_results(existing: list[dict], new: list[dict]) -> list[dict]:
    seen = {d.get("url") for d in existing}
    return existing + [d for d in new if d.get("url") not in seen]


# ── Public round functions ────────────────────────────────────────────────────

def run_round1(
    ctx: ScanContext,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Round 1: discovery — web scrape, WHOIS, subdomains, emails, exposed docs."""
    config = ctx.config

    # Seed person_names from user-provided owner names
    if ctx.target_context.get("owner_names"):
        ctx.person_names = list(dict.fromkeys(ctx.target_context["owner_names"]))
        log_fn(f"[{_ts()}] Round 1 → Persone da onboarding: {ctx.person_names}")

    # Seed emails from user-provided contact email
    if ctx.target_context.get("contact_email"):
        ctx.emails.append(ctx.target_context["contact_email"])

    # Web scraping
    log_fn(f"[{_ts()}] Round 1 → Web scraping {ctx.domain}: avvio...")
    progress_fn(0.02)
    try:
        ctx.scraped_contacts = scrape_domain(ctx.domain)
        log_fn(
            f"[{_ts()}] Round 1 → Scraping: "
            f"{len(ctx.scraped_contacts.get('emails', []))} email, "
            f"{len(ctx.scraped_contacts.get('social_links', []))} social links, "
            f"{ctx.scraped_contacts.get('pages_scraped', 0)} pagine"
        )
    except Exception as exc:
        ctx.scraped_contacts = {}
        log_fn(f"[{_ts()}] ⚠️ Round 1 → Scraping ERRORE: {exc}")
    progress_fn(0.08)

    # WHOIS
    log_fn(f"[{_ts()}] Round 1 → WHOIS: avvio...")
    try:
        ctx.whois_data = fetch_whois(ctx.domain)
        log_fn(
            f"[{_ts()}] Round 1 → WHOIS: "
            f"registrant={ctx.whois_data.get('registrant_name') or 'N/D'}, "
            f"org={ctx.whois_data.get('registrant_org') or 'N/D'}"
        )
    except Exception as exc:
        ctx.whois_data = {}
        log_fn(f"[{_ts()}] ⚠️ Round 1 → WHOIS ERRORE: {exc}")
    progress_fn(0.12)

    # Subdomain enumeration (crt.sh + HackerTarget — no key needed)
    log_fn(f"[{_ts()}] Round 1 → Subdomain enum (crt.sh + HackerTarget): avvio...")
    try:
        ctx.subdomains = get_subdomains(ctx.domain)
        log_fn(f"[{_ts()}] Round 1 → Subdomains: {len(ctx.subdomains)}")
    except Exception as exc:
        ctx.subdomains = []
        log_fn(f"[{_ts()}] ⚠️ Round 1 → Subdomains ERRORE: {exc}")
    progress_fn(0.16)

    # VirusTotal subdomains
    if config.get("vt_key"):
        log_fn(f"[{_ts()}] Round 1 → VirusTotal subdomains: avvio...")
        try:
            ctx.vt_subdomains = fetch_vt_subdomains(config["vt_key"], ctx.domain)
            log_fn(f"[{_ts()}] Round 1 → VirusTotal: {len(ctx.vt_subdomains)} subdomains")
        except ValueError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1 → VirusTotal key invalida: {exc}")
        except Exception as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1 → VirusTotal ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Round 1 → VirusTotal: key mancante, skip")
    progress_fn(0.20)

    # Hunter.io emails
    hunter_emails: list[str] = []
    if config.get("hunter_key"):
        log_fn(f"[{_ts()}] Round 1 → Email Hunter.io: avvio...")
        try:
            hunter_emails = fetch_emails_for_domain(ctx.domain, config["hunter_key"])
            log_fn(f"[{_ts()}] Round 1 → Hunter.io: {len(hunter_emails)} email trovate")
        except ValueError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1 → Hunter.io key invalida: {exc}")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1 → Hunter.io ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Round 1 → Hunter.io: key mancante, skip")
    progress_fn(0.24)

    # Merge all discovered emails (scraped + hunter + user-provided), dedup
    all_emails = list(dict.fromkeys(
        ctx.emails
        + ctx.scraped_contacts.get("emails", [])
        + hunter_emails
    ))

    # Add WHOIS registrant email if present
    whois_email = ctx.whois_data.get("registrant_email")
    if whois_email and whois_email not in all_emails:
        all_emails.append(whois_email)
    ctx.emails = all_emails
    log_fn(f"[{_ts()}] Round 1 → Email totali (merged): {len(ctx.emails)}")

    # Extract P.IVA from scraping
    ctx.piva = ctx.scraped_contacts.get("piva")
    if ctx.piva:
        log_fn(f"[{_ts()}] Round 1 → P.IVA estratta da scraping: {ctx.piva}")
    progress_fn(0.26)

    # Social profiles from scraping
    for slink in ctx.scraped_contacts.get("social_links", []):
        ctx.social_profiles.append(SocialProfile(
            platform=slink["platform"],
            url=slink["url"],
            source="scraped",
        ))

    # Add WHOIS registrant name to person_names (only if not already from user context)
    registrant = ctx.whois_data.get("registrant_name")
    if registrant and registrant not in ctx.person_names:
        ctx.person_names.append(registrant)
    ctx.person_names = list(dict.fromkeys(ctx.person_names))
    log_fn(f"[{_ts()}] Round 1 → Persone seed: {ctx.person_names or 'nessuna'}")
    progress_fn(0.28)

    # Exposed documents dork (generic)
    if config.get("serper_key") or config.get("serpapi_key"):
        log_fn(f"[{_ts()}] Round 1 → Dorking documenti esposti: avvio...")
        try:
            ctx.exposed_documents = search_exposed_documents(
                ctx.domain,
                config.get("serper_key", ""),
                fallback_key=config.get("serpapi_key", ""),
            )
            log_fn(f"[{_ts()}] Round 1 → Documenti esposti: {len(ctx.exposed_documents)}")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1 → Dorking ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Round 1 → Dorking: nessuna key Serper/SerpAPI, skip")
    progress_fn(0.32)

    return ctx


def run_round1_5(
    ctx: ScanContext,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Round 1.5: Gemini strategic guidance + PhoneBook.cz emails + OpenCorporates officers."""
    config = ctx.config
    company = _get_company_name(ctx)
    city = ctx.target_context.get("city", "")

    # Gemini strategic guidance
    if config.get("ai_key"):
        log_fn(f"[{_ts()}] Round 1.5 → Gemini guidance strategica: avvio...")
        try:
            from modules.gemini_guidance import run_gemini_guidance
            guidance = run_gemini_guidance(
                ctx, config["ai_key"], config.get("model_name", "gemini-2.5-flash"), company
            )
            ctx.gemini_guidance = guidance

            # Merge key_people into person_names
            for p in guidance.get("key_people", []):
                if p and p not in ctx.person_names:
                    ctx.person_names.append(p)

            # Store related domain suggestions
            ctx.related_domains = list(dict.fromkeys(guidance.get("related_domains", [])))

            # Use P.IVA from Gemini if not found by scraping
            if not ctx.piva and guidance.get("piva"):
                ctx.piva = guidance["piva"]
                log_fn(f"[{_ts()}] Round 1.5 → P.IVA da Gemini: {ctx.piva}")

            log_fn(
                f"[{_ts()}] Round 1.5 → Guidance: "
                f"settore={guidance.get('sector') or 'N/D'}, "
                f"persone={len(guidance.get('key_people', []))}, "
                f"domini correlati={len(guidance.get('related_domains', []))}, "
                f"query={len(guidance.get('dork_queries', []))}"
            )
        except Exception as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1.5 → Gemini guidance ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Round 1.5 → Gemini guidance: key mancante, skip")
    progress_fn(0.33)

    # PhoneBook.cz email discovery
    log_fn(f"[{_ts()}] Round 1.5 → PhoneBook.cz email discovery: avvio...")
    try:
        from modules.phonebook_client import fetch_emails_phonebook
        pb_emails = fetch_emails_phonebook(ctx.domain)
        ctx.phonebook_emails = pb_emails
        for e in pb_emails:
            if e not in ctx.emails:
                ctx.emails.append(e)
        log_fn(f"[{_ts()}] Round 1.5 → PhoneBook.cz: {len(pb_emails)} email trovate")
    except Exception as exc:
        log_fn(f"[{_ts()}] ⚠️ Round 1.5 → PhoneBook.cz ERRORE: {exc}")
    progress_fn(0.35)

    # OpenCorporates — Italian company registry officers (requires OPENCORPORATES_API_KEY)
    oc_key = config.get("opencorporates_key", "")
    serper = config.get("serper_key", "")
    serpapi = config.get("serpapi_key", "")
    has_dork = bool(serper or serpapi)

    if oc_key:
        log_fn(f"[{_ts()}] Round 1.5 → OpenCorporates (Registro Imprese) '{company}': avvio...")
        try:
            from modules.opencorporates_client import find_company_officers
            officers = find_company_officers(company, city, api_token=oc_key)
            ctx.company_officers = officers
            for o in officers:
                name = (o.get("name") or "").strip()
                if name and name not in ctx.person_names:
                    ctx.person_names.append(name)
            ctx.person_names = list(dict.fromkeys(ctx.person_names))
            log_fn(f"[{_ts()}] Round 1.5 → OpenCorporates: {len(officers)} persone trovate")
        except Exception as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1.5 → OpenCorporates ERRORE: {exc}")
    elif has_dork:
        # Dork fallback: search Italian registry sites for company info
        log_fn(f"[{_ts()}] Round 1.5 → Registry dork fallback (nessuna chiave OpenCorporates): avvio...")
        try:
            reg_dork = search_by_query(
                f'"{company}" ("titolare" OR "amministratore" OR "socio unico") '
                f'site:registro.imprese.it OR site:camcom.it OR site:ufficiocamerale.it',
                serper, fallback_key=serpapi,
            )
            ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, reg_dork)
            log_fn(f"[{_ts()}] Round 1.5 → Registry dork: {len(reg_dork)} risultati")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 1.5 → Registry dork ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Round 1.5 → Registro Imprese: nessuna chiave OpenCorporates né Serper, skip")
    progress_fn(0.38)

    return ctx


def run_round2(
    ctx: ScanContext,
    max_people: int = 5,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Round 2: enrichment — breach check, social dork, GitHub/Pastebin/brand dork."""
    config = ctx.config
    serper = config.get("serper_key", "")
    serpapi = config.get("serpapi_key", "")
    company = _get_company_name(ctx)
    city = ctx.target_context.get("city", "")
    has_dork = bool(serper or serpapi)

    log_fn(f"[{_ts()}] Round 2 → Company name per dork: '{company}'" + (f" | Città: '{city}'" if city else ""))

    # Breach check per email
    log_fn(f"[{_ts()}] Round 2 → Breach check: {len(ctx.emails)} email...")
    progress_fn(0.34)

    hibp_results: dict[str, list[str]] = {}
    if ctx.emails and config.get("hibp_key"):
        try:
            hibp_results = check_emails_batch(config["hibp_key"], ctx.emails)
            n_hit = sum(1 for v in hibp_results.values() if v)
            log_fn(f"[{_ts()}] Round 2 → HIBP: {n_hit}/{len(ctx.emails)} compromesse")
        except ValueError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → HIBP key invalida: {exc}")
        except Exception as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → HIBP ERRORE: {exc}")
    elif not ctx.emails:
        log_fn(f"[{_ts()}] Round 2 → HIBP: nessuna email trovata, skip")
    else:
        log_fn(f"[{_ts()}] Round 2 → HIBP: key mancante, skip")

    leaklookup_results: dict[str, list[str]] = {}
    if ctx.emails and config.get("leaklookup_key"):
        try:
            leaklookup_results = check_emails_for_breaches(ctx.emails, config["leaklookup_key"])
            n_hit = sum(1 for v in leaklookup_results.values() if v)
            log_fn(f"[{_ts()}] Round 2 → Leak-Lookup: {n_hit}/{len(ctx.emails)} compromesse")
        except ValueError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → Leak-Lookup key invalida: {exc}")
        except Exception as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → Leak-Lookup ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Round 2 → Leak-Lookup: {'nessuna email' if not ctx.emails else 'key mancante'}, skip")

    # Merge breach results per email
    for email in ctx.emails:
        ctx.breach_results.append(BreachResult(
            email=email,
            hibp_breaches=hibp_results.get(email, []),
            leaklookup_sources=leaklookup_results.get(email, []),
        ))
    n_breached = sum(1 for r in ctx.breach_results if r.hibp_breaches or r.leaklookup_sources)
    log_fn(f"[{_ts()}] Round 2 → Breach totali: {n_breached} email compromesse")
    progress_fn(0.50)

    # Social dork per person_names
    if has_dork and ctx.person_names:
        log_fn(f"[{_ts()}] Round 2 → Social dork per {min(len(ctx.person_names), max_people)} persone...")
        for name in ctx.person_names[:max_people]:
            search_company = company if company.lower() not in name.lower() else ""
            try:
                linkedin = search_linkedin_profiles(name, search_company, serper, serpapi, city=city)
                for item in linkedin:
                    ctx.social_dork_results.append({**item, "person": name, "source": "linkedin", "verified": False})
                log_fn(f"[{_ts()}] Round 2 → LinkedIn dork '{name}'" + (f" + '{city}'" if city else "") + f": {len(linkedin)} candidati")
            except RuntimeError as exc:
                log_fn(f"[{_ts()}] ⚠️ Round 2 → LinkedIn dork ERRORE: {exc}")

        # Twitter presence for company
        try:
            twitter = search_twitter_presence(company, serper, serpapi, city=city)
            for item in twitter:
                ctx.social_dork_results.append({**item, "source": "twitter", "verified": False})
            log_fn(f"[{_ts()}] Round 2 → Twitter dork '{company}'" + (f" + '{city}'" if city else "") + f": {len(twitter)} candidati")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → Twitter dork ERRORE: {exc}")

        # Instagram dork per person
        for name in ctx.person_names[:max_people]:
            try:
                insta = search_instagram_profiles(name, company, serper, serpapi, city=city)
                for item in insta:
                    ctx.instagram_results.append({**item, "person": name, "verified": False})
                if insta:
                    log_fn(f"[{_ts()}] Round 2 → Instagram dork '{name}': {len(insta)} candidati")
            except RuntimeError as exc:
                log_fn(f"[{_ts()}] ⚠️ Round 2 → Instagram dork ERRORE: {exc}")

        # Facebook dork for company
        try:
            fb = search_facebook_profiles(company, serper, serpapi, city=city)
            for item in fb:
                ctx.facebook_results.append({**item, "verified": False})
            log_fn(f"[{_ts()}] Round 2 → Facebook dork '{company}'" + (f" + '{city}'" if city else "") + f": {len(fb)} candidati")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → Facebook dork ERRORE: {exc}")
    elif not has_dork:
        log_fn(f"[{_ts()}] Round 2 → Social dork: nessuna key Serper/SerpAPI, skip")
    else:
        log_fn(f"[{_ts()}] Round 2 → Social dork: nessuna persona identificata, skip")
    progress_fn(0.62)

    # GitHub dork
    if has_dork:
        log_fn(f"[{_ts()}] Round 2 → GitHub dork '{ctx.domain}': avvio...")
        try:
            gh = search_github_mentions(ctx.domain, company, serper, serpapi)
            ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, gh)
            log_fn(f"[{_ts()}] Round 2 → GitHub: {len(gh)} risultati")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → GitHub dork ERRORE: {exc}")

        # Pastebin dork
        log_fn(f"[{_ts()}] Round 2 → Pastebin dork '{ctx.domain}': avvio...")
        try:
            pb = search_pastebin_mentions(ctx.domain, serper, serpapi)
            ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, pb)
            log_fn(f"[{_ts()}] Round 2 → Pastebin: {len(pb)} risultati")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → Pastebin dork ERRORE: {exc}")

        # Brand documents dork (domain-centric: hosted ON site + external refs to this domain)
        log_fn(f"[{_ts()}] Round 2 → Brand docs dork '{ctx.domain}': avvio...")
        try:
            bd = search_brand_documents(ctx.domain, company, serper, serpapi)
            ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, bd)
            log_fn(f"[{_ts()}] Round 2 → Brand docs: {len(bd)} risultati")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → Brand docs dork ERRORE: {exc}")

        # P.IVA dork — finds related domains and external mentions
        if ctx.piva:
            log_fn(f"[{_ts()}] Round 2 → P.IVA dork '{ctx.piva}': avvio...")
            try:
                piva_res = search_piva_mentions(ctx.piva, serper, serpapi)
                ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, piva_res)
                log_fn(f"[{_ts()}] Round 2 → P.IVA dork: {len(piva_res)} risultati")
            except RuntimeError as exc:
                log_fn(f"[{_ts()}] ⚠️ Round 2 → P.IVA dork ERRORE: {exc}")

        # Email pattern external dork — finds employee emails on external sites
        log_fn(f"[{_ts()}] Round 2 → Email pattern dork '@{ctx.domain}': avvio...")
        try:
            ep = search_email_pattern_external(ctx.domain, serper, serpapi)
            ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, ep)
            log_fn(f"[{_ts()}] Round 2 → Email pattern: {len(ep)} risultati")
        except RuntimeError as exc:
            log_fn(f"[{_ts()}] ⚠️ Round 2 → Email pattern dork ERRORE: {exc}")

        # Execute Gemini guidance dork queries from Round 1.5
        guidance_queries = ctx.gemini_guidance.get("dork_queries", [])
        if guidance_queries:
            log_fn(f"[{_ts()}] Round 2 → Eseguo {len(guidance_queries)} query da Gemini guidance...")
            for query in guidance_queries[:5]:
                try:
                    gq_res = search_by_query(query, serper, fallback_key=serpapi)
                    ctx.llm_followup_results = _dedup_dork_results(ctx.llm_followup_results, gq_res)
                    log_fn(f"[{_ts()}] Round 2 → Guidance query '{query[:60]}': {len(gq_res)} risultati")
                except RuntimeError as exc:
                    log_fn(f"[{_ts()}] ⚠️ Round 2 → Guidance query ERRORE: {exc}")
    progress_fn(0.73)

    return ctx


def run_round3(
    ctx: ScanContext,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Round 3: LLM suggests additional people + queries, executes follow-up dorks."""
    config = ctx.config
    if not config.get("ai_key"):
        log_fn(f"[{_ts()}] Round 3 → Gemini API Key mancante, skip")
        progress_fn(0.90)
        return ctx

    serper = config.get("serper_key", "")
    serpapi = config.get("serpapi_key", "")
    has_dork = bool(serper or serpapi)
    company = _get_company_name(ctx)
    city = ctx.target_context.get("city", "")

    log_fn(f"[{_ts()}] Round 3 → Gemini entity extraction: avvio...")
    progress_fn(0.74)

    try:
        client = genai.Client(api_key=config["ai_key"])
        prompt = _build_entity_extraction_prompt(ctx)
        response = client.models.generate_content(
            model=config.get("model_name", "gemini-2.5-flash"),
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json",
            ),
        )
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        suggested = json.loads(raw)
        ctx.llm_suggested_people = suggested.get("people", [])[:_MAX_FOLLOW_UP]
        ctx.llm_suggested_queries = suggested.get("queries", [])[:_MAX_FOLLOW_UP]
        log_fn(
            f"[{_ts()}] Round 3 → Gemini: "
            f"{len(ctx.llm_suggested_people)} persone, "
            f"{len(ctx.llm_suggested_queries)} query suggerite"
        )
    except json.JSONDecodeError as exc:
        log_fn(f"[{_ts()}] ⚠️ Round 3 → Gemini JSON parse ERRORE: {exc}")
        progress_fn(0.90)
        return ctx
    except Exception as exc:
        log_fn(f"[{_ts()}] ⚠️ Round 3 → Gemini ERRORE: {exc}")
        progress_fn(0.90)
        return ctx

    progress_fn(0.78)

    # Execute dorks for suggested people
    if has_dork:
        for name in ctx.llm_suggested_people:
            linkedin: list[dict] = []
            twitter: list[dict] = []
            try:
                linkedin = search_linkedin_profiles(name, company, serper, serpapi, city=city)
                log_fn(f"[{_ts()}] Round 3 → LinkedIn dork '{name}': {len(linkedin)} candidati")
            except RuntimeError as exc:
                log_fn(f"[{_ts()}] ⚠️ Round 3 → LinkedIn dork '{name}' ERRORE: {exc}")
            try:
                twitter = search_twitter_presence(name, serper, serpapi, city=city)
                log_fn(f"[{_ts()}] Round 3 → Twitter dork '{name}': {len(twitter)} candidati")
            except RuntimeError as exc:
                log_fn(f"[{_ts()}] ⚠️ Round 3 → Twitter dork '{name}' ERRORE: {exc}")
            ctx.person_profiles.append(PersonProfile(
                name=name,
                linkedin_results=linkedin,
                twitter_results=twitter,
            ))

        progress_fn(0.84)

        # Execute suggested dork queries
        for query in ctx.llm_suggested_queries:
            try:
                results = search_by_query(query, serper, fallback_key=serpapi)
                ctx.llm_followup_results = _dedup_dork_results(ctx.llm_followup_results, results)
                log_fn(f"[{_ts()}] Round 3 → Query '{query[:60]}': {len(results)} risultati")
            except RuntimeError as exc:
                log_fn(f"[{_ts()}] ⚠️ Round 3 → Query dork ERRORE: {exc}")
    elif not has_dork:
        log_fn(f"[{_ts()}] Round 3 → Dork follow-up: nessuna key Serper/SerpAPI, skip")

    progress_fn(0.90)
    return ctx


def _build_entity_extraction_prompt(ctx: ScanContext) -> str:
    """Prompt for Gemini to suggest additional people and dork queries to investigate."""
    company = _get_company_name(ctx)
    city = ctx.target_context.get("city", "")
    known_people = ctx.person_names + [pp.name for pp in ctx.person_profiles]

    breach_summary = [
        {"email": r.email,
         "hibp": r.hibp_breaches[:3],
         "leaklookup": r.leaklookup_sources[:3]}
        for r in ctx.breach_results[:10]
        if r.hibp_breaches or r.leaklookup_sources
    ]

    social_found = [
        {"platform": p.platform, "url": p.url}
        for p in ctx.social_profiles[:5]
    ] + ctx.social_dork_results[:5]

    payload = {
        "domain": ctx.domain,
        "company_name": company,
        "city": city,
        "sector": ctx.gemini_guidance.get("sector", ""),
        "person_names_known": known_people,
        "company_officers": [
            {"name": o["name"], "role": o.get("role")}
            for o in ctx.company_officers[:5]
        ],
        "piva": ctx.piva,
        "related_domains": ctx.related_domains[:5],
        "emails_count": len(ctx.emails),
        "breach_summary": breach_summary,
        "subdomains_sample": (ctx.subdomains + ctx.vt_subdomains)[:10],
        "social_profiles_found": social_found,
        "instagram_results_count": len(ctx.instagram_results),
        "facebook_results_count": len(ctx.facebook_results),
        "brand_dork_results_count": len(ctx.brand_dork_results),
        "tech_hints": ctx.scraped_contacts.get("tech_hints", []),
        "whois_registrant": ctx.whois_data.get("registrant_name"),
        "whois_org": ctx.whois_data.get("registrant_org"),
        "scraped_emails": ctx.scraped_contacts.get("emails", []),
        "company_aliases": ctx.gemini_guidance.get("company_aliases", []),
    }

    return (
        "Sei un analista OSINT. Analizza questi dati di ricognizione passiva su un'azienda target.\n\n"
        "REGOLA CRITICA: Suggerisci persone SOLO se hai evidenza concreta nei dati (es. profilo LinkedIn "
        "trovato, nome nel sito, email con nome, etc.). NON inventare nomi basandoti sul nome "
        "dell'azienda o del dominio. Se non ci sono evidenze di persone specifiche, restituisci "
        "people come array vuoto [].\n\n"
        "Per le query dork: suggerisci query Google specifiche e utili (usa site:, filetype:, "
        "intitle:, etc.) per trovare informazioni aggiuntive sull'azienda, non già cercate.\n\n"
        "Rispondi SOLO con JSON valido:\n"
        '{"people": ["Nome Cognome", ...], "queries": ["query dork", ...]}\n\n'
        "Limiti: max 5 persone (solo se c'è evidenza concreta), max 5 query.\n\n"
        f"DATI:\n{json.dumps(payload, ensure_ascii=False, default=str)}"
    )


def run_final(
    ctx: ScanContext,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Final round: generate unified LLM report and build graph data."""
    from modules.graph_builder import build_graph_data
    from modules.unified_report import generate_unified_report

    log_fn(f"[{_ts()}] Final → Generazione report unificato Gemini...")
    progress_fn(0.91)

    if ctx.config.get("ai_key"):
        try:
            ctx.unified_report = generate_unified_report(
                ctx,
                api_key=ctx.config["ai_key"],
                model_name=ctx.config.get("model_name", "gemini-2.5-flash"),
            )
            log_fn(f"[{_ts()}] Final → Report generato ({len(ctx.unified_report or '')} chars)")
        except RuntimeError as exc:
            ctx.unified_report = None
            log_fn(f"[{_ts()}] ⚠️ Final → Report ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Final → Gemini key mancante, report skip")
    progress_fn(0.96)

    try:
        ctx.graph_data = build_graph_data(ctx)
        n_nodes = len((ctx.graph_data or {}).get("nodes", []))
        n_edges = len((ctx.graph_data or {}).get("edges", []))
        log_fn(f"[{_ts()}] Final → Grafo: {n_nodes} nodi, {n_edges} archi")
    except Exception as exc:
        log_fn(f"[{_ts()}] ⚠️ Final → Grafo ERRORE: {exc}")
    progress_fn(1.0)

    return ctx
