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
    search_exposed_documents,
    search_github_mentions,
    search_linkedin_profiles,
    search_pastebin_mentions,
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

_MAX_PEOPLE_ROUND2 = 5
_MAX_FOLLOW_UP = 5


def _noop_log(msg: str) -> None:
    pass


def _noop_progress(val: float) -> None:
    pass


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _get_company_name(ctx: ScanContext) -> str:
    """Derive company name from WHOIS org or domain label."""
    org = ctx.whois_data.get("registrant_org") or ""
    # Exclude generic registrar names
    generic = ("register", "privacy", "whoisguard", "domains", "protection", "srl", "spa", "ltd")
    if org and not any(g in org.lower() for g in generic):
        return org.strip()
    return ctx.domain.split(".")[0].replace("-", " ").title()


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

    # Web scraping
    log_fn(f"[{_ts()}] Round 1 → Web scraping {ctx.domain}: avvio...")
    progress_fn(0.02)
    ctx.scraped_contacts = scrape_domain(ctx.domain)
    log_fn(
        f"[{_ts()}] Round 1 → Scraping: "
        f"{len(ctx.scraped_contacts.get('emails', []))} email, "
        f"{len(ctx.scraped_contacts.get('social_links', []))} social links"
    )
    progress_fn(0.08)

    # WHOIS
    log_fn(f"[{_ts()}] Round 1 → WHOIS: avvio...")
    ctx.whois_data = fetch_whois(ctx.domain)
    log_fn(f"[{_ts()}] Round 1 → WHOIS: registrant={ctx.whois_data.get('registrant_name') or 'N/D'}")
    progress_fn(0.12)

    # Subdomain enumeration (crt.sh — always free)
    log_fn(f"[{_ts()}] Round 1 → Subdomain enum (crt.sh): avvio...")
    try:
        ctx.subdomains = get_subdomains(ctx.domain)
    except RuntimeError:
        ctx.subdomains = []
    log_fn(f"[{_ts()}] Round 1 → crt.sh subdomains: {len(ctx.subdomains)}")
    progress_fn(0.16)

    # VirusTotal subdomains
    if config.get("vt_key"):
        log_fn(f"[{_ts()}] Round 1 → VirusTotal subdomains: avvio...")
        try:
            ctx.vt_subdomains = fetch_vt_subdomains(config["vt_key"], ctx.domain)
        except (ValueError, RuntimeError):
            ctx.vt_subdomains = []
        log_fn(f"[{_ts()}] Round 1 → VirusTotal subdomains: {len(ctx.vt_subdomains)}")
    progress_fn(0.20)

    # Hunter.io emails
    if config.get("hunter_key"):
        log_fn(f"[{_ts()}] Round 1 → Email Hunter.io: avvio...")
        try:
            hunter_emails = fetch_emails_for_domain(ctx.domain, config["hunter_key"])
        except (ValueError, RuntimeError):
            hunter_emails = []
        log_fn(f"[{_ts()}] Round 1 → Hunter.io: {len(hunter_emails)} email")
    else:
        hunter_emails = []
    progress_fn(0.24)

    # Merge all discovered emails (scraped + hunter), dedup
    all_emails: list[str] = list(dict.fromkeys(
        ctx.scraped_contacts.get("emails", []) + hunter_emails
    ))
    ctx.emails = all_emails

    # Add WHOIS registrant email if present
    whois_email = ctx.whois_data.get("registrant_email")
    if whois_email and whois_email not in ctx.emails:
        ctx.emails.append(whois_email)
    log_fn(f"[{_ts()}] Round 1 → Email totali (merged): {len(ctx.emails)}")
    progress_fn(0.26)

    # Social profiles from scraping
    for slink in ctx.scraped_contacts.get("social_links", []):
        ctx.social_profiles.append(SocialProfile(
            platform=slink["platform"],
            url=slink["url"],
            source="scraped",
        ))

    # Build person_names from WHOIS registrant
    person_names: list[str] = []
    registrant = ctx.whois_data.get("registrant_name")
    if registrant:
        person_names.append(registrant)
    ctx.person_names = list(dict.fromkeys(person_names))
    log_fn(f"[{_ts()}] Round 1 → Persone identificate: {len(ctx.person_names)}")
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
        except RuntimeError:
            ctx.exposed_documents = []
        log_fn(f"[{_ts()}] Round 1 → Documenti esposti: {len(ctx.exposed_documents)}")
    progress_fn(0.32)

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
    has_dork = bool(serper or serpapi)

    # Breach check per email
    log_fn(f"[{_ts()}] Round 2 → Breach check: {len(ctx.emails)} email...")
    progress_fn(0.34)

    hibp_results: dict[str, list[str]] = {}
    if ctx.emails and config.get("hibp_key"):
        try:
            hibp_results = check_emails_batch(config["hibp_key"], ctx.emails)
            log_fn(f"[{_ts()}] Round 2 → HIBP: {sum(1 for v in hibp_results.values() if v)} compromesse")
        except ValueError:
            log_fn(f"[{_ts()}] Round 2 → HIBP: API key non valida")

    leaklookup_results: dict[str, list[str]] = {}
    if ctx.emails and config.get("leaklookup_key"):
        try:
            leaklookup_results = check_emails_for_breaches(ctx.emails, config["leaklookup_key"])
            log_fn(f"[{_ts()}] Round 2 → Leak-Lookup: {sum(1 for v in leaklookup_results.values() if v)} compromesse")
        except ValueError:
            log_fn(f"[{_ts()}] Round 2 → Leak-Lookup: API key non valida")

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
        log_fn(f"[{_ts()}] Round 2 → Social dork per {len(ctx.person_names[:max_people])} persone...")
        for name in ctx.person_names[:max_people]:
            try:
                linkedin = search_linkedin_profiles(name, company, serper, serpapi)
                for item in linkedin:
                    ctx.social_dork_results.append({**item, "person": name, "source": "linkedin"})
                log_fn(f"[{_ts()}] Round 2 → LinkedIn dork '{name}': {len(linkedin)} risultati")
            except RuntimeError:
                pass

        # Twitter presence for company
        try:
            twitter = search_twitter_presence(company, serper, serpapi)
            for item in twitter:
                ctx.social_dork_results.append({**item, "source": "twitter"})
            log_fn(f"[{_ts()}] Round 2 → Twitter dork: {len(twitter)} risultati")
        except RuntimeError:
            pass
    progress_fn(0.60)

    # GitHub dork
    if has_dork:
        log_fn(f"[{_ts()}] Round 2 → GitHub dork: avvio...")
        try:
            gh = search_github_mentions(ctx.domain, company, serper, serpapi)
            ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, gh)
            log_fn(f"[{_ts()}] Round 2 → GitHub: {len(gh)} risultati")
        except RuntimeError:
            pass

        # Pastebin dork
        log_fn(f"[{_ts()}] Round 2 → Pastebin dork: avvio...")
        try:
            pb = search_pastebin_mentions(ctx.domain, serper, serpapi)
            ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, pb)
            log_fn(f"[{_ts()}] Round 2 → Pastebin: {len(pb)} risultati")
        except RuntimeError:
            pass

        # Brand documents dork
        if company:
            log_fn(f"[{_ts()}] Round 2 → Brand documents dork: avvio...")
            try:
                bd = search_brand_documents(company, serper, serpapi)
                ctx.brand_dork_results = _dedup_dork_results(ctx.brand_dork_results, bd)
                log_fn(f"[{_ts()}] Round 2 → Brand docs: {len(bd)} risultati")
            except RuntimeError:
                pass
    progress_fn(0.72)

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
    except Exception:
        progress_fn(0.90)
        return ctx

    log_fn(
        f"[{_ts()}] Round 3 → Gemini: "
        f"{len(ctx.llm_suggested_people)} persone, "
        f"{len(ctx.llm_suggested_queries)} query suggerite"
    )
    progress_fn(0.78)

    # Execute dorks for suggested people
    if has_dork:
        for name in ctx.llm_suggested_people:
            linkedin: list[dict] = []
            twitter: list[dict] = []
            try:
                linkedin = search_linkedin_profiles(name, company, serper, serpapi)
                log_fn(f"[{_ts()}] Round 3 → LinkedIn dork '{name}': {len(linkedin)}")
            except RuntimeError:
                pass
            try:
                twitter = search_twitter_presence(name, serper, serpapi)
                log_fn(f"[{_ts()}] Round 3 → Twitter dork '{name}': {len(twitter)}")
            except RuntimeError:
                pass
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
                log_fn(f"[{_ts()}] Round 3 → Query '{query[:50]}': {len(results)}")
            except RuntimeError:
                pass

    progress_fn(0.90)
    return ctx


def _build_entity_extraction_prompt(ctx: ScanContext) -> str:
    """Prompt for Gemini to suggest additional people and dork queries to investigate."""
    company = _get_company_name(ctx)

    breach_summary = [
        {"email": r.email,
         "hibp": r.hibp_breaches[:3],
         "leaklookup": r.leaklookup_sources[:3]}
        for r in ctx.breach_results[:10]
        if r.hibp_breaches or r.leaklookup_sources
    ]

    payload = {
        "domain": ctx.domain,
        "company_name": company,
        "person_names_found": ctx.person_names,
        "emails_count": len(ctx.emails),
        "breach_summary": breach_summary,
        "subdomains_count": len(ctx.subdomains) + len(ctx.vt_subdomains),
        "social_profiles_found": [
            {"platform": p.platform, "url": p.url}
            for p in ctx.social_profiles[:5]
        ],
        "social_dork_results_count": len(ctx.social_dork_results),
        "brand_dork_results_count": len(ctx.brand_dork_results),
        "tech_hints": ctx.scraped_contacts.get("tech_hints", []),
        "whois_registrant": ctx.whois_data.get("registrant_name"),
        "whois_org": ctx.whois_data.get("registrant_org"),
    }

    return (
        "Sei un analista OSINT. Analizza questi dati di ricognizione passiva su un'azienda target. "
        "Identifica eventuali PERSONE AGGIUNTIVE (es. altri soci, manager, tecnici) "
        "e QUERY GOOGLE DORK aggiuntive che vale la pena eseguire per trovare più informazioni. "
        "Rispondi SOLO con JSON valido, nessun testo aggiuntivo:\n"
        '{"people": ["Nome Cognome", ...], "queries": ["query dork", ...]}\n\n'
        "Limiti: max 5 persone, max 5 query. "
        "Le query devono essere query Google reali (usa site:, filetype:, intitle:, etc.).\n\n"
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
        except RuntimeError:
            ctx.unified_report = None
    log_fn(f"[{_ts()}] Final → Report generato ({len(ctx.unified_report or '')} chars)")
    progress_fn(0.96)

    ctx.graph_data = build_graph_data(ctx)
    n_nodes = len((ctx.graph_data or {}).get("nodes", []))
    n_edges = len((ctx.graph_data or {}).get("edges", []))
    log_fn(f"[{_ts()}] Final → Grafo: {n_nodes} nodi, {n_edges} archi")
    progress_fn(1.0)

    return ctx
