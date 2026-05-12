"""Dispatches Gemini tool calls to existing OSINT modules and writes results into ScanContext."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from modules.agent.agent_state import AgentState
from modules.agent.budget_tracker import BudgetTracker
from modules.scan_context import BreachResult, PersonProfile, ScanContext, SocialProfile

LogFn = Callable[[str], None]


def _with_retry(fn: Callable, max_retries: int = 3) -> Any:
    for attempt in range(max_retries):
        try:
            return fn()
        except RuntimeError as exc:
            msg = str(exc).lower()
            if ("429" in msg or "quota" in msg or "rate" in msg) and attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            elif attempt == max_retries - 1:
                return None
        except Exception:
            return None
    return None


def _dedup_urls(existing: list[dict], new: list[dict]) -> list[dict]:
    seen = {d.get("url") for d in existing}
    return existing + [d for d in new if d.get("url") not in seen]


def execute_tool(
    tool_name: str,
    args: dict,
    state: AgentState,
    budget: BudgetTracker,
    log_fn: LogFn,
) -> dict:
    """
    Dispatch tool_name to the matching OSINT module function.
    Writes results directly into state.ctx.
    Returns a summary dict for Gemini history and the tool_call_log.
    Never raises — returns {"error": "..."} on failure.
    """
    ctx = state.ctx
    cfg = ctx.config

    try:
        return _dispatch(tool_name, args, ctx, cfg, budget, log_fn)
    except Exception as exc:
        log_fn(f"[agent] ERROR in {tool_name}: {exc}")
        return {"error": str(exc), "summary": f"errore: {exc}"}


def _dispatch(
    tool_name: str,
    args: dict,
    ctx: ScanContext,
    cfg: dict,
    budget: BudgetTracker,
    log_fn: LogFn,
) -> dict:
    # ── Free discovery ────────────────────────────────────────────────────────

    if tool_name == "scrape_domain":
        from modules.web_scraper import scrape_domain
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto — scoprilo prima con atoka/dork/email", "summary": "skip: domain unknown"}
        if ctx.domain is None:
            ctx.domain = domain
        result = _with_retry(lambda: scrape_domain(domain)) or {}
        new_emails = [e for e in result.get("emails", []) if e not in ctx.emails]
        ctx.emails = list(dict.fromkeys(ctx.emails + new_emails))
        ctx.scraped_contacts = result
        if result.get("piva") and not ctx.piva:
            ctx.piva = result["piva"]
        for link_data in result.get("social_links", []):
            if isinstance(link_data, dict):
                url = link_data.get("url", "")
                plat = link_data.get("platform") or _detect_platform(url)
            else:
                url = link_data
                plat = _detect_platform(url)
            if url and plat and not any(p.url == url for p in ctx.social_profiles):
                ctx.social_profiles.append(SocialProfile(platform=plat, url=url, source="scraped"))
        log_fn(f"[agent] scrape_domain({domain}) → {len(new_emails)} nuove email, piva={ctx.piva}")
        return {
            "emails_found": len(ctx.emails),
            "new_emails": new_emails,
            "piva": ctx.piva,
            "social_links": len(ctx.social_profiles),
            "summary": f"{len(new_emails)} email trovate, piva={ctx.piva}",
        }

    if tool_name == "run_theharvester":
        from modules.theharvester_client import run_theharvester
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto — scoprilo prima con atoka/dork/email", "summary": "skip: domain unknown"}
        if ctx.domain is None:
            ctx.domain = domain
        result = _with_retry(lambda: run_theharvester(domain, cfg)) or {"emails": [], "subdomains": [], "skipped_reason": "timeout/errore"}
        skip = result.get("skipped_reason")
        if skip:
            log_fn(f"[agent] run_theharvester({domain}) → skip: {skip}")
            return {"summary": f"skip: {skip}", "skipped_reason": skip}
        new_emails = [e for e in result.get("emails", []) if e not in ctx.emails]
        ctx.emails = list(dict.fromkeys(ctx.emails + new_emails))
        new_subs = [s for s in result.get("subdomains", []) if s not in ctx.subdomains]
        ctx.subdomains = list(dict.fromkeys(ctx.subdomains + new_subs))
        log_fn(f"[agent] run_theharvester({domain}) → {len(new_emails)} email, {len(new_subs)} sottodomini")
        return {
            "new_emails": new_emails,
            "new_subdomains": len(new_subs),
            "total_emails": len(ctx.emails),
            "total_subdomains": len(ctx.subdomains),
            "summary": f"theHarvester: {len(new_emails)} nuove email, {len(new_subs)} nuovi sottodomini",
        }

    if tool_name == "fetch_whois":
        from modules.whois_client import fetch_whois
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto — scoprilo prima con atoka/dork/email", "summary": "skip: domain unknown"}
        if ctx.domain is None:
            ctx.domain = domain
        result = _with_retry(lambda: fetch_whois(domain)) or {}
        ctx.whois_data = result
        registrant = result.get("registrant_name") or result.get("registrant_org") or "n/d"
        if registrant and registrant != "n/d" and registrant not in ctx.person_names:
            ctx.person_names.append(registrant)
        log_fn(f"[agent] fetch_whois({domain}) → registrante={registrant}")
        return {"whois_registrant": registrant, "summary": f"registrante={registrant}"}

    if tool_name == "get_subdomains":
        from modules.osint_subdomains import get_subdomains
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto — scoprilo prima con atoka/dork/email", "summary": "skip: domain unknown"}
        if ctx.domain is None:
            ctx.domain = domain
        result = _with_retry(lambda: get_subdomains(domain)) or []
        new_subs = [s for s in result if s not in ctx.subdomains]
        ctx.subdomains = list(dict.fromkeys(ctx.subdomains + new_subs))
        log_fn(f"[agent] get_subdomains({domain}) → {len(new_subs)} nuovi sottodomini")
        return {"new_subdomains": len(new_subs), "total": len(ctx.subdomains), "summary": f"{len(new_subs)} nuovi sottodomini"}

    if tool_name == "fetch_emails_phonebook":
        from modules.phonebook_client import fetch_emails_phonebook
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto — scoprilo prima con atoka/dork/email", "summary": "skip: domain unknown"}
        if ctx.domain is None:
            ctx.domain = domain
        result = _with_retry(lambda: fetch_emails_phonebook(domain)) or []
        new_emails = [e for e in result if e not in ctx.emails]
        ctx.emails = list(dict.fromkeys(ctx.emails + new_emails))
        ctx.phonebook_emails = list(dict.fromkeys(ctx.phonebook_emails + result))
        log_fn(f"[agent] fetch_emails_phonebook({domain}) → {len(new_emails)} nuove email")
        return {"new_emails": new_emails, "summary": f"{len(new_emails)} email da PhoneBook"}

    # ── API-gated discovery ───────────────────────────────────────────────────

    if tool_name == "fetch_vt_subdomains":
        from modules.vt_client import fetch_vt_subdomains
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto — scoprilo prima con atoka/dork/email", "summary": "skip: domain unknown"}
        if ctx.domain is None:
            ctx.domain = domain
        vt_key = cfg.get("vt_key", "")
        if not vt_key:
            return {"error": "vt_key mancante", "summary": "skip: no vt_key"}
        result = _with_retry(lambda: fetch_vt_subdomains(vt_key, domain)) or []
        new_subs = [s for s in result if s not in ctx.vt_subdomains and s not in ctx.subdomains]
        ctx.vt_subdomains = list(dict.fromkeys(ctx.vt_subdomains + new_subs))
        budget.record("vt")
        log_fn(f"[agent] fetch_vt_subdomains({domain}) → {len(new_subs)} nuovi sottodomini VT")
        return {"new_subdomains": len(new_subs), "summary": f"{len(new_subs)} sottodomini da VirusTotal"}

    if tool_name == "fetch_emails_hunter":
        from modules.osint_hunter import fetch_emails_for_domain
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto — scoprilo prima con atoka/dork/email", "summary": "skip: domain unknown"}
        if ctx.domain is None:
            ctx.domain = domain
        hunter_key = cfg.get("hunter_key", "")
        if not hunter_key:
            return {"error": "hunter_key mancante", "summary": "skip: no hunter_key"}
        result = _with_retry(lambda: fetch_emails_for_domain(domain, hunter_key)) or []
        new_emails = [e for e in result if e not in ctx.emails]
        ctx.emails = list(dict.fromkeys(ctx.emails + new_emails))
        budget.record("hunter")
        log_fn(f"[agent] fetch_emails_hunter({domain}) → {len(new_emails)} nuove email")
        return {"new_emails": new_emails, "summary": f"{len(new_emails)} email da Hunter"}

    if tool_name == "find_company_officers":
        from modules.opencorporates_client import find_company_officers
        company_name = args.get("company_name", "")
        city = args.get("city", "")
        oc_key = cfg.get("opencorporates_key", "")
        if not company_name:
            return {"error": "company_name richiesto", "summary": "skip: nessun company_name"}
        result = _with_retry(lambda: find_company_officers(company_name, city, oc_key)) or []
        new_officers = [o for o in result if o not in ctx.company_officers]
        ctx.company_officers = ctx.company_officers + new_officers
        for o in new_officers:
            name = o.get("name", "")
            if name and name not in ctx.person_names:
                ctx.person_names.append(name)
        budget.record("opencorporates")
        log_fn(f"[agent] find_company_officers({company_name}) → {len(new_officers)} officer")
        return {"officers_found": len(new_officers), "names": [o.get("name") for o in new_officers[:5]], "summary": f"{len(new_officers)} titolari/soci trovati"}

    # ── Breach checking ───────────────────────────────────────────────────────

    if tool_name == "check_emails_hibp":
        from modules.hibp_client import check_emails_batch
        emails = args.get("emails", [])
        hibp_key = cfg.get("hibp_key", "")
        if not hibp_key:
            return {"error": "hibp_key mancante", "summary": "skip: no hibp_key"}
        if not emails:
            return {"summary": "nessuna email da verificare"}
        # Only check emails actually discovered by tools — reject hallucinated addresses
        discovered = set(ctx.emails)
        hallucinated = [e for e in emails if e not in discovered]
        emails = [e for e in emails if e in discovered]
        if hallucinated:
            log_fn(f"[agent] ⚠️ check_emails_hibp: {len(hallucinated)} email non scoperte filtrate: {hallucinated[:3]}")
        if not emails:
            return {"summary": "nessuna email valida da verificare — le email devono essere scoperte da tool prima", "filtered": hallucinated}
        already_checked = {r.email for r in ctx.breach_results}
        new_emails = [e for e in emails if e not in already_checked]
        if not new_emails:
            return {"summary": "tutte le email già verificate"}
        result = _with_retry(lambda: check_emails_batch(hibp_key, new_emails)) or {}
        _merge_breach_results(ctx, new_emails, result, {})
        budget.record("hibp", len(new_emails))
        compromised = sum(1 for e in new_emails if result.get(e))
        log_fn(f"[agent] check_emails_hibp({len(new_emails)} email) → {compromised} compromesse")
        return {
            "checked": len(new_emails),
            "compromised": compromised,
            "details": {e: result.get(e, []) for e in new_emails},
            "summary": f"{compromised}/{len(new_emails)} email compromesse (HIBP)",
        }

    if tool_name == "check_emails_leaklookup":
        from modules.osint_leaklookup import check_emails_for_breaches
        emails = args.get("emails", [])
        ll_key = cfg.get("leaklookup_key", "")
        if not ll_key:
            return {"error": "leaklookup_key mancante", "summary": "skip: no leaklookup_key"}
        if not emails:
            return {"summary": "nessuna email da verificare"}
        # Only check emails actually discovered by tools — reject hallucinated addresses
        discovered = set(ctx.emails)
        hallucinated = [e for e in emails if e not in discovered]
        emails = [e for e in emails if e in discovered]
        if hallucinated:
            log_fn(f"[agent] ⚠️ check_emails_leaklookup: {len(hallucinated)} email non scoperte filtrate: {hallucinated[:3]}")
        if not emails:
            return {"summary": "nessuna email valida da verificare — le email devono essere scoperte da tool prima", "filtered": hallucinated}
        result = _with_retry(lambda: check_emails_for_breaches(emails, ll_key)) or {}
        _merge_breach_results(ctx, emails, {}, result)
        budget.record("leaklookup", len(emails))
        compromised = sum(1 for e in emails if result.get(e))
        log_fn(f"[agent] check_emails_leaklookup({len(emails)} email) → {compromised} risultati")
        return {
            "checked": len(emails),
            "compromised": compromised,
            "summary": f"{compromised}/{len(emails)} email in Leak-Lookup",
        }

    # ── Google Dorking ────────────────────────────────────────────────────────

    if tool_name == "search_linkedin_profiles":
        from modules.osint_dorking import search_linkedin_profiles
        name = args.get("name", "")
        company = args.get("company", "")
        city = args.get("city", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_linkedin_profiles(name, company, serper_key, serpapi_key, city=city)) or []
        new = _dedup_urls(ctx.social_dork_results, result)
        ctx.social_dork_results = new
        budget.record("serper")
        if name and name not in ctx.person_names:
            ctx.person_names.append(name)
            pp = _find_or_create_person_profile(ctx, name)
            pp.linkedin_results = result
        log_fn(f"[agent] search_linkedin_profiles({name}) → {len(result)} risultati")
        return {"results": len(result), "urls": [r.get("url") for r in result[:3]], "summary": f"{len(result)} profili LinkedIn per {name}"}

    if tool_name == "search_twitter_presence":
        from modules.osint_dorking import search_twitter_presence
        company = args.get("company", "")
        city = args.get("city", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_twitter_presence(company, serper_key, serpapi_key, city=city)) or []
        ctx.social_dork_results = _dedup_urls(ctx.social_dork_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_twitter_presence({company}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} profili Twitter per {company}"}

    if tool_name == "search_instagram_profiles":
        from modules.osint_dorking import search_instagram_profiles
        name = args.get("name", "")
        company = args.get("company", "")
        city = args.get("city", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_instagram_profiles(name, company, serper_key, serpapi_key, city=city)) or []
        ctx.instagram_results = _dedup_urls(ctx.instagram_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_instagram_profiles({name}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} profili Instagram per {name}"}

    if tool_name == "search_facebook_profiles":
        from modules.osint_dorking import search_facebook_profiles
        name_or_company = args.get("name_or_company", "")
        city = args.get("city", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_facebook_profiles(name_or_company, serper_key, serpapi_key, city=city)) or []
        ctx.facebook_results = _dedup_urls(ctx.facebook_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_facebook_profiles({name_or_company}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} profili Facebook per {name_or_company}"}

    if tool_name == "search_github_mentions":
        from modules.osint_dorking import search_github_mentions
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto", "summary": "skip: domain unknown"}
        company = args.get("company", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_github_mentions(domain, company, serper_key, serpapi_key)) or []
        ctx.brand_dork_results = _dedup_urls(ctx.brand_dork_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_github_mentions({domain}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} menzioni GitHub"}

    if tool_name == "search_pastebin_mentions":
        from modules.osint_dorking import search_pastebin_mentions
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto", "summary": "skip: domain unknown"}
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_pastebin_mentions(domain, serper_key, serpapi_key)) or []
        ctx.brand_dork_results = _dedup_urls(ctx.brand_dork_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_pastebin_mentions({domain}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} menzioni Pastebin"}

    if tool_name == "search_brand_documents":
        from modules.osint_dorking import search_brand_documents
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto", "summary": "skip: domain unknown"}
        company = args.get("company", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_brand_documents(domain, company, serper_key, serpapi_key)) or []
        ctx.brand_dork_results = _dedup_urls(ctx.brand_dork_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_brand_documents({domain}) → {len(result)} documenti")
        return {"results": len(result), "summary": f"{len(result)} documenti esposti"}

    if tool_name == "search_piva_mentions":
        from modules.osint_dorking import search_piva_mentions
        piva = args.get("piva", ctx.piva or "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        if not piva:
            return {"summary": "skip: piva non nota"}
        result = _with_retry(lambda: search_piva_mentions(piva, serper_key, serpapi_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_piva_mentions({piva}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} menzioni P.IVA {piva}"}

    if tool_name == "search_email_pattern_external":
        import re as _re
        from modules.osint_dorking import search_email_pattern_external
        domain = args.get("domain") or ctx.domain
        if not domain:
            return {"error": "domain non ancora noto", "summary": "skip: domain unknown"}
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_email_pattern_external(domain, serper_key, serpapi_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, result)
        # Extract actual email addresses from search snippets
        _email_re = _re.compile(
            r'\b[a-zA-Z0-9._%+\-]+@' + _re.escape(domain) + r'\b',
            _re.IGNORECASE,
        )
        found_in_snippets: list[str] = []
        for item in result:
            for field in ("snippet", "title", "body"):
                text = item.get(field, "")
                found_in_snippets.extend(_email_re.findall(text))
        deduped = list(dict.fromkeys(e.lower() for e in found_in_snippets))
        new_emails = [e for e in deduped if e not in ctx.emails]
        if new_emails:
            ctx.emails = list(dict.fromkeys(ctx.emails + new_emails))
        budget.record("serper")
        log_fn(f"[agent] search_email_pattern_external({domain}) → {len(result)} risultati, {len(new_emails)} email estratte")
        return {
            "results": len(result),
            "new_emails": new_emails,
            "summary": f"{len(result)} risultati, {len(new_emails)} email estratte dai snippet",
        }

    if tool_name == "search_by_query":
        from modules.osint_dorking import search_by_query
        query = args.get("query", "")
        tag = args.get("context_tag", "custom")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        if not query:
            return {"summary": "skip: query vuota"}
        result = _with_retry(lambda: search_by_query(query, serper_key, fallback_key=serpapi_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, result)
        if query not in ctx.llm_suggested_queries:
            ctx.llm_suggested_queries.append(query)
        budget.record("serper")
        log_fn(f"[agent] search_by_query[{tag}]({query[:60]}) → {len(result)} risultati")
        return {"results": len(result), "query": query, "summary": f"{len(result)} risultati per '{query[:40]}'"}

    # ── Registry & Personal OSINT ─────────────────────────────────────────────

    if tool_name == "fetch_pec_email":
        from modules.inipec_client import fetch_pec_by_company, fetch_pec_by_person
        company_name = args.get("company_name", "")
        city = args.get("city", "")
        first_name = args.get("first_name", "")
        last_name = args.get("last_name", "")
        pec_emails: list[str] = []
        if company_name:
            pec_emails += _with_retry(lambda: fetch_pec_by_company(company_name, city)) or []
        if first_name and last_name:
            pec_emails += _with_retry(lambda: fetch_pec_by_person(first_name, last_name)) or []
        pec_emails = list(dict.fromkeys(pec_emails))
        new_emails = [e for e in pec_emails if e not in ctx.emails]
        ctx.emails = list(dict.fromkeys(ctx.emails + new_emails))
        log_fn(f"[agent] fetch_pec_email({company_name or first_name+' '+last_name}) → {len(pec_emails)} PEC")
        return {"pec_emails": pec_emails, "new_to_emails": new_emails, "summary": f"{len(pec_emails)} PEC trovate: {pec_emails[:3]}"}

    if tool_name == "fetch_atoka_company":
        from modules.atoka_client import search_company
        company_name = args.get("company_name", "")
        city = args.get("city", "")
        piva = args.get("piva", ctx.piva or "")
        atoka_key = cfg.get("atoka_key", "")
        if not atoka_key:
            return {"error": "atoka_key mancante", "summary": "skip: no atoka_key"}
        result = _with_retry(lambda: search_company(company_name, city, piva, atoka_key)) or {}
        if result:
            ctx.atoka_data = result
            if result.get("piva") and not ctx.piva:
                ctx.piva = result["piva"]
            if result.get("pec") and result["pec"] not in ctx.emails:
                ctx.emails.append(result["pec"])
            if result.get("email") and result["email"] not in ctx.emails:
                ctx.emails.append(result["email"])
            for o in result.get("officers", []):
                name = o.get("name", "")
                if name and name not in ctx.person_names:
                    ctx.person_names.append(name)
                if o not in ctx.company_officers:
                    ctx.company_officers.append(o)
        budget.record("atoka")
        log_fn(f"[agent] fetch_atoka_company({company_name}) → {bool(result)}")
        return {
            "found": bool(result),
            "piva": result.get("piva", ""),
            "sede": result.get("sede", ""),
            "ateco": result.get("ateco", ""),
            "officers": [o.get("name") for o in result.get("officers", [])],
            "pec": result.get("pec", ""),
            "summary": f"Atoka: {result.get('name','n/d')} — {result.get('sede','')}" if result else "nessun risultato",
        }

    if tool_name == "search_dehashed":
        from modules.dehashed_client import search as dehashed_search
        query = args.get("query", "")
        query_type = args.get("query_type", "username")
        dh_key = cfg.get("dehashed_key", "")
        dh_email = cfg.get("dehashed_email", "")
        if not dh_key or not dh_email:
            return {"error": "dehashed credentials mancanti", "summary": "skip: no dehashed_key/email"}
        if not query:
            return {"summary": "skip: query vuota"}
        result = _with_retry(lambda: dehashed_search(query, query_type, dh_email, dh_key)) or []
        # Extract discovered emails and add to ctx
        found_emails = list({r["email"] for r in result if r.get("email")})
        new_emails = [e for e in found_emails if e and e not in ctx.emails]
        ctx.emails = list(dict.fromkeys(ctx.emails + new_emails))
        # Add breach info
        for r in result:
            if r.get("email"):
                _merge_breach_results(ctx, [r["email"]], {}, {})
        # Store raw results in followup
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, [
            {"title": f"[DeHashed] {r.get('database_name','?')} — {r.get('username','?')}", "url": "", **r}
            for r in result[:20]
        ])
        budget.record("dehashed")
        log_fn(f"[agent] search_dehashed({query_type}:{query}) → {len(result)} record")
        return {
            "records": len(result),
            "emails_found": found_emails[:10],
            "usernames": [r.get("username") for r in result[:5] if r.get("username")],
            "phones": [r.get("phone") for r in result[:5] if r.get("phone")],
            "databases": list({r.get("database_name") for r in result if r.get("database_name")})[:5],
            "summary": f"{len(result)} record DeHashed per {query_type}:{query}",
        }

    if tool_name == "search_intelx":
        from modules.intelx_client import search as intelx_search
        query = args.get("query", "")
        intelx_key = cfg.get("intelx_key", "")
        if not intelx_key:
            return {"error": "intelx_key mancante", "summary": "skip: no intelx_key"}
        if not query:
            return {"summary": "skip: query vuota"}
        result = _with_retry(lambda: intelx_search(query, intelx_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, [
            {"title": f"[IntelX] {r.get('bucket','?')} — {r.get('name','?')}", "url": "", **r}
            for r in result[:20]
        ])
        budget.record("intelx")
        log_fn(f"[agent] search_intelx({query}) → {len(result)} record")
        return {
            "records": len(result),
            "buckets": list({r.get("bucket") for r in result if r.get("bucket")})[:5],
            "summary": f"{len(result)} record IntelX per '{query}'",
        }

    if tool_name == "scrape_social_bio":
        from modules.social_scraper import scrape_facebook_bio, scrape_instagram_bio
        url = args.get("url", "")
        platform = args.get("platform", "").lower()
        if not url:
            return {"summary": "skip: url vuoto"}
        if platform == "instagram":
            bio_data = _with_retry(lambda: scrape_instagram_bio(url)) or {}
        elif platform == "facebook":
            bio_data = _with_retry(lambda: scrape_facebook_bio(url)) or {}
        else:
            return {"error": "platform deve essere 'instagram' o 'facebook'", "summary": "skip: platform non riconosciuta"}
        if bio_data.get("email") and bio_data["email"] not in ctx.emails:
            ctx.emails.append(bio_data["email"])
        if bio_data.get("phone"):
            phones = ctx.scraped_contacts.get("phones", [])
            if bio_data["phone"] not in phones:
                phones.append(bio_data["phone"])
                ctx.scraped_contacts["phones"] = phones
        log_fn(f"[agent] scrape_social_bio({platform}:{url[:50]}) → {list(bio_data.keys())}")
        return {**bio_data, "summary": f"bio scraped: email={bio_data.get('email','')}, phone={bio_data.get('phone','')}"}

    if tool_name == "search_pagine_bianche":
        from modules.osint_dorking import search_pagine_bianche
        name = args.get("name", "")
        city = args.get("city", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_pagine_bianche(name, city, serper_key, serpapi_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_pagine_bianche({name}) → {len(result)} risultati")
        return {"results": len(result), "urls": [r.get("url") for r in result[:3]], "summary": f"{len(result)} risultati Pagine Bianche per {name}"}

    if tool_name == "search_username_leaks":
        from modules.osint_dorking import search_username_leaks
        username = args.get("username", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        if not username:
            return {"summary": "skip: username vuoto"}
        result = _with_retry(lambda: search_username_leaks(username, serper_key, serpapi_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_username_leaks({username}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} leak per username {username}"}

    if tool_name == "search_registry_dork":
        from modules.osint_dorking import search_registry_dork
        company_name = args.get("company_name", "")
        piva = args.get("piva", ctx.piva or "")
        city = args.get("city", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_registry_dork(company_name, piva, city, serper_key, serpapi_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_registry_dork({company_name}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} risultati registro imprese per {company_name}"}

    if tool_name == "search_person_advanced":
        from modules.osint_dorking import search_person_advanced
        name = args.get("name", "")
        city = args.get("city", "")
        serper_key = cfg.get("serper_key", "")
        serpapi_key = cfg.get("serpapi_key", "")
        if not (serper_key or serpapi_key):
            return {"error": "serper_key mancante", "summary": "skip: no serper_key"}
        result = _with_retry(lambda: search_person_advanced(name, city, serper_key, serpapi_key)) or []
        ctx.llm_followup_results = _dedup_urls(ctx.llm_followup_results, result)
        budget.record("serper")
        log_fn(f"[agent] search_person_advanced({name}) → {len(result)} risultati")
        return {"results": len(result), "summary": f"{len(result)} menzioni contatto per {name}"}

    return {"error": f"tool sconosciuto: {tool_name}", "summary": f"tool non riconosciuto: {tool_name}"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def derive_usernames(full_name: str) -> list[str]:
    """Derive common Italian username patterns from a full name.

    E.g. "Samantha Fontana" → [samantha.fontana, sfontana, samanthafontana, samantha_fontana, fontanas]
    """
    parts = full_name.lower().split()
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    first, last = parts[0], parts[-1]
    return list(dict.fromkeys([
        f"{first}.{last}",
        f"{first[0]}{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{last}{first[0]}",
        f"{last}.{first}",
    ]))


def _detect_platform(url: str) -> str | None:
    url_lower = url.lower()
    for platform in ("linkedin", "twitter", "instagram", "facebook", "x.com"):
        if platform in url_lower:
            return "twitter" if platform == "x.com" else platform
    return None


def _merge_breach_results(
    ctx: ScanContext,
    emails: list[str],
    hibp_map: dict[str, list[str]],
    ll_map: dict[str, list[str]],
) -> None:
    existing = {r.email: r for r in ctx.breach_results}
    for email in emails:
        if email in existing:
            if hibp_map.get(email):
                existing[email].hibp_breaches = list(dict.fromkeys(
                    existing[email].hibp_breaches + hibp_map[email]
                ))
            if ll_map.get(email):
                existing[email].leaklookup_sources = list(dict.fromkeys(
                    existing[email].leaklookup_sources + ll_map[email]
                ))
        else:
            ctx.breach_results.append(BreachResult(
                email=email,
                hibp_breaches=hibp_map.get(email, []),
                leaklookup_sources=ll_map.get(email, []),
            ))


def _find_or_create_person_profile(ctx: ScanContext, name: str) -> PersonProfile:
    for pp in ctx.person_profiles:
        if pp.name == name:
            return pp
    pp = PersonProfile(name=name, linkedin_results=[], twitter_results=[])
    ctx.person_profiles.append(pp)
    return pp
