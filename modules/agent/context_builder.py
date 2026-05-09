"""Builds a compact context summary for each Gemini agent iteration."""

from __future__ import annotations

from modules.agent.budget_tracker import BudgetTracker
from modules.agent.tool_executor import derive_usernames
from modules.scan_context import ScanContext


def _missing_services(config: dict) -> list[str]:
    key_map = {
        "hunter": "hunter_key",
        "hibp": "hibp_key",
        "vt": "vt_key",
        "leaklookup": "leaklookup_key",
        "serper": "serper_key",
        "opencorporates": "opencorporates_key",
        "atoka": "atoka_key",
        "dehashed": "dehashed_key",
        "intelx": "intelx_key",
    }
    missing = []
    for svc, key in key_map.items():
        if not config.get(key) and not (svc == "serper" and config.get("serpapi_key")):
            missing.append(svc)
    return missing


def build_context_summary(
    ctx: ScanContext,
    budget: BudgetTracker,
    tool_call_log: list[dict],
    iteration: int,
) -> str:
    n_breached = sum(
        1 for r in ctx.breach_results if r.hibp_breaches or r.leaklookup_sources
    )
    emails_breach_checked = {r.email for r in ctx.breach_results}
    all_subs = list(dict.fromkeys(ctx.subdomains + ctx.vt_subdomains))
    all_people = list(dict.fromkeys(
        ctx.person_names
        + ctx.llm_suggested_people
        + [o.get("name", "") for o in ctx.company_officers]
        + [pp.name for pp in ctx.person_profiles]
    ))
    all_people = [p for p in all_people if p]

    log_lines = []
    for entry in tool_call_log[-15:]:
        if entry.get("skipped_reason"):
            log_lines.append(f"  [SKIP] {entry['tool']}({entry['args']}) — {entry['skipped_reason']}")
        else:
            log_lines.append(f"  {entry['tool']}({entry['args']}) → {entry.get('result_summary', '')}")

    missing = _missing_services(ctx.config)
    missing_str = "\n".join(f"  {s}: NO KEY" for s in missing) if missing else "  (nessuna mancante)"

    budget_lines = "\n".join(
        f"  {svc}: {info['remaining']} rimanenti (usati {info['used']})"
        for svc, info in budget.summary_dict().items()
    )

    emails_sample = ctx.emails[:5]
    unchecked = [e for e in ctx.emails if e not in emails_breach_checked]

    # Derive usernames for known persons (for DeHashed/IntelX/leak searches)
    derived_usernames: list[str] = []
    for name in all_people[:5]:
        derived_usernames.extend(derive_usernames(name))
    derived_usernames = list(dict.fromkeys(derived_usernames))[:15]

    # Atoka summary if available
    atoka_summary = ""
    if getattr(ctx, "atoka_data", {}):
        ad = ctx.atoka_data
        atoka_summary = f"  atoka: {ad.get('name','')} | {ad.get('sede','')} | ATECO={ad.get('ateco','')}"

    piva_hint = ctx.target_context.get("piva_hint", "")
    email_hint = ctx.target_context.get("contact_email", "")

    return f"""=== OSINT AGENT CONTEXT — iterazione {iteration} ===

TARGET
  domain: {ctx.domain if ctx.domain else "NON ANCORA NOTO"}
  company: {ctx.target_context.get("company_name") or "sconosciuto"}
  city: {ctx.target_context.get("city") or ""}
  sector: {ctx.gemini_guidance.get("sector") or "sconosciuto"}
  piva_hint: {piva_hint or "—"}
  email_hint: {email_hint or "—"}

DISCOVERY
  emails_trovate: {len(ctx.emails)} — campione: {emails_sample}
  email_non_ancora_verificate_breach: {unchecked[:10]}
  persone_note: {all_people[:8]}
  usernames_derivati_da_nomi: {derived_usernames}
  company_officers: {len(ctx.company_officers)} (da OpenCorporates/Atoka)
{atoka_summary}
  sottodomini_totali: {len(all_subs)}
  profili_social_scraping: {len(ctx.social_profiles)}
  piva: {ctx.piva or "non trovata"}
  whois_registrante: {ctx.whois_data.get("registrant_name") or "non trovato"}
  whois_org: {ctx.whois_data.get("registrant_org") or "non trovato"}
  domini_correlati: {ctx.related_domains[:5]}
  phonebook_emails: {len(ctx.phonebook_emails)}

BREACH
  email_verificate: {len(ctx.breach_results)}
  email_compromesse: {n_breached}

DORK RESULTS
  social_dork: {len(ctx.social_dork_results)}
  instagram: {len(ctx.instagram_results)}
  facebook: {len(ctx.facebook_results)}
  brand_documents: {len(ctx.brand_dork_results)}
  documenti_esposti: {len(ctx.exposed_documents)}
  llm_followup: {len(ctx.llm_followup_results)}

TOOLS GIÀ CHIAMATI (ultime 15 voci — non ripetere tool+args identici):
{chr(10).join(log_lines) if log_lines else "  (nessuno ancora)"}

BUDGET RIMANENTE
{budget_lines}
  iterazioni_rimanenti: {budget.iterations_remaining(iteration)}

MISSING KEYS (tool non disponibili):
{missing_str}

Decidi il prossimo tool da chiamare, oppure chiama finish_investigation se l'indagine è completa."""
