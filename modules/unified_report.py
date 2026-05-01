"""Unified LLM report generator that cross-correlates all OSINT pipeline data."""

from __future__ import annotations

import json
from dataclasses import asdict

from google import genai
from google.genai import types as genai_types

from modules.scan_context import ScanContext

_SYSTEM_PROMPT = (
    "Sei un analista senior di Threat Intelligence e Red Team. "
    "Hai ricevuto dati OSINT aggregati da fonti multiple su un dominio aziendale target. "
    "Produci un unico report esecutivo cross-correlato in Markdown strutturato. "
    "Il report deve identificare catene di attacco concrete che collegano email compromesse, "
    "infrastruttura esposta, sottodomini vulnerabili e documenti sensibili. "
    "Non inventare dati. Cita esplicitamente le correlazioni trovate tra le sezioni. "
    "Usa italiano."
)


def _summarize_host(host: dict) -> dict:
    """Compact host representation to stay within token budget."""
    ports = list(host.get("ports", {}).values())
    return {
        "ip": host.get("ip"),
        "org": host.get("org"),
        "country": host.get("country"),
        "sources_ok": host.get("sources_ok", []),
        "ports": [
            {
                "port": p.get("port"),
                "service": p.get("service"),
                "product": p.get("product"),
                "vulns": p.get("vulns", [])[:3],
                "leaks": [lk[:80] for lk in p.get("leaks", [])[:3]],
            }
            for p in ports[:20]
        ],
        "host_leaks": [lk[:80] for lk in host.get("host_leaks", [])[:5]],
    }


def _build_unified_prompt(ctx: ScanContext) -> str:
    sections: list[str] = [f"# ANALISI OSINT — TARGET: {ctx.domain}\n"]

    # Section 1: Email breach
    sections.append("## SEZIONE 1: EMAIL E BREACH")
    sections.append(f"Email trovate (Hunter.io): {len(ctx.emails)}")
    if ctx.breach_data:
        sections.append(json.dumps(ctx.breach_data, ensure_ascii=False))
    else:
        sections.append("Nessun dato breach disponibile.")

    # Section 2: Network infrastructure
    sections.append("\n## SEZIONE 2: INFRASTRUTTURA DI RETE")
    sections.append(f"IP primario: {ctx.primary_ip or 'N/D'}")
    if ctx.primary_host:
        sections.append(json.dumps(_summarize_host(ctx.primary_host), ensure_ascii=False))
    sub_hosts = [
        {"subdomain": r.subdomain, "ip": r.ip, **_summarize_host(r.merged_host)}
        for r in ctx.subdomain_results
        if r.merged_host and r.merged_host.get("sources_ok")
    ][:10]
    if sub_hosts:
        sections.append(f"Sottodomini con dati network ({len(sub_hosts)}):")
        sections.append(json.dumps(sub_hosts, ensure_ascii=False))

    # Section 3: Subdomains
    sections.append("\n## SEZIONE 3: SOTTODOMINI (Certificate Transparency)")
    sections.append(f"Totale sottodomini rilevati: {len(ctx.subdomains)}")
    if ctx.subdomains:
        sections.append(json.dumps(ctx.subdomains[:50], ensure_ascii=False))

    # Section 4: Exposed documents
    sections.append("\n## SEZIONE 4: DOCUMENTI ESPOSTI (Google Dorking)")
    all_docs = ctx.exposed_documents + ctx.targeted_dork_results
    sections.append(f"Documenti totali trovati: {len(all_docs)}")
    if all_docs:
        sections.append(json.dumps(all_docs[:20], ensure_ascii=False))

    # Section 5: Email-IP correlations
    sections.append("\n## SEZIONE 5: CORRELAZIONI EMAIL-IP")
    correlated = [
        {"email": c.email, "breach_sources": c.breach_sources,
         "correlated_ips": c.correlated_ips, "matches": c.leakix_summary_matches[:3]}
        for c in ctx.email_ip_correlations
        if c.correlated_ips or c.breach_sources
    ]
    if correlated:
        sections.append(json.dumps(correlated, ensure_ascii=False))
    else:
        sections.append("Nessuna correlazione diretta email-IP rilevata.")

    # Section 6: Follow-up hosts from Round 3
    if ctx.follow_up_host_results:
        sections.append("\n## SEZIONE 6: ENTITÀ AGGIUNTIVE (Round 3 LLM-guided)")
        follow_up = [_summarize_host(h) for h in ctx.follow_up_host_results[:5]]
        sections.append(json.dumps(follow_up, ensure_ascii=False))

    # Instructions
    sections.append("""
---
Struttura il report con questi capitoli (usa intestazioni Markdown ##):
1. **Executive Summary** (3-5 righe)
2. **Livello di Rischio Complessivo** — indica [BASSO|MEDIO|ALTO|CRITICO] con motivazione
3. **Catene di Attacco Identificate** — formato: `Email compromessa → Breach → IP esposto → Servizio vulnerabile → Impatto`
4. **Analisi per Dominio di Rischio**:
   - Credential Exposure
   - Network Exposure
   - Data Leakage (documenti)
   - Sottodomini dimenticati/ambienti di test
5. **Correlazioni Cross-Pipeline** (la sezione più importante — collega email, IP, breach, documenti)
6. **Entità Correlate di Terze Parti** (se presenti dati Round 3)
7. **Raccomandazioni Prioritizzate** — usa etichette P1 (critico), P2 (alto), P3 (medio)
""")

    return "\n".join(sections)


def generate_unified_report(ctx: ScanContext, api_key: str, model_name: str) -> str:
    """Generate a single cross-correlated threat intelligence report from all scan data.

    Raises:
        RuntimeError on Gemini API failure.
    """
    client = genai.Client(api_key=api_key)
    prompt = _build_unified_prompt(ctx)

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.3,
            ),
        )
    except Exception as exc:
        raise RuntimeError(f"Gemini unified report failed: {exc}") from exc

    return response.text
