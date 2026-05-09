"""Unified LLM report generator — person+data focused OSINT cross-correlation."""

from __future__ import annotations

import json

from google import genai
from google.genai import types as genai_types

from modules.scan_context import ScanContext
from modules.token_logger import log_llm_call

_SYSTEM_PROMPT = (
    "Sei un analista senior di Threat Intelligence specializzato in OSINT su persone e aziende. "
    "Hai ricevuto dati raccolti passivamente su un target aziendale da fonti multiple. "
    "Produci un report esecutivo focalizzato sull'esposizione di dati personali, "
    "credenziali compromesse e footprint digitale involontario. "
    "Non inventare dati. Cita esplicitamente solo ciò che è presente nei dati. "
    "Usa italiano."
)


def _build_unified_prompt(ctx: ScanContext) -> str:
    sections: list[str] = [f"# ANALISI OSINT — TARGET: {ctx.domain}\n"]

    # Section 1: Persone identificate
    sections.append("## SEZIONE 1: PERSONE IDENTIFICATE")
    all_people = list(dict.fromkeys(
        ctx.person_names + ctx.llm_suggested_people
        + [pp.name for pp in ctx.person_profiles]
    ))
    sections.append(f"Persone trovate: {len(all_people)}")
    if all_people:
        sections.append(json.dumps(all_people, ensure_ascii=False))

    whois_registrant = ctx.whois_data.get("registrant_name")
    if whois_registrant:
        sections.append(f"Registrante WHOIS: {whois_registrant}")
        sections.append(f"Org WHOIS: {ctx.whois_data.get('registrant_org') or 'N/D'}")

    # Section 2: Email e breach
    sections.append("\n## SEZIONE 2: EMAIL E BREACH")
    sections.append(f"Email totali trovate: {len(ctx.emails)}")
    if ctx.breach_results:
        breach_data = [
            {
                "email": r.email,
                "hibp_breaches": r.hibp_breaches,
                "leaklookup_sources": r.leaklookup_sources,
                "compromessa": bool(r.hibp_breaches or r.leaklookup_sources),
            }
            for r in ctx.breach_results
        ]
        sections.append(json.dumps(breach_data, ensure_ascii=False))
    else:
        sections.append("Nessun dato breach disponibile.")

    # Section 3: Profili social
    sections.append("\n## SEZIONE 3: PROFILI SOCIAL TROVATI")
    scraped_social = [
        {"platform": p.platform, "url": p.url, "fonte": p.source}
        for p in ctx.social_profiles
    ]
    dork_social = ctx.social_dork_results[:20]
    all_social = scraped_social + dork_social
    sections.append(f"Profili social totali: {len(all_social)}")
    if all_social:
        sections.append(json.dumps(all_social, ensure_ascii=False))

    # Section 4: Documenti esposti
    sections.append("\n## SEZIONE 4: DOCUMENTI ESPOSTI E BRAND DORK")
    sections.append(
        f"IMPORTANTE: Includi nell'analisi SOLO documenti il cui URL contiene '{ctx.domain}' "
        f"o che citano esplicitamente il dominio target. Ignora documenti di organizzazioni "
        f"omonime o non correlate — verifica sempre che l'URL appartenga al target."
    )
    all_docs = ctx.exposed_documents + ctx.brand_dork_results
    sections.append(f"Documenti trovati (da filtrare per rilevanza): {len(all_docs)}")
    if all_docs:
        sections.append(json.dumps(all_docs[:30], ensure_ascii=False))

    # Section 5: WHOIS + P.IVA
    sections.append("\n## SEZIONE 5: DATI WHOIS E P.IVA")
    if ctx.whois_data:
        sections.append(json.dumps(ctx.whois_data, ensure_ascii=False))
    else:
        sections.append("WHOIS non disponibile.")
    if ctx.piva:
        sections.append(f"P.IVA trovata: {ctx.piva}")

    # Section 5b: Related domains
    if ctx.related_domains:
        sections.append("\n## SEZIONE 5b: DOMINI CORRELATI (stimati)")
        sections.append(f"Domini potenzialmente correlati: {len(ctx.related_domains)}")
        sections.append(json.dumps(ctx.related_domains, ensure_ascii=False))

    # Section 6: Sottodomini
    sections.append("\n## SEZIONE 6: SOTTODOMINI")
    all_subs = list(dict.fromkeys(ctx.subdomains + ctx.vt_subdomains))
    sections.append(f"Totale sottodomini (crt.sh + VirusTotal): {len(all_subs)}")
    if all_subs:
        sections.append(json.dumps(all_subs[:50], ensure_ascii=False))

    # Section 6b: Titolari/Soci (OpenCorporates)
    if ctx.company_officers:
        sections.append("\n## SEZIONE 6b: TITOLARI E SOCI (Registro Imprese)")
        officers_data = [
            {
                "nome": o["name"],
                "ruolo": o.get("role"),
                "in_carica": o.get("current"),
                "azienda": o.get("company_name"),
            }
            for o in ctx.company_officers
        ]
        sections.append(f"Persone registrate: {len(officers_data)}")
        sections.append(json.dumps(officers_data, ensure_ascii=False))

    # Section 6c: Instagram / Facebook
    all_ig_fb = [
        {**r, "platform": "instagram"} for r in ctx.instagram_results[:10]
    ] + [
        {**r, "platform": "facebook"} for r in ctx.facebook_results[:10]
    ]
    if all_ig_fb:
        sections.append("\n## SEZIONE 6c: INSTAGRAM E FACEBOOK")
        sections.append(
            "IMPORTANTE: Questi sono risultati di ricerca Google — non profili verificati. "
            "Indicare sempre come 'possibile profilo candidato'."
        )
        sections.append(f"Risultati totali Instagram/Facebook: {len(all_ig_fb)}")
        sections.append(json.dumps(all_ig_fb, ensure_ascii=False))

    # Section 7: Round 3 entities
    if ctx.person_profiles or ctx.llm_followup_results:
        sections.append("\n## SEZIONE 7: ENTITÀ AGGIUNTIVE (Round 3 LLM-guided)")
        if ctx.person_profiles:
            pp_data = [
                {
                    "nome": pp.name,
                    "linkedin_results": len(pp.linkedin_results),
                    "twitter_results": len(pp.twitter_results),
                    "linkedin_urls": [r.get("url") for r in pp.linkedin_results[:3]],
                    "twitter_urls": [r.get("url") for r in pp.twitter_results[:3]],
                }
                for pp in ctx.person_profiles
            ]
            sections.append(f"Persone aggiuntive investigate: {len(pp_data)}")
            sections.append(json.dumps(pp_data, ensure_ascii=False))
        if ctx.llm_followup_results:
            sections.append(f"Risultati query aggiuntive: {len(ctx.llm_followup_results)}")
            sections.append(json.dumps(ctx.llm_followup_results[:10], ensure_ascii=False))

    # Tech hints
    tech = ctx.scraped_contacts.get("tech_hints", [])
    if tech:
        sections.append(f"\n## SEZIONE 8: TECNOLOGIE RILEVATE\n{json.dumps(tech, ensure_ascii=False)}")

    # Instructions
    sections.append(f"""
---
Struttura il report con questi capitoli (usa intestazioni Markdown ##):
1. **Executive Summary** (3-5 righe)
2. **Livello di Rischio Complessivo** — indica [BASSO|MEDIO|ALTO|CRITICO] con motivazione
3. **Soggetti Esposti** — titolari, soci e dipendenti identificati
   - Includi persone da Registro Imprese (OpenCorporates) con ruolo ufficiale
   - Per profili social (LinkedIn/Twitter/Instagram/Facebook): usa sempre "possibile profilo" o "profilo candidato"
   - Non affermare appartenenza con certezza. Se più candidati, elencali come lista.
   - Se matching basato solo sul nome senza altri segnali: ometti o scrivi "nessun profilo verificabile trovato"
4. **Credential Exposure** — per ogni email compromessa: breach sources, tipo dato, rischio
5. **Esposizione Documentale** — includi SOLO documenti il cui URL contiene '{ctx.domain}' o che citano esplicitamente questo dominio. Documenti di aziende omonime (stesso nome, sito diverso): ESCLUDI o marca "non correlato al target".
6. **Footprint Digitale** — GitHub, Pastebin, Instagram, Facebook, menzioni web, P.IVA dork
7. **Infrastruttura e Domini** — sottodomini attivi, domini correlati stimati (se presenti)
8. **Correlazioni Cross-Pipeline** — collega persone → email → breach → documenti → social → registro
9. **Raccomandazioni Prioritizzate** — P1 (critico), P2 (alto), P3 (medio)
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

    usage = response.usage_metadata
    log_llm_call(
        call_site="unified_report",
        model=model_name,
        input_tokens=getattr(usage, "prompt_token_count", 0),
        output_tokens=getattr(usage, "candidates_token_count", 0),
        target=ctx.domain or ctx.target_context.get("company_name") or "unknown",
    )
    return response.text
