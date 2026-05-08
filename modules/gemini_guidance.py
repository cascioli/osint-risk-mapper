"""Round 1.5 — Gemini strategic OSINT guidance.

Called after Round 1 (WHOIS + scraping completed) but before Round 2
(breach + social dork). Provides structured intelligence to guide Round 2:
company aliases, related domains, key people, P.IVA, and suggested dork queries.

Returns {} on any failure — never raises.
"""

from __future__ import annotations

import json

from google import genai
from google.genai import types as genai_types

from modules.scan_context import ScanContext

_SYSTEM = (
    "Sei un analista OSINT specializzato in aziende italiane. "
    "Analizza i dati raccolti passivamente e fornisci indicazioni strategiche in formato JSON "
    "per guidare la fase successiva di ricerca. "
    "Basa ogni affermazione SOLO sui dati presenti — non inventare nomi, domini o numeri."
)


def _build_guidance_prompt(ctx: ScanContext, company: str) -> str:
    city = ctx.target_context.get("city", "")
    payload = {
        "domain": ctx.domain,
        "company_name": company,
        "city": city,
        "whois": {
            "registrant_name": ctx.whois_data.get("registrant_name"),
            "registrant_org": ctx.whois_data.get("registrant_org"),
            "registrant_email": ctx.whois_data.get("registrant_email"),
            "registrant_city": ctx.whois_data.get("registrant_city"),
            "registrar": ctx.whois_data.get("registrar"),
            "creation_date": ctx.whois_data.get("creation_date"),
            "name_servers": ctx.whois_data.get("name_servers"),
        },
        "piva_found": ctx.piva,
        "emails_scraped": ctx.scraped_contacts.get("emails", [])[:10],
        "phones_scraped": ctx.scraped_contacts.get("phones", [])[:5],
        "person_names_found": ctx.person_names[:10],
        "tech_hints": ctx.scraped_contacts.get("tech_hints", []),
        "subdomains_sample": (ctx.subdomains + ctx.vt_subdomains)[:10],
        "social_links_scraped": [s.url for s in ctx.social_profiles[:10]],
        "pages_scraped": ctx.scraped_contacts.get("pages_scraped", 0),
    }

    return (
        "Dati OSINT Fase 1 (web scraping + WHOIS + subdomini):\n\n"
        f"{json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
        "Rispondi SOLO con JSON valido, senza testo aggiuntivo:\n"
        "{\n"
        '  "company_aliases": ["..."],\n'
        '  "related_domains": ["esempio.it"],\n'
        '  "key_people": ["Nome Cognome"],\n'
        '  "piva": "12345678901",\n'
        '  "dork_queries": ["query Google"],\n'
        '  "sector": "farmaceutico"\n'
        "}\n\n"
        "Regole:\n"
        "- company_aliases: max 3, solo nomi certi e verificabili dai dati. Array vuoto se non ci sono evidenze.\n"
        "- related_domains: max 5, solo domini plausibilmente correlati (es. stesso registrante, varianti del marchio). "
        "Formato: solo il dominio (es. 'farmacia-fontana.com'), senza https://.\n"
        "- key_people: max 5, SOLO persone con evidenza concreta nei dati (email nominativa, profilo social, WHOIS). "
        "NON inventare nomi basandoti sul nome dell'azienda. Array vuoto se non c'è evidenza.\n"
        "- piva: stringa di 11 cifre se presente nei dati o deducibile con certezza, altrimenti null.\n"
        "- dork_queries: max 5 query Google non ancora eseguite, specifiche e utili per questo target.\n"
        "- sector: settore aziendale in italiano (es. farmaceutico, edile, ristorazione, consulenza IT)."
    )


def run_gemini_guidance(
    ctx: ScanContext,
    api_key: str,
    model_name: str,
    company: str,
) -> dict:
    """Call Gemini for Round 1.5 strategic OSINT guidance.

    Returns structured dict or {} on any failure.
    Keys: company_aliases, related_domains, key_people, piva, dork_queries, sector
    """
    client = genai.Client(api_key=api_key)
    prompt = _build_guidance_prompt(ctx, company)

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=_SYSTEM,
                temperature=0.1,
                response_mime_type="application/json",
            ),
        )
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw)
        # Sanitize: ensure expected keys are present
        return {
            "company_aliases": result.get("company_aliases", [])[:3],
            "related_domains": result.get("related_domains", [])[:5],
            "key_people": result.get("key_people", [])[:5],
            "piva": result.get("piva"),
            "dork_queries": result.get("dork_queries", [])[:5],
            "sector": result.get("sector", ""),
        }
    except Exception:
        return {}
