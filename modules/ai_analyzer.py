"""AI-powered threat intelligence report generator (Gemini only)."""

from __future__ import annotations

import json

from google import genai
from google.genai import types as genai_types

from modules.token_logger import log_llm_call


_SYSTEM_PROMPT = (
    "Sei un analista di Threat Intelligence. "
    "Analizza questi dati relativi alle email aziendali compromesse per questo dominio. "
    "Valuta il rischio di credential stuffing o phishing mirato. "
    "Scrivi un report esecutivo. Non inventare dati. "
    "Nel dataset troverai anche una lista di sottodomini associati al target. "
    "Analizzali e segnala esplicitamente se noti sottodomini che indicano potenziali "
    "ambienti dimenticati, di test o di amministrazione (cerca parole chiave come "
    "test, dev, staging, backup, old, admin, vpn, portal). "
    "Spiega perché rappresentano un rischio per un'azienda. "
    "Il dataset contiene anche un elenco di documenti e file aziendali indicizzati "
    "pubblicamente dai motori di ricerca. Valuta se l'esposizione di questi file "
    "(es. estensioni .sql, .bak, .env o documenti amministrativi) rappresenta un "
    "rischio di Data Leakage e Insecure Direct Object Reference (IDOR). "
    "Fornisci raccomandazioni su come limitare l'indicizzazione."
)


def generate_risk_report(
    data_json: dict,
    provider: str,
    model_name: str,
    api_key: str,
    subdomains: list[str] | None = None,
    exposed_documents: list[dict[str, str]] | None = None,
) -> str:
    """Generate an executive risk report from aggregated breach data via Gemini.

    Args:
        data_json:          Dict mapping email addresses to lists of breach source names.
        provider:           Ignored — always uses Gemini.
        model_name:         Gemini model ID (e.g. "gemini-2.5-flash").
        api_key:            Google AI Studio API key.
        subdomains:         Optional list of subdomains from Certificate Transparency.
        exposed_documents:  Optional list of dicts with "title" and "url" keys.

    Returns:
        The raw text of the AI-generated report.

    Raises:
        RuntimeError: On API call failures.
    """
    subdomain_section = ""
    if subdomains:
        subdomain_section = (
            "\n\nSottodomini rilevati via Certificate Transparency:\n"
            f"```json\n{json.dumps(subdomains, indent=2, ensure_ascii=False)}\n```\n"
        )

    dorking_section = ""
    if exposed_documents:
        dorking_section = (
            "\n\nDocumenti e file sensibili indicizzati pubblicamente (Google Dorking):\n"
            f"```json\n{json.dumps(exposed_documents, indent=2, ensure_ascii=False)}\n```\n"
        )

    user_prompt = (
        "Di seguito i dati OSINT sui breach email del dominio target:\n\n"
        f"```json\n{json.dumps(data_json, indent=2, ensure_ascii=False)}\n```\n"
        f"{subdomain_section}"
        f"{dorking_section}\n"
        "Scrivi un report esecutivo di Threat Intelligence strutturato con:\n"
        "1. Sommario del rischio\n"
        "2. Email più a rischio e relative esposizioni\n"
        "3. Vettori di attacco probabili (credential stuffing, phishing)\n"
        "4. Analisi dei sottodomini a rischio (se presenti)\n"
        "5. Analisi dei documenti esposti e rischio Data Leakage / IDOR (se presenti)\n"
        "6. Raccomandazioni immediate\n"
    )

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.3,
            ),
        )
        usage = response.usage_metadata
        log_llm_call(
            call_site="ai_analyzer",
            model=model_name,
            input_tokens=getattr(usage, "prompt_token_count", 0),
            output_tokens=getattr(usage, "candidates_token_count", 0),
            target=next(iter(data_json), "unknown") if data_json else "unknown",
        )
        return response.text or ""
    except Exception as exc:
        raise RuntimeError(f"Gemini API error: {exc}") from exc
