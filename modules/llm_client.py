"""LLM analysis module for host/network OSINT data (Gemini only)."""

import json
from typing import Any

from google import genai
from google.genai import types as genai_types

from modules.token_logger import log_llm_call


SYSTEM_PROMPT = (
    "Sei un analista SOC. Analizza questi dati OSINT aggregati e deduplicati "
    "relativi all'infrastruttura di rete di un host. "
    "Scrivi un report esecutivo sui rischi principali (porte esposte, servizi vulnerabili, "
    "leak rilevati) e assegna un livello di rischio complessivo (Basso/Medio/Alto/Critico). "
    "Sii conciso e non inventare dati."
)

_EXCLUDED_KEYS: frozenset[str] = frozenset({"sources_queried"})


def _build_prompt(data: dict[str, Any]) -> str:
    payload = {k: v for k, v in data.items() if k not in _EXCLUDED_KEYS}
    if "ports" in payload and isinstance(payload["ports"], dict):
        payload["ports"] = list(payload["ports"].values())
    return json.dumps(payload, indent=2, ensure_ascii=False)


def analyze_with_gemini(
    api_key: str,
    model_name: str,
    data: dict[str, Any],
) -> str:
    """Send host data to Google Gemini and return the generated risk report.

    Args:
        api_key:    Google AI Studio API key.
        model_name: Gemini model ID (e.g. 'gemini-2.5-flash').
        data:       Merged host dict from merger.merge_sources.

    Returns:
        Report text produced by the model.

    Raises:
        RuntimeError: On API call failures.
    """
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=_build_prompt(data),
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.3,
            ),
        )
        usage = response.usage_metadata
        log_llm_call(
            call_site="llm_client",
            model=model_name,
            input_tokens=getattr(usage, "prompt_token_count", 0),
            output_tokens=getattr(usage, "candidates_token_count", 0),
            target=data.get("domain", "host_analysis") if isinstance(data, dict) else "host_analysis",
        )
        return response.text or ""
    except Exception as exc:
        raise RuntimeError(f"Gemini API error (host report): {exc}") from exc
