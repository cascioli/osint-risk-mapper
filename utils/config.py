"""Secure credential loading — Streamlit secrets (Cloud) with .env fallback (local)."""

import os

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

_KEYS = [
    "HUNTER_API_KEY",
    "LEAKLOOKUP_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "HIBP_API_KEY",
    "GEMINI_API_KEY",
    "SERPER_API_KEY",
    "SERPAPI_KEY",
    "OPENCORPORATES_API_KEY",
]


def get_api_keys() -> dict[str, str]:
    """Load API keys from st.secrets (Streamlit Cloud) or environment variables (local)."""
    def _get(key: str) -> str:
        try:
            return st.secrets.get(key, "") or os.getenv(key, "")
        except Exception:
            return os.getenv(key, "")

    return {k: _get(k) for k in _KEYS}
