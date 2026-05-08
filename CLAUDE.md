# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run app
streamlit run app.py

# Install dependencies
pip install -r requirements.txt

# Configure secrets (copy and edit)
cp .env.example .env
```

No test suite, no lint config, no CI/CD pipeline exists in this project.

## Architecture

**4-round synergistic OSINT pipeline** — all passive, no active scanning.

```
domain input
  → Round 1: emails (Hunter) + subdomains (crt.sh) + primary IP network scan (ZoomEye+Censys+LeakIX) + generic dorking
  → Round 2: subdomain network scans + exposed service detection + targeted dorking + email-IP correlation
  → Round 3: Gemini extracts suggested IPs/domains → follow-up scans (max 5+5, deduplicated)
  → Final:   unified LLM report + connection graph
  → UI:      display + CSV/Markdown/ZIP export
```

### Key files

| File | Role |
|------|------|
| `app.py` | Streamlit entry point; manages session state, 4 pipeline phases, export |
| `modules/orchestrator.py` | `run_round1/2/3/final()` — executes pipeline, emits progress callbacks |
| `modules/scan_context.py` | `ScanContext` dataclass — shared state flowing through all rounds |
| `modules/merger.py` | Deduplicates and merges ZoomEye + Censys + LeakIX by port |
| `modules/unified_report.py` | Cross-correlated final Gemini report |
| `modules/graph_builder.py` | NetworkX + Plotly connection graph |
| `modules/dashboard_map.py` | Foggia province heatmap (separate Streamlit page) |
| `utils/config.py` | Loads API keys from `st.secrets` (Streamlit Cloud) or `.env` (local) |

### `ScanContext` — the central data model

Dataclass defined in `modules/scan_context.py`. Passed by reference through all 4 rounds, accumulating results. Key fields:

- **Round 1:** `emails`, `breach_data`, `subdomains`, `primary_ip`, `primary_host`, `exposed_documents`
- **Round 2:** `subdomain_results`, `exposed_services`, `targeted_dork_results`, `email_ip_correlations`
- **Round 3:** `llm_suggested_ips`, `llm_suggested_domains`, `follow_up_host_results`
- **Final:** `unified_report`, `graph_data`

Supporting dataclasses: `SubdomainScanResult`, `EmailBreachCorrelation`, `ExposedService`.

### Orchestrator callbacks

`run_round*()` functions accept `log_fn` and `progress_fn` callbacks for UI decoupling. Pass Streamlit placeholders in `app.py`, or plain functions for testing.

### Graceful degradation

Missing API keys disable modules silently (`if config.get("KEY"): ...`). App runs with whatever keys are present.

## API keys required

| Key | Service | Env var(s) |
|-----|---------|------------|
| Hunter.io | Email discovery | `HUNTER_API_KEY` |
| Leak-Lookup | Breach verification | `LEAKLOOKUP_API_KEY` |
| ZoomEye | Host/service scan | `ZOOMEYE_API_KEY` |
| Censys | Port scan + banners | `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| LeakIX | Leak events | `LEAKIX_API_KEY` |
| Google Gemini 2.5 Flash | AI analysis + entity extraction | `GEMINI_API_KEY` |
| Serper or SerpAPI | Google dorking | `SERPER_API_KEY` or `SERPAPI_KEY` |

crt.sh needs no key.

## Stack

Python 3.10+ · Streamlit · Pandas · Requests · google-genai (Gemini) · Plotly · NetworkX · python-dotenv
