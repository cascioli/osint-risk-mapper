# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run app
streamlit run app.py

# Install dependencies
.venv/Scripts/pip install -r requirements.txt

# Configure secrets (copy and edit)
cp .env.example .env
```

No test suite, no lint config, no CI/CD pipeline exists in this project.

## Architecture

**5-round person+data OSINT pipeline** — all passive, no active scanning. Designed for SMB targets on shared hosting (Aruba/OVH/Cloudflare) where IP scanning is useless.

```
domain input
  → Round 1:   web scrape (contacts/social/tech/P.IVA) + WHOIS + subdomains (crt.sh+VT) + Hunter emails + generic dork
  → Round 1.5: Gemini strategic guidance (sector/aliases/people/related domains) + PhoneBook.cz emails + OpenCorporates officers
  → Round 2:   breach check (HIBP+LeakLookup) + LinkedIn/Twitter/Instagram/Facebook dork + P.IVA dork + email pattern dork + GitHub/Pastebin/brand dork + Gemini guidance queries
  → Round 3:   Gemini deep-dive entity extraction → follow-up dorks (max 5+5)
  → Final:     unified LLM report (person+data focused) + connection graph
  → UI:        display + CSV/Markdown/ZIP export
```

### Key files

| File | Role |
|------|------|
| `app.py` | Streamlit entry point; manages session state, pipeline phases, export |
| `modules/orchestrator.py` | `run_round1/1_5/2/3/final()` — executes pipeline, emits progress callbacks |
| `modules/scan_context.py` | `ScanContext` dataclass — shared state flowing through all rounds |
| `modules/web_scraper.py` | BeautifulSoup scraper — emails, phones, social links, tech hints, P.IVA |
| `modules/whois_client.py` | python-whois + raw NIC.it parser — registrant name, org, email, dates |
| `modules/gemini_guidance.py` | Round 1.5 Gemini call — strategic OSINT guidance (sector, aliases, people, domains) |
| `modules/phonebook_client.py` | PhoneBook.cz email discovery (best-effort, JS-rendered fallback) |
| `modules/opencorporates_client.py` | OpenCorporates REST API — Italian company officers (requires OPENCORPORATES_API_KEY) |
| `modules/vt_client.py` | VirusTotal API v3 — passive subdomain enumeration |
| `modules/hibp_client.py` | HaveIBeenPwned API v3 — breach check per email |
| `modules/osint_dorking.py` | Google dork functions: docs, LinkedIn, Twitter, Instagram, Facebook, GitHub, Pastebin, P.IVA, email pattern |
| `modules/osint_hunter.py` | Hunter.io email discovery |
| `modules/osint_subdomains.py` | crt.sh + HackerTarget subdomain enum (with retry/fallback) |
| `modules/osint_leaklookup.py` | Leak-Lookup breach check per email |
| `modules/unified_report.py` | Cross-correlated final Gemini report (person+data focused) |
| `modules/graph_builder.py` | NetworkX + Plotly connection graph (people/breaches/social nodes) |
| `modules/dashboard_map.py` | Foggia province heatmap (separate Streamlit page) |
| `utils/config.py` | Loads API keys from `st.secrets` (Streamlit Cloud) or `.env` (local) |

### `ScanContext` — the central data model

Dataclass defined in `modules/scan_context.py`. Passed by reference through all rounds.

- **Round 1:** `emails`, `scraped_contacts`, `whois_data`, `subdomains`, `vt_subdomains`, `exposed_documents`, `person_names`, `piva`
- **Round 1.5:** `gemini_guidance`, `company_officers`, `phonebook_emails`, `related_domains`
- **Round 2:** `breach_results`, `social_profiles`, `social_dork_results`, `brand_dork_results`, `instagram_results`, `facebook_results`
- **Round 3:** `llm_suggested_people`, `llm_suggested_queries`, `person_profiles`, `llm_followup_results`
- **Final:** `unified_report`, `graph_data`

Supporting dataclasses: `BreachResult`, `SocialProfile`, `PersonProfile`.

### Orchestrator callbacks

`run_round*()` functions accept `log_fn` and `progress_fn` callbacks for UI decoupling. Pass Streamlit placeholders in `app.py`, or plain functions for testing.

### Graceful degradation

Missing API keys disable modules silently (`if config.get("KEY"): ...`). App runs with whatever keys are present. Web scraping, WHOIS, PhoneBook.cz, and crt.sh always run (no key needed). OpenCorporates falls back to a registry dork when OPENCORPORATES_API_KEY is absent but Serper is present.

## API keys required

| Key | Service | Env var(s) |
|-----|---------|------------|
| Hunter.io | Email discovery | `HUNTER_API_KEY` |
| Leak-Lookup | Breach verification | `LEAKLOOKUP_API_KEY` |
| HaveIBeenPwned | Breach check per email | `HIBP_API_KEY` |
| VirusTotal | Passive subdomain enum | `VIRUSTOTAL_API_KEY` |
| Google Gemini 2.5 Flash | AI analysis + guidance + reports | `GEMINI_API_KEY` |
| Serper or SerpAPI | Google dorking (all dork functions) | `SERPER_API_KEY` or `SERPAPI_KEY` |
| OpenCorporates | Italian company registry officers | `OPENCORPORATES_API_KEY` (optional — dork fallback if absent) |

crt.sh, HackerTarget, BeautifulSoup scraping, python-whois, and PhoneBook.cz need no key.

## Stack

Python 3.10+ · Streamlit · Pandas · Requests · BeautifulSoup4 · python-whois · google-genai (Gemini) · Plotly · NetworkX · python-dotenv
