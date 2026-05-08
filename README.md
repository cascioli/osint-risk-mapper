# OSINT Risk Mapper

### Passive Attack Surface Management for SMBs

> AI-powered passive reconnaissance tool that maps digital identity risks and hidden assets of a corporate domain — without touching a single network packet.

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B?logo=streamlit&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![OSINT: Passive Only](https://img.shields.io/badge/OSINT-Passive%20Only-orange)
![Last Commit](https://img.shields.io/github/last-commit/cascioli/osintriskmapper)

---

## Why I built it

Working with the local business ecosystem — agricultural SMBs, logistics companies, and small professional firms in the Foggia province — I noticed a recurring pattern: these companies **are not vulnerable because of complex infrastructure**, but for much more mundane and overlooked reasons.

Corporate credentials leaked in data breaches. Abandoned subdomains exposing admin panels. Excel files with price lists indexed by Google. Nobody knows. Nobody looks. Nobody finds them — until someone else does.

**OSINT Risk Mapper** gives a security professional (or a company curious about its own exposure) a complete passive reconnaissance tool that aggregates multiple sources and translates technical data into a risk report understandable even by someone who doesn't read Nmap output for fun.

---

## Ethical Disclaimer

> [!WARNING]
> **This tool is designed exclusively for ethical, defensive, and preventive use.**
>
> - Uses **exclusively passive techniques** (OSINT) via public APIs and existing intelligence databases.
> - **Does not perform active network scanning**, does not send packets to targets, does not exploit vulnerabilities.
> - **Does not download, access, or modify** data or third-party systems.
> - Must be used **only on domains you own** or for which you have **explicit written authorization**.
>
> Unauthorized use may constitute offenses under Italian Criminal Code arts. 615-ter et seq. and the Computer Fraud and Abuse Act (CFAA). The author disclaims all liability for misuse.

---

## How it works

OSINT Risk Mapper runs a **5-round person + data pipeline** — all passive, no active scanning. Designed for SMB targets on shared hosting (Aruba/OVH/Cloudflare) where IP scanning is useless and irrelevant.

```
domain input
  → Round 1:   web scrape (contacts/social/tech/VAT) + WHOIS + subdomains (crt.sh+VT)
                + Hunter.io emails + generic document dork
  → Round 1.5: Gemini strategic guidance (sector/aliases/people/related domains)
                + PhoneBook.cz emails + OpenCorporates company officers
  → Round 2:   breach check (HIBP + LeakLookup) + LinkedIn/Twitter/Instagram/Facebook dorks
                + VAT dork + email pattern dork + GitHub/Pastebin/brand dorks
                + Gemini-guided custom queries
  → Round 3:   Gemini deep-dive entity extraction → follow-up dorks (max 5+5)
  → Final:     unified LLM report (person + data focused) + interactive connection graph
  → Export:    CSV ZIP archive + Markdown report
```

---

## Features

### Round 1 — Discovery

- **Web scraping** (BeautifulSoup): extracts emails, phone numbers, social links, tech stack hints, and Italian VAT numbers directly from the target site
- **WHOIS lookup** (python-whois + raw NIC.it parser): registrant name, organization, dates
- **Subdomain enumeration**: Certificate Transparency logs via crt.sh + HackerTarget (free, no key), optionally enhanced with VirusTotal passive DNS
- **Email discovery**: Hunter.io API integration
- **Document dork**: Google-indexed `.pdf`, `.doc`, `.xls`, `.xlsx`, `.sql`, `.env`, `.bak` files

### Round 1.5 — Strategic Guidance

- **Gemini LLM analysis**: identifies company sector, likely aliases, key people to investigate, and related domains
- **OpenCorporates**: fetches Italian company officers (directors, administrators) from the official corporate registry
- **PhoneBook.cz**: additional email enumeration

### Round 2 — Enrichment

- **Breach check**: cross-references all discovered emails against HaveIBeenPwned (HIBP) and Leak-Lookup
- **Social dorks**: LinkedIn, Twitter, Instagram, Facebook targeted searches for each identified person
- **Brand intelligence dorks**: GitHub code leaks, Pastebin mentions, VAT number cross-references

### Round 3 — LLM-Guided Iteration

- Gemini extracts additional people and investigative angles from accumulated data
- Runs up to 5 + 5 follow-up dorks for newly suggested persons and queries
- Controlled iteration to cap API costs

### Final — Reporting

- **Unified AI report**: Gemini-generated executive summary focused on data exposure and compromised credentials
- **Interactive connection graph**: NetworkX + Plotly visualization with node types: domain, person, email, breach, social profile, document, subdomain

---

## Outputs

| Output | Format | Contents |
|--------|--------|----------|
| Dashboard | Streamlit UI | Metrics cards, AI report, connection graph, expandable data tables |
| CSV archive | `.zip` | `emails`, `people`, `breaches`, `social`, `subdomains`, `documents`, `whois`, `officers`, `related_domains`, `instagram_facebook` |
| Markdown report | `.md` | Summary stats + full AI report text |

---

## Architecture

```
osintriskmapper/
├── app.py                      # Streamlit entry point — session state, pipeline phases, export
├── modules/
│   ├── orchestrator.py         # run_round1/1_5/2/3/final() — pipeline execution with callbacks
│   ├── scan_context.py         # ScanContext dataclass — shared state across all rounds
│   ├── web_scraper.py          # BeautifulSoup — emails, phones, social links, tech, VAT
│   ├── whois_client.py         # python-whois + raw NIC.it parser
│   ├── gemini_guidance.py      # Round 1.5 Gemini strategic guidance
│   ├── phonebook_client.py     # PhoneBook.cz email discovery
│   ├── opencorporates_client.py# OpenCorporates REST API — Italian company officers
│   ├── vt_client.py            # VirusTotal API v3 — passive subdomain enumeration
│   ├── hibp_client.py          # HaveIBeenPwned API v3 — breach check per email
│   ├── osint_dorking.py        # Google dork functions (docs/LinkedIn/Twitter/GitHub/Pastebin/VAT)
│   ├── osint_hunter.py         # Hunter.io email discovery
│   ├── osint_leaklookup.py     # Leak-Lookup breach check
│   ├── osint_subdomains.py     # crt.sh + HackerTarget subdomain enumeration
│   ├── unified_report.py       # Cross-correlated final Gemini report
│   ├── graph_builder.py        # NetworkX + Plotly connection graph
│   ├── dashboard_map.py        # Foggia province heatmap (demo page)
│   ├── ai_analyzer.py          # AI analysis helpers
│   ├── llm_client.py           # LLM client wrapper
│   └── ui.py                   # Reusable Streamlit UI components
└── utils/
    └── config.py               # API key loader — st.secrets (cloud) or .env (local)
```

**Design principles:**

- Each OSINT module is independent and testable in isolation
- All rounds share a single `ScanContext` dataclass passed by reference
- Orchestrator callbacks (`log_fn`, `progress_fn`) decouple pipeline logic from UI
- Missing API keys silently disable modules — app runs with whatever keys are present
- API keys are never hardcoded — loaded from `.env` via `python-dotenv`, never committed

---

## API Keys

All keys are optional. Missing keys silently disable the corresponding module.

| Variable | Service | Free Tier | Get it |
|----------|---------|-----------|--------|
| `GEMINI_API_KEY` | Google Gemini 2.5 Flash | Yes | [aistudio.google.com](https://aistudio.google.com) |
| `SERPER_API_KEY` | Serper.dev (Google dorking) | 2,500 queries/mo | [serper.dev](https://serper.dev) |
| `SERPAPI_KEY` | SerpAPI (Google dorking, alt.) | 100 searches/mo | [serpapi.com](https://serpapi.com) |
| `HUNTER_API_KEY` | Hunter.io email discovery | 25 searches/mo | [hunter.io](https://hunter.io) |
| `HIBP_API_KEY` | HaveIBeenPwned breach check | Paid (cheap) | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) |
| `LEAKLOOKUP_API_KEY` | Leak-Lookup breach DB | Yes | [leak-lookup.com](https://leak-lookup.com) |
| `VIRUSTOTAL_API_KEY` | VirusTotal passive DNS | 500 req/day | [virustotal.com](https://www.virustotal.com) |
| `OPENCORPORATES_API_KEY` | OpenCorporates company registry | Yes (limited) | [opencorporates.com](https://opencorporates.com/api_accounts/new) |

> **Always free, no key needed:** crt.sh, HackerTarget, BeautifulSoup web scraping, python-whois, PhoneBook.cz

---

## Installation

**Prerequisites:** Python 3.10+, `git`

```bash
# 1. Clone the repository
git clone https://github.com/cascioli/osintriskmapper.git
cd osintriskmapper

# 2. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env
```

Edit `.env` and add the keys you have:

```env
GEMINI_API_KEY=your_gemini_key
SERPER_API_KEY=your_serper_key
HUNTER_API_KEY=your_hunter_key
HIBP_API_KEY=your_hibp_key
# ... leave others blank to disable those modules
```

---

## Usage

```bash
streamlit run app.py
```

Browser opens at `http://localhost:8501`.

1. **Enter the target domain** (e.g., `company.com`)
2. **Optionally fill in** company name, known employee names, city, and a known contact email to improve results
3. **Click Avvia Analisi** — the pipeline runs all rounds automatically
4. **Review results** in expandable sections: metrics, AI report, connection graph, breach table, social profiles, subdomains, exposed documents
5. **Export** via CSV ZIP or Markdown report

> The sidebar shows which data sources are active based on your API keys.

---

## Stack

| Component | Technology |
|-----------|-----------|
| UI / Dashboard | [Streamlit](https://streamlit.io) |
| Data manipulation | [Pandas](https://pandas.pydata.org) |
| AI analysis | Google Gemini 2.5 Flash (`google-genai`) |
| Connection graph | [NetworkX](https://networkx.org) + [Plotly](https://plotly.com) |
| Web scraping | [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) |
| WHOIS | [python-whois](https://pypi.org/project/python-whois/) |
| HTTP client | [Requests](https://requests.readthedocs.io) |
| Config management | [python-dotenv](https://pypi.org/project/python-dotenv/) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

Found a vulnerability or want to report a sensitive finding? See [SECURITY.md](SECURITY.md).

---

## License

MIT — free to use, modify, and distribute with attribution.
