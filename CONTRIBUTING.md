# Contributing to OSINT Risk Mapper

Thanks for your interest. Contributions are welcome — especially new OSINT data sources, bug fixes, and performance improvements.

## Before you start

- All contributions must be **strictly passive** — no active scanning, no packet injection, no exploitation techniques.
- By submitting a PR you confirm the code is your own work and can be released under the MIT license.

## What's useful

- **New free OSINT sources** — integrations that work without an API key are particularly valuable (following the pattern of crt.sh, HackerTarget, PhoneBook.cz)
- **New optional API integrations** — must degrade gracefully when the key is absent (`if config.get("KEY"): ...`)
- **Bug fixes** — especially around rate limits, parsing edge cases, and encoding issues with non-ASCII company names
- **Export improvements** — additional CSV columns, better Markdown formatting, new export formats
- **UI improvements** — Streamlit component enhancements in `modules/ui.py`

## What to avoid

- Active network scanning (Nmap, Masscan, direct socket connections to target IPs)
- Hardcoded API keys or credentials of any kind
- New dependencies for functionality already covered by the existing stack
- Changes to `CLAUDE.md` — that file is for the AI assistant, not for humans

## How to contribute

1. Fork the repository and create a branch from `main`
2. Follow the existing module pattern — one file per data source in `modules/`
3. Add the new key (if any) to `.env.example` with an empty value
4. Add the key to the API Keys table in `README.md`
5. Update `modules/scan_context.py` if you add new data fields to `ScanContext`
6. Update `modules/orchestrator.py` to call your module in the appropriate round
7. Test with at least one real domain you own before submitting
8. Open a pull request with a clear description of what the module does and which data source it queries

## Module pattern

```python
# modules/myservice_client.py

import requests
from utils.config import get_config

def fetch_data(domain: str) -> list[str]:
    config = get_config()
    api_key = config.get("MYSERVICE_API_KEY")
    if not api_key:
        return []
    # ... implementation
```

Key invariants:
- Return an empty list/dict on failure — never raise to the caller
- Log errors via `log_fn` callback if available, not `print()`
- Respect rate limits — add `time.sleep()` between paginated requests if needed

## Reporting bugs

Open a GitHub Issue with:
- Python version and OS
- Which API keys are configured (just the names, not the values)
- The domain that triggered the bug (if it's a public domain you're authorized to test)
- The full error traceback from the Streamlit execution log
