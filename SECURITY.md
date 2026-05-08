# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest (`main`) | Yes |

Only the current `main` branch receives security fixes. There are no versioned releases at this time.

## Scope

OSINT Risk Mapper is a **passive reconnaissance tool**. It does not host user data, run a server accessible from the internet, or process credentials beyond loading them from a local `.env` file.

Security reports are relevant for:

- **API key handling** — improper storage, logging, or transmission of keys loaded from `.env`
- **Dependency vulnerabilities** — known CVEs in `requirements.txt` packages that affect this tool's attack surface
- **Output injection** — cases where target-controlled data (scraped content, WHOIS fields, breach data) could lead to XSS, path traversal, or command injection in the Streamlit UI or exported files
- **Sensitive data in exports** — bugs that cause API keys or `.env` values to appear in CSV/Markdown exports

Out of scope:

- Vulnerabilities in third-party services (Hunter.io, HIBP, Serper, etc.)
- Issues only reproducible when the tool is deliberately misconfigured or used without authorization
- Findings produced *by* the tool against a target domain (that's expected behavior)

## Reporting a vulnerability

**Do not open a public GitHub Issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability reporting](https://github.com/cascioli/osintriskmapper/security/advisories/new), or email directly at the address listed on the GitHub profile.

Include:

- Description of the vulnerability and its potential impact
- Steps to reproduce (minimal example preferred)
- Python version, OS, and relevant dependency versions (`pip freeze | grep <package>`)

Expected response time: within 7 days for acknowledgment, fix timeline depends on severity.

## Responsible disclosure

If you discover that OSINT Risk Mapper produced results revealing a real security exposure in a company you are **not authorized to test**, please:

1. Do not use, share, or store that data
2. Notify the affected organization through responsible disclosure channels (e.g., their `security.txt`)
3. Report the tool behavior to this project if it represents a bug or unexpected output
