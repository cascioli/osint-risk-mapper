"""theHarvester subprocess wrapper — passive OSINT email + subdomain discovery.

theHarvester must be installed separately (requires Python >=3.12):
  pip install git+https://github.com/laramies/theHarvester.git
  OR installed system-wide (Kali: pre-installed; pip install theHarvester via Python 3.12+)

The module gracefully skips if the binary is not found in PATH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

_FREE_SOURCES = [
    "bing", "dnsdumpster", "crtsh", "hackertarget",
    "anubis", "rapiddns", "otx", "urlscan", "yahoo",
]


def _write_api_keys(config: dict) -> None:
    config_dir = Path.home() / ".theHarvester"
    config_dir.mkdir(exist_ok=True)
    lines = ["apikeys:"]
    if config.get("hunter_key"):
        lines += ["  hunter:", f"    key: {config['hunter_key']}"]
    if config.get("vt_key"):
        lines += ["  virustotal:", f"    key: {config['vt_key']}"]
    if config.get("intelx_key"):
        lines += ["  intelx:", f"    key: {config['intelx_key']}", "    url: https://2.intelx.io"]
    with open(config_dir / "api-keys.yaml", "w") as f:
        f.write("\n".join(lines) + "\n")


def _get_sources(config: dict) -> str:
    sources = list(_FREE_SOURCES)
    if config.get("hunter_key"):
        sources.append("hunter")
    if config.get("vt_key"):
        sources.append("virustotal")
    if config.get("intelx_key"):
        sources.append("intelx")
    return ",".join(sources)


def _find_binary() -> str | None:
    """Return theHarvester binary path if found in PATH, else None."""
    return shutil.which("theHarvester") or shutil.which("theharvester")


def run_theharvester(domain: str, config: dict) -> dict[str, list[str]]:
    """Run theHarvester for domain. Returns {"emails": [...], "subdomains": [...]}."""
    empty: dict[str, list[str]] = {"emails": [], "subdomains": []}
    if not domain:
        return empty

    binary = _find_binary()
    if not binary:
        return empty

    _write_api_keys(config)
    sources = _get_sources(config)

    with tempfile.TemporaryDirectory() as tmpdir:
        outfile = Path(tmpdir) / "harvest"
        cmd = [binary, "-d", domain, "-b", sources, "-f", str(outfile), "-l", "500"]
        try:
            subprocess.run(cmd, capture_output=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            return empty
        except Exception:
            return empty

        json_file = outfile.with_suffix(".json")
        if not json_file.exists():
            return empty

        with open(json_file) as f:
            data = json.load(f)

    raw_emails = data.get("emails", [])
    emails = list(dict.fromkeys(
        e.lower().strip() for e in raw_emails if isinstance(e, str) and "@" in e
    ))

    # hosts may be "hostname:ip" — strip IP part
    raw_hosts = data.get("hosts", [])
    hosts = [h.split(":")[0] for h in raw_hosts if isinstance(h, str) and h]
    subdomains = list(dict.fromkeys(
        h for h in hosts if domain in h and h != domain
    ))

    return {"emails": emails, "subdomains": subdomains}
