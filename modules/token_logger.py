"""JSONL token logger for all LLM calls."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path


_LOG_DIR = Path(__file__).parent.parent / "logs"


def log_llm_call(
    call_site: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    target: str,
) -> None:
    """Append one JSONL record to logs/osint_tokens_YYYYMMDD.jsonl."""
    try:
        _LOG_DIR.mkdir(exist_ok=True)
        log_path = _LOG_DIR / f"osint_tokens_{datetime.now().strftime('%Y%m%d')}.jsonl"
        record = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "target": target or "unknown",
            "call_site": call_site,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass  # never crash the caller
