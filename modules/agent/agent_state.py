"""AgentState — wraps ScanContext with agentic loop metadata."""

from __future__ import annotations

from dataclasses import dataclass, field

from modules.scan_context import ScanContext


@dataclass
class AgentState:
    ctx: ScanContext
    agent_iterations: int = 0
    tool_call_log: list[dict] = field(default_factory=list)
    # Each entry: {iteration, tool, args, result_summary, duration_ms, skipped_reason}
    agent_summary: str = ""
    seen_calls: set[tuple] = field(default_factory=set)
