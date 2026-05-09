"""Budget tracking and per-service call limits for the agentic loop."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BudgetConfig:
    max_iterations: int = 30
    max_gemini_calls: int = 20
    max_serper_calls: int = 40
    max_hibp_calls: int = 20
    max_hunter_calls: int = 3
    max_vt_calls: int = 3
    max_leaklookup_calls: int = 20
    max_opencorporates_calls: int = 5


class BudgetTracker:
    def __init__(self, config: BudgetConfig | None = None) -> None:
        self.config = config or BudgetConfig()
        self._counts: dict[str, int] = {}

    def record(self, service: str, count: int = 1) -> None:
        self._counts[service] = self._counts.get(service, 0) + count

    def can_call(self, service: str) -> bool:
        limit = getattr(self.config, f"max_{service}_calls", None)
        if limit is None:
            return True
        return self._counts.get(service, 0) < limit

    def remaining(self, service: str) -> int:
        limit = getattr(self.config, f"max_{service}_calls", None)
        if limit is None:
            return 9999
        return max(0, limit - self._counts.get(service, 0))

    def iterations_remaining(self, current: int) -> int:
        return max(0, self.config.max_iterations - current)

    def summary_dict(self) -> dict[str, dict]:
        services = ["gemini", "serper", "hibp", "hunter", "vt", "leaklookup", "opencorporates"]
        return {
            s: {"used": self._counts.get(s, 0), "remaining": self.remaining(s)}
            for s in services
        }
