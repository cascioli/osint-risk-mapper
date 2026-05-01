"""Shared data model for multi-round synergistic OSINT scan."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SubdomainScanResult:
    subdomain: str
    ip: str | None
    merged_host: dict | None  # output of merge_sources; None = same IP as primary or DNS fail


@dataclass
class EmailBreachCorrelation:
    email: str
    breach_sources: list[str]
    correlated_ips: list[str]          # IPs whose LeakIX data matched this email
    leakix_summary_matches: list[str]  # raw leak labels that triggered the match


@dataclass
class ExposedService:
    ip: str
    port: int
    service_name: str
    product: str
    leak_labels: list[str]


@dataclass
class ScanContext:
    domain: str
    config: dict[str, str]

    # Round 1 — basic scans
    emails: list[str] = field(default_factory=list)
    breach_data: dict[str, list[str]] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    exposed_documents: list[dict] = field(default_factory=list)
    primary_ip: str | None = None
    primary_host: dict | None = None

    # Round 2 — synergistic scans
    subdomain_results: list[SubdomainScanResult] = field(default_factory=list)
    targeted_dork_results: list[dict] = field(default_factory=list)
    email_ip_correlations: list[EmailBreachCorrelation] = field(default_factory=list)
    exposed_services: list[ExposedService] = field(default_factory=list)

    # Round 3 — LLM-guided entity discovery
    llm_suggested_ips: list[str] = field(default_factory=list)
    llm_suggested_domains: list[str] = field(default_factory=list)
    follow_up_host_results: list[dict] = field(default_factory=list)

    # Final outputs
    unified_report: str | None = None
    graph_data: dict | None = None
