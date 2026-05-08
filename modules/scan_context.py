"""Shared data model for multi-round person+data OSINT scan."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BreachResult:
    email: str
    hibp_breaches: list[str]
    leaklookup_sources: list[str]


@dataclass
class SocialProfile:
    platform: str   # "linkedin", "twitter", "instagram", "facebook"
    url: str
    source: str     # "scraped" | "dork"


@dataclass
class PersonProfile:
    name: str
    linkedin_results: list[dict]
    twitter_results: list[dict]


@dataclass
class ScanContext:
    domain: str
    config: dict[str, str]

    # Round 1 — discovery
    emails: list[str] = field(default_factory=list)
    scraped_contacts: dict = field(default_factory=dict)
    whois_data: dict = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    vt_subdomains: list[str] = field(default_factory=list)
    exposed_documents: list[dict] = field(default_factory=list)
    person_names: list[str] = field(default_factory=list)

    # Round 2 — enrichment
    breach_results: list[BreachResult] = field(default_factory=list)
    social_profiles: list[SocialProfile] = field(default_factory=list)
    social_dork_results: list[dict] = field(default_factory=list)
    brand_dork_results: list[dict] = field(default_factory=list)

    # Round 3 — LLM-guided iteration
    llm_suggested_people: list[str] = field(default_factory=list)
    llm_suggested_queries: list[str] = field(default_factory=list)
    person_profiles: list[PersonProfile] = field(default_factory=list)
    llm_followup_results: list[dict] = field(default_factory=list)

    # Final outputs
    unified_report: str | None = None
    graph_data: dict | None = None
