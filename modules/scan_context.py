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

    # User-provided target context (from onboarding form)
    target_context: dict = field(default_factory=dict)
    # {company_name: str, owner_names: list[str], city: str, contact_email: str}

    # Round 1 — discovery
    emails: list[str] = field(default_factory=list)
    scraped_contacts: dict = field(default_factory=dict)
    whois_data: dict = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    vt_subdomains: list[str] = field(default_factory=list)
    exposed_documents: list[dict] = field(default_factory=list)
    person_names: list[str] = field(default_factory=list)
    piva: str | None = None  # Partita IVA extracted from scraping or WHOIS

    # Round 1.5 — Gemini strategic guidance + company registry + PhoneBook
    gemini_guidance: dict = field(default_factory=dict)
    # Keys: company_aliases, related_domains, key_people, piva, dork_queries, sector
    company_officers: list[dict] = field(default_factory=list)
    # Each: {name, role, current, start_date, company_name, company_url}
    phonebook_emails: list[str] = field(default_factory=list)
    related_domains: list[str] = field(default_factory=list)

    # Round 2 — enrichment
    breach_results: list[BreachResult] = field(default_factory=list)
    social_profiles: list[SocialProfile] = field(default_factory=list)
    social_dork_results: list[dict] = field(default_factory=list)
    brand_dork_results: list[dict] = field(default_factory=list)
    instagram_results: list[dict] = field(default_factory=list)
    facebook_results: list[dict] = field(default_factory=list)

    # Round 3 — LLM-guided iteration
    llm_suggested_people: list[str] = field(default_factory=list)
    llm_suggested_queries: list[str] = field(default_factory=list)
    person_profiles: list[PersonProfile] = field(default_factory=list)
    llm_followup_results: list[dict] = field(default_factory=list)

    # Final outputs
    unified_report: str | None = None
    graph_data: dict | None = None

    # Agent mode metadata (0 / [] / "" when pipeline mode was used)
    agent_iterations: int = 0
    agent_tool_call_log: list[dict] = field(default_factory=list)
    agent_summary: str = ""
