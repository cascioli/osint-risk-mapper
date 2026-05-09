"""Gemini FunctionDeclaration schemas for all 20 OSINT tools + dedup helpers."""

from __future__ import annotations

from google.genai import types as genai_types

# Maps tool name → service token used for budget tracking.
# None means the tool is free (no API key needed).
TOOL_SERVICE_MAP: dict[str, str | None] = {
    "scrape_domain": None,
    "fetch_whois": None,
    "get_subdomains": None,
    "fetch_emails_phonebook": None,
    "fetch_vt_subdomains": "vt",
    "fetch_emails_hunter": "hunter",
    "find_company_officers": "opencorporates",
    "check_emails_hibp": "hibp",
    "check_emails_leaklookup": "leaklookup",
    "search_by_query": "serper",
    "search_linkedin_profiles": "serper",
    "search_twitter_presence": "serper",
    "search_instagram_profiles": "serper",
    "search_facebook_profiles": "serper",
    "search_github_mentions": "serper",
    "search_pastebin_mentions": "serper",
    "search_brand_documents": "serper",
    "search_piva_mentions": "serper",
    "search_email_pattern_external": "serper",
    "fetch_pec_email": None,
    "fetch_atoka_company": "atoka",
    "search_dehashed": "dehashed",
    "search_intelx": "intelx",
    "scrape_social_bio": None,
    "search_pagine_bianche": "serper",
    "search_username_leaks": "serper",
    "search_registry_dork": "serper",
    "search_person_advanced": "serper",
    "finish_investigation": None,
}

_STR = {"type": "string"}
_STR_OPT = {"type": "string", "description": "Optional, can be empty string"}


def _decl(name: str, description: str, props: dict, required: list[str]) -> genai_types.FunctionDeclaration:
    return genai_types.FunctionDeclaration(
        name=name,
        description=description,
        parameters={
            "type": "object",
            "properties": props,
            "required": required,
        },
    )


def get_tool_declarations() -> list[genai_types.FunctionDeclaration]:
    return [
        # ── Free discovery ────────────────────────────────────────────────────
        _decl(
            "scrape_domain",
            "Scraping passivo del dominio target: estrae email, telefoni, link social, "
            "tech hints e P.IVA. Chiamare SEMPRE come primo tool.",
            {"domain": {**_STR, "description": "Dominio target, es. example.it"}},
            ["domain"],
        ),
        _decl(
            "fetch_whois",
            "WHOIS del dominio: registrante, org, email, date, nameserver. Chiamare come secondo tool.",
            {"domain": {**_STR, "description": "Dominio target"}},
            ["domain"],
        ),
        _decl(
            "get_subdomains",
            "Enumerazione sottodomini via crt.sh e HackerTarget. Gratuito, nessuna API key.",
            {"domain": {**_STR, "description": "Dominio target"}},
            ["domain"],
        ),
        _decl(
            "fetch_emails_phonebook",
            "Ricerca email via PhoneBook.cz. Gratuito, complementare a Hunter.io.",
            {"domain": {**_STR, "description": "Dominio target"}},
            ["domain"],
        ),
        # ── API-gated discovery ───────────────────────────────────────────────
        _decl(
            "fetch_vt_subdomains",
            "Sottodomini aggiuntivi da VirusTotal passive DNS. Budget: max_vt_calls.",
            {"domain": {**_STR, "description": "Dominio target"}},
            ["domain"],
        ),
        _decl(
            "fetch_emails_hunter",
            "Scoperta email via Hunter.io domain-search. Budget: max_hunter_calls.",
            {"domain": {**_STR, "description": "Dominio target"}},
            ["domain"],
        ),
        _decl(
            "find_company_officers",
            "Titolari e soci da OpenCorporates (registro italiano). Budget: max_opencorporates_calls.",
            {
                "company_name": {**_STR, "description": "Nome commerciale o ragione sociale"},
                "city": {**_STR, "description": "Città per disambiguare, può essere vuoto"},
            },
            ["company_name"],
        ),
        # ── Breach checking ───────────────────────────────────────────────────
        _decl(
            "check_emails_hibp",
            "Verifica email contro HaveIBeenPwned. Budget: max_hibp_calls (conta per email). "
            "Chiamare dopo la scoperta email. Max 10 email per chiamata.",
            {
                "emails": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista di email da verificare. Max 10 per chiamata.",
                },
            },
            ["emails"],
        ),
        _decl(
            "check_emails_leaklookup",
            "Verifica email contro Leak-Lookup. Budget: max_leaklookup_calls (conta per email). "
            "Complementare a HIBP. Max 10 email per chiamata.",
            {
                "emails": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista di email da verificare. Max 10 per chiamata.",
                },
            },
            ["emails"],
        ),
        # ── Google Dorking ────────────────────────────────────────────────────
        _decl(
            "search_linkedin_profiles",
            "Cerca profili LinkedIn di una persona via Google dorking. Budget: max_serper_calls.",
            {
                "name": {**_STR, "description": "Nome completo della persona"},
                "company": {**_STR, "description": "Nome azienda per restringere, può essere vuoto"},
                "city": {**_STR, "description": "Città per filtrare geograficamente, può essere vuoto"},
            },
            ["name"],
        ),
        _decl(
            "search_twitter_presence",
            "Cerca presenza Twitter/X di un'azienda o persona via Google dorking. Budget: max_serper_calls.",
            {
                "company": {**_STR, "description": "Nome azienda o persona"},
                "city": {**_STR, "description": "Città opzionale"},
            },
            ["company"],
        ),
        _decl(
            "search_instagram_profiles",
            "Cerca profili Instagram via Google dorking. Budget: max_serper_calls.",
            {
                "name": {**_STR, "description": "Nome persona o azienda"},
                "company": {**_STR, "description": "Nome azienda, può essere vuoto"},
                "city": {**_STR, "description": "Città opzionale"},
            },
            ["name"],
        ),
        _decl(
            "search_facebook_profiles",
            "Cerca pagine/profili Facebook via Google dorking. Budget: max_serper_calls.",
            {
                "name_or_company": {**_STR, "description": "Nome persona o azienda"},
                "city": {**_STR, "description": "Città opzionale"},
            },
            ["name_or_company"],
        ),
        _decl(
            "search_github_mentions",
            "Cerca codice, config o credenziali leakate su GitHub. Budget: max_serper_calls.",
            {
                "domain": {**_STR, "description": "Dominio target"},
                "company": {**_STR, "description": "Nome azienda, può essere vuoto"},
            },
            ["domain"],
        ),
        _decl(
            "search_pastebin_mentions",
            "Cerca leak su Pastebin che menzionano il dominio. Budget: max_serper_calls.",
            {"domain": {**_STR, "description": "Dominio target"}},
            ["domain"],
        ),
        _decl(
            "search_brand_documents",
            "Trova documenti sensibili (PDF, DOC, XLS) ospitati sul dominio o che vi fanno riferimento. "
            "Budget: max_serper_calls.",
            {
                "domain": {**_STR, "description": "Dominio target"},
                "company": {**_STR, "description": "Nome azienda, può essere vuoto"},
            },
            ["domain"],
        ),
        _decl(
            "search_piva_mentions",
            "Cerca menzioni esterne della P.IVA per trovare domini correlati. "
            "Chiamare solo se piva è nota. Budget: max_serper_calls.",
            {"piva": {**_STR, "description": "Numero P.IVA italiano (11 cifre)"}},
            ["piva"],
        ),
        _decl(
            "search_email_pattern_external",
            "Cerca indirizzi @dominio menzionati su siti esterni (non sul sito stesso). "
            "Budget: max_serper_calls.",
            {"domain": {**_STR, "description": "Dominio target"}},
            ["domain"],
        ),
        _decl(
            "search_by_query",
            "Esegue una query Google dork personalizzata via Serper. "
            "Usare per follow-up mirati non coperti dagli altri tool. Budget: max_serper_calls.",
            {
                "query": {**_STR, "description": "Query Google dork completa"},
                "context_tag": {**_STR, "description": "Etichetta breve per il log, es. 'piva_dork'"},
            },
            ["query"],
        ),
        # ── Registry & Personal OSINT ─────────────────────────────────────────
        _decl(
            "fetch_pec_email",
            "Cerca la PEC ufficiale dell'azienda o del titolare su inipec.gov.it. "
            "PEC = email legale certificata italiana, ottima per identificare contatto reale. "
            "Gratuito. Chiamare appena company_name o nome titolare è noto.",
            {
                "company_name": {**_STR, "description": "Nome commerciale o ragione sociale, può essere vuoto"},
                "city": {**_STR, "description": "Città per disambiguare, può essere vuoto"},
                "first_name": {**_STR, "description": "Nome del titolare/legale rappresentante, può essere vuoto"},
                "last_name": {**_STR, "description": "Cognome del titolare/legale rappresentante, può essere vuoto"},
            },
            [],
        ),
        _decl(
            "fetch_atoka_company",
            "Dati aziendali completi da Atoka.io: ATECO, sede legale, fatturato, soci, PEC, email, telefono. "
            "Richiede atoka budget > 0.",
            {
                "company_name": {**_STR, "description": "Nome commerciale o ragione sociale"},
                "city": {**_STR, "description": "Città per disambiguare, può essere vuoto"},
                "piva": {**_STR, "description": "P.IVA se nota, può essere vuoto"},
            },
            ["company_name"],
        ),
        _decl(
            "search_dehashed",
            "Cerca nel database breach DeHashed per username, email, nome o telefono. "
            "Ottimo per trovare email personale, telefono, password hash da nome titolare. "
            "query_type: 'username'|'email'|'name'|'phone'. Budget: max_dehashed_calls.",
            {
                "query": {**_STR, "description": "Valore da cercare (username, email, nome completo, telefono)"},
                "query_type": {**_STR, "description": "Tipo di campo: username | email | name | phone"},
            },
            ["query", "query_type"],
        ),
        _decl(
            "search_intelx",
            "Cerca su IntelX leaked databases. Supporta email, username, dominio, telefono. "
            "Complementare a DeHashed. Budget: max_intelx_calls.",
            {
                "query": {**_STR, "description": "Valore da cercare: email, username, dominio, numero di telefono"},
            },
            ["query"],
        ),
        _decl(
            "scrape_social_bio",
            "Scraping profilo pubblico Instagram o Facebook: estrae email, telefono, sito web, WhatsApp dalla bio. "
            "Gratuito. Chiamare su ogni profilo Instagram/Facebook trovato dai dork social.",
            {
                "url": {**_STR, "description": "URL completo del profilo (es. https://www.instagram.com/username/)"},
                "platform": {**_STR, "description": "Piattaforma: 'instagram' o 'facebook'"},
            },
            ["url", "platform"],
        ),
        _decl(
            "search_pagine_bianche",
            "Cerca telefono e indirizzo di una persona su paginebianche.it e paginegialle.it via Google dork. "
            "Molto efficace per titolari di PMI italiane. Budget: max_serper_calls.",
            {
                "name": {**_STR, "description": "Nome completo della persona"},
                "city": {**_STR, "description": "Città, può essere vuoto"},
            },
            ["name"],
        ),
        _decl(
            "search_username_leaks",
            "Cerca uno username derivato dal nome (es. sfontana) su Pastebin, GitHub, forum leak. "
            "Trova leak contenenti email personale o password. Budget: max_serper_calls.",
            {
                "username": {**_STR, "description": "Username da cercare (es. sfontana, samantha.fontana)"},
            },
            ["username"],
        ),
        _decl(
            "search_registry_dork",
            "Dork su fonti camerali italiane (registroimprese.it, impresainungiorno.gov.it, codicefiscale.net) "
            "per trovare CF, sede, ATECO, soci via Google. Budget: max_serper_calls.",
            {
                "company_name": {**_STR, "description": "Nome commerciale o ragione sociale"},
                "piva": {**_STR, "description": "P.IVA se nota, può essere vuoto"},
                "city": {**_STR, "description": "Città, può essere vuoto"},
            },
            ["company_name"],
        ),
        _decl(
            "search_person_advanced",
            "Dork avanzato per trovare email, telefono, indirizzo di una persona su tutti i siti pubblici. "
            "Cerca menzioni del nome con parole chiave contatto. Budget: max_serper_calls.",
            {
                "name": {**_STR, "description": "Nome completo della persona"},
                "city": {**_STR, "description": "Città, può essere vuoto"},
            },
            ["name"],
        ),
        # ── Terminal signal ───────────────────────────────────────────────────
        _decl(
            "finish_investigation",
            "Segnala che l'indagine è completa. Chiamare quando hai raccolto informazioni sufficienti "
            "o quando tutti i tool utili sono stati esauriti. Attiva la generazione del report finale.",
            {"reason": {**_STR, "description": "Spiegazione in italiano del perché l'indagine è completa"}},
            ["reason"],
        ),
    ]


def make_call_key(tool_name: str, args: dict) -> tuple:
    """Order-independent dedup key for seen_calls set."""
    flat = {k: str(v) for k, v in args.items()}
    return (tool_name, frozenset(flat.items()))
