"""OSINT Risk Mapper — entry point.

Passive Threat Intelligence tool for corporate domains. Person+data focused pipeline:
  Round 1 — web scrape, WHOIS, subdomains, email discovery, exposed docs
  Round 2 — breach check (HIBP + Leak-Lookup), social dork, GitHub/Pastebin dork
  Round 3 — LLM-guided: suggests additional people + queries, executes follow-ups
  Final   — unified cross-correlated report + connection graph

No active scanning — all data comes from pre-indexed public sources.

Usage:
    streamlit run app.py
"""

from __future__ import annotations

import io
import zipfile
from datetime import datetime

import pandas as pd
import streamlit as st

from modules.dashboard_map import generate_mock_province_data, render_heatmap
from modules.graph_builder import render_connection_graph
from modules.orchestrator import run_final, run_round1, run_round2, run_round3
from modules.scan_context import ScanContext
from utils.config import get_api_keys

_GEMINI_MODEL = "gemini-2.5-flash"
_MAX_SCANS_PER_SESSION = 5


# ── Sidebar ────────────────────────────────────────────────────────────────────

def _status(label: str, ok: bool) -> None:
    icon = "✅" if ok else "❌"
    st.markdown(f"{icon} {label}")


def _render_sidebar(env: dict[str, str]) -> dict:
    """Build sidebar with mode selector and feature status indicators."""
    with st.sidebar:
        st.header("🗺️ Modalità")
        mode = st.radio(
            "Seleziona modalità",
            ["Analisi Target", "Heatmap Territoriale"],
            label_visibility="collapsed",
        )
        st.markdown("---")

        st.header("⚙️ Stato Servizi")
        _status("Web Scraping (BeautifulSoup)", True)
        _status("WHOIS (python-whois)", True)
        _status("Subdomains crt.sh", True)
        _status("Subdomains (VirusTotal)", bool(env["VIRUSTOTAL_API_KEY"]))
        _status("Email Discovery (Hunter.io)", bool(env["HUNTER_API_KEY"]))
        _status("Breach Check (HIBP)", bool(env["HIBP_API_KEY"]))
        _status("Breach DB (Leak-Lookup)", bool(env["LEAKLOOKUP_API_KEY"]))
        _status("Google Dorking (Serper.dev)", bool(env["SERPER_API_KEY"]) or bool(env["SERPAPI_KEY"]))
        _status("AI Reports (Gemini)", bool(env["GEMINI_API_KEY"]))
        st.markdown("---")

        st.header("⚙️ Impostazioni Analisi")
        max_people = st.slider(
            "Max persone per social dork (Round 2)",
            min_value=1, max_value=10, value=5, step=1,
            key="max_people_dork",
            help="Numero massimo di persone identificate per cui eseguire il dork LinkedIn/Twitter.",
        )
        st.caption("Subdomain Enumeration (crt.sh) sempre attivo — nessuna key richiesta.")

    return {
        "mode": mode,
        "provider": "gemini",
        "model_name": _GEMINI_MODEL,
        "ai_key": env["GEMINI_API_KEY"],
        "hunter_key": env["HUNTER_API_KEY"],
        "leaklookup_key": env["LEAKLOOKUP_API_KEY"],
        "hibp_key": env["HIBP_API_KEY"],
        "vt_key": env["VIRUSTOTAL_API_KEY"],
        "serper_key": env["SERPER_API_KEY"],
        "serpapi_key": env["SERPAPI_KEY"],
        "max_people_dork": max_people,
    }


# ── Breach helpers ─────────────────────────────────────────────────────────────

def _build_breach_dataframe(ctx: ScanContext) -> pd.DataFrame:
    rows = []
    for result in ctx.breach_results:
        all_breaches = list(dict.fromkeys(result.hibp_breaches + result.leaklookup_sources))
        compromised = bool(all_breaches)
        rows.append({
            "Indirizzo Email": result.email,
            "Stato": "🔴 Compromessa" if compromised else "🟢 Non rilevata",
            "HIBP Breach": ", ".join(result.hibp_breaches) if result.hibp_breaches else "—",
            "Leak-Lookup": ", ".join(result.leaklookup_sources) if result.leaklookup_sources else "—",
            "_compromised": compromised,
        })
    return pd.DataFrame(rows)


def _render_breach_table(df: pd.DataFrame) -> None:
    display = df.drop(columns=["_compromised"])

    def colour_row(row: pd.Series) -> list[str]:
        bg = (
            "background-color: #ffd6d6"
            if df.loc[row.name, "_compromised"]
            else "background-color: #d6f5d6"
        )
        return [bg] * len(row)

    st.dataframe(
        display.style.apply(colour_row, axis=1).hide(axis="index"),
        width="stretch",
    )


def _render_idle_welcome() -> None:
    st.markdown("""
    #### Come usare OSINT Risk Mapper
    1. Inserisci un **dominio aziendale** nel campo sopra (es. `azienda.it`)
    2. Clicca **Analizza** — tutti i moduli vengono eseguiti automaticamente
    3. Monitora il progresso in tempo reale tramite la barra e il log terminale
    4. Al termine, esplora i risultati per sezione e scarica i report

    | Modulo | Fonte | Round |
    |--------|-------|-------|
    | Web Scraping (contatti, social, tech) | BeautifulSoup | 1 |
    | WHOIS (registrante, org, date) | python-whois | 1 |
    | Subdomain Enum | crt.sh + VirusTotal | 1 |
    | Email Discovery | Hunter.io + scraping | 1 |
    | Documenti esposti | Google Dorking | 1 |
    | Breach Check Email | HIBP + Leak-Lookup | 2 |
    | Social Dork (LinkedIn, Twitter) | Google Dorking | 2 |
    | GitHub + Pastebin Dork | Google Dorking | 2 |
    | LLM Entity Extraction | Gemini | 3 |
    | Unified Report + Graph | Gemini | Final |
    """)


def _render_running_phase(config: dict, domain: str) -> None:
    ctx = ScanContext(domain=domain, config=config)
    st.session_state.scan_log = []
    LOG_MAX = 40

    progress_bar = st.progress(0.0, text="Avvio analisi...")
    log_placeholder = st.empty()

    def log_fn(msg: str) -> None:
        st.session_state.scan_log.append(msg)
        lines = "\n".join(st.session_state.scan_log[-LOG_MAX:])
        log_placeholder.markdown(f"```\n{lines}\n```")

    def progress_fn(val: float) -> None:
        progress_bar.progress(val, text=f"Analisi in corso... {int(val * 100)}%")

    max_people = config.get("max_people_dork", 5)
    ctx = run_round1(ctx, log_fn=log_fn, progress_fn=progress_fn)
    ctx = run_round2(ctx, max_people=max_people, log_fn=log_fn, progress_fn=progress_fn)
    ctx = run_round3(ctx, log_fn=log_fn, progress_fn=progress_fn)
    ctx = run_final(ctx, log_fn=log_fn, progress_fn=progress_fn)

    st.session_state.scan_ctx = ctx
    st.session_state.scan_phase = "final"
    st.rerun()


def _build_csv_zip(ctx: ScanContext) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        if ctx.emails:
            zf.writestr("emails.csv", pd.DataFrame({"email": ctx.emails}).to_csv(index=False))

        if ctx.person_names or ctx.llm_suggested_people:
            all_people = list(dict.fromkeys(
                ctx.person_names + ctx.llm_suggested_people
                + [pp.name for pp in ctx.person_profiles]
            ))
            zf.writestr("people.csv", pd.DataFrame({"name": all_people}).to_csv(index=False))

        if ctx.breach_results:
            rows = [
                {
                    "email": r.email,
                    "hibp_breaches": "; ".join(r.hibp_breaches),
                    "leaklookup_sources": "; ".join(r.leaklookup_sources),
                    "compromessa": bool(r.hibp_breaches or r.leaklookup_sources),
                }
                for r in ctx.breach_results
            ]
            zf.writestr("breaches.csv", pd.DataFrame(rows).to_csv(index=False))

        all_social = (
            [{"platform": p.platform, "url": p.url, "source": p.source} for p in ctx.social_profiles]
            + ctx.social_dork_results
        )
        if all_social:
            zf.writestr("social.csv", pd.DataFrame(all_social).to_csv(index=False))

        all_subs = list(dict.fromkeys(ctx.subdomains + ctx.vt_subdomains))
        if all_subs:
            zf.writestr("subdomains.csv", pd.DataFrame({"subdomain": all_subs}).to_csv(index=False))

        all_docs = ctx.exposed_documents + ctx.brand_dork_results + ctx.llm_followup_results
        if all_docs:
            zf.writestr("documents.csv", pd.DataFrame(all_docs).to_csv(index=False))

        if ctx.whois_data:
            zf.writestr("whois.csv", pd.DataFrame([ctx.whois_data]).to_csv(index=False))

    return buf.getvalue()


def _build_report_md(ctx: ScanContext) -> str:
    all_people = list(dict.fromkeys(
        ctx.person_names + ctx.llm_suggested_people
        + [pp.name for pp in ctx.person_profiles]
    ))
    n_breached = sum(1 for r in ctx.breach_results if r.hibp_breaches or r.leaklookup_sources)
    all_docs = ctx.exposed_documents + ctx.brand_dork_results + ctx.llm_followup_results

    lines = [
        f"# OSINT Risk Mapper — {ctx.domain}",
        f"Generato: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Riepilogo",
        f"- Persone identificate: {len(all_people)}",
        f"- Email trovate: {len(ctx.emails)}",
        f"- Email compromesse: {n_breached}",
        f"- Profili social: {len(ctx.social_profiles) + len(ctx.social_dork_results)}",
        f"- Sottodomini: {len(ctx.subdomains) + len(ctx.vt_subdomains)}",
        f"- Documenti esposti: {len(all_docs)}",
        f"- Entità Round 3: {len(ctx.person_profiles)}",
        "",
    ]
    if ctx.unified_report:
        lines += ["---", "", ctx.unified_report]
    return "\n".join(lines)


def _render_final_phase(ctx: ScanContext) -> None:
    st.success(f"✅ Analisi completata per **{ctx.domain}**")

    all_people = list(dict.fromkeys(
        ctx.person_names + ctx.llm_suggested_people
        + [pp.name for pp in ctx.person_profiles]
    ))
    n_breached = sum(1 for r in ctx.breach_results if r.hibp_breaches or r.leaklookup_sources)
    n_social = len(ctx.social_profiles) + len(ctx.social_dork_results)
    all_subs = list(dict.fromkeys(ctx.subdomains + ctx.vt_subdomains))

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Sottodomini", len(all_subs))
    c2.metric("Email", len(ctx.emails))
    c3.metric("Persone", len(all_people))
    c4.metric("Breach", n_breached)
    c5.metric("Profili Social", n_social)

    date_str = datetime.now().strftime("%Y%m%d_%H%M")
    col_csv, col_md = st.columns(2)
    with col_csv:
        st.download_button(
            "⬇️ Scarica CSV (ZIP)", data=_build_csv_zip(ctx),
            file_name=f"osint_{ctx.domain}_{date_str}.zip",
            mime="application/zip", use_container_width=True,
        )
    with col_md:
        st.download_button(
            "⬇️ Scarica Report (Markdown)", data=_build_report_md(ctx),
            file_name=f"osint_report_{ctx.domain}_{date_str}.md",
            mime="text/markdown", use_container_width=True,
        )

    st.divider()

    with st.expander("📋 Report Unificato AI", expanded=True):
        if ctx.unified_report:
            st.markdown(ctx.unified_report)
        else:
            st.warning("Report non disponibile — Gemini API Key mancante.")

    with st.expander("🕸️ Grafo Connessioni", expanded=True):
        if ctx.graph_data:
            fig = render_connection_graph(ctx.graph_data)
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "🔵 Dominio · 🟠 Persona · 🟡 Email · 🔴 Breach · 🟢 Profilo Social · "
                "🟡 Documento · 🔷 Sottodominio"
            )
        else:
            st.info("Grafo non disponibile.")

    with st.expander("👥 Persone Identificate", expanded=bool(all_people)):
        if all_people:
            st.dataframe(
                pd.DataFrame({"Nome": all_people}).style.hide(axis="index"),
                use_container_width=True,
            )
            scraping_contacts = ctx.scraped_contacts
            if scraping_contacts.get("phones"):
                st.markdown("**Telefoni trovati:**")
                for phone in scraping_contacts["phones"]:
                    st.code(phone)
            if scraping_contacts.get("tech_hints"):
                st.markdown(f"**Tecnologie rilevate:** {', '.join(scraping_contacts['tech_hints'])}")
        else:
            st.info("Nessuna persona identificata.")

    with st.expander("🌐 WHOIS", expanded=bool(ctx.whois_data)):
        if ctx.whois_data:
            clean = {k: v for k, v in ctx.whois_data.items() if v}
            st.json(clean)
        else:
            st.info("Dati WHOIS non disponibili.")

    with st.expander("📧 Email Breach", expanded=bool(ctx.breach_results)):
        if ctx.breach_results:
            df = _build_breach_dataframe(ctx)
            _render_breach_table(df)
        else:
            st.info("Nessun dato email disponibile.")

    with st.expander("🔗 Profili Social Trovati", expanded=bool(n_social)):
        scraped_rows = [
            {"Piattaforma": p.platform, "URL": p.url, "Fonte": p.source}
            for p in ctx.social_profiles
        ]
        dork_rows = [
            {"Piattaforma": "dork", "URL": d.get("url", ""), "Titolo": d.get("title", ""), "Fonte": "dork"}
            for d in ctx.social_dork_results
        ]
        all_rows = scraped_rows + dork_rows
        if all_rows:
            st.dataframe(pd.DataFrame(all_rows).style.hide(axis="index"), use_container_width=True)
        else:
            st.info("Nessun profilo social trovato.")

    all_docs = ctx.exposed_documents + ctx.brand_dork_results + ctx.llm_followup_results
    with st.expander("📄 Documenti e Menzioni Web", expanded=bool(all_docs)):
        if all_docs:
            df = pd.DataFrame(all_docs).rename(columns={"title": "Titolo", "url": "URL"})
            st.dataframe(df.style.hide(axis="index"), use_container_width=True)
        else:
            st.info("Nessun documento o menzione trovata.")

    with st.expander("🔗 Subdomain Enumeration", expanded=False):
        if all_subs:
            st.dataframe(
                pd.DataFrame({"Sottodominio": all_subs}).style.hide(axis="index"),
                use_container_width=True,
            )
        else:
            st.info("Nessun sottodominio trovato.")

    with st.expander(
        "🤖 Persone e Query Suggerite (Round 3)",
        expanded=bool(ctx.llm_suggested_people or ctx.llm_suggested_queries),
    ):
        col_p, col_q = st.columns(2)
        with col_p:
            st.markdown("**Persone suggerite da Gemini:**")
            for name in ctx.llm_suggested_people:
                st.code(name)
        with col_q:
            st.markdown("**Query dork suggerite:**")
            for q in ctx.llm_suggested_queries:
                st.code(q)
        if ctx.person_profiles:
            st.markdown("**Profili investigati Round 3:**")
            for pp in ctx.person_profiles:
                st.markdown(f"- **{pp.name}**: {len(pp.linkedin_results)} LinkedIn, {len(pp.twitter_results)} Twitter")

    with st.expander("📟 Log di Esecuzione", expanded=False):
        st.code("\n".join(st.session_state.get("scan_log", [])), language=None)


# ── Heatmap page ───────────────────────────────────────────────────────────────

_CYBER_CSS = """
<style>
.stApp { background-color: #050d1a !important; }
.cyber-title {
    font-family: monospace; color: #00d4ff;
    text-shadow: 0 0 12px rgba(0,212,255,0.4);
    font-size: 1.6rem; font-weight: bold;
    border-bottom: 1px solid rgba(0,212,255,0.25);
    padding-bottom: 8px; margin-bottom: 16px;
}
.cyber-banner {
    font-family: monospace; color: #00d4ff;
    background: #0a1628;
    border: 1px solid rgba(0,212,255,0.25);
    border-left: 3px solid #00d4ff;
    padding: 10px 16px; font-size: 0.82rem;
    margin-bottom: 20px; line-height: 1.6;
}
.kpi-card {
    background: #0a1628;
    border: 1px solid rgba(0,212,255,0.2);
    border-top: 2px solid #00d4ff;
    padding: 18px 12px; text-align: center;
    font-family: monospace;
}
.kpi-value {
    color: #00d4ff; font-size: 2rem; font-weight: bold;
    text-shadow: 0 0 10px rgba(0,212,255,0.5);
    line-height: 1.1;
}
.kpi-label {
    color: rgba(0,212,255,0.55); font-size: 0.65rem;
    letter-spacing: 2px; margin-top: 6px;
}
.cyber-section {
    font-family: monospace; color: #00d4ff;
    font-size: 0.9rem; letter-spacing: 1px;
    border-bottom: 1px solid rgba(0,212,255,0.15);
    padding-bottom: 4px; margin: 20px 0 10px;
}
[data-testid="stDataFrame"] {
    border: 1px solid rgba(0,212,255,0.2) !important;
}
</style>
"""


def _kpi_card(value: str, label: str) -> str:
    return (
        f'<div class="kpi-card">'
        f'<div class="kpi-value">{value}</div>'
        f'<div class="kpi-label">{label}</div>'
        f'</div>'
    )


def _render_heatmap_page() -> None:
    st.markdown(_CYBER_CSS, unsafe_allow_html=True)

    st.markdown(
        '<div class="cyber-title">&gt; RISK_MAP :: PROVINCIA DI FOGGIA</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="cyber-banner">'
        "// GDPR COMPLIANCE — i dati sono aggregati a livello comunale.<br>"
        "// Nessuna informazione identificativa delle singole aziende è esposta.<br>"
        "// Fonte: dati simulati a scopo dimostrativo."
        "</div>",
        unsafe_allow_html=True,
    )

    df = generate_mock_province_data()
    tot_pmi = int(df["PMI_Analizzate"].sum())
    tot_vuln = int(df["Vulnerabilita_Critiche"].sum())
    top_comune = df.loc[df["Rischio_Medio"].idxmax(), "Comune"].upper()
    avg_risk = round(float(df["Rischio_Medio"].mean()), 1)

    k1, k2, k3, k4 = st.columns(4)
    k1.markdown(_kpi_card(str(tot_pmi), "PMI ANALIZZATE"), unsafe_allow_html=True)
    k2.markdown(_kpi_card(str(tot_vuln), "VULN CRITICHE"), unsafe_allow_html=True)
    k3.markdown(_kpi_card(top_comune, "TOP RISK"), unsafe_allow_html=True)
    k4.markdown(_kpi_card(str(avg_risk), "RISCHIO MEDIO"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    with st.spinner("// loading geo-data..."):
        fig = render_heatmap()

    if fig is None:
        st.error(
            "❌ Impossibile caricare il GeoJSON remoto. "
            "Verifica la connessione internet e riprova."
        )
    else:
        st.plotly_chart(fig, use_container_width=True)

    st.markdown(
        '<div class="cyber-section">&gt; DATA_TABLE :: COMUNI</div>',
        unsafe_allow_html=True,
    )
    st.dataframe(df, width="stretch", hide_index=True)


# ── Analysis page ───────────────────────────────────────────────────────────────

def _render_analysis_page(config: dict) -> None:
    st.title("🔍 OSINT Risk Mapper")
    st.caption("Threat Intelligence passiva · Person+Data OSINT per domini aziendali")
    st.markdown("---")
    st.info(
        "⚠️ **Strumento OSINT passivo** — interroga esclusivamente database pubblici e "
        "API di terze parti. Nessuna connessione diretta al target. "
        "Utilizzare solo su domini per cui si dispone di autorizzazione esplicita."
    )
    st.markdown("---")

    for key, default in [
        ("scan_count", 0), ("scan_phase", "idle"),
        ("scan_ctx", None), ("scan_log", []), ("scan_domain", ""),
    ]:
        if key not in st.session_state:
            st.session_state[key] = default

    phase = st.session_state.scan_phase

    if phase in ("idle", "final"):
        col_input, col_btn = st.columns([4, 1])
        with col_input:
            domain: str = st.text_input(
                "Dominio target",
                placeholder="es: azienda.it",
                help="Nome a dominio da analizzare (senza http://)",
                label_visibility="collapsed",
                key="domain_input",
            )
        with col_btn:
            analyze_btn = st.button("🔍 Analizza", use_container_width=True, type="primary")
        if st.session_state.scan_count > 0:
            st.caption(f"Analisi questa sessione: {st.session_state.scan_count}/{_MAX_SCANS_PER_SESSION}")

        if analyze_btn:
            if st.session_state.scan_count >= _MAX_SCANS_PER_SESSION:
                st.warning(
                    f"⚠️ Limite di {_MAX_SCANS_PER_SESSION} analisi per sessione raggiunto. "
                    "Ricarica la pagina per continuare."
                )
                st.stop()
            domain_clean = (
                domain.strip().lower()
                .removeprefix("https://")
                .removeprefix("http://")
                .rstrip("/")
            )
            if not domain_clean:
                st.error("❌ Inserisci un nome a dominio prima di procedere.")
                return
            st.session_state.scan_phase = "running"
            st.session_state.scan_ctx = None
            st.session_state.scan_log = []
            st.session_state.scan_domain = domain_clean
            st.session_state.scan_count += 1
            st.rerun()

    if phase == "idle":
        _render_idle_welcome()
        return

    if phase == "running":
        target = st.session_state.scan_domain
        st.markdown(f"**Analisi in corso per:** `{target}`")
        _render_running_phase(config, target)
        return

    if phase == "final":
        ctx = st.session_state.scan_ctx
        if ctx is None:
            st.session_state.scan_phase = "idle"
            st.rerun()
            return
        if st.button("🔄 Nuova Analisi"):
            st.session_state.scan_phase = "idle"
            st.session_state.scan_ctx = None
            st.session_state.scan_domain = ""
            st.rerun()
        _render_final_phase(ctx)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    st.set_page_config(
        page_title="OSINT Risk Mapper",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    env = get_api_keys()
    config = _render_sidebar(env)

    if config["mode"] == "Heatmap Territoriale":
        _render_heatmap_page()
    else:
        _render_analysis_page(config)


if __name__ == "__main__":
    main()
