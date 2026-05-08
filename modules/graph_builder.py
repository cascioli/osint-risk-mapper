"""Connection graph builder and Plotly renderer for OSINT scan results — person+data model."""

from __future__ import annotations

import math

import plotly.graph_objects as go

from modules.scan_context import ScanContext

_NODE_COLORS: dict[str, str] = {
    "domain":    "#00d4ff",
    "person":    "#ff8c00",
    "subdomain": "#0080ff",
    "email":     "#ffaa00",
    "breach":    "#ff0000",
    "document":  "#ffff00",
    "social":    "#00ff88",
}

_NODE_SIZES: dict[str, int] = {
    "domain":    24,
    "person":    18,
    "subdomain": 10,
    "email":     14,
    "breach":    12,
    "document":  10,
    "social":    12,
}


def build_graph_data(ctx: ScanContext) -> dict:
    """Build node/edge data from a completed ScanContext."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, label: str, node_type: str, metadata: dict | None = None) -> None:
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "color": _NODE_COLORS.get(node_type, "#aaaaaa"),
                "size": _NODE_SIZES.get(node_type, 10),
                "metadata": metadata or {},
            }

    def add_edge(src: str, dst: str, relationship: str, weight: float = 1.0) -> None:
        edges.append({"source": src, "target": dst, "relationship": relationship, "weight": weight})

    # Root domain
    domain_id = f"domain:{ctx.domain}"
    add_node(domain_id, ctx.domain, "domain")

    # People (from scraping, WHOIS, Round 3)
    all_people = list(dict.fromkeys(
        ctx.person_names + ctx.llm_suggested_people
        + [pp.name for pp in ctx.person_profiles]
    ))
    for name in all_people:
        person_id = f"person:{name}"
        add_node(person_id, name, "person")
        add_edge(domain_id, person_id, "has_person")

    # Emails and breaches
    for result in ctx.breach_results:
        email_id = f"email:{result.email}"
        add_node(email_id, result.email, "email")
        add_edge(domain_id, email_id, "has_email")

        for breach in dict.fromkeys(result.hibp_breaches + result.leaklookup_sources):
            breach_id = f"breach:{breach}"
            add_node(breach_id, breach, "breach")
            add_edge(email_id, breach_id, "breached_in")

    # Emails without breach data (just discovered)
    for email in ctx.emails:
        email_id = f"email:{email}"
        if email_id not in nodes:
            add_node(email_id, email, "email")
            add_edge(domain_id, email_id, "has_email")

    # Social profiles (scraped)
    for sp in ctx.social_profiles:
        soc_id = f"social:scraped:{sp.platform}:{sp.url[:40]}"
        label = f"{sp.platform}: {sp.url[sp.url.rfind('/')+1:][:25] or sp.platform}"
        add_node(soc_id, label, "social", {"url": sp.url, "platform": sp.platform})
        add_edge(domain_id, soc_id, "has_social")

    # Person profiles with their social dork results (Round 3)
    for pp in ctx.person_profiles:
        person_id = f"person:{pp.name}"
        if person_id not in nodes:
            add_node(person_id, pp.name, "person")
            add_edge(domain_id, person_id, "has_person")
        for item in (pp.linkedin_results + pp.twitter_results)[:5]:
            url = item.get("url", "")
            soc_id = f"social:dork:{url[:40]}"
            add_node(soc_id, item.get("title", "Profile")[:30], "social", {"url": url})
            add_edge(person_id, soc_id, "found_on")

    # Documents (exposed + brand dork + follow-up)
    all_docs = ctx.exposed_documents + ctx.brand_dork_results + ctx.llm_followup_results
    for i, doc in enumerate(all_docs[:25]):
        doc_id = f"document:{i}:{doc.get('url', '')[:40]}"
        title = (doc.get("title") or "Document")[:40]
        add_node(doc_id, title, "document", {"url": doc.get("url", "")})
        add_edge(domain_id, doc_id, "has_document")

    # Subdomains
    all_subs = list(dict.fromkeys(ctx.subdomains + ctx.vt_subdomains))
    for sub in all_subs[:30]:
        sub_id = f"subdomain:{sub}"
        add_node(sub_id, sub, "subdomain")
        add_edge(domain_id, sub_id, "has_subdomain")

    return {"nodes": list(nodes.values()), "edges": edges}


def _compute_layout(nodes: list[dict], edges: list[dict]) -> dict[str, tuple[float, float]]:
    """Compute node positions. Try networkx spring layout, fall back to circular by type."""
    try:
        import networkx as nx

        G = nx.Graph()
        for node in nodes:
            G.add_node(node["id"])
        for edge in edges:
            G.add_edge(edge["source"], edge["target"])

        pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)
        return {node_id: (float(x), float(y)) for node_id, (x, y) in pos.items()}

    except ImportError:
        pass

    # Fallback: circular layout grouped by node type
    type_order = ["domain", "person", "email", "breach", "social", "document", "subdomain"]
    grouped: dict[str, list[str]] = {t: [] for t in type_order}
    for node in nodes:
        grouped.setdefault(node["type"], []).append(node["id"])

    positions: dict[str, tuple[float, float]] = {}
    radius = 1.0
    for ring_idx, node_type in enumerate(type_order):
        group = grouped.get(node_type, [])
        if not group:
            continue
        r = radius * (ring_idx + 1)
        for i, node_id in enumerate(group):
            angle = 2 * math.pi * i / max(len(group), 1)
            positions[node_id] = (r * math.cos(angle), r * math.sin(angle))

    return positions


def render_connection_graph(graph_data: dict) -> go.Figure:
    """Render an interactive Plotly network graph from build_graph_data output."""
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes:
        fig = go.Figure()
        fig.update_layout(
            title="Nessun dato da visualizzare",
            paper_bgcolor="#050d1a",
            plot_bgcolor="#050d1a",
            font_color="#00d4ff",
        )
        return fig

    positions = _compute_layout(nodes, edges)

    # Edge traces
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for edge in edges:
        src_pos = positions.get(edge["source"])
        dst_pos = positions.get(edge["target"])
        if not src_pos or not dst_pos:
            continue
        edge_x += [src_pos[0], dst_pos[0], None]
        edge_y += [src_pos[1], dst_pos[1], None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=0.8, color="rgba(0,212,255,0.2)"),
        hoverinfo="none",
        showlegend=False,
    )

    type_order = ["domain", "person", "email", "breach", "social", "document", "subdomain"]
    type_labels = {
        "domain":    "Dominio",
        "person":    "Persona",
        "email":     "Email",
        "breach":    "Breach",
        "social":    "Profilo Social",
        "document":  "Documento",
        "subdomain": "Sottodominio",
    }

    grouped: dict[str, list[dict]] = {t: [] for t in type_order}
    for node in nodes:
        grouped.setdefault(node["type"], []).append(node)

    node_traces: list[go.Scatter] = []
    for node_type in type_order:
        group = grouped.get(node_type, [])
        if not group:
            continue

        xs = [positions.get(n["id"], (0, 0))[0] for n in group]
        ys = [positions.get(n["id"], (0, 0))[1] for n in group]
        texts = [n["label"] for n in group]
        hovers = []
        for n in group:
            meta = n.get("metadata", {})
            hover_parts = [f"<b>{n['label']}</b>", f"Tipo: {n['type']}"]
            for k, v in meta.items():
                if v:
                    hover_parts.append(f"{k}: {v}")
            hovers.append("<br>".join(hover_parts))

        color = _NODE_COLORS.get(node_type, "#aaaaaa")
        size = _NODE_SIZES.get(node_type, 10)

        node_traces.append(go.Scatter(
            x=xs, y=ys,
            mode="markers+text",
            name=type_labels.get(node_type, node_type),
            text=texts,
            textposition="top center",
            textfont=dict(size=9, color=color),
            hovertext=hovers,
            hoverinfo="text",
            marker=dict(
                size=size,
                color=color,
                line=dict(width=1, color="rgba(0,0,0,0.5)"),
                opacity=0.9,
            ),
        ))

    fig = go.Figure(data=[edge_trace] + node_traces)
    fig.update_layout(
        title=dict(
            text="🕸️ Grafo delle Connessioni OSINT",
            font=dict(family="monospace", size=16, color="#00d4ff"),
        ),
        paper_bgcolor="#050d1a",
        plot_bgcolor="#050d1a",
        font=dict(color="#00d4ff"),
        showlegend=True,
        legend=dict(
            bgcolor="rgba(10,22,40,0.8)",
            bordercolor="rgba(0,212,255,0.3)",
            borderwidth=1,
            font=dict(color="#00d4ff", size=10),
        ),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        hovermode="closest",
        margin=dict(l=20, r=20, t=60, b=20),
        height=650,
    )

    return fig
