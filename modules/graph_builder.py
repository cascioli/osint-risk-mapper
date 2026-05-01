"""Connection graph builder and Plotly renderer for OSINT scan results."""

from __future__ import annotations

import math

import plotly.graph_objects as go

from modules.scan_context import ScanContext

_NODE_COLORS: dict[str, str] = {
    "domain":    "#00d4ff",
    "ip":        "#7b00ff",
    "subdomain": "#0080ff",
    "email":     "#ff8c00",
    "port":      "#ff006e",
    "breach":    "#ff0000",
    "document":  "#ffff00",
}

_NODE_SIZES: dict[str, int] = {
    "domain":    24,
    "ip":        18,
    "subdomain": 12,
    "email":     14,
    "port":       8,
    "breach":    12,
    "document":  10,
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

    # Primary IP
    if ctx.primary_ip:
        ip_id = f"ip:{ctx.primary_ip}"
        host = ctx.primary_host or {}
        add_node(ip_id, ctx.primary_ip, "ip", {
            "org": host.get("org", ""),
            "country": host.get("country", ""),
            "sources": host.get("sources_ok", []),
        })
        add_edge(domain_id, ip_id, "resolves_to")

        # Ports on primary IP
        for port_info in host.get("ports", {}).values():
            port_num = port_info.get("port", 0)
            svc = port_info.get("service") or port_info.get("product") or str(port_num)
            port_id = f"port:{ctx.primary_ip}:{port_num}"
            add_node(port_id, f":{port_num} {svc}", "port", {
                "vulns": port_info.get("vulns", [])[:3],
                "leaks": port_info.get("leaks", [])[:2],
            })
            add_edge(ip_id, port_id, "exposes_port")

    # Subdomains
    for result in ctx.subdomain_results:
        sub_id = f"subdomain:{result.subdomain}"
        add_node(sub_id, result.subdomain, "subdomain")
        add_edge(domain_id, sub_id, "has_subdomain")

        if result.ip:
            ip_id = f"ip:{result.ip}"
            host = result.merged_host or {}
            if result.merged_host:
                add_node(ip_id, result.ip, "ip", {
                    "org": host.get("org", ""),
                    "country": host.get("country", ""),
                    "sources": host.get("sources_ok", []),
                })
                add_edge(sub_id, ip_id, "resolves_to")

                for port_info in host.get("ports", {}).values():
                    port_num = port_info.get("port", 0)
                    svc = port_info.get("service") or port_info.get("product") or str(port_num)
                    port_id = f"port:{result.ip}:{port_num}"
                    add_node(port_id, f":{port_num} {svc}", "port", {
                        "vulns": port_info.get("vulns", [])[:3],
                        "leaks": port_info.get("leaks", [])[:2],
                    })
                    add_edge(ip_id, port_id, "exposes_port")
            else:
                # Same IP as another host — just link subdomain to existing IP node
                if ip_id in nodes:
                    add_edge(sub_id, ip_id, "resolves_to")

    # Emails and breaches
    for email, breach_sources in ctx.breach_data.items():
        email_id = f"email:{email}"
        add_node(email_id, email, "email")
        add_edge(domain_id, email_id, "has_email")

        for src in breach_sources:
            breach_id = f"breach:{src}"
            add_node(breach_id, src, "breach")
            add_edge(email_id, breach_id, "breached_in")

    # Email-IP correlations
    for corr in ctx.email_ip_correlations:
        email_id = f"email:{corr.email}"
        for ip in corr.correlated_ips:
            ip_id = f"ip:{ip}"
            if email_id in nodes and ip_id in nodes:
                add_edge(email_id, ip_id, "correlated_with", weight=0.5)

    # Exposed documents
    all_docs = ctx.exposed_documents + ctx.targeted_dork_results
    for i, doc in enumerate(all_docs[:20]):
        doc_id = f"document:{i}:{doc.get('url', '')[:40]}"
        title = (doc.get("title") or "Document")[:40]
        add_node(doc_id, title, "document", {"url": doc.get("url", "")})
        add_edge(domain_id, doc_id, "has_document")

    # Follow-up hosts from Round 3
    for host in ctx.follow_up_host_results:
        ip = host.get("ip", "")
        if not ip:
            continue
        ip_id = f"ip:{ip}"
        add_node(ip_id, ip, "ip", {
            "org": host.get("org", ""),
            "country": host.get("country", ""),
            "sources": host.get("sources_ok", []),
            "note": "Round 3 entity",
        })
        add_edge(domain_id, ip_id, "suggests", weight=0.5)

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
    type_order = ["domain", "ip", "subdomain", "email", "breach", "port", "document"]
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

    # Build edge traces
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

    # Build one scatter trace per node type for legend grouping
    type_order = ["domain", "ip", "subdomain", "email", "breach", "port", "document"]
    type_labels = {
        "domain": "Dominio",
        "ip": "IP",
        "subdomain": "Sottodominio",
        "email": "Email",
        "breach": "Breach",
        "port": "Porta/Servizio",
        "document": "Documento",
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
