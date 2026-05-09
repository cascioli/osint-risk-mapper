"""Agentic OSINT loop — OpenAI drives tool selection each iteration.

Drop-in replacement for loop.py when provider='openai'.
Uses gpt-4o-mini by default (very cheap, ~$0.15/1M input tokens).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import datetime

from openai import OpenAI, RateLimitError

from modules.agent.agent_state import AgentState
from modules.agent.budget_tracker import BudgetConfig, BudgetTracker
from modules.agent.context_builder import build_context_summary
from modules.agent.system_prompt import AGENT_SYSTEM_PROMPT
from modules.agent.tool_executor import execute_tool
from modules.agent.tool_registry import TOOL_SERVICE_MAP, get_tool_declarations, make_call_key
from modules.scan_context import ScanContext

LogFn = Callable[[str], None]
ProgressFn = Callable[[float], None]

_DEFAULT_MODEL = "gpt-4o-mini"
_FALLBACK_MODEL = "gpt-4o-mini"  # same — already cheapest; no fallback needed


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _noop_log(msg: str) -> None:
    pass


def _noop_progress(val: float) -> None:
    pass


def _declarations_to_openai_tools(declarations) -> list[dict]:
    """Convert Gemini FunctionDeclaration list → OpenAI tools format."""
    tools = []
    for decl in declarations:
        tools.append({
            "type": "function",
            "function": {
                "name": decl.name,
                "description": decl.description,
                "parameters": decl.parameters,
            },
        })
    return tools


def _openai_call(
    client: OpenAI,
    model: str,
    messages: list[dict],
    tools: list[dict],
    log_fn: LogFn,
) -> tuple[object, str]:
    """Call OpenAI with tool_choice='required'. Returns (message, model_used)."""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="required",
            temperature=0.1,
        )
        return response.choices[0].message, model
    except RateLimitError as exc:
        delay = 20.0
        log_fn(f"[{_ts()}] [agent/openai] Rate limit — attendo {delay:.0f}s poi riprovo")
        time.sleep(delay)
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="required",
            temperature=0.1,
        )
        return response.choices[0].message, model


def _run_final_phase(ctx: ScanContext, log_fn: LogFn, progress_fn: ProgressFn) -> None:
    from modules.graph_builder import build_graph_data
    from modules.unified_report import generate_unified_report

    log_fn(f"[{_ts()}] Final → Generazione report unificato...")
    progress_fn(0.88)

    ai_key = ctx.config.get("ai_key", "")
    ai_provider = ctx.config.get("provider", "gemini")

    if ai_provider == "openai" and ai_key:
        # Generate report via OpenAI
        try:
            openai_client = OpenAI(api_key=ai_key)
            prompt = _build_report_prompt(ctx)
            resp = openai_client.chat.completions.create(
                model=ctx.config.get("model_name", _DEFAULT_MODEL),
                messages=[
                    {"role": "system", "content": "Sei un analista OSINT esperto. Produci report professionali in italiano."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            ctx.unified_report = resp.choices[0].message.content
            log_fn(f"[{_ts()}] Final → Report OpenAI generato ({len(ctx.unified_report or '')} chars)")
        except Exception as exc:
            ctx.unified_report = None
            log_fn(f"[{_ts()}] ⚠️ Final → Report ERRORE: {exc}")
    elif ctx.config.get("gemini_key") or (ai_provider == "gemini" and ai_key):
        from modules.unified_report import generate_unified_report
        try:
            gemini_key = ctx.config.get("gemini_key") or ai_key
            ctx.unified_report = generate_unified_report(ctx, api_key=gemini_key)
            log_fn(f"[{_ts()}] Final → Report Gemini generato ({len(ctx.unified_report or '')} chars)")
        except Exception as exc:
            ctx.unified_report = None
            log_fn(f"[{_ts()}] ⚠️ Final → Report ERRORE: {exc}")
    else:
        log_fn(f"[{_ts()}] Final → AI key mancante, report skip")

    progress_fn(0.95)

    try:
        ctx.graph_data = build_graph_data(ctx)
        n_nodes = len((ctx.graph_data or {}).get("nodes", []))
        n_edges = len((ctx.graph_data or {}).get("edges", []))
        log_fn(f"[{_ts()}] Final → Grafo: {n_nodes} nodi, {n_edges} archi")
    except Exception as exc:
        log_fn(f"[{_ts()}] ⚠️ Final → Grafo ERRORE: {exc}")

    progress_fn(1.0)


def _build_report_prompt(ctx: ScanContext) -> str:
    """Build a concise OSINT summary prompt for the final report."""
    emails = ctx.emails[:20]
    people = list(dict.fromkeys(
        ctx.person_names + ctx.llm_suggested_people
        + [o.get("name", "") for o in ctx.company_officers]
    ))[:10]
    breached = [r.email for r in ctx.breach_results if r.hibp_breaches or r.leaklookup_sources]
    subs = list(dict.fromkeys(ctx.subdomains + ctx.vt_subdomains))[:15]

    return f"""Produci un report OSINT professionale in italiano per il target: {ctx.domain}

Dati raccolti:
- Azienda: {ctx.target_context.get("company_name", "sconosciuta")}
- Email trovate: {emails}
- Email compromesse in breach: {breached}
- Persone identificate: {people}
- Sottodomini: {subs}
- WHOIS registrante: {ctx.whois_data.get("registrant_name", "non trovato")}
- P.IVA: {ctx.piva or "non trovata"}
- Company officers: {[o.get("name") for o in ctx.company_officers[:5]]}
- Social dork results: {len(ctx.social_dork_results)} trovati
- Documenti esposti: {len(ctx.exposed_documents)} trovati
- Atoka data: {ctx.atoka_data}
- Iterazioni agente: {ctx.agent_iterations}

Struttura il report con sezioni: Sommario Esecutivo, Persone Chiave, Rischi Email/Breach, Infrastruttura, Social/Web Presence, Raccomandazioni."""


def run_openai_agent_loop(
    ctx: ScanContext,
    budget_config: BudgetConfig | None = None,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """OpenAI-powered agentic loop. Drop-in replacement for run_agent_loop."""
    state = AgentState(ctx=ctx)
    budget = BudgetTracker(budget_config or BudgetConfig())

    ai_key = ctx.config.get("ai_key", "")
    if not ai_key:
        log_fn(f"[{_ts()}] ⚠️ agent/openai: OPENAI_API_KEY mancante — skip agente")
        return ctx

    client = OpenAI(api_key=ai_key)
    declarations = get_tool_declarations()
    tools = _declarations_to_openai_tools(declarations)

    # OpenAI conversation: system + alternating user/assistant/tool messages
    messages: list[dict] = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
    ]

    max_iter = budget.config.max_iterations
    log_fn(f"[{_ts()}] [agent/openai] Avvio loop — modello {_DEFAULT_MODEL}, max {max_iter} iterazioni")
    progress_fn(0.03)

    while state.agent_iterations < max_iter:
        state.agent_iterations += 1
        pct = 0.03 + 0.82 * (state.agent_iterations / max_iter)
        progress_fn(min(pct, 0.85))

        if not budget.can_call("gemini"):
            log_fn(f"[{_ts()}] [agent/openai] Budget iterazioni esaurito — forzo finish")
            break

        # Inject updated context summary as user message each iteration
        context_summary = build_context_summary(
            ctx=state.ctx,
            budget=budget,
            tool_call_log=state.tool_call_log,
            iteration=state.agent_iterations,
        )
        # Only add a new user message if last message is not already a user/tool message
        # (OpenAI allows consecutive tool messages followed by a user message)
        if state.agent_iterations == 1:
            messages.append({"role": "user", "content": context_summary})
        # iterations 2+: last message is already a tool result (role=tool),
        # which OpenAI treats as part of assistant's turn — we need a user turn to continue
        elif messages and messages[-1].get("role") == "tool":
            messages.append({"role": "user", "content": f"[iter {state.agent_iterations}] Continua l'indagine. Scegli il prossimo tool."})

        try:
            message, model_used = _openai_call(client, _DEFAULT_MODEL, messages, tools, log_fn)
            budget.record("gemini")  # reuse gemini budget slot as "llm calls" counter
        except Exception as exc:
            log_fn(f"[{_ts()}] [agent/openai] Errore OpenAI: {exc}")
            break

        # Append assistant message to history
        messages.append(message)

        if not message.tool_calls:
            # No tool call (shouldn't happen with tool_choice='required')
            text = message.content or ""
            log_fn(f"[{_ts()}] [agent/openai] Risposta testo (no tool): {text[:100]}")
            state.agent_summary = text
            break

        # Process first tool call
        tc = message.tool_calls[0]
        tool_name = tc.function.name
        try:
            args = json.loads(tc.function.arguments)
        except json.JSONDecodeError:
            args = {}

        # Terminal signal
        if tool_name == "finish_investigation":
            reason = args.get("reason", "")
            state.agent_summary = reason
            log_fn(f"[{_ts()}] [agent/openai] FINE indagine: {reason}")
            # Feed tool result so conversation is valid
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps({"status": "ok", "reason": reason}),
            })
            break

        # Dedup check
        call_key = make_call_key(tool_name, args)
        if call_key in state.seen_calls:
            log_fn(f"[{_ts()}] [agent/openai] SKIP duplicato: {tool_name}({args})")
            state.tool_call_log.append({
                "iteration": state.agent_iterations,
                "tool": tool_name,
                "args": args,
                "result_summary": "",
                "duration_ms": 0,
                "skipped_reason": "duplicato",
            })
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": f"Tool {tool_name} con questi argomenti è già stato eseguito. Scegli azione diversa o chiama finish_investigation.",
            })
            continue

        state.seen_calls.add(call_key)

        # Budget check
        service = TOOL_SERVICE_MAP.get(tool_name)
        if service and not budget.can_call(service):
            log_fn(f"[{_ts()}] [agent/openai] Budget {service} esaurito — skip {tool_name}")
            state.tool_call_log.append({
                "iteration": state.agent_iterations,
                "tool": tool_name,
                "args": args,
                "result_summary": "",
                "duration_ms": 0,
                "skipped_reason": f"budget {service} esaurito",
            })
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": f"Budget per {service} esaurito. Scegli un tool diverso o chiama finish_investigation.",
            })
            continue

        # Execute tool
        t0 = time.monotonic()
        log_fn(f"[{_ts()}] [agent/openai] iter {state.agent_iterations}: {tool_name}({_fmt_args(args)})")
        result = execute_tool(tool_name, args, state, budget, log_fn)
        duration_ms = int((time.monotonic() - t0) * 1000)

        state.tool_call_log.append({
            "iteration": state.agent_iterations,
            "tool": tool_name,
            "args": args,
            "result_summary": result.get("summary", ""),
            "duration_ms": duration_ms,
            "skipped_reason": None,
        })

        enriched = {
            **result,
            "_budget": {s: budget.remaining(s) for s in ["gemini", "serper", "hibp", "hunter", "vt", "leaklookup", "opencorporates"]},
            "_stato": (
                f"emails={len(ctx.emails)} persone={len(ctx.person_names)} "
                f"breach_verificate={len(ctx.breach_results)} "
                f"sottodomini={len(ctx.subdomains) + len(ctx.vt_subdomains)} "
                f"iter_rimaste={budget.iterations_remaining(state.agent_iterations)}"
            ),
        }

        messages.append({
            "role": "tool",
            "tool_call_id": tc.id,
            "content": json.dumps(enriched, default=str),
        })

    log_fn(f"[{_ts()}] [agent/openai] Loop completato dopo {state.agent_iterations} iterazioni")
    log_fn(f"[{_ts()}] [agent/openai] Tool chiamati: {len(state.tool_call_log)}")

    ctx.agent_iterations = state.agent_iterations
    ctx.agent_tool_call_log = state.tool_call_log
    ctx.agent_summary = state.agent_summary

    _run_final_phase(ctx, log_fn, progress_fn)
    return ctx


def _fmt_args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        val = str(v)
        if len(val) > 40:
            val = val[:37] + "..."
        parts.append(f"{k}={val!r}")
    return ", ".join(parts)
