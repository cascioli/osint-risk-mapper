"""Agentic OSINT loop — Gemini drives tool selection each iteration."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import datetime

from google import genai
from google.genai import types as genai_types

from modules.agent.agent_state import AgentState
from modules.agent.budget_tracker import BudgetConfig, BudgetTracker
from modules.agent.context_builder import build_context_summary
from modules.agent.system_prompt import AGENT_SYSTEM_PROMPT
from modules.agent.tool_executor import execute_tool
from modules.agent.tool_registry import TOOL_SERVICE_MAP, get_tool_declarations, make_call_key
from modules.scan_context import ScanContext
from modules.token_logger import log_llm_call

LogFn = Callable[[str], None]
ProgressFn = Callable[[float], None]

_FALLBACK_MODEL = "gemini-2.5-flash-lite"


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _noop_log(msg: str) -> None:
    pass


def _is_rate_limit(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "resource_exhausted" in msg


def _extract_retry_delay(exc: Exception, default: float = 20.0) -> float:
    """Parse retryDelay seconds from Gemini 429 error body, add 2s buffer."""
    msg = str(exc)
    for pattern in [r"retryDelay.*?(\d+(?:\.\d+)?)s", r"retry in ([\d.]+)s"]:
        m = re.search(pattern, msg, re.IGNORECASE)
        if m:
            return float(m.group(1)) + 2.0
    return default


def _gemini_call(
    client: genai.Client,
    model: str,
    contents: list,
    config: genai_types.GenerateContentConfig,
    log_fn: LogFn,
) -> tuple[genai_types.GenerateContentResponse, str]:
    """
    Call Gemini with automatic fallback to _FALLBACK_MODEL on rate limit (429).
    Returns (response, model_used).
    Raises on non-rate-limit errors or if fallback also fails.
    """
    try:
        return client.models.generate_content(model=model, contents=contents, config=config), model
    except Exception as exc:
        if not _is_rate_limit(exc):
            raise
        delay = _extract_retry_delay(exc)
        log_fn(f"[{_ts()}] [agent] Rate limit 429 — attendo {delay:.0f}s poi fallback a {_FALLBACK_MODEL}")
        time.sleep(delay)
        response = client.models.generate_content(model=_FALLBACK_MODEL, contents=contents, config=config)
        return response, _FALLBACK_MODEL


def _noop_progress(val: float) -> None:
    pass


def _run_final_phase(ctx: ScanContext, log_fn: LogFn, progress_fn: ProgressFn) -> None:
    from modules.graph_builder import build_graph_data
    from modules.unified_report import generate_unified_report

    log_fn(f"[{_ts()}] Final → Generazione report unificato Gemini...")
    progress_fn(0.88)

    if ctx.config.get("ai_key"):
        primary_model = ctx.config.get("model_name", "gemini-2.5-flash")
        for attempt_model in [primary_model, _FALLBACK_MODEL]:
            try:
                ctx.unified_report = generate_unified_report(
                    ctx,
                    api_key=ctx.config["ai_key"],
                    model_name=attempt_model,
                )
                log_fn(f"[{_ts()}] Final → Report generato con {attempt_model} ({len(ctx.unified_report or '')} chars)")
                break
            except RuntimeError as exc:
                if _is_rate_limit(exc) and attempt_model == primary_model:
                    delay = _extract_retry_delay(exc)
                    log_fn(f"[{_ts()}] Final → Rate limit — attendo {delay:.0f}s poi fallback a {_FALLBACK_MODEL}")
                    time.sleep(delay)
                else:
                    ctx.unified_report = None
                    log_fn(f"[{_ts()}] ⚠️ Final → Report ERRORE: {exc}")
                    break
    else:
        log_fn(f"[{_ts()}] Final → Gemini key mancante, report skip")

    progress_fn(0.95)

    try:
        ctx.graph_data = build_graph_data(ctx)
        n_nodes = len((ctx.graph_data or {}).get("nodes", []))
        n_edges = len((ctx.graph_data or {}).get("edges", []))
        log_fn(f"[{_ts()}] Final → Grafo: {n_nodes} nodi, {n_edges} archi")
    except Exception as exc:
        log_fn(f"[{_ts()}] ⚠️ Final → Grafo ERRORE: {exc}")

    progress_fn(1.0)


def run_agent_loop(
    ctx: ScanContext,
    budget_config: BudgetConfig | None = None,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """
    Agentic replacement for run_round1..run_final.
    Returns the completed ScanContext — compatible with _render_final_phase.
    """
    state = AgentState(ctx=ctx)
    budget = BudgetTracker(budget_config or BudgetConfig())

    ai_key = ctx.config.get("ai_key", "")
    if not ai_key:
        log_fn(f"[{_ts()}] ⚠️ agent: GEMINI_API_KEY mancante — skip agente")
        return ctx

    # Seed known contact email before first iteration so agent breach-checks it
    _contact_email = ctx.target_context.get("contact_email", "").strip().lower()
    if _contact_email and _contact_email not in ctx.emails:
        ctx.emails.append(_contact_email)
        log_fn(f"[{_ts()}] [agent] Email input seedata: {_contact_email}")

    client = genai.Client(api_key=ai_key)
    declarations = get_tool_declarations()
    tool = genai_types.Tool(function_declarations=declarations)
    gen_config = genai_types.GenerateContentConfig(
        tools=[tool],
        tool_config=genai_types.ToolConfig(
            function_calling_config=genai_types.FunctionCallingConfig(mode="ANY"),
        ),
        temperature=0.1,
        system_instruction=AGENT_SYSTEM_PROMPT,
    )

    # Gemini requires: user → model → user → model → ...
    # The initial context summary is the only explicit user turn.
    # Subsequent iterations rely on the history (which ends with a function_response
    # user turn after each tool call), so no extra user turn is ever prepended.
    history: list[genai_types.Content] = []
    max_iter = budget.config.max_iterations
    log_fn(f"[{_ts()}] [agent] Avvio loop agentico — max {max_iter} iterazioni")
    progress_fn(0.03)

    while state.agent_iterations < max_iter:
        state.agent_iterations += 1
        pct = 0.03 + 0.82 * (state.agent_iterations / max_iter)
        progress_fn(min(pct, 0.85))

        if not budget.can_call("gemini"):
            log_fn(f"[{_ts()}] [agent] Budget Gemini esaurito — forzo finish")
            break

        # First iteration: seed history with the initial context summary (user turn).
        # Subsequent iterations: history already ends with a function_response (user turn)
        # from the previous tool call — appending another user turn would violate the
        # Gemini turn-ordering requirement (no two consecutive user turns).
        if state.agent_iterations == 1:
            context_summary = build_context_summary(
                ctx=state.ctx,
                budget=budget,
                tool_call_log=state.tool_call_log,
                iteration=state.agent_iterations,
            )
            history = [genai_types.Content(
                role="user",
                parts=[genai_types.Part.from_text(text=context_summary)],
            )]

        try:
            response, model_used = _gemini_call(
                client,
                ctx.config.get("model_name", "gemini-2.5-flash"),
                history,
                gen_config,
                log_fn,
            )
            budget.record("gemini")
            if model_used != ctx.config.get("model_name", "gemini-2.5-flash"):
                log_fn(f"[{_ts()}] [agent] Usato modello fallback: {model_used}")
            _usage = getattr(response, "usage_metadata", None)
            log_llm_call(
                call_site="gemini_agent_loop",
                model=model_used,
                input_tokens=getattr(_usage, "prompt_token_count", 0),
                output_tokens=getattr(_usage, "candidates_token_count", 0),
                target=ctx.domain or ctx.target_context.get("company_name", "unknown"),
            )
        except Exception as exc:
            log_fn(f"[{_ts()}] [agent] Errore Gemini: {exc}")
            break

        if not response.candidates:
            log_fn(f"[{_ts()}] [agent] Nessun candidato nella risposta")
            break

        candidate = response.candidates[0]
        if not candidate.content or not candidate.content.parts:
            log_fn(f"[{_ts()}] [agent] Risposta vuota")
            break

        # Extract function call from first part with function_call
        fc = None
        fc_part = None
        for part in candidate.content.parts:
            if hasattr(part, "function_call") and part.function_call:
                fc = part.function_call
                fc_part = part
                break

        if fc is None:
            # No function call — model returned text (shouldn't happen with mode=ANY)
            text = "".join(p.text for p in candidate.content.parts if hasattr(p, "text") and p.text)
            log_fn(f"[{_ts()}] [agent] Risposta testo (no tool call): {text[:100]}")
            state.agent_summary = text
            break

        tool_name = fc.name
        args = dict(fc.args) if fc.args else {}

        # Terminal signal
        if tool_name == "finish_investigation":
            reason = args.get("reason", "")
            state.agent_summary = reason
            log_fn(f"[{_ts()}] [agent] FINE indagine: {reason}")
            break

        # Think tool — log reasoning, no ctx side effects, exempt from dedup
        if tool_name == "think":
            reasoning = args.get("reasoning", "")
            log_fn(f"[{_ts()}] [agent] 💭 {reasoning}")
            state.tool_call_log.append({
                "iteration": state.agent_iterations,
                "tool": "think",
                "args": args,
                "result_summary": reasoning[:120],
                "duration_ms": 0,
                "skipped_reason": None,
            })
            history.append(candidate.content)
            history.append(genai_types.Content(
                role="user",
                parts=[genai_types.Part.from_function_response(
                    name="think",
                    response={"status": "ok", "summary": "ragionamento registrato"},
                )],
            ))
            continue

        # Dedup check
        call_key = make_call_key(tool_name, args)
        if call_key in state.seen_calls:
            log_fn(f"[{_ts()}] [agent] SKIP duplicato: {tool_name}({args})")
            state.tool_call_log.append({
                "iteration": state.agent_iterations,
                "tool": tool_name,
                "args": args,
                "result_summary": "",
                "duration_ms": 0,
                "skipped_reason": "duplicato",
            })
            history.append(candidate.content)
            history.append(genai_types.Content(
                role="user",
                parts=[genai_types.Part.from_function_response(
                    name=tool_name,
                    response={"error": f"Tool {tool_name} con questi argomenti è già stato eseguito. Scegli un'azione diversa o chiama finish_investigation."},
                )],
            ))
            continue

        state.seen_calls.add(call_key)

        # Budget check for service
        service = TOOL_SERVICE_MAP.get(tool_name)
        if service and not budget.can_call(service):
            log_fn(f"[{_ts()}] [agent] Budget {service} esaurito — skip {tool_name}")
            state.tool_call_log.append({
                "iteration": state.agent_iterations,
                "tool": tool_name,
                "args": args,
                "result_summary": "",
                "duration_ms": 0,
                "skipped_reason": f"budget {service} esaurito",
            })
            history.append(candidate.content)
            history.append(genai_types.Content(
                role="user",
                parts=[genai_types.Part.from_function_response(
                    name=tool_name,
                    response={"error": f"Budget per {service} esaurito. Scegli un tool diverso o chiama finish_investigation."},  # noqa: E501
                )],
            ))
            continue

        # Execute tool
        t0 = time.monotonic()
        log_fn(f"[{_ts()}] [agent] iter {state.agent_iterations}: {tool_name}({_fmt_args(args)})")
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

        # Enrich the function response with current budget/state so Gemini
        # can track progress without a separate user turn each iteration.
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

        # Feed result back into conversation history
        history.append(candidate.content)
        history.append(genai_types.Content(
            role="user",
            parts=[genai_types.Part.from_function_response(
                name=tool_name,
                response=enriched,
            )],
        ))

    log_fn(f"[{_ts()}] [agent] Loop completato dopo {state.agent_iterations} iterazioni")
    log_fn(f"[{_ts()}] [agent] Tool chiamati: {len(state.tool_call_log)}, budget Gemini usato: {budget._counts.get('gemini', 0)}")

    # Copy agent metadata to ctx
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
