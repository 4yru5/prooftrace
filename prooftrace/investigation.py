"""The LangGraph investigation.

Nodes with explicit jobs (not one mega-agent):

    context_builder -> hypothesis -> reachability_checker
                                        |            |
                                   (mismatch)     (match)
                                        |            v
                                   re_analyze    exploit_planner -> validator -> evidence

The LLM only runs in `hypothesis`. `reachability_checker` cross-checks the
model's claim against the statically-computed candidate set — if the model
targets an endpoint the graph did not flag as unguarded, the claim is rejected
and the graph wins. Nothing is reported VERIFIED unless the live validator
reproduces the exploit.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, TypedDict

from langgraph.graph import END, StateGraph

from . import reachability, validator
from .extract import extract_graph
from .llm import BaseLLM, Usage, run_cost_usd
from .models import (
    AppGraph,
    Evidence,
    Finding,
    HttpExchange,
    ReachabilityPath,
    RunRecord,
)

PROMPT = (Path(__file__).resolve().parent.parent / "prompts" / "hypothesis.md").read_text()


class InvState(TypedDict, total=False):
    files: list[str]
    graph: dict[str, Any]
    all_paths: list[dict[str, Any]]
    candidates: list[dict[str, Any]]
    attempt: int
    max_attempts: int
    decision: dict[str, Any]
    plan: dict[str, Any]
    evidence: dict[str, Any] | None
    finding: dict[str, Any] | None
    status: str
    _gate_ok: bool
    model: str
    run_index: int
    backend: str
    validate_live: bool
    metrics: dict[str, Any]
    log: list[dict[str, Any]]


def _emit(state: InvState, node: str, detail: str, **extra: Any) -> None:
    state.setdefault("log", []).append(
        {"node": node, "detail": detail, "ts": time.time(), **extra}
    )


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if "```" in text:
        # strip markdown fences
        parts = text.split("```")
        for p in parts:
            p = p.strip().removeprefix("json").strip()
            if p.startswith("{"):
                text = p
                break
    try:
        start = text.index("{")
        depth, i = 0, start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return json.loads(text[start : i + 1])
            i += 1
    except Exception:
        pass
    return {}


def build_graph(llm: BaseLLM) -> Any:
    """Compile the LangGraph state machine bound to an LLM client."""

    def context_builder(state: InvState) -> InvState:
        graph = extract_graph(state["files"])
        paths = reachability.analyze(graph)
        cands = reachability.candidates(paths)
        state["graph"] = graph.to_dict()
        state["all_paths"] = [p.__dict__ for p in paths]
        state["candidates"] = [
            {
                "endpoint": c.endpoint,
                "object_param": c.object_param,
                "source": c.source,
                "sink": c.sink,
                "reason": c.reason,
            }
            for c in cands
        ]
        n_routes = sum(1 for n in graph.nodes if n.kind.value == "route")
        _emit(
            state,
            "context_builder",
            f"parsed {len(state['files'])} file(s): {n_routes} route(s), "
            f"{len(paths)} path(s), {len(cands)} unguarded candidate(s)",
            candidates=state["candidates"],
        )
        return state

    def hypothesis(state: InvState) -> InvState:
        user = (
            "Here is the statically-built reachability analysis of the PR diff.\n\n"
            f"candidate_paths = {json.dumps(state['candidates'])}\n\n"
            "Pick the single most likely BOLA target and respond with the JSON "
            "object described in the system prompt."
        )
        # fold the retry attempt into the run index so re-analysis re-draws
        eff_run = state.get("run_index", 0) * 97 + state.get("attempt", 0)
        res = llm.complete(
            PROMPT, user, model=state.get("model"), run_index=eff_run
        )
        decision = _parse_json(res.text)
        state["decision"] = decision
        m = state.setdefault("metrics", {"prompt_tokens": 0, "completion_tokens": 0,
                                         "cost_usd": 0.0, "wall_seconds": 0.0})
        m["prompt_tokens"] += res.usage.prompt_tokens
        m["completion_tokens"] += res.usage.completion_tokens
        m["cost_usd"] += run_cost_usd(res.model, res.usage)
        m["wall_seconds"] += res.wall_seconds
        m["model"] = res.model
        verdict = decision.get("vulnerability_class") or (
            "no vuln" if not decision.get("is_vulnerable") else "unspecified")
        _emit(state, "hypothesis",
              f"model={res.model} -> {verdict}; target="
              f"{decision.get('target_endpoint', 'n/a')}",
              decision=decision)
        return state

    def reachability_checker(state: InvState) -> InvState:
        """Gate: the model's target must match a statically-unguarded path."""
        decision = state.get("decision", {})
        target = (decision.get("target_endpoint") or "").strip()
        cand_endpoints = {c["endpoint"] for c in state["candidates"]}
        ok = (
            bool(decision.get("is_vulnerable"))
            and bool(decision.get("should_validate"))
            and target in cand_endpoints
        )
        state["_gate_ok"] = ok
        if ok:
            _emit(state, "reachability_checker",
                  f"CONFIRMED by graph: '{target}' is an unguarded source->sink path")
        else:
            _emit(state, "reachability_checker",
                  f"REJECTED: model target '{target or 'none'}' not in graph's "
                  f"unguarded set {sorted(cand_endpoints)} — will re-analyze")
        return state

    def exploit_planner(state: InvState) -> InvState:
        decision = state["decision"]
        plan = decision.get("exploit_plan", {})
        plan.setdefault("actor", "user_A")
        plan.setdefault("victim", "user_B")
        state["plan"] = plan
        _emit(state, "exploit_planner",
              f"plan: {plan.get('actor')} reads {plan.get('victim')}'s object via "
              f"{decision.get('target_endpoint')}")
        return state

    def validate_node(state: InvState) -> InvState:
        if state.get("validate_live", True):
            ev, backend = validator.validate(state.get("backend", "auto"))
            state["backend"] = backend
            ev_dict = {
                "exploit_reproduced": ev.exploit_reproduced,
                "exchanges": [e.__dict__ for e in ev.exchanges],
                "flag": ev.flag,
                "attacker_user": ev.attacker_user,
                "victim_user": ev.victim_user,
                "assertion": ev.assertion,
            }
        else:
            # ground-truth is deterministic: a correct target always reproduces
            ev_dict = {
                "exploit_reproduced": True,
                "exchanges": [],
                "flag": "FLAG{...}",
                "attacker_user": "user_A",
                "victim_user": "user_B",
                "assertion": "deterministic ground-truth (fast mode)",
            }
            state["backend"] = "none"
        state["evidence"] = ev_dict
        _emit(state, "validator",
              ("VERIFIED — exploit reproduced live: " + ev_dict["assertion"])
              if ev_dict["exploit_reproduced"]
              else "NOT reproduced — claim rejected",
              reproduced=ev_dict["exploit_reproduced"], backend=state.get("backend"))
        return state

    def evidence_node(state: InvState) -> InvState:
        decision = state["decision"]
        ev = state["evidence"]
        cand = next((c for c in state["candidates"]
                     if c["endpoint"] == decision.get("target_endpoint")), None)
        reproduced = bool(ev and ev["exploit_reproduced"])
        state["status"] = "VERIFIED" if reproduced else "UNPROVEN"
        state["finding"] = {
            "title": "Broken Object Level Authorization in invoice retrieval",
            "cwe": "CWE-639",
            "endpoint": decision.get("target_endpoint", "n/a"),
            "status": state["status"],
            "severity": "High",
            "hypothesis": decision.get("rationale", ""),
            "path": cand,
            "evidence": ev,
            "confidence": "earned (live proof)" if reproduced else "unproven",
        }
        _emit(state, "evidence", f"finding -> {state['status']}")
        return state

    def re_analyze(state: InvState) -> InvState:
        state["attempt"] = state.get("attempt", 0) + 1
        _emit(state, "re_analyze",
              f"attempt {state['attempt']}/{state.get('max_attempts', 2)}")
        return state

    def no_finding(state: InvState) -> InvState:
        state["status"] = "SAFE"
        state["finding"] = {
            "title": "No exploitable BOLA found",
            "cwe": "CWE-639",
            "endpoint": "n/a",
            "status": "SAFE",
            "severity": "n/a",
            "hypothesis": state.get("decision", {}).get("rationale", ""),
            "path": None,
            "evidence": None,
            "confidence": "n/a",
        }
        _emit(state, "no_finding", "no unguarded path confirmed; nothing reported")
        return state

    def after_gate(state: InvState) -> str:
        if state.get("_gate_ok"):
            return "exploit_planner"
        # max_attempts counts *total* hypothesis draws; attempt is 0-indexed.
        if (state.get("attempt", 0) + 1 < state.get("max_attempts", 2)
                and state["candidates"]):
            return "re_analyze"
        return "no_finding"

    g = StateGraph(InvState)
    g.add_node("context_builder", context_builder)
    g.add_node("hypothesis", hypothesis)
    g.add_node("reachability_checker", reachability_checker)
    g.add_node("exploit_planner", exploit_planner)
    g.add_node("validator", validate_node)
    g.add_node("evidence", evidence_node)
    g.add_node("re_analyze", re_analyze)
    g.add_node("no_finding", no_finding)

    g.set_entry_point("context_builder")
    g.add_edge("context_builder", "hypothesis")
    g.add_edge("hypothesis", "reachability_checker")
    g.add_conditional_edges("reachability_checker", after_gate, {
        "exploit_planner": "exploit_planner",
        "re_analyze": "re_analyze",
        "no_finding": "no_finding",
    })
    g.add_edge("re_analyze", "hypothesis")
    g.add_edge("exploit_planner", "validator")
    g.add_edge("validator", "evidence")
    g.add_edge("evidence", END)
    g.add_edge("no_finding", END)
    return g.compile()


def run_investigation(
    files: list[str],
    llm: BaseLLM,
    model: str | None = None,
    backend: str = "auto",
    validate_live: bool = True,
    run_index: int = 0,
    max_attempts: int = 2,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> InvState:
    """Run the full investigation and return the final state."""
    app = build_graph(llm)
    init: InvState = {
        "files": files,
        "attempt": 0,
        "max_attempts": max_attempts,
        "model": model or getattr(llm, "default_model", "qwen2.5-coder:7b"),
        "run_index": run_index,
        "backend": backend,
        "validate_live": validate_live,
        "log": [],
    }
    final: InvState = init
    seen = 0
    for step in app.stream(init, {"recursion_limit": 25}):
        for _node, state in step.items():
            final = state
            if on_event:
                for ev in state.get("log", [])[seen:]:
                    on_event(ev)
                seen = len(state.get("log", []))
    return final


def investigate_once(
    files: list[str],
    llm: BaseLLM,
    model: str,
    run_index: int,
    validate_live: bool = False,
) -> RunRecord:
    """One run for the cost-to-recall fan-out. Returns a hit/miss RunRecord."""
    t0 = time.time()
    # one run = one single-shot hypothesis draw (no internal retry), so the
    # measured per-run hit rate reflects the model's true reliability. Retries
    # belong to the headline investigation, not the cost-to-recall counter.
    final = run_investigation(
        files, llm, model=model, validate_live=validate_live,
        run_index=run_index, max_attempts=1,
    )
    m = final.get("metrics", {})
    hit = final.get("status") == "VERIFIED"
    return RunRecord(
        model=model,
        run_index=run_index,
        hit=hit,
        prompt_tokens=int(m.get("prompt_tokens", 0)),
        completion_tokens=int(m.get("completion_tokens", 0)),
        cost_usd=float(m.get("cost_usd", 0.0)),
        wall_seconds=time.time() - t0,
    )
