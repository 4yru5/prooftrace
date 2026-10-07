"""Temporal activities — the side-effecting stages of the pipeline.

Each stage is an activity so Temporal can retry the expensive/flaky ones (LLM,
sandbox) independently and keep a durable history. Activities exchange plain
dicts so everything is JSON-serialisable and visible in the Temporal Web UI.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from temporalio import activity

from . import reachability, validator
from .extract import extract_graph
from .llm import get_llm, run_cost_usd
from .investigation import _parse_json

PROMPT = (Path(__file__).resolve().parent.parent / "prompts" / "hypothesis.md").read_text()


@activity.defn
async def extract_and_reach(files: list[str]) -> dict[str, Any]:
    graph = extract_graph(files)
    paths = reachability.analyze(graph)
    cands = reachability.candidates(paths)
    return {
        "graph": graph.to_dict(),
        "candidates": [
            {"endpoint": c.endpoint, "object_param": c.object_param,
             "source": c.source, "sink": c.sink, "reason": c.reason}
            for c in cands
        ],
        "all_paths": [p.__dict__ for p in paths],
    }


@activity.defn
async def hypothesize(params: dict[str, Any]) -> dict[str, Any]:
    candidates = params["candidates"]
    model = params.get("model")
    run_index = params.get("run_index", 0)
    prefer = params.get("llm", "auto")
    llm = get_llm(prefer)
    user = (
        "Here is the statically-built reachability analysis of the PR diff.\n\n"
        f"candidate_paths = {json.dumps(candidates)}\n\n"
        "Pick the single most likely BOLA target and respond with the JSON object."
    )
    res = llm.complete(PROMPT, user, model=model, run_index=run_index)
    decision = _parse_json(res.text)
    return {
        "decision": decision,
        "model": res.model,
        "prompt_tokens": res.usage.prompt_tokens,
        "completion_tokens": res.usage.completion_tokens,
        "cost_usd": run_cost_usd(res.model, res.usage),
        "wall_seconds": res.wall_seconds,
    }


@activity.defn
async def validate_exploit(backend: str = "auto") -> dict[str, Any]:
    ev, resolved = validator.validate(backend)
    return {
        "exploit_reproduced": ev.exploit_reproduced,
        "exchanges": [e.__dict__ for e in ev.exchanges],
        "flag": ev.flag,
        "attacker_user": ev.attacker_user,
        "victim_user": ev.victim_user,
        "assertion": ev.assertion,
        "backend": resolved,
    }
