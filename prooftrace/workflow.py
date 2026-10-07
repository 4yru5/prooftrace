"""Temporal workflows — the durable rail around the investigation.

ProofTraceWorkflow wraps one PR investigation: each stage is a retried activity
and a cost ledger accrues across stages. CostToRecallWorkflow is the honest
motivation for Temporal — durable fan-out of many cheap model runs, each with
its own retry, accumulating a cost ledger (the Mythos cost-to-recall thesis
made executable).
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from .activities import extract_and_reach, hypothesize, validate_exploit

TASK_QUEUE = "prooftrace"

_FAST_RETRY = RetryPolicy(maximum_attempts=3, initial_interval=timedelta(seconds=1))
_SANDBOX_RETRY = RetryPolicy(maximum_attempts=3, initial_interval=timedelta(seconds=2))


@workflow.defn
class ProofTraceWorkflow:
    @workflow.run
    async def run(self, params: dict[str, Any]) -> dict[str, Any]:
        files = params["files"]
        model = params.get("model")
        backend = params.get("backend", "auto")
        max_attempts = params.get("max_attempts", 2)
        ledger = {"prompt_tokens": 0, "completion_tokens": 0,
                  "cost_usd": 0.0, "wall_seconds": 0.0, "model": model}
        log: list[dict[str, Any]] = []

        ctx = await workflow.execute_activity(
            extract_and_reach, files,
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=_FAST_RETRY,
        )
        candidates = ctx["candidates"]
        log.append({"node": "context_builder",
                    "detail": f"{len(candidates)} unguarded candidate(s)"})

        decision, gate_ok = {}, False
        for attempt in range(max_attempts):
            h = await workflow.execute_activity(
                hypothesize,
                {"candidates": candidates, "model": model,
                 "run_index": attempt, "llm": params.get("llm", "auto")},
                start_to_close_timeout=timedelta(seconds=200),
                retry_policy=_FAST_RETRY,
            )
            decision = h["decision"]
            ledger["prompt_tokens"] += h["prompt_tokens"]
            ledger["completion_tokens"] += h["completion_tokens"]
            ledger["cost_usd"] += h["cost_usd"]
            ledger["wall_seconds"] += h["wall_seconds"]
            ledger["model"] = h["model"]
            target = (decision.get("target_endpoint") or "").strip()
            cand_eps = {c["endpoint"] for c in candidates}
            gate_ok = (decision.get("is_vulnerable") and
                       decision.get("should_validate") and target in cand_eps)
            log.append({"node": "hypothesis",
                        "detail": f"attempt {attempt}: target={target} gate_ok={gate_ok}"})
            if gate_ok:
                break

        if not gate_ok:
            return {
                "finding": {"status": "SAFE", "title": "No exploitable BOLA found",
                            "cwe": "CWE-639", "endpoint": "n/a", "severity": "n/a",
                            "hypothesis": decision.get("rationale", ""),
                            "path": None, "evidence": None, "confidence": "n/a"},
                "ledger": ledger, "log": log,
            }

        ev = await workflow.execute_activity(
            validate_exploit, backend,
            start_to_close_timeout=timedelta(seconds=120),
            retry_policy=_SANDBOX_RETRY,
        )
        log.append({"node": "validator",
                    "detail": "VERIFIED" if ev["exploit_reproduced"] else "not reproduced"})

        cand = next((c for c in candidates
                     if c["endpoint"] == decision.get("target_endpoint")), None)
        reproduced = ev["exploit_reproduced"]
        finding = {
            "title": "Broken Object Level Authorization in invoice retrieval",
            "cwe": "CWE-639",
            "endpoint": decision.get("target_endpoint", "n/a"),
            "status": "VERIFIED" if reproduced else "UNPROVEN",
            "severity": "High",
            "hypothesis": decision.get("rationale", ""),
            "path": cand,
            "evidence": ev,
            "confidence": "earned (live proof)" if reproduced else "unproven",
        }
        return {"finding": finding, "ledger": ledger, "log": log}


@workflow.defn
class CostToRecallWorkflow:
    @workflow.run
    async def run(self, params: dict[str, Any]) -> dict[str, Any]:
        candidates = params["candidates"]
        models = params["models"]
        runs = params["runs_per_model"]
        results: dict[str, list[dict[str, Any]]] = {}
        for model in models:
            recs = []
            for i in range(runs):
                h = await workflow.execute_activity(
                    hypothesize,
                    {"candidates": candidates, "model": model,
                     "run_index": i, "llm": params.get("llm", "auto")},
                    start_to_close_timeout=timedelta(seconds=200),
                    retry_policy=_FAST_RETRY,
                )
                d = h["decision"]
                target = (d.get("target_endpoint") or "").strip()
                cand_eps = {c["endpoint"] for c in candidates}
                hit = bool(d.get("is_vulnerable") and d.get("should_validate")
                           and target in cand_eps)
                recs.append({
                    "model": model, "run_index": i, "hit": hit,
                    "prompt_tokens": h["prompt_tokens"],
                    "completion_tokens": h["completion_tokens"],
                    "cost_usd": h["cost_usd"], "wall_seconds": h["wall_seconds"],
                })
            results[model] = recs
        return {"results": results}
