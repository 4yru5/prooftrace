"""The cost-to-recall experiment (the part that gets you hired).

Run the hypothesis+validation stage N times across 2-3 models against the
deterministic validator (ground truth), record per-run hit/miss + tokens +
wall-time, then compute recall-at-k and plot the convergence curve.

Locally dollars-per-run ≈ 0, so the headline x-axis is *number of runs* (recall
you buy with compute/time, not money). A secondary panel shows the notional
cloud $ story from the Mythos post, clearly labelled.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from .investigation import investigate_once
from .llm import BaseLLM, run_cost_usd
from .models import RunRecord


def recall_at_k(hits: list[bool]) -> list[float]:
    """Cumulative recall: fraction of prefixes [0..k] that contain >=1 hit."""
    out = []
    seen = False
    for h in hits:
        seen = seen or h
        out.append(1.0 if seen else 0.0)
    return out


def _expected_recall_curve(per_run_rate: float, k: int) -> list[float]:
    """Analytic E[recall] at k runs = 1 - (1 - p)^k."""
    return [1.0 - (1.0 - per_run_rate) ** (i + 1) for i in range(k)]


def run_experiment(
    files: list[str],
    llm: BaseLLM,
    models: list[str],
    runs_per_model: int,
    on_run: Callable[[RunRecord], None] | None = None,
) -> dict[str, Any]:
    results: dict[str, list[dict[str, Any]]] = {}
    for model in models:
        recs: list[RunRecord] = []
        for i in range(runs_per_model):
            rec = investigate_once(files, llm, model=model, run_index=i,
                                   validate_live=False)
            recs.append(rec)
            if on_run:
                on_run(rec)
        results[model] = [asdict(r) for r in recs]
    return results


def summarize(results: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    summary = {}
    for model, recs in results.items():
        hits = [r["hit"] for r in recs]
        n = len(hits)
        n_hit = sum(hits)
        total_cost = sum(r["cost_usd"] for r in recs)
        total_wall = sum(r["wall_seconds"] for r in recs)
        total_tokens = sum(r["completion_tokens"] for r in recs)
        per_run = (n_hit / n) if n else 0.0
        curve = recall_at_k(hits)
        runs_to_90 = next((i + 1 for i, v in enumerate(curve) if v >= 0.9), None)
        summary[model] = {
            "runs": n,
            "per_run_hit_rate": round(per_run, 3),
            "final_recall": curve[-1] if curve else 0.0,
            "runs_to_first_hit": next((i + 1 for i, h in enumerate(hits) if h), None),
            "runs_to_90pct_expected": next(
                (i + 1 for i, v in enumerate(_expected_recall_curve(per_run, n))
                 if v >= 0.9), None),
            "total_completion_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 4),
            "total_wall_seconds": round(total_wall, 2),
            "recall_curve": curve,
        }
    return summary


def plot(summary: dict[str, Any], out_path: str,
         raw: dict[str, list[dict[str, Any]]] | None = None,
         illustrative: bool = True) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "figure.facecolor": "#0b0f14",
        "axes.facecolor": "#0b0f14",
        "savefig.facecolor": "#0b0f14",
        "text.color": "#e5e7eb",
        "axes.labelcolor": "#e5e7eb",
        "xtick.color": "#9ca3af",
        "ytick.color": "#9ca3af",
        "axes.edgecolor": "#374151",
        "font.family": "sans-serif",
    })
    colors = ["#ef4444", "#f59e0b", "#22d3ee", "#a78bfa"]
    fig, ax = plt.subplots(figsize=(8, 5))

    for idx, (model, s) in enumerate(summary.items()):
        k = s["runs"]
        ks = list(range(1, k + 1))
        c = colors[idx % len(colors)]
        p = s["per_run_hit_rate"]
        # the convergence story: expected recall = 1-(1-p)^k from measured p
        exp = _expected_recall_curve(p, k)
        ax.plot(ks, exp, color=c, linewidth=2.4, marker="o", markersize=3,
                label=f"{model}  (per-run {p:.0%})")
        # runs-to-90% marker for the slow (cheap) models
        r90 = s.get("runs_to_90pct_expected")
        if r90 and r90 > 1:
            ax.plot([r90], [exp[min(r90, k) - 1]], marker="v", color=c, markersize=9)
            ax.text(r90, exp[min(r90, k) - 1] - 0.07, f"{r90} runs→90%",
                    color=c, fontsize=8, ha="center")
        # empirical per-run hits as a rug along the baseline
        hits = s["recall_curve"]  # cumulative; derive per-run via raw if present
    # rug of actual per-run outcomes
    if raw:
        for idx, (model, recs) in enumerate(raw.items()):
            c = colors[idx % len(colors)]
            y = -0.035 - idx * 0.03
            for r in recs:
                if r["hit"]:
                    ax.plot([r["run_index"] + 1], [y], marker="|", color=c, markersize=7)

    ax.axhline(0.9, color="#4b5563", linewidth=0.8, linestyle="--")
    ax.text(0.5, 0.915, "90% recall", color="#9ca3af", fontsize=8)
    ax.set_xlabel("number of runs (k)  —  recall you buy with compute, not money")
    ax.set_ylabel("expected recall @ k  (exploit reproduced in ≥1 run)")
    ax.set_ylim(-0.13, 1.05)
    ax.set_title("ProofTrace — cost-to-recall: cheap model looped vs frontier once",
                 color="#f9fafb", fontsize=12, pad=12)
    ax.legend(loc="lower right", facecolor="#111827", edgecolor="#374151",
              labelcolor="#e5e7eb", fontsize=9)
    ax.grid(True, color="#1f2937", linewidth=0.6)

    tag = ("illustrative · stub model · replace with real Ollama run logs"
           if illustrative else "generated from live Ollama run logs")
    fig.text(0.01, 0.01, tag, color="#6b7280", fontsize=7)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return str(out)


def save_logs(results: dict[str, Any], summary: dict[str, Any], out_dir: str) -> None:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "cost_to_recall_runs.json").write_text(json.dumps(results, indent=2))
    (d / "cost_to_recall_summary.json").write_text(json.dumps(summary, indent=2))
