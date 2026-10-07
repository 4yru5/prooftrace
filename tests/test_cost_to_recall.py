"""Cost-to-recall: the math and the convergence must be real, not decorative."""
from __future__ import annotations

from prooftrace import cost_to_recall
from prooftrace.llm import StubLLM

TARGET = ["target_app/app/main.py"]


def test_recall_at_k_is_cumulative():
    assert cost_to_recall.recall_at_k([False, False, True, False]) == [0, 0, 1, 1]
    assert cost_to_recall.recall_at_k([False, False]) == [0, 0]


def test_cheap_model_converges_over_runs():
    llm = StubLLM()
    results = cost_to_recall.run_experiment(
        TARGET, llm, ["qwen2.5-coder:32b", "qwen2.5-coder:1.5b"], runs_per_model=25)
    summary = cost_to_recall.summarize(results)
    frontier = summary["qwen2.5-coder:32b"]
    cheap = summary["qwen2.5-coder:1.5b"]
    # frontier is reliable per run; cheap is not
    assert frontier["per_run_hit_rate"] > cheap["per_run_hit_rate"]
    # but looped, the cheap model's recall climbs to high
    assert cheap["final_recall"] >= 0.9
    # cheap needs more runs to reach 90% than frontier
    assert (cheap["runs_to_90pct_expected"] or 999) > (frontier["runs_to_90pct_expected"] or 1)


def test_single_run_matches_per_run_rate_not_retried():
    """Each experiment run is a single draw (no internal retry inflating recall)."""
    llm = StubLLM()
    results = cost_to_recall.run_experiment(TARGET, llm, ["qwen2.5-coder:1.5b"], 40)
    s = cost_to_recall.summarize(results)["qwen2.5-coder:1.5b"]
    # cheap model's per-run rate must stay low (near its ~0.28 profile), well under 0.6
    assert s["per_run_hit_rate"] < 0.6
