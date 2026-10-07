"""The investigation: VERIFIED only via live proof; the graph rejects hallucinations."""
from __future__ import annotations

from prooftrace.investigation import run_investigation
from prooftrace.llm import BaseLLM, LLMResult, StubLLM, Usage

TARGET = ["target_app/app/main.py"]


def test_end_to_end_verified_with_stub():
    final = run_investigation(TARGET, StubLLM(), model="qwen2.5-coder:32b",
                              backend="subprocess", validate_live=True, max_attempts=3)
    assert final["status"] == "VERIFIED"
    f = final["finding"]
    assert f["cwe"] == "CWE-639"
    assert f["evidence"]["exploit_reproduced"] is True
    assert "FLAG{" in (f["evidence"]["flag"] or "")


class _LyingLLM(BaseLLM):
    """Always claims a vuln on a guarded endpoint that the graph did not flag."""
    name = "liar"

    def complete(self, system, user, model=None, temperature=0.2, run_index=0):
        import json
        payload = {
            "is_vulnerable": True,
            "vulnerability_class": "BOLA",
            "target_endpoint": "GET /api/invoices/{invoice_id}/secure",  # guarded!
            "object_param": "invoice_id",
            "rationale": "I insist this is vulnerable",
            "should_validate": True,
        }
        return LLMResult(json.dumps(payload), model or "liar", Usage(10, 10), 0.0)


def test_graph_rejects_hallucinated_target():
    """A model targeting a guarded/cleared endpoint must NOT yield VERIFIED."""
    final = run_investigation(TARGET, _LyingLLM(), model="liar",
                              backend="subprocess", validate_live=True, max_attempts=2)
    assert final["status"] != "VERIFIED"
    # nothing should be reported as proven
    assert final["finding"]["status"] in {"SAFE", "UNPROVEN"}


class _SilentLLM(BaseLLM):
    name = "silent"

    def complete(self, system, user, model=None, temperature=0.2, run_index=0):
        import json
        return LLMResult(json.dumps({"is_vulnerable": False, "should_validate": False}),
                         model or "silent", Usage(10, 10), 0.0)


def test_safe_when_model_finds_nothing():
    final = run_investigation(TARGET, _SilentLLM(), model="silent",
                              backend="subprocess", validate_live=True, max_attempts=2)
    assert final["status"] == "SAFE"
    assert final["finding"]["evidence"] is None
