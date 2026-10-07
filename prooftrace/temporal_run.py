"""Trigger the ProofTraceWorkflow against a running Temporal dev server + worker.

Usage: uv run python -m prooftrace.temporal_run
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path

from temporalio.client import Client

from . import pr, pr_comment
from .workflow import TASK_QUEUE, ProofTraceWorkflow

ART = Path(__file__).resolve().parent.parent / "artifacts"


async def main(target: str = "localhost:7233") -> None:
    client = await Client.connect(target)
    params = {
        "files": pr.changed_files(),
        "model": os.environ.get("PROOFTRACE_MODEL", "qwen2.5-coder:7b"),
        "backend": os.environ.get("PROOFTRACE_SANDBOX", "auto"),
        "llm": os.environ.get("PROOFTRACE_LLM", "auto"),
        "max_attempts": 3,
    }
    handle = await client.start_workflow(
        ProofTraceWorkflow.run, params,
        id=f"prooftrace-{uuid.uuid4().hex[:8]}", task_queue=TASK_QUEUE)
    print(f"  workflow id: {handle.id}")
    result = await handle.result()

    finding = result["finding"]
    ledger = result["ledger"]
    print(f"  status: {finding['status']}  ({finding['endpoint']})")
    print(f"  ledger: model={ledger.get('model')} "
          f"tokens={ledger.get('prompt_tokens')}+{ledger.get('completion_tokens')} "
          f"wall={ledger.get('wall_seconds', 0):.2f}s")

    ART.mkdir(parents=True, exist_ok=True)
    (ART / "finding_temporal.json").write_text(json.dumps(result, indent=2, default=str))
    (ART / "pr_comment_temporal.md").write_text(
        pr_comment.render(finding, {**ledger, "backend": "temporal"}))
    print(f"  artifacts -> {ART}/finding_temporal.json, pr_comment_temporal.md")


if __name__ == "__main__":
    asyncio.run(main())
