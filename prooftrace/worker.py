"""Temporal worker: hosts the ProofTrace workflows + activities.

Run against a local dev server (`temporal server start-dev`, Web UI :8233).
No cloud, no key.
"""
from __future__ import annotations

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from .activities import extract_and_reach, hypothesize, validate_exploit
from .workflow import TASK_QUEUE, CostToRecallWorkflow, ProofTraceWorkflow

DEFAULT_TARGET = "localhost:7233"


async def main(target: str = DEFAULT_TARGET) -> None:
    client = await Client.connect(target)
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[ProofTraceWorkflow, CostToRecallWorkflow],
        activities=[extract_and_reach, hypothesize, validate_exploit],
    )
    print(f"[worker] connected to {target}, task-queue={TASK_QUEUE!r}; waiting for work…")
    await worker.run()


if __name__ == "__main__":
    import sys
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET))
