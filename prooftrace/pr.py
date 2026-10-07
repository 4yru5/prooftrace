"""Load the demo pull request: changed files, diff text, metadata.

The diff is a real unified diff (the PR that adds the vulnerable endpoint);
ProofTrace analyses the changed files it names.
"""
from __future__ import annotations

import json
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo"


def meta() -> dict:
    return json.loads((DEMO_DIR / "pr.meta.json").read_text())


def diff_text() -> str:
    return (DEMO_DIR / "pr.diff").read_text()


def changed_files() -> list[str]:
    root = Path(__file__).resolve().parent.parent
    return [str(root / f) for f in meta()["files"]]
