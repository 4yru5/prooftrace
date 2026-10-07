"""Render a finding as a PR comment (Markdown panel; no GitHub token needed).

The comment leads with the binary earned claim (VERIFIED, with the HTTP
transcript), not a fake-precise confidence number — matching the "PoC || GTFO"
culture: the proof carries the claim.
"""
from __future__ import annotations

from typing import Any


def render(finding: dict[str, Any], run_meta: dict[str, Any] | None = None) -> str:
    status = finding.get("status", "UNPROVEN")
    badge = {
        "VERIFIED": "🟥 **VERIFIED** — exploit reproduced live",
        "UNPROVEN": "🟨 **UNPROVEN** — claim not reproduced",
        "SAFE": "🟩 **SAFE** — no exploitable path confirmed",
    }.get(status, status)

    lines: list[str] = []
    lines.append(f"## ProofTrace finding — {badge}")
    lines.append("")
    lines.append(f"**{finding.get('title')}**  ·  `{finding.get('cwe')}`  ·  "
                 f"severity **{finding.get('severity')}**")
    lines.append("")
    lines.append(f"**Endpoint:** `{finding.get('endpoint')}`")
    lines.append("")

    path = finding.get("path")
    if path:
        lines.append("### Source → sink path (tree-sitter)")
        lines.append("")
        lines.append("```")
        lines.append(f"source  {path.get('object_param')}  (attacker-controlled path param)")
        lines.append("   │  flows to")
        lines.append("   ▼")
        lines.append(f"sink    db.execute(...)   ← no ownership check on the path")
        lines.append("```")
        lines.append("")
        lines.append(f"> {path.get('reason')}")
        lines.append("")

    lines.append("### Hypothesis")
    lines.append(f"{finding.get('hypothesis', '').strip() or '_n/a_'}")
    lines.append("")

    ev = finding.get("evidence")
    if ev and ev.get("exchanges"):
        lines.append("### Proof — live HTTP transcript")
        lines.append("")
        lines.append("```http")
        for ex in ev["exchanges"]:
            lines.append(ex["request"].rstrip())
            body = ex["response_body"]
            if len(body) > 300:
                body = body[:300] + "…"
            lines.append(f"-> {ex['response_status']} {body}")
            lines.append("")
        lines.append("```")
        lines.append("")
        if ev.get("assertion"):
            lines.append(f"**Assertion:** {ev['assertion']}")
            lines.append("")
        if ev.get("flag"):
            lines.append(f"**Flag recovered:** `{ev['flag']}`")
            lines.append("")

    if run_meta:
        lines.append("### Run")
        lines.append(
            f"- investigator: `{run_meta.get('investigator', 'n/a')}`  ·  "
            f"model: `{run_meta.get('model', 'n/a')}`  ·  "
            f"sandbox: `{run_meta.get('backend', 'n/a')}`  ·  "
            f"tokens: {run_meta.get('prompt_tokens', 0)}+"
            f"{run_meta.get('completion_tokens', 0)}  ·  "
            f"wall: {run_meta.get('wall_seconds', 0):.1f}s"
        )
        lines.append("")

    lines.append("---")
    lines.append("_The goal isn't more findings. It's fewer findings we can actually prove._")
    lines.append("")
    lines.append("<sub>ProofTrace · reachability-first · LLM-as-investigator · "
                 "validated against a live instance. PoC || GTFO.</sub>")
    return "\n".join(lines)
