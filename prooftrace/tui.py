"""Live run visualization — a Rich TUI that streams the investigation.

A visual debugger, not a dashboard: the pipeline stages light up as the
LangGraph nodes advance, candidate paths and the streaming log fill in, and the
run ends on the VERIFIED banner with the live HTTP transcript. Records cleanly
under VHS (deterministic, no browser, no stall).
"""
from __future__ import annotations

import time
from typing import Any

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import investigation
from .llm import BaseLLM

STAGES = [
    ("context_builder", "parse diff · build graph"),
    ("hypothesis", "LLM forms a hypothesis"),
    ("reachability_checker", "graph confirms / rejects"),
    ("exploit_planner", "plan the exploit"),
    ("validator", "reproduce live"),
    ("evidence", "assemble proof"),
]
STAGE_IDS = [s[0] for s in STAGES]


def _pipeline_panel(current: str | None, done: set[str], status: str | None) -> Panel:
    t = Table.grid(padding=(0, 1))
    t.add_column()
    for sid, label in STAGES:
        if sid in done:
            mark, style = "✓", "bold green"
        elif sid == current:
            mark, style = "▶", "bold yellow"
        else:
            mark, style = "·", "dim"
        t.add_row(Text(f" {mark} {label}", style=style))
    color = {"VERIFIED": "red", "SAFE": "green", "UNPROVEN": "yellow"}.get(status or "", "cyan")
    return Panel(t, title="[bold]investigation[/]", border_style=color, width=38)


def _log_panel(events: list[dict[str, Any]]) -> Panel:
    lines = []
    for e in events[-12:]:
        node = e.get("node", "")
        detail = e.get("detail", "")
        lines.append(Text.assemble((f"{node:>20} ", "bold cyan"), (detail, "white")))
    body = Group(*lines) if lines else Text("…", style="dim")
    return Panel(body, title="[bold]agent log[/]", border_style="grey37")


def _candidates_panel(candidates: list[dict[str, Any]]) -> Panel:
    if not candidates:
        return Panel(Text("awaiting reachability…", style="dim"),
                     title="[bold]candidate paths[/]", border_style="grey37")
    t = Table.grid(padding=(0, 1))
    t.add_column()
    for c in candidates:
        t.add_row(Text.assemble(("● ", "bold red"),
                                (c["endpoint"], "bold white")))
        t.add_row(Text(f"   source {c.get('object_param')} → sink (unguarded)", style="dim"))
    return Panel(t, title="[bold red]unguarded source→sink[/]", border_style="red")


def _proof_panel(final: dict[str, Any]) -> Panel:
    status = final.get("status")
    finding = final.get("finding") or {}
    ev = finding.get("evidence") or {}
    rows = []
    if status == "VERIFIED":
        rows.append(Text("  VERIFIED — exploit reproduced live  ",
                         style="bold white on red"))
    elif status == "SAFE":
        rows.append(Text("  SAFE — nothing reported  ", style="bold white on green"))
    else:
        rows.append(Text(f"  {status}  ", style="bold black on yellow"))
    rows.append(Text(""))
    for ex in ev.get("exchanges", []):
        rows.append(Text(ex["request"].rstrip(), style="cyan"))
        body = ex["response_body"]
        if len(body) > 120:
            body = body[:120] + "…"
        st = ex["response_status"]
        sty = "bold red" if st == 200 else "dim"
        rows.append(Text(f"  → {st} {body}", style=sty))
    if ev.get("assertion"):
        rows.append(Text(""))
        rows.append(Text(f"assert: {ev['assertion']}", style="bold yellow"))
    if ev.get("flag"):
        rows.append(Text(f"flag:   {ev['flag']}", style="bold green"))
    color = {"VERIFIED": "red", "SAFE": "green"}.get(status or "", "yellow")
    return Panel(Group(*rows), title="[bold]proof[/]", border_style=color)


def _header() -> Panel:
    return Panel(
        Align.center(Text.assemble(
            ("ProofTrace", "bold red"),
            ("  ·  PR → reachability → exploit → proof", "white"))),
        border_style="red")


def run_live(files: list[str], llm: BaseLLM, model: str | None = None,
             backend: str = "auto", console: Console | None = None,
             pace: float = 1.0) -> dict[str, Any]:
    console = console or Console()
    events: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    done: set[str] = set()
    current = {"node": None}
    state_holder: dict[str, Any] = {}

    def layout(final: dict[str, Any] | None = None):
        status = (final or {}).get("status")
        top = Table.grid(expand=True)
        top.add_column(ratio=1)
        top.add_column(ratio=2)
        left = _pipeline_panel(current["node"], done, status)
        right = Group(_candidates_panel(candidates), _log_panel(events))
        top.add_row(left, right)
        parts = [_header(), top]
        if final and final.get("finding"):
            parts.append(_proof_panel(final))
        return Group(*parts)

    with Live(layout(), console=console, refresh_per_second=12, screen=False) as live:
        def on_event(ev: dict[str, Any]):
            node = ev.get("node")
            if current["node"] and current["node"] != node:
                done.add(current["node"])
            current["node"] = node
            events.append(ev)
            if ev.get("candidates"):
                candidates.clear()
                candidates.extend(ev["candidates"])
            live.update(layout())
            time.sleep(0.55 * pace)  # let each node beat breathe for the recording

        final = investigation.run_investigation(
            files, llm, model=model, backend=backend,
            validate_live=True, on_event=on_event)
        done.update(STAGE_IDS)
        current["node"] = None
        live.update(layout(final))
        time.sleep(1.2 * pace)
        return final
