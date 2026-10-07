"""ProofTrace CLI — one entrypoint for analyze / demo / cost-to-recall / graph / watch.

`prooftrace demo` is the self-running 90s demo: it streams the live
investigation, renders the graph, posts the proof, and plots cost-to-recall —
no clicks, no key.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from . import cost_to_recall, graphviz_render, pr, pr_comment, tui
from .extract import extract_graph
from .investigation import run_investigation
from .llm import get_llm
from .models import AppGraph, ReachabilityPath
from . import reachability

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
DEMO_MODEL = os.environ.get("PROOFTRACE_MODEL", "qwen2.5-coder:7b")
COST_MODELS = ["qwen2.5-coder:32b", "qwen2.5-coder:7b", "qwen2.5-coder:1.5b"]
PACE = float(os.environ.get("PROOFTRACE_PACE", "1.0"))


def _beat(seconds: float) -> None:
    time.sleep(seconds * PACE)


def _console() -> Console:
    return Console(highlight=False)


def _title_card(c: Console) -> None:
    c.print()
    c.print(Panel(
        Text.assemble(
            ("ProofTrace\n", "bold red"),
            ("PR → Reachability → Exploit → Proof\n\n", "bold white"),
            ("A security reviewer that proves a vulnerability is reachable and\n", "white"),
            ("exploitable before it says a word.  100% local · no API key.", "dim"),
        ),
        border_style="red", padding=(1, 4)))
    _beat(2.2)


def _show_pr(c: Console) -> None:
    m = pr.meta()
    c.print()
    c.print(Panel(
        Text.assemble(
            (f"PR #{m['number']}  ", "bold cyan"), (m["title"] + "\n", "bold white"),
            (f"{m['author']} wants to merge {m['branch']} → {m['base']}\n\n", "dim"),
            (m["description"], "white")),
        title="[bold]incoming pull request[/]", border_style="cyan"))
    c.print(Syntax(pr.diff_text(), "diff", theme="ansi_dark", line_numbers=False))
    c.print(Text("  authenticated · parameterized query → a scanner sees nothing.",
                 style="italic yellow"))
    _beat(4.0)


def _render_graphs(final: dict) -> dict:
    graph = AppGraph.from_dict(final["graph"])
    paths = reachability.analyze(graph)
    proven = next((p for p in paths if p.is_candidate), None)
    return graphviz_render.render_views(graph, proven, str(ART))


def _write_artifacts(final: dict, run_meta: dict) -> dict:
    ART.mkdir(parents=True, exist_ok=True)
    (ART / "app_graph.json").write_text(json.dumps(final["graph"], indent=2))
    (ART / "finding.json").write_text(json.dumps(final["finding"], indent=2, default=str))
    comment = pr_comment.render(final["finding"], run_meta)
    (ART / "pr_comment.md").write_text(comment)
    graphs = _render_graphs(final)
    return {"comment": comment, "graphs": graphs}


def cmd_analyze(args) -> int:
    c = _console()
    llm = get_llm(args.llm)
    c.print(f"[dim]investigator: {llm.name} · model {DEMO_MODEL}[/]")
    final = run_investigation(
        pr.changed_files(), llm, model=DEMO_MODEL,
        backend=args.backend, validate_live=True, max_attempts=3)
    run_meta = {**final.get("metrics", {}), "backend": final.get("backend"),
                "investigator": llm.name}
    out = _write_artifacts(final, run_meta)
    c.print(Markdown(out["comment"]))
    c.print(f"\n[green]artifacts →[/] {ART}")
    return 0 if final["status"] in ("VERIFIED", "SAFE") else 1


def cmd_graph(args) -> int:
    c = _console()
    graph = extract_graph(pr.changed_files())
    paths = reachability.analyze(graph)
    proven = next((p for p in paths if p.is_candidate), None)
    graphs = graphviz_render.render_views(graph, proven, str(ART))
    for k, v in graphs.items():
        c.print(f"[green]{k}[/] → {v}")
    return 0


def cmd_cost(args) -> int:
    c = _console()
    llm = get_llm(args.llm)
    illustrative = llm.name == "stub"
    c.print(Panel(Text.assemble(
        ("cost-to-recall\n", "bold red"),
        (f"investigator: {llm.name}  ·  {args.runs} runs × {len(COST_MODELS)} models\n", "white"),
        ("recall you buy with compute, not money (local $ ≈ 0)", "dim")),
        border_style="red"))
    files = pr.changed_files()

    def on_run(rec):
        mark = "[red]●[/]" if rec.hit else "[dim]○[/]"
        c.print(f"  {mark} {rec.model:22} run {rec.run_index:>2}  "
                f"hit={str(rec.hit):5}  {rec.completion_tokens} tok")

    results = cost_to_recall.run_experiment(files, llm, COST_MODELS, args.runs, on_run)
    summary = cost_to_recall.summarize(results)
    cost_to_recall.save_logs(results, summary, str(ART))
    chart = cost_to_recall.plot(summary, str(ART / "cost_to_recall.png"),
                                raw=results, illustrative=illustrative)
    c.print()
    for model, s in summary.items():
        c.print(f"[bold]{model}[/]: per-run {s['per_run_hit_rate']:.0%} · "
                f"recall@{s['runs']}={s['final_recall']:.0%} · "
                f"first hit @ run {s['runs_to_first_hit']}")
    c.print(f"\n[green]chart →[/] {chart}  [dim]({'illustrative/stub' if illustrative else 'live logs'})[/]")
    return 0


def cmd_demo(args) -> int:
    c = _console()
    llm = get_llm(args.llm)
    _title_card(c)
    _show_pr(c)
    c.print(f"\n[bold]▶ analyzing with {llm.name} (model {DEMO_MODEL})…[/]\n")
    final = tui.run_live(pr.changed_files(), llm, model=DEMO_MODEL,
                         backend=args.backend, console=c, pace=PACE)
    run_meta = {**final.get("metrics", {}), "backend": final.get("backend")}
    out = _write_artifacts(final, run_meta)
    _beat(2.5)  # peak 1: the live proof breathes

    c.print()
    c.print(Panel(Text.assemble(
        ("source→sink graph rendered — proven path in red, safe path cleared\n", "white"),
        (f"  sparse: {out['graphs'].get('sparse_svg')}\n", "dim"),
        (f"  proven: {out['graphs'].get('proven_svg')}", "dim")),
        title="[bold]graph[/]", border_style="grey37"))
    _beat(2.0)

    c.print()
    c.print(Panel(Markdown(out["comment"]), title="[bold]PR comment posted[/]",
                  border_style="red"))
    _beat(3.5)

    if not args.no_cost:
        c.print("\n[bold]▶ cost-to-recall — cheap model looped vs frontier once…[/]\n")
        files = pr.changed_files()
        # stream per-run hits live so there is motion, not dead air
        prev_fast = os.environ.get("PROOFTRACE_FAST")
        os.environ["PROOFTRACE_FAST"] = "1"
        tally: dict[str, list[bool]] = {m: [] for m in COST_MODELS}

        def on_run(rec):
            tally[rec.model].append(rec.hit)

        results = cost_to_recall.run_experiment(files, llm, COST_MODELS, args.runs, on_run)
        if prev_fast is None:
            os.environ.pop("PROOFTRACE_FAST", None)
        else:
            os.environ["PROOFTRACE_FAST"] = prev_fast
        summary = cost_to_recall.summarize(results)
        cost_to_recall.save_logs(results, summary, str(ART))
        chart = cost_to_recall.plot(summary, str(ART / "cost_to_recall.png"),
                                    raw=results, illustrative=(llm.name == "stub"))
        for model, s in summary.items():
            seq = "".join("●" if h else "·" for h in tally[model])
            r90 = s.get("runs_to_90pct_expected")
            tag = f"→90% @ {r90} runs" if r90 else ""
            c.print(f"  {model:22} per-run {s['per_run_hit_rate']:>4.0%}  "
                    f"[red]{seq}[/]  {tag}")
            _beat(0.8)
        c.print(f"\n[green]convergence chart →[/] {chart}")
        _beat(3.0)  # peak 2: the chart breathes

    c.print()
    c.print(Panel(Text(
        "The goal isn't more findings. It's fewer findings we can actually prove.",
        style="bold white", justify="center"), border_style="red"))
    _beat(3.0)
    return 0


def cmd_watch(args) -> int:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    c = _console()
    target = str((ROOT / "target_app").resolve())
    c.print(Panel(Text.assemble(
        ("continuous review\n", "bold red"),
        (f"watching {target}\n", "white"),
        ("every change re-runs the full ProofTrace gate — a gate, not a one-shot script.", "dim")),
        border_style="red"))

    class H(FileSystemEventHandler):
        def __init__(self):
            self.last = 0.0

        def on_any_event(self, event):
            if event.is_directory or not str(event.src_path).endswith(".py"):
                return
            if time.time() - self.last < 1.5:
                return
            self.last = time.time()
            c.print(f"\n[yellow]change detected:[/] {event.src_path} — re-reviewing…")
            llm = get_llm(args.llm)
            final = run_investigation(pr.changed_files(), llm, model=DEMO_MODEL,
                                      backend=args.backend, validate_live=True,
                                      max_attempts=3)
            st = final["status"]
            color = {"VERIFIED": "red", "SAFE": "green"}.get(st, "yellow")
            c.print(f"  [{color}]{st}[/] — {final['finding']['endpoint']}")

    obs = Observer()
    obs.schedule(H(), target, recursive=True)
    obs.start()
    c.print("[dim]ctrl-c to stop[/]")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="prooftrace", description=__doc__)
    p.add_argument("--llm", default=os.environ.get("PROOFTRACE_LLM", "auto"),
                   choices=["auto", "ollama", "stub"],
                   help="investigator backend (auto = Ollama if reachable, else stub)")
    p.add_argument("--backend", default=os.environ.get("PROOFTRACE_SANDBOX", "auto"),
                   choices=["auto", "docker", "subprocess"], help="validation sandbox")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("analyze", help="run the investigation on the PR, write artifacts")
    sub.add_parser("graph", help="render the reachability graph (DOT/SVG)")

    d = sub.add_parser("demo", help="the self-running 90s demo")
    d.add_argument("--runs", type=int, default=12)
    d.add_argument("--no-cost", action="store_true")

    ctr = sub.add_parser("cost-to-recall", help="run the convergence experiment")
    ctr.add_argument("--runs", type=int, default=20)

    sub.add_parser("watch", help="continuous review: re-run on every change")

    args = p.parse_args(argv)
    fn = {
        "analyze": cmd_analyze, "graph": cmd_graph, "demo": cmd_demo,
        "cost-to-recall": cmd_cost, "watch": cmd_watch,
    }[args.cmd]
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
