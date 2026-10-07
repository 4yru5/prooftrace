"""Render the AppGraph to Graphviz DOT (and SVG/PNG if `dot` is installed).

Two views from the same JSON:
  * sparse  — just the diff's nodes (before reachability)
  * proven  — the attacker-controlled source->sink path lit red, the cleared
              safe path greyed, ownership guards drawn as green checks

Looks like a compiler tool, embeds in the README, versionable, zero runtime.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .models import AppGraph, EdgeKind, NodeKind, ReachabilityPath

_FILL = {
    NodeKind.ROUTE: "#1f2937",
    NodeKind.SOURCE: "#b45309",
    NodeKind.SINK: "#7c2d12",
    NodeKind.SANITIZER: "#14532d",
    NodeKind.CALL: "#374151",
}
_SHAPE = {
    NodeKind.ROUTE: "box",
    NodeKind.SOURCE: "cds",
    NodeKind.SINK: "cylinder",
    NodeKind.SANITIZER: "octagon",
    NodeKind.CALL: "box",
}


def to_dot(graph: AppGraph, proven: ReachabilityPath | None = None,
           title: str = "ProofTrace reachability graph") -> str:
    proven_nodes = set(proven.node_ids) if proven else set()
    proven_edges = set()
    if proven:
        ids = proven.node_ids
        proven_edges = {(ids[i], ids[i + 1]) for i in range(len(ids) - 1)}

    lines = [
        "digraph ProofTrace {",
        '  rankdir=LR;',
        '  bgcolor="transparent";',
        f'  label="{title}"; labelloc=t; fontcolor="#e5e7eb"; fontname="Helvetica"; fontsize=12;',
        '  node [style="filled,rounded", fontname="Helvetica", fontcolor="#f9fafb", '
        'color="#4b5563", fontsize=11];',
        '  edge [color="#6b7280", fontname="Helvetica", fontcolor="#9ca3af", fontsize=9];',
    ]

    for n in graph.nodes:
        fill = _FILL.get(n.kind, "#374151")
        shape = _SHAPE.get(n.kind, "box")
        pen = ""
        label = n.label.replace('"', "'")
        sub = ""
        if n.kind == NodeKind.SINK and n.meta.get("owner_filtered"):
            sub = "\\n(owner-filtered ✓)"
        if n.id in proven_nodes:
            pen = ', color="#ef4444", penwidth=2.4'
        lines.append(
            f'  "{n.id}" [label="{label}{sub}", shape={shape}, '
            f'fillcolor="{fill}"{pen}];'
        )

    for e in graph.edges:
        key = (e.src, e.dst)
        attrs = []
        if e.kind == EdgeKind.GUARDS:
            attrs.append('color="#22c55e"')
            attrs.append('label="guards"')
            attrs.append("style=dashed")
        elif e.kind == EdgeKind.FLOWS_TO:
            attrs.append('label="flows to"')
        if key in proven_edges:
            attrs.append('color="#ef4444"')
            attrs.append("penwidth=2.4")
        attr = f" [{', '.join(attrs)}]" if attrs else ""
        lines.append(f'  "{e.src}" -> "{e.dst}"{attr};')

    lines.append("}")
    return "\n".join(lines)


def render(dot: str, out_path: str, fmt: str = "svg") -> str | None:
    """Render DOT to SVG/PNG using the `dot` CLI if present. Returns path or None."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    dot_file = out.with_suffix(".dot")
    dot_file.write_text(dot)
    if not shutil.which("dot"):
        return str(dot_file)  # at least the DOT source is written
    subprocess.run(
        ["dot", f"-T{fmt}", str(dot_file), "-o", str(out)],
        check=True,
    )
    return str(out)


def render_views(graph: AppGraph, proven: ReachabilityPath | None,
                 out_dir: str) -> dict[str, str | None]:
    d = Path(out_dir)
    sparse = to_dot(graph, None, "ProofTrace — diff graph (before reachability)")
    full = to_dot(graph, proven, "ProofTrace — proven source→sink path (red)")
    return {
        "sparse_svg": render(sparse, str(d / "graph_sparse.svg")),
        "proven_svg": render(full, str(d / "graph_proven.svg")),
    }
