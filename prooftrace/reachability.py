"""Reachability pass over the AppGraph.

For every route, decide whether an attacker-controlled source reaches a
sensitive sink *without an ownership/authorization guard on the path*. An
unguarded source->sink is a BOLA candidate; a guarded one is cleared.

Authentication (identity) is deliberately NOT treated as an ownership guard:
the whole BOLA class is "authenticated but not authorized". This distinction is
the precision signal — the safe endpoint must come back cleared.
"""
from __future__ import annotations

from .models import AppGraph, EdgeKind, NodeKind, ReachabilityPath


def _sink_is_owner_guarded(graph: AppGraph, sink_id: str) -> bool:
    """True if a SANITIZER guards this sink via an ownership filter."""
    for e in graph.edges:
        if e.kind == EdgeKind.GUARDS and e.dst == sink_id:
            return True
    return False


def analyze(graph: AppGraph) -> list[ReachabilityPath]:
    paths: list[ReachabilityPath] = []

    routes = [n for n in graph.nodes if n.kind == NodeKind.ROUTE]
    for route in routes:
        endpoint = route.label
        # sources attached to this route
        source_ids = [
            e.dst
            for e in graph.out_edges(route.id)
            if e.kind == EdgeKind.CALLS
            and (graph.node(e.dst) or _dummy()).kind == NodeKind.SOURCE
        ]
        # the route meta records whether any sink was owner-filtered (safe)
        owner_filtered = bool(route.meta.get("owner_filtered_sink"))
        ownership_check = bool(route.meta.get("ownership_check"))

        for source_id in source_ids:
            source = graph.node(source_id)
            if source is None:
                continue
            # which sinks does this source flow to?
            for e in graph.out_edges(source_id):
                if e.kind != EdgeKind.FLOWS_TO:
                    continue
                sink = graph.node(e.dst)
                if sink is None or sink.kind != NodeKind.SINK:
                    continue

                sink_guarded = _sink_is_owner_guarded(graph, sink.id)
                guarded = sink_guarded or owner_filtered or ownership_check

                if guarded:
                    reason = (
                        "object scoped to caller: an ownership filter / check "
                        "constrains the sink to the authenticated user"
                    )
                else:
                    reason = (
                        "attacker-controlled path param reaches a DB read with "
                        "authentication but NO ownership check — the returned "
                        "object can belong to another user (BOLA / CWE-639)"
                    )

                paths.append(
                    ReachabilityPath(
                        route=route.meta.get("func", route.id),
                        source=source_id,
                        sink=sink.id,
                        node_ids=[route.id, source_id, sink.id],
                        guarded=guarded,
                        reason=reason,
                        endpoint=endpoint,
                        object_param=source.meta.get("param"),
                    )
                )

    return paths


def candidates(paths: list[ReachabilityPath]) -> list[ReachabilityPath]:
    """Only the unguarded source->sink paths — the ones worth exploiting."""
    return [p for p in paths if p.is_candidate]


class _Dummy:
    kind = None


def _dummy() -> "_Dummy":
    return _Dummy()
