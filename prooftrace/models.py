"""Typed data model shared across the ProofTrace pipeline.

Plain dataclasses with JSON (de)serialisation so every stage's output is
inspectable on disk and reproducible — a reviewer can diff the graph JSON, the
finding, and the run ledger without running the agent.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    ROUTE = "route"            # an HTTP route handler
    SOURCE = "source"          # attacker-controlled input (path param, query, body)
    SINK = "sink"              # sensitive operation (DB read/write)
    SANITIZER = "sanitizer"    # auth / ownership / authorization check
    CALL = "call"              # an intermediate function call


class EdgeKind(str, Enum):
    FLOWS_TO = "flows_to"      # dataflow: value moves from a -> b
    CALLS = "calls"            # control-flow: a invokes b
    GUARDS = "guards"          # a sanitizer guards b


@dataclass
class Node:
    id: str
    kind: NodeKind
    label: str
    file: str
    line: int
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind


@dataclass
class AppGraph:
    """Source->sink graph extracted from the changed code by tree-sitter."""
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def node(self, node_id: str) -> Node | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def out_edges(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.src == node_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }

    def to_json(self, path: str | None = None) -> str:
        s = json.dumps(self.to_dict(), indent=2, default=str)
        if path:
            with open(path, "w") as fh:
                fh.write(s)
        return s

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AppGraph":
        nodes = [Node(**{**n, "kind": NodeKind(n["kind"])}) for n in d["nodes"]]
        edges = [Edge(**{**e, "kind": EdgeKind(e["kind"])}) for e in d["edges"]]
        return cls(nodes=nodes, edges=edges)


@dataclass
class ReachabilityPath:
    """A concrete path source -> ... -> sink and whether a guard covers it."""
    route: str
    source: str
    sink: str
    node_ids: list[str]
    guarded: bool                 # is there an ownership/authorization check?
    reason: str
    endpoint: str                 # HTTP method + path, e.g. "GET /api/invoices/{id}"
    object_param: str | None = None  # the attacker-controlled id param

    @property
    def is_candidate(self) -> bool:
        """Unguarded source->sink = a BOLA candidate worth investigating."""
        return not self.guarded


@dataclass
class HttpExchange:
    request: str
    response_status: int
    response_body: str


@dataclass
class Evidence:
    """Output of the live validator — the ground truth, no LLM involved."""
    exploit_reproduced: bool
    exchanges: list[HttpExchange] = field(default_factory=list)
    flag: str | None = None
    attacker_user: str | None = None
    victim_user: str | None = None
    assertion: str = ""

    def transcript(self) -> str:
        out = []
        for ex in self.exchanges:
            out.append(ex.request)
            out.append(f"-> {ex.response_status} {ex.response_body}")
            out.append("")
        return "\n".join(out).strip()


@dataclass
class Finding:
    title: str
    cwe: str
    endpoint: str
    status: str                    # "VERIFIED" | "UNPROVEN" | "SAFE"
    severity: str
    path: ReachabilityPath | None
    hypothesis: str
    evidence: Evidence | None
    confidence: str = "n/a"        # coarse secondary label only

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "cwe": self.cwe,
            "endpoint": self.endpoint,
            "status": self.status,
            "severity": self.severity,
            "path": asdict(self.path) if self.path else None,
            "hypothesis": self.hypothesis,
            "evidence": asdict(self.evidence) if self.evidence else None,
            "confidence": self.confidence,
        }


@dataclass
class RunRecord:
    """One investigation run — the unit the cost-to-recall experiment counts."""
    model: str
    run_index: int
    hit: bool                      # did this run reach a VERIFIED finding?
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    wall_seconds: float
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
