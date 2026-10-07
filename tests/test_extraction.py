"""tree-sitter extraction + reachability: the graph must be earned, not hardcoded."""
from __future__ import annotations

from prooftrace import reachability
from prooftrace.extract import extract_graph
from prooftrace.models import NodeKind

TARGET = ["target_app/app/main.py"]


def test_graph_recovers_routes_sources_sinks():
    g = extract_graph(TARGET)
    kinds = [n.kind for n in g.nodes]
    assert NodeKind.ROUTE in kinds
    assert NodeKind.SOURCE in kinds
    assert NodeKind.SINK in kinds
    assert NodeKind.SANITIZER in kinds  # auth dependency detected


def test_vulnerable_endpoint_is_flagged():
    g = extract_graph(TARGET)
    cands = reachability.candidates(reachability.analyze(g))
    endpoints = {c.endpoint for c in cands}
    assert "GET /api/invoices/{invoice_id}" in endpoints


def test_secure_endpoint_is_cleared_precision():
    """Same-shape ownership-filtered endpoint must NOT be flagged (precision)."""
    g = extract_graph(TARGET)
    paths = reachability.analyze(g)
    secure = [p for p in paths if p.endpoint.endswith("/secure")]
    assert secure, "secure endpoint path should be present"
    assert all(p.guarded for p in secure)
    cand_endpoints = {c.endpoint for c in reachability.candidates(paths)}
    assert "GET /api/invoices/{invoice_id}/secure" not in cand_endpoints


def test_exactly_one_candidate():
    g = extract_graph(TARGET)
    cands = reachability.candidates(reachability.analyze(g))
    assert len(cands) == 1  # only the real BOLA, no false positives


def test_source_is_attacker_controlled_path_param():
    g = extract_graph(TARGET)
    cand = reachability.candidates(reachability.analyze(g))[0]
    assert cand.object_param == "invoice_id"
