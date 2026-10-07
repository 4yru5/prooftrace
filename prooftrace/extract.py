"""tree-sitter extraction: changed Python files -> source->sink AppGraph.

We parse the real AST (not regex) and recover, per HTTP route:
  * sources     — attacker-controlled inputs (path params)
  * sinks       — DB operations (`.execute(...)`)
  * sanitizers  — authentication dependency (`Depends(authenticate)`)
  * guards      — an *ownership* check (SQL `WHERE owner = :user`, or an
                  explicit `owner_id == user` comparison) that scopes the
                  object to the caller

The guard vs no-guard distinction is the whole point: it is what separates a
safe endpoint from a BOLA (CWE-639) endpoint, and it is invisible to grep.
"""
from __future__ import annotations

import re
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Node as TSNode, Parser

from .models import AppGraph, Edge, EdgeKind, Node, NodeKind

PY_LANGUAGE = Language(tspython.language())

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
AUTH_DEP_NAMES = {"authenticate", "get_current_user", "current_user", "require_auth"}


def _parser() -> Parser:
    p = Parser()
    # tree-sitter >=0.22 sets language via attribute; older via constructor arg.
    try:
        p.language = PY_LANGUAGE
    except Exception:  # pragma: no cover - version shim
        p = Parser(PY_LANGUAGE)
    return p


def _text(node: TSNode, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _walk(node: TSNode):
    yield node
    for child in node.children:
        yield from _walk(child)


def _string_literals(node: TSNode, src: bytes) -> list[str]:
    out = []
    for n in _walk(node):
        if n.type == "string":
            raw = _text(n, src)
            out.append(raw.strip("'\"bfru"))  # crude but fine for our literals
    return out


def _sql_has_owner_filter(sql: str) -> bool:
    """Does the SQL scope rows to a caller-provided owner?"""
    s = sql.lower()
    return bool(re.search(r"where[^;]*\bowner(_id)?\b\s*(=|in)", s))


def _decorator_route(dec: TSNode, src: bytes) -> tuple[str, str] | None:
    """Return (METHOD, path) if decorator is `@<x>.<method>("<path>")`."""
    call = next((c for c in dec.children if c.type == "call"), None)
    if call is None:
        return None
    fn = call.child_by_field_name("function")
    if fn is None or fn.type != "attribute":
        return None
    attr = fn.child_by_field_name("attribute")
    method = _text(attr, src) if attr else ""
    if method.lower() not in HTTP_METHODS:
        return None
    args = call.child_by_field_name("arguments")
    paths = _string_literals(args, src) if args else []
    path = paths[0] if paths else "/"
    return method.upper(), path


def _path_params(path: str) -> list[str]:
    return re.findall(r"\{(\w+)\}", path)


def _function_defs(root: TSNode):
    """Yield (func_node, decorators) for every top-level function."""
    for n in _walk(root):
        if n.type == "decorated_definition":
            decs = [c for c in n.children if c.type == "decorator"]
            fdef = next(
                (c for c in n.children if c.type == "function_definition"), None
            )
            if fdef is not None:
                yield fdef, decs


def _param_names_with_auth(fdef: TSNode, src: bytes) -> tuple[list[str], bool]:
    """Return (param names, has_auth_dependency)."""
    params_node = fdef.child_by_field_name("parameters")
    names: list[str] = []
    has_auth = False
    if params_node is None:
        return names, has_auth
    text = _text(params_node, src)
    for n in _walk(params_node):
        if n.type == "identifier" and n.parent and n.parent.type in (
            "parameters",
            "default_parameter",
            "typed_parameter",
            "typed_default_parameter",
        ):
            nm = _text(n, src)
            if nm not in names:
                names.append(nm)
    if "Depends(" in text and any(a in text for a in AUTH_DEP_NAMES):
        has_auth = True
    return names, has_auth


def _db_calls(fdef: TSNode, src: bytes) -> list[tuple[int, str, str]]:
    """Return (line, kind, sql) for each `.execute(<sql>, ...)` call.

    kind is 'read' or 'write' inferred from the SQL verb.
    """
    out: list[tuple[int, str, str]] = []
    for n in _walk(fdef):
        if n.type != "call":
            continue
        fn = n.child_by_field_name("function")
        if fn is None or fn.type != "attribute":
            continue
        attr = fn.child_by_field_name("attribute")
        if attr is None or _text(attr, src) != "execute":
            continue
        args = n.child_by_field_name("arguments")
        sqls = _string_literals(args, src) if args else []
        sql = sqls[0] if sqls else ""
        verb = sql.strip().split(" ", 1)[0].lower() if sql else ""
        kind = "read" if verb in {"select", "pragma"} else "write"
        out.append((n.start_point[0] + 1, kind, sql))
    return out


def _has_ownership_comparison(fdef: TSNode, src: bytes, user_params: list[str]) -> bool:
    """Detect an explicit `owner_id == user` style guard in the body."""
    for n in _walk(fdef):
        if n.type == "comparison_operator":
            txt = _text(n, src)
            if "owner" in txt and any(u in txt for u in user_params):
                return True
    return False


def extract_graph(files: list[str]) -> AppGraph:
    """Build an AppGraph from a list of changed Python file paths."""
    graph = AppGraph()
    parser = _parser()

    for file in files:
        p = Path(file)
        if p.suffix != ".py" or not p.exists():
            continue
        src = p.read_bytes()
        tree = parser.parse(src)
        rel = str(p)

        for fdef, decs in _function_defs(tree.root_node):
            route = None
            for dec in decs:
                route = _decorator_route(dec, src)
                if route:
                    break
            if route is None:
                continue  # not an HTTP handler

            method, path = route
            endpoint = f"{method} {path}"
            fname = _text(fdef.child_by_field_name("name"), src)
            line = fdef.start_point[0] + 1

            route_id = f"route:{fname}"
            graph.nodes.append(
                Node(route_id, NodeKind.ROUTE, endpoint, rel, line, {"func": fname})
            )

            param_names, has_auth = _param_names_with_auth(fdef, src)
            sanitizer_id = None
            if has_auth:
                sanitizer_id = f"auth:{fname}"
                graph.nodes.append(
                    Node(
                        sanitizer_id,
                        NodeKind.SANITIZER,
                        "authenticate (identity)",
                        rel,
                        line,
                        {"kind": "authentication"},
                    )
                )
                graph.edges.append(Edge(sanitizer_id, route_id, EdgeKind.GUARDS))

            # sources: path params
            source_ids = []
            for param in _path_params(path):
                sid = f"source:{fname}:{param}"
                source_ids.append((sid, param))
                graph.nodes.append(
                    Node(
                        sid,
                        NodeKind.SOURCE,
                        f"path param `{param}`",
                        rel,
                        line,
                        {"attacker_controlled": True, "param": param},
                    )
                )
                graph.edges.append(Edge(route_id, sid, EdgeKind.CALLS))

            # sinks: DB calls, and whether an ownership filter scopes them
            owner_filtered_sink = False
            for sline, kind, sql in _db_calls(fdef, src):
                sink_id = f"sink:{fname}:{sline}"
                owner_filter = _sql_has_owner_filter(sql)
                owner_filtered_sink = owner_filtered_sink or owner_filter
                graph.nodes.append(
                    Node(
                        sink_id,
                        NodeKind.SINK,
                        f"db.execute ({kind})",
                        rel,
                        sline,
                        {"sql": sql, "op": kind, "owner_filtered": owner_filter},
                    )
                )
                for sid, _param in source_ids:
                    graph.edges.append(Edge(sid, sink_id, EdgeKind.FLOWS_TO))
                # a SQL-level owner filter is an ownership guard on this sink
                if owner_filter and sanitizer_id:
                    graph.edges.append(Edge(sanitizer_id, sink_id, EdgeKind.GUARDS))

            # explicit `owner_id == user` comparison guard anywhere in the body
            if _has_ownership_comparison(fdef, src, param_names) and sanitizer_id:
                # mark the route as having an authorization (not just authn) guard
                r = graph.node(route_id)
                if r:
                    r.meta["ownership_check"] = True

            # remember owner-filter result on the route for reachability
            r = graph.node(route_id)
            if r:
                r.meta["owner_filtered_sink"] = owner_filtered_sink

    return graph
