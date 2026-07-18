"""C# / .NET source-sink locator (tree-sitter).

Detects ASP.NET Core entry points (controller actions, minimal-API endpoints,
Razor Page handlers) as sources, and common injection / deserialization / file /
SSRF / command sinks. Candidates only — the LLM phases decide exploitability.
"""
from __future__ import annotations

from pathlib import Path

from .base import Hit

name = "csharp"
extensions = (".cs",)

# --- Catalogs (seed, not a boundary) ------------------------------------------
# Invocation callee leaf/dotted -> category. Dotted keys (with a ".") are matched
# by suffix; bare keys are matched on the callee's last segment.
CS_SINK_CALLS: dict[str, str] = {
    "ExecuteReader": "sql_query",
    "ExecuteNonQuery": "sql_query",
    "ExecuteScalar": "sql_query",
    "ExecuteReaderAsync": "sql_query",
    "ExecuteNonQueryAsync": "sql_query",
    "ExecuteScalarAsync": "sql_query",
    "ExecuteSqlRaw": "sql_query",
    "ExecuteSqlRawAsync": "sql_query",
    "FromSqlRaw": "sql_query",
    "SqlQueryRaw": "sql_query",
    "Process.Start": "os_command",
    "Deserialize": "unsafe_deser",
    "ReadAllText": "file_access",
    "WriteAllText": "file_access",
    "ReadAllBytes": "file_access",
    "WriteAllBytes": "file_access",
    "OpenRead": "file_access",
    "OpenWrite": "file_access",
    "Path.Combine": "path_traversal_candidate",
    "GetAsync": "ssrf_candidate",
    "GetStringAsync": "ssrf_candidate",
    "GetByteArrayAsync": "ssrf_candidate",
    "CreateInstance": "reflection",
    "Assembly.Load": "reflection",
    "Redirect": "open_redirect_candidate",
}

# `new <Type>(...)` -> category.
CS_SINK_NEW: dict[str, str] = {
    "SqlCommand": "sql_query",
    "Process": "os_command",
    "BinaryFormatter": "unsafe_deser",
    "NetDataContractSerializer": "unsafe_deser",
    "LosFormatter": "unsafe_deser",
    "ObjectStateFormatter": "unsafe_deser",
    "SoapFormatter": "unsafe_deser",
    "XmlTextReader": "xxe_candidate",
}

HTTP_ATTRS = {"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch",
              "HttpHead", "Route"}
CONTROLLER_ATTRS = {"ApiController", "Controller"}
MINIMAL_API = {"MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch", "MapMethods"}

# Lazy singletons so importing this module never fails if the grammar is absent.
_PARSER = None


def _parser():
    global _PARSER
    if _PARSER is None:
        from tree_sitter import Language, Parser
        import tree_sitter_c_sharp
        _PARSER = Parser(Language(tree_sitter_c_sharp.language()))
    return _PARSER


def _line(node) -> int:
    return node.start_point[0] + 1


def _leaf(dotted: str) -> str:
    seg = dotted.split(".")[-1]
    return seg.split("<")[0].strip()  # drop generic args, e.g. CreateInstance<T>


def _match_sink_call(dotted: str) -> str | None:
    leaf = _leaf(dotted)
    for key, cat in CS_SINK_CALLS.items():
        if "." in key:
            if dotted == key or dotted.endswith("." + key):
                return cat
        elif leaf == key:
            return cat
    return None


def _attr_names(node) -> set[str]:
    """Attribute identifiers on a class/method (from its attribute_list children)."""
    names: set[str] = set()
    for child in node.children:
        if child.type == "attribute_list":
            for att in child.children:
                if att.type == "attribute":
                    n = att.child_by_field_name("name")
                    if n is not None:
                        names.add(_leaf(n.text.decode()))
    return names


def _is_controller_class(node) -> bool:
    if _attr_names(node) & CONTROLLER_ATTRS:
        return True
    for child in node.children:
        if child.type == "base_list":
            for ident in child.children:
                if ident.type == "identifier":
                    t = ident.text.decode()
                    if t == "ControllerBase" or t.endswith("Controller"):
                        return True
    return False


def _is_public(method_node) -> bool:
    return any(c.type == "modifier" and c.text.decode() == "public"
              for c in method_node.children)


def _walk(node, in_controller: bool, path: str, hits: list[Hit]) -> None:
    t = node.type

    if t == "class_declaration":
        in_controller = _is_controller_class(node)

    elif t == "method_declaration":
        attrs = _attr_names(node)
        name_node = node.child_by_field_name("name")
        mname = name_node.text.decode() if name_node else "<anon>"
        if attrs & HTTP_ATTRS:
            hits.append(Hit("source", "http_handler", path, _line(node), mname, "csharp"))
        elif in_controller and _is_public(node):
            hits.append(Hit("source", "http_handler", path, _line(node), mname, "csharp"))
        elif mname.startswith(("OnGet", "OnPost", "OnPut", "OnDelete")):
            hits.append(Hit("source", "razor_handler", path, _line(node), mname, "csharp"))

    elif t == "invocation_expression":
        fn = node.child_by_field_name("function")
        if fn is not None:
            dotted = fn.text.decode().replace("\n", "").strip()
            if _leaf(dotted) in MINIMAL_API:
                hits.append(Hit("source", "http_handler", path, _line(node), dotted, "csharp"))
            cat = _match_sink_call(dotted)
            if cat:
                hits.append(Hit("sink", cat, path, _line(node), dotted, "csharp"))

    elif t == "object_creation_expression":
        ty = node.child_by_field_name("type")
        if ty is not None:
            cat = CS_SINK_NEW.get(_leaf(ty.text.decode()))
            if cat:
                hits.append(Hit("sink", cat, path, _line(node),
                                "new " + ty.text.decode(), "csharp"))

    for child in node.children:
        _walk(child, in_controller, path, hits)


def scan_file(path: Path) -> list[Hit]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    tree = _parser().parse(data)
    hits: list[Hit] = []
    _walk(tree.root_node, False, str(path), hits)
    return hits
