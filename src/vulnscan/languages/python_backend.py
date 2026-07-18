"""Python source/sink locator (stdlib AST)."""
from __future__ import annotations

import ast
from pathlib import Path

from .base import Hit

SINK_CALLS: dict[str, str] = {
    "eval": "code_exec",
    "exec": "code_exec",
    "os.system": "os_command",
    "os.popen": "os_command",
    "subprocess.call": "os_command",
    "subprocess.run": "os_command",
    "subprocess.Popen": "os_command",
    "pickle.load": "unsafe_deser",
    "pickle.loads": "unsafe_deser",
    "yaml.load": "unsafe_deser",
    "marshal.loads": "unsafe_deser",
    "cursor.execute": "sql_query",
    "cursor.executemany": "sql_query",
    "open": "file_access",
    "requests.get": "ssrf_candidate",
    "requests.post": "ssrf_candidate",
    "urllib.request.urlopen": "ssrf_candidate",
    "render_template_string": "template_injection",
    "send_file": "path_traversal_candidate",
}

SOURCE_DECORATORS: dict[str, str] = {
    "route": "http_handler",
    "get": "http_handler",
    "post": "http_handler",
    "put": "http_handler",
    "delete": "http_handler",
    "websocket": "ws_handler",
    "task": "queue_consumer",
}

name = "python"
extensions = (".py",)


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def scan_file(path: Path) -> list[Hit]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, ValueError):
        return []

    hits: list[Hit] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            if dotted:
                for key, cat in SINK_CALLS.items():
                    key_leaf = key.split(".")[-1]
                    if dotted == key or dotted.endswith("." + key) or dotted == key_leaf:
                        hits.append(Hit("sink", cat, str(path), node.lineno, dotted, "python"))
                        break
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = _dotted(dec.func) if isinstance(dec, ast.Call) else _dotted(dec)
                leaf = dec_name.split(".")[-1] if dec_name else ""
                if leaf in SOURCE_DECORATORS:
                    hits.append(Hit("source", SOURCE_DECORATORS[leaf],
                                    str(path), node.lineno, node.name, "python"))
    return hits
