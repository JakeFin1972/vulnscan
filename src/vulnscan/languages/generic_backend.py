"""Generic tree-sitter backend driven by YAML language definition files.

Each YAML file under languages/defs/ describes sources and sinks using
declarative match predicates. Adding a new language requires only a new YAML
file plus its tree-sitter grammar package — no changes to core Python code.

Supported match predicates (see yaml_loader.py for the full schema):
  node                        tree-sitter node type (required)
  has_attribute               method has one of these attribute names
  has_class_attribute         enclosing class has one of these attribute names
  in_class_deriving           enclosing class base list contains one (exact name)
  in_class_deriving_endswith  enclosing class base name ends with one of these
  is_public                   method has "public" modifier (C#/Java-style)
  name_startswith             node's name field starts with one of these prefixes
  callee_leaf_in              invocation callee's last segment is in list
  callee_dotted_endswith      invocation callee's dotted text ends with one
  type_in                     object_creation_expression type name is in list
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

from .base import Hit

# ── Helpers for extracting node text ─────────────────────────────────────────

def _decode(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _leaf(dotted: str) -> str:
    """Last segment of a dotted name, stripping generic type args."""
    seg = dotted.split(".")[-1]
    return seg.split("<")[0].strip()


def _attr_names(node) -> set[str]:
    """Attribute identifiers attached to a method or class node."""
    names: set[str] = set()
    for child in node.children:
        if child.type == "attribute_list":
            for att in child.children:
                if att.type == "attribute":
                    n = att.child_by_field_name("name")
                    if n is not None:
                        names.add(_leaf(_decode(n)))
    return names


def _base_names(class_node) -> set[str]:
    """Base class / interface names from a class_declaration's base_list."""
    names: set[str] = set()
    for child in class_node.children:
        if child.type == "base_list":
            for item in child.children:
                if item.type in ("identifier", "generic_name"):
                    names.add(_decode(item).split("<")[0].strip())
    return names


def _is_public(node) -> bool:
    return any(c.type == "modifier" and _decode(c) == "public" for c in node.children)


def _method_name(node) -> str:
    n = node.child_by_field_name("name")
    return _decode(n) if n else "<anon>"


def _invocation_callee(node) -> str:
    fn = node.child_by_field_name("function")
    return _decode(fn).replace("\n", "").strip() if fn else ""


def _creation_type(node) -> str:
    # C# uses field "type"; TypeScript/JS new_expression uses field "constructor"
    ty = node.child_by_field_name("type") or node.child_by_field_name("constructor")
    return _leaf(_decode(ty)) if ty else ""


# ── Predicate matching ────────────────────────────────────────────────────────

def _matches(node, match: dict, ctx: dict) -> bool:
    """Return True if `node` satisfies all predicates in `match`."""
    node_type = node.type
    if match["node"] != node_type:
        return False

    # ── method_declaration predicates ────────────────────────────────────────
    if node_type == "method_declaration":
        if "has_attribute" in match:
            if not (_attr_names(node) & set(match["has_attribute"])):
                return False
        if "has_class_attribute" in match:
            if not (ctx.get("class_attrs", set()) & set(match["has_class_attribute"])):
                return False
        if "in_class_deriving" in match:
            bases = ctx.get("class_bases", set())
            if not (bases & set(match["in_class_deriving"])):
                return False
        if "in_class_deriving_endswith" in match:
            bases = ctx.get("class_bases", set())
            suffixes = match["in_class_deriving_endswith"]
            if not any(b.endswith(s) for b in bases for s in suffixes):
                return False
        if match.get("is_public") and not _is_public(node):
            return False
        if "name_startswith" in match:
            name = _method_name(node)
            if not any(name.startswith(p) for p in match["name_startswith"]):
                return False

    # ── invocation_expression (C#) / call_expression (TypeScript/JS) ─────────
    elif node_type in ("invocation_expression", "call_expression"):
        callee = _invocation_callee(node)
        if "callee_leaf_in" in match:
            if _leaf(callee) not in set(match["callee_leaf_in"]):
                return False
        if "callee_dotted_endswith" in match:
            suffixes = match["callee_dotted_endswith"]
            if not any(callee == s or callee.endswith("." + s) for s in suffixes):
                return False

    # ── object_creation_expression (C#) / new_expression (TypeScript/JS) ─────
    elif node_type in ("object_creation_expression", "new_expression"):
        if "type_in" in match:
            if _creation_type(node) not in set(match["type_in"]):
                return False

    else:
        # Unknown node type for the remaining predicates — skip non-node predicates
        pass

    return True


def _node_name(node) -> str:
    """Best-effort name for a matched node (used as Hit.name)."""
    t = node.type
    if t == "method_declaration":
        return _method_name(node)
    if t in ("invocation_expression", "call_expression"):
        return _invocation_callee(node)
    if t in ("object_creation_expression", "new_expression"):
        n = node.child_by_field_name("type") or node.child_by_field_name("constructor")
        return "new " + _decode(n) if n else "new <anon>"
    n = node.child_by_field_name("name")
    return _decode(n) if n else node.type


# ── AST walker ───────────────────────────────────────────────────────────────

def _walk(node, ctx: dict, rules: list[tuple[str, dict, str, str]],
          hits: list[Hit], path: str) -> None:
    """Recursively walk the tree-sitter AST, emitting Hits for matched rules.

    `rules` is a flat list of (kind, match_dict, category, language_name).
    `ctx`   carries class-level context through the recursion.
    """
    # Update class context when entering a class declaration
    if node.type == "class_declaration":
        ctx = dict(ctx)
        ctx["class_attrs"] = _attr_names(node)
        ctx["class_bases"] = _base_names(node)

    # Check each rule against the current node
    for kind, match, category, lang_name in rules:
        if _matches(node, match, ctx):
            hits.append(Hit(
                kind=kind,
                category=category,
                file=path,
                line=node.start_point[0] + 1,
                name=_node_name(node),
                language=lang_name,
            ))

    for child in node.children:
        _walk(child, ctx, rules, hits, path)


# ── Public backend class ──────────────────────────────────────────────────────

class YamlBackend:
    """A language backend backed by a YAML definition file."""

    def __init__(self, defn: dict) -> None:
        self.name: str = defn["name"]
        self.extensions: tuple[str, ...] = tuple(defn["extensions"])
        self._grammar_module: str = defn["grammar"]
        self._grammar_function: str = defn.get("grammar_function", "language")
        self._rules: list[tuple[str, dict, str, str]] = []
        for rule in defn.get("sources", []):
            self._rules.append(("source", rule["match"], rule["category"], self.name))
        for rule in defn.get("sinks", []):
            self._rules.append(("sink", rule["match"], rule["category"], self.name))
        self._parser = None

    def _get_parser(self):
        if self._parser is None:
            from tree_sitter import Language, Parser  # noqa: PLC0415
            mod = importlib.import_module(self._grammar_module)
            grammar_fn = getattr(mod, self._grammar_function)
            self._parser = Parser(Language(grammar_fn()))
        return self._parser

    def scan_file(self, path: Path) -> list[Hit]:
        try:
            data = path.read_bytes()
        except OSError:
            return []
        parser = self._get_parser()
        tree = parser.parse(data)
        hits: list[Hit] = []
        _walk(tree.root_node, {}, self._rules, hits, str(path))
        # Deduplicate: same kind + file + line + name might be matched by
        # multiple rules (e.g. a controller method that also has an HTTP attr).
        seen: set[tuple] = set()
        deduped: list[Hit] = []
        for h in hits:
            key = (h.kind, h.file, h.line, h.name)
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped


# ── Registry helpers ──────────────────────────────────────────────────────────

def load_backends_from_defs(defs_dir: Path) -> list[tuple[YamlBackend, str | None]]:
    """Load all YAML backends from `defs_dir/*.yaml`.

    Returns a list of (backend, error_msg) tuples.
    `error_msg` is None on success; set to a warning string if the grammar
    module can't be imported (backend is still returned but won't scan files).
    """
    from .yaml_loader import load_yaml_def, YamlDefinitionError  # noqa: PLC0415

    results: list[tuple[YamlBackend, str | None]] = []
    for yaml_path in sorted(defs_dir.glob("*.yaml")):
        try:
            defn = load_yaml_def(yaml_path)
        except YamlDefinitionError as exc:
            print(f"warning: skipping {yaml_path.name}: {exc}", file=sys.stderr)
            continue

        backend = YamlBackend(defn)

        # Probe grammar availability without crashing
        try:
            importlib.import_module(defn["grammar"])
            grammar_err = None
        except Exception as exc:  # noqa: BLE001
            grammar_err = (
                f"grammar '{defn['grammar']}' not installed ({exc}). "
                f"Install with: pip install {defn['grammar'].replace('_', '-')}"
            )
            print(f"warning: {yaml_path.name}: {grammar_err}", file=sys.stderr)

        results.append((backend, grammar_err))

    return results
