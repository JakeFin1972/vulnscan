"""Load and validate YAML language definition files.

Schema (validate on load — fail fast with a clear error):
  name: str
  extensions: list[str]        # each must start with "."
  grammar: str                 # importable module exposing .language()
  sources: list[Rule]
  sinks: list[Rule]

Rule schema:
  id: str
  category: str                # must be in SOURCE_RANK for sources
  match:
    node: str                  # tree-sitter node type (required)
    # one or more of the following predicates:
    has_attribute: list[str]           # method/class has one of these attributes
    has_class_attribute: list[str]     # enclosing class has one of these attributes
    in_class_deriving: list[str]       # enclosing class base list contains one (exact)
    in_class_deriving_endswith: list[str]  # enclosing class base ends with one
    is_public: bool                    # method has "public" modifier
    name_startswith: list[str]         # node name starts with one of these
    callee_leaf_in: list[str]          # invocation callee last segment in list
    callee_dotted_endswith: list[str]  # invocation callee dotted path ends with one
    type_in: list[str]                 # object_creation_expression type in list
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml as _yaml
except ImportError as _e:
    raise ImportError(
        "pyyaml is required for YAML language definitions. "
        "Install with: pip install pyyaml"
    ) from _e

from .base import SOURCE_RANK

_KNOWN_SOURCE_CATS = set(SOURCE_RANK.keys())
_VALID_MATCH_PREDICATES = {
    "node",
    "has_attribute",
    "has_class_attribute",
    "in_class_deriving",
    "in_class_deriving_endswith",
    "is_public",
    "name_startswith",
    "callee_leaf_in",
    "callee_dotted_endswith",
    "type_in",
}


class YamlDefinitionError(ValueError):
    """Raised when a YAML language definition fails validation."""


def _check(condition: bool, msg: str) -> None:
    if not condition:
        raise YamlDefinitionError(msg)


def _validate_rule(rule: Any, kind: str, index: int) -> None:
    prefix = f"{kind}[{index}]"
    _check(isinstance(rule, dict), f"{prefix}: must be a mapping")
    _check("id" in rule, f"{prefix}: missing required key 'id'")
    _check(isinstance(rule["id"], str) and rule["id"],
           f"{prefix}: 'id' must be a non-empty string")
    _check("category" in rule, f"{prefix}: missing required key 'category'")
    _check(isinstance(rule["category"], str) and rule["category"],
           f"{prefix}: 'category' must be a non-empty string")
    if kind == "sources":
        _check(rule["category"] in _KNOWN_SOURCE_CATS,
               f"{prefix}(id={rule['id']}): unknown source category '{rule['category']}'. "
               f"Known categories: {sorted(_KNOWN_SOURCE_CATS)}")
    _check("match" in rule, f"{prefix}(id={rule['id']}): missing required key 'match'")
    match = rule["match"]
    _check(isinstance(match, dict), f"{prefix}(id={rule['id']}): 'match' must be a mapping")
    _check("node" in match, f"{prefix}(id={rule['id']}): 'match' must contain 'node'")
    _check(isinstance(match["node"], str) and match["node"],
           f"{prefix}(id={rule['id']}): 'match.node' must be a non-empty string")
    unknown = set(match.keys()) - _VALID_MATCH_PREDICATES
    if unknown:
        raise YamlDefinitionError(
            f"{prefix}(id={rule['id']}): unknown match predicates: {sorted(unknown)}. "
            f"Supported: {sorted(_VALID_MATCH_PREDICATES)}"
        )
    # List predicates must actually be lists of strings
    for list_pred in ("has_attribute", "has_class_attribute", "in_class_deriving",
                      "in_class_deriving_endswith", "name_startswith",
                      "callee_leaf_in", "callee_dotted_endswith", "type_in"):
        if list_pred in match:
            val = match[list_pred]
            _check(isinstance(val, list) and all(isinstance(s, str) for s in val),
                   f"{prefix}(id={rule['id']}): '{list_pred}' must be a list of strings")
    if "is_public" in match:
        _check(isinstance(match["is_public"], bool),
               f"{prefix}(id={rule['id']}): 'is_public' must be a boolean")


def load_yaml_def(path: Path) -> dict:
    """Load and validate a YAML language definition file.

    Returns the validated definition dict.
    Raises YamlDefinitionError with a descriptive message on any problem.
    """
    try:
        raw = _yaml.safe_load(path.read_text(encoding="utf-8"))
    except _yaml.YAMLError as exc:
        raise YamlDefinitionError(f"{path.name}: YAML parse error: {exc}") from exc

    _check(isinstance(raw, dict), f"{path.name}: top-level must be a mapping")
    for key in ("name", "extensions", "grammar"):
        _check(key in raw, f"{path.name}: missing required top-level key '{key}'")
    _check(isinstance(raw["name"], str) and raw["name"],
           f"{path.name}: 'name' must be a non-empty string")
    _check(isinstance(raw["extensions"], list) and raw["extensions"],
           f"{path.name}: 'extensions' must be a non-empty list")
    for ext in raw["extensions"]:
        _check(isinstance(ext, str) and ext.startswith("."),
               f"{path.name}: each extension must be a string starting with '.', got {ext!r}")
    _check(isinstance(raw["grammar"], str) and raw["grammar"],
           f"{path.name}: 'grammar' must be a non-empty string (importable module name)")

    for section in ("sources", "sinks"):
        rules = raw.get(section, [])
        _check(isinstance(rules, list),
               f"{path.name}: '{section}' must be a list")
        for i, rule in enumerate(rules):
            _validate_rule(rule, section, i)

    return raw
