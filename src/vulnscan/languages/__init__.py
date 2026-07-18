"""Language backend registry.

Priority order:
  1. YAML-driven backends loaded from languages/defs/*.yaml (generic tree-sitter).
     A YAML backend whose grammar module can't be imported is registered but
     skipped at scan time with a warning (graceful degradation).
  2. Native Python backend (stdlib AST) — kept because tree-sitter-python is
     not a standard dependency and the stdlib AST reaches equivalent coverage
     for the sources/sinks we care about. If a tree-sitter-python def is added
     to defs/ it will take precedence for .py files automatically.

Adding a new language requires ONLY a new .yaml file in languages/defs/ plus
its tree-sitter grammar package — no edits to any .py file.
"""
from __future__ import annotations

import sys
from pathlib import Path

from . import python_backend
from .base import Hit
from .generic_backend import YamlBackend, load_backends_from_defs

_DEFS_DIR = Path(__file__).parent / "defs"

# ── Load YAML backends ────────────────────────────────────────────────────────
_YAML_BACKENDS: list[YamlBackend] = []
_YAML_GRAMMAR_ERRORS: dict[str, str] = {}  # name -> error message

for _backend, _err in load_backends_from_defs(_DEFS_DIR):
    _YAML_BACKENDS.append(_backend)
    if _err:
        _YAML_GRAMMAR_ERRORS[_backend.name] = _err

# ── Build extension → backend map ────────────────────────────────────────────
# YAML backends take priority; native backends fill in the rest.
_BY_EXT: dict[str, object] = {}

# Native Python backend (stdlib AST) — registered first as the fallback
for _ext in python_backend.extensions:
    _BY_EXT[_ext] = python_backend

# YAML backends override native ones for their extensions
for _b in _YAML_BACKENDS:
    for _ext in _b.extensions:
        _BY_EXT[_ext] = _b

# Keep csharp_backend importable for backward compatibility (test_csharp.py
# imports it directly to probe grammar availability). But the registry no
# longer uses it — csharp.yaml is authoritative for .cs files.

SUPPORTED_EXTENSIONS = tuple(sorted(_BY_EXT))


def backend_for(path: Path):
    return _BY_EXT.get(path.suffix)


def scan_path(path: Path) -> list[Hit]:
    backend = backend_for(path)
    if backend is None:
        return []
    # Graceful degradation: YAML backends with missing grammars return [] from
    # scan_file (the grammar probe in load_backends_from_defs already warned).
    try:
        return backend.scan_file(path)
    except Exception as exc:  # noqa: BLE001
        print(f"warning: scan of {path} failed ({exc}); skipping", file=sys.stderr)
        return []


def warn_if_degraded() -> None:
    for name, err in _YAML_GRAMMAR_ERRORS.items():
        print(f"warning: language '{name}' unavailable: {err}", file=sys.stderr)
    # Legacy path: if csharp is handled by YAML, no separate csharp warning needed.
    # If somehow csharp.yaml is missing, nothing to warn about (it simply isn't registered).
