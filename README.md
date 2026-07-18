# vulnscan

**GitHub:** https://github.com/JakeFin1972/vulnscan

A standalone, attacker-first source-code vulnerability scanner. Traces
attacker-reachable entry points forward to dangerous sinks, then **adversarially
falsifies every candidate** before reporting — so what reaches you is a short
list of defensible findings, not a wall of maybes.

The analysis brain is a Claude Code skill (Opus-class model). A small Python
CLI does Phase-1 recon and hands the skill a focused starting map. A local
**FastAPI engine + React web UI** provide a professional interface for managing
scans, findings, and language definitions.

**Languages shipped:** Python (stdlib AST) and C#/.NET (tree-sitter via a
declarative YAML definition). Adding a new language requires **only a new YAML
file** — no changes to core Python code.

## Authorized use only

Defensive tooling for code **you own or are explicitly authorized to test**. The
skill confirms authorization before scanning and scopes reproductions to the
minimum a code owner needs to confirm a finding on their own system — not
turnkey exploits.

---

## Layout

```
pyproject.toml              # installable package + console scripts
install.sh / uninstall.sh
skills/
  vulnscan/                 # Hunt → Disprove → Report
  vulnscan-fix/             # TDD remediation: RED → GREEN → review
  vulnscan-verify/          # independent, read-only fix check
src/vulnscan/
  recon.py                  # Phase-1 recon orchestrator + CLI (vulnscan-recon)
  harness.py                # single-test runner (vulnscan-runtest)
  api.py                    # FastAPI engine  (vulnscan.api:app)
  languages/
    __init__.py             # registry: YAML backends > native backends
    base.py                 # Hit dataclass + SOURCE_RANK + LanguageBackend protocol
    generic_backend.py      # generic tree-sitter backend driven by YAML defs
    yaml_loader.py          # YAML def validation with descriptive errors
    python_backend.py       # Python (stdlib AST — no tree-sitter required)
    csharp_backend.py       # C# legacy backend (kept for backward compat)
    defs/
      csharp.yaml           # declarative C# sources + sinks (authoritative)
      <newlang>.yaml        # drop here to add a language — zero .py edits needed
ui/
  src/                      # React + Vite + Tailwind + shadcn/ui
  dist/                     # built output (after npm run build)
tests/
  test_recon.py             # recon orchestrator + Python backend
  test_csharp.py            # C# backend (tree-sitter)
  test_harness.py           # RED → GREEN test gate
  test_yaml_backend.py      # YAML loader validation, generic backend, parity
  test_api.py               # FastAPI endpoints
```

---

## Install

```bash
./install.sh
# • Copies skills/ → ~/.claude/skills/
# • pip install -e ".[dev]"
# • npm install && npm run build   (if npm is available)
```

In an externally-managed Python environment, add `--break-system-packages` to
the pip line inside `install.sh`, or activate a venv first.

---

## Run

### Web UI + API

```bash
# Start the API (serves at http://127.0.0.1:8765)
uvicorn vulnscan.api:app --host 127.0.0.1 --port 8765

# Serve the UI (any static server, or Vite's preview)
cd ui && npm run preview          # http://localhost:4173
```

Then open the UI in your browser. The Dashboard lets you start scans, view
findings by severity, and check language coverage. The **Languages screen** has
a YAML editor with live validation — the headline feature for adding new
languages.

OpenAPI docs are at `http://localhost:8765/docs`.

### CLI

```bash
# Phase-1 recon — fast candidate map
vulnscan-recon /path/to/authorized/repo --json recon.json

# Full analysis (inside Claude Code, Opus-class model)
/vulnscan

# TDD fix loop
/vulnscan-fix

# Independent fix verification
/vulnscan-verify

# Deterministic RED→GREEN gate
vulnscan-runtest --repo . --python "tests/test_sec.py::test_no_sqli"
```

---

## Adding a language

1. Create `src/vulnscan/languages/defs/<name>.yaml` (see `csharp.yaml` for the
   full schema and predicate reference).
2. Install the tree-sitter grammar: `pip install tree-sitter-<name>`.
3. Restart the API. The new language appears immediately in `/languages` and the
   UI — no Python code changes needed.

The UI's Languages screen also has a built-in YAML editor with live validation
and a dry-run rule count preview.

**Supported match predicates:**

| Predicate | Node type | Meaning |
|-----------|-----------|---------|
| `has_attribute` | `method_declaration` | Method has one of these attribute names |
| `has_class_attribute` | `method_declaration` | Enclosing class has one of these attribute names |
| `in_class_deriving` | `method_declaration` | Enclosing class base list contains one (exact) |
| `in_class_deriving_endswith` | `method_declaration` | Enclosing class base name ends with one |
| `is_public` | `method_declaration` | Method has `public` modifier |
| `name_startswith` | `method_declaration` | Method name starts with one of these |
| `callee_leaf_in` | `invocation_expression` | Callee last segment in list |
| `callee_dotted_endswith` | `invocation_expression` | Callee dotted text ends with one |
| `type_in` | `object_creation_expression` | Object type name in list |

---

## Test

```bash
# With an activated venv / uv:
python -m pytest -q
# or
PYTHONPATH=src .venv/bin/python -m pytest -q
```

47 tests across recon, C# backend, harness RED→GREEN cycle, YAML validation,
generic backend parity, and API endpoints.

---

## Provenance

Clean-room design inspired by the public method Capital One described in their
open-source VulnHunter. Phase names, schema, recon heuristics, and
falsification kill-conditions are original — not a fork. Apache-2.0.
