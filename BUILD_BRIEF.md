# Claude Code build brief — vulnscan, professional edition

## Mission
Take the existing `vulnscan` project (a forward-taint adversarial vulnerability
scanner) from a CLI + Claude Code skills into a **well-functioning, easy-to-use,
professional tool** with a clean local web UI and a **config-driven language
system** so new languages can be added without touching core code.

## Non-negotiable scope
This is **defensive tooling for authorized code review only.** Keep the
authorized-use confirmation in the scanner skill. The scanner produces *minimal
reproductions for a code owner to confirm a finding on their own system* — never
generalized, portable exploits. Do not remove or weaken these guardrails.

## What already exists (build on it, don't rewrite from scratch)
- `src/vulnscan/recon.py` — Phase-1 recon orchestrator + `vulnscan-recon` CLI.
- `src/vulnscan/languages/` — pluggable backends: `python_backend.py` (stdlib
  AST) and `csharp_backend.py` (tree-sitter). Each exposes
  `scan_file(path) -> list[Hit]`; registry degrades gracefully if a grammar is missing.
- `src/vulnscan/harness.py` — `vulnscan-runtest`, deterministic pytest/dotnet gate.
- `skills/vulnscan`, `skills/vulnscan-fix`, `skills/vulnscan-verify` — the
  Hunt → Fix → Verify method as Claude Code skills.
- `tests/` — 15 passing tests. Keep them green.

## Deliverables

### 1. Config-driven language definitions (the core upgrade)
Replace hardcoded per-language dicts with **declarative definition files** under
`languages/defs/*.yaml`, consumed by a single generic tree-sitter backend.
Adding a language must require **only** a new YAML file plus its tree-sitter
grammar dependency — zero changes to core Python.

Definition schema (implement exactly this; validate on load with a clear error):
```yaml
name: csharp
extensions: [".cs"]
grammar: tree_sitter_c_sharp        # importable module exposing .language()
sources:
  - id: aspnet_action
    category: http_handler          # must map to a known attacker-proximity rank
    match: { node: method_declaration, has_attribute: [HttpGet, HttpPost, Route] }
  - id: minimal_api
    category: http_handler
    match: { node: invocation_expression, callee_leaf_in: [MapGet, MapPost] }
sinks:
  - id: sql_exec
    category: sql_query
    match: { node: invocation_expression,
             callee_leaf_in: [ExecuteReader, ExecuteNonQuery, FromSqlRaw, ExecuteSqlRaw] }
  - id: sql_new
    category: sql_query
    match: { node: object_creation_expression, type_in: [SqlCommand] }
  - id: os_command
    category: os_command
    match: { node: invocation_expression, callee_dotted_endswith: [Process.Start] }
```
Supported `match` predicates: `node` (tree-sitter node type), `has_attribute`,
`callee_leaf_in`, `callee_dotted_endswith`, `type_in`, plus `in_class_deriving`
(for controller-convention detection). Port the existing Python and C# backends
to this format; keep the stdlib-AST Python path only if a tree-sitter-python def
can't reach parity (justify in a comment).

### 2. Engine API
A local `FastAPI` service (`vulnscan.api`) exposing:
- `POST /scans` — start recon+scan on an authorized path; returns a scan id.
- `GET /scans/{id}` / `GET /scans` — status + history.
- `GET /findings?scan_id=` — findings in the existing report schema.
- `GET /languages` / `POST /languages` / `PUT /languages/{name}` — read and
  validate language definitions (validation only writes if the def parses).
- `POST /runtest` — proxy to the harness for RED/GREEN gating.
Add OpenAPI docs, CORS for the local UI, and a `--host/--port` flag.

### 3. Professional local web UI
A single-page app (React + Vite + Tailwind + shadcn/ui) served locally, talking
to the API. Must be **fast, keyboard-navigable, and free of marketing fluff.**
Screens:
- **Dashboard** — scan summary, severity breakdown, findings-over-time, language
  coverage.
- **Findings** — dense filterable table (severity, language, category, CWE);
  detail drawer showing the **source→sink path** (monospaced, file:line hops),
  the disproof log, capability, and fix status. Severity color-coded.
- **Scans** — history, re-run, per-scan counts.
- **Languages** — list every definition with source/sink counts; an editor to
  add/edit a YAML def with **live validation** and a "dry-run against a sample
  file" preview. This is the headline feature — make adding a language obvious.
- **Settings** — engine host/port, authorized-paths allowlist.

### 4. Keep the CLI, skills, and tests first-class
The UI is additive. `vulnscan-recon`, `vulnscan-runtest`, and the three skills
must keep working. Update `install.sh` and `README.md`.

## Design bar (easy-to-use + professional)
- Clean, dense, security-tooling aesthetic. Slate/graphite base, one teal accent,
  clear severity ramp (critical→low). Inter for UI, a mono face for code/paths.
- Empty states, loading states, and error states all handled — never a blank page.
- Every destructive or scan action confirms the target path is authorized.

## Acceptance criteria (all must be objectively true)
1. `python -m pytest` passes, including **new** tests for the generic backend,
   YAML validation, and the API endpoints.
2. Adding `languages/defs/<newlang>.yaml` (with its grammar installed) makes that
   language scannable with **no edits** to any `.py` file — proven by a test that
   loads a fixture def and finds a planted source+sink.
3. C# and Python parity: the ported defs reproduce today's findings on the
   existing sample repos (snapshot test).
4. `uvicorn vulnscan.api:app` serves; `GET /findings` returns the report schema.
5. `npm run build` produces the UI; it loads, lists findings from a seeded scan,
   opens a finding's source→sink path, and the Languages screen validates a good
   def and rejects a malformed one with a specific message.
6. Graceful degradation: a def whose grammar isn't installed is skipped with a
   warning, not a crash.

## Out of scope
Cloud hosting, multi-user auth, and the batch/headless runtime. Local-first only.

## Working style
Small commits, tests alongside code, no invented tree-sitter APIs — verify node
types and field names against the installed grammar before writing matchers.
Keep prose in the UI and docs direct and expertise-forward.
