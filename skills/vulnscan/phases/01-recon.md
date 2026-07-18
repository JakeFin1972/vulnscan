# Phase 1 — Recon: map the attack surface

Goal: produce two ranked inventories — **sources** (attacker-reachable entry
points) and **sinks** (dangerous operations) — before you trace anything.

## Steps

1. **Fingerprint the stack.** Identify languages, frameworks, and the request
   lifecycle. Where does external input enter? (Route tables, controller
   decorators, message handlers, `main()` arg parsing, deserializers.)
2. **Enumerate sources.** Glob/Grep for entry-point markers per framework.
   For Python: route/handler decorators. For C#/.NET: `[HttpGet/HttpPost/...]`
   actions, public methods on `Controller`/`ControllerBase` classes, minimal-API
   `app.MapGet/MapPost/...`, and Razor `OnGet/OnPost` handlers. Record file:line
   and classify by attacker proximity (see SKILL.md).
3. **Enumerate sinks.** If a recon seed was generated
   (`vulnscan-recon <repo> --json recon.json`), load `recon.json` for the
   candidate source/sink inventory and prioritised same-file pairs. Otherwise
   Grep for the framework's sink patterns directly. Record file:line and category.
4. **Rank.** Sort sources by attacker proximity, sinks by blast radius. The
   Cartesian product is your candidate space — but you will not brute-force it.
   Phase 2 only chases pairs where a plausible data path exists.

## Fan-out

For a large repo, spawn one `Agent` per top-level module to build partial
inventories, then merge. Deduplicate by file:line.

## Output

Two lists. Do not analyze reachability yet — that is Phase 2. Resist the urge to
flag a scary-looking sink now; a sink with no reachable source is not a finding.
