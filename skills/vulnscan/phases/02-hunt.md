# Phase 2 — Hunt: trace source → sink

Goal: for each promising source, follow attacker-controlled data **forward**
until it either reaches a dangerous sink or provably dies.

## Method

1. Pick a source from the Phase 1 inventory, highest attacker-proximity first.
2. Model the tainted value. Follow it through assignments, function calls,
   returns, and object fields. Taint propagates through: string ops,
   concatenation, formatting, collection membership, and most transforms.
3. Taint is **cleared** only by a genuine neutralizer: parameterized query
   binding, context-correct encoding, strict allow-list validation, safe type
   coercion. Note where clearing happens — you will re-examine it in Phase 3.
4. If the tainted value reaches a sink still attacker-influencable, record a
   **candidate** with the full path (file:line at each hop).
5. If it dies, drop it silently — no candidate.

## Rules

- Trace real call graphs, not names. A function called `sanitize()` that does
  nothing is not sanitization; read it.
- Cross file and module boundaries. Most real bugs span layers (controller →
  service → data access).
- Interprocedural is mandatory; do not stop at the first function boundary.
- Do not judge exploitability here — that is Phase 3. Phase 2 is generous;
  Phase 3 is ruthless. Keeping those roles separate is what controls false
  positives.

## Fan-out

One `Agent` per source (or per source cluster) traced in parallel; merge
candidates. Each candidate carries its own path evidence.

## Output

A list of candidate findings, each an end-to-end path from source to sink.
Expect this list to be too long. Phase 3 will cut it down.
