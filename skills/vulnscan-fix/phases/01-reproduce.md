# Fix Phase 1 — Reproduce and pin

Goal: independently confirm the finding is real and choose exactly where to break
the taint path.

## Steps

1. Read the finding: source, sink, path hops, claimed capability.
2. Open each file on the path. Trace the tainted value forward yourself. Confirm
   there is no neutralizer between source and sink.
3. Decide the fix point. Prefer, in order:
   - **At the sink** — parameterize / encode / use the safe API (most robust;
     closes the path regardless of caller).
   - **At the boundary** — strict validation / allow-listing on entry (good when
     the sink can't be changed).
   - Avoid mid-path string scrubbing / blocklists — they leak.
4. Note every sibling call site that shares the same sink or pattern. They are
   part of this fix's scope even if the report listed only one.

## Stop condition

If you cannot re-confirm the taint actually reaches the sink unneutralized,
**do not fix**. Report "not reproduced" with what you checked. A fix for a
non-bug adds risk and noise.
