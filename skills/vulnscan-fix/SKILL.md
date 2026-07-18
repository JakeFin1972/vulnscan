---
name: vulnscan-fix
description: >
  Test-driven remediation for a single verified vulnerability finding. Writes a
  failing security test that proves the bug (RED), implements the smallest fix
  that closes the taint path (GREEN), confirms no regressions, and produces a
  reviewable diff. Authorized code only.
allowed-tools: [Read, Edit, Glob, Grep, Bash]
---

# vulnscan-fix — test-driven vulnerability remediation

Input: **one** finding object from the scanner's report schema (source, sink,
path, capability), plus write access to the repo it came from.

## Prime directive

Close the vulnerability with the **smallest change that provably works**, and
prove it with a test that fails before your fix and passes after. You are
editing code the operator is authorized to change. A fix you cannot back with a
failing-then-passing test is not a fix — it is a hope.

Before editing, confirm the operator wants this finding fixed in this repo. Fix
one finding per run; batch fixes hide regressions.

## Guardrails

- **Minimal.** Prefer the narrowest correct change (parameterize the query,
  encode at the sink, validate at the boundary). Do not refactor unrelated code.
- **No behavior loss.** Legitimate inputs must still work. If the safe fix
  changes a contract, say so explicitly in the review — don't silently break it.
- **Scoped proof, not a weapon.** The RED test uses the *minimum* malicious-shaped
  input needed to demonstrate the flaw, and it lives in the test harness against
  the operator's own code. Do not produce a general, portable exploit.
- **One finding, one fix, one test.** Keep the diff reviewable.

## Phase 1 — Reproduce and pin (`phases/01-reproduce.md`)

Re-derive the bug yourself; don't trust the report blindly. Read the full
source→sink path, confirm the taint reaches the sink with no neutralizer, and
identify the single best place to break the path. If you *cannot* re-confirm the
finding, stop and report it as **not reproduced** — do not invent a fix.

## Phase 2 — RED (`phases/02-red.md`)

Write a security test that asserts the *safe* behavior and therefore **fails
today** because the vulnerability exists. Requirements:

- It exercises the real path (calls the actual handler/function, not a mock of
  the vulnerable line).
- It fails **for the right reason** — the vulnerability — not a typo, import
  error, or skipped test.
- Run it and confirm it fails. Use the harness for a deterministic result:
  `vulnscan-runtest --repo <path> --python "<nodeid>"` (or `--dotnet "<filter>"`).

A RED phase that doesn't produce a genuine, correctly-reasoned failure invalidates
everything after it. Do not proceed until the test fails as intended.

## Phase 3 — GREEN (`phases/03-green.md`)

Implement the minimal fix. Then:

1. Re-run the security test — it must now **pass**.
2. Run the surrounding suite — confirm **no regressions**. If something breaks,
   the fix is too broad or wrong; revise, don't suppress.
3. If the same vulnerable pattern appears at sibling call sites on the same
   path, note them — a fix that closes one of five identical holes is not done.

## Phase 4 — Review (`phases/04-review.md`)

Produce: the diff, a two-sentence rationale (what was open, what closes it), the
new test, the regression result, and any residual risk (sibling sites, contract
changes, follow-ups). Assign one owner for the change. Hand off to
`vulnscan-verify` for an independent check before merge.
