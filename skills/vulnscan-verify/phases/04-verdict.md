# Verify Check 4 — New risk, then verdict

## New risk

Did closing this hole open another?
- A new sink introduced by the fix (e.g. logging the raw payload, a new file
  write, a new outbound request).
- A new trust assumption (now trusting a header/flag that an attacker controls).
- Secrets or sensitive data newly exposed in errors or logs.

## Verdict

Combine all four checks:

- **PASS** — test integrity holds, path structurally closed, no regressions, no
  new risk.
- **NEEDS-WORK** — on the right track but incomplete: blocklist fix, open sibling
  path, contract change, or a weak test. List exactly what to change.
- **FAIL** — the test is theater or the path is still open.

Emit the verdict JSON from SKILL.md. Do not soften a verdict to be agreeable;
the fixer's confidence is not evidence, and a wrong PASS is worse than an honest
NEEDS-WORK.
