# Fix Phase 4 — Review and hand off

Goal: a reviewable package a human can merge with confidence, and a clean hand-off
to independent verification.

## Emit

```json
{
  "finding_id": "VULN-001",
  "status": "fixed",
  "fix_point": "sink|boundary",
  "diff": "<unified diff of the change>",
  "rationale": "what was open in one sentence; what closes it in one sentence",
  "security_test": "path::name of the RED->GREEN test",
  "red_result": "failed before fix (reason)",
  "green_result": "passes after fix; suite: N passed, 0 regressions",
  "sibling_sites": ["file:line ...  fixed | scoped-out because ..."],
  "residual_risk": "contract changes, follow-ups, or 'none'",
  "owner": "single accountable owner for this change"
}
```

## Rules

- If Phase 1 said **not reproduced**, emit that instead — no diff, no test.
- Do not merge on your own say-so. Hand the diff + finding to `vulnscan-verify`
  for an independent, read-only check. Its NEEDS-WORK verdict outranks your
  confidence.
- Keep the write-up in the operator's preferred voice: direct, no filler.
