# Verify Check 3 — Behavior preservation

A fix that breaks legitimate use is not shippable, however secure.

## Steps

1. Run the surrounding test suite (`vulnscan-runtest` or the project's runner).
   Report pass/fail counts.
2. Reason about legitimate inputs the fix now touches: does valid data still
   flow through? Did an allow-list become too strict? Did input validation
   reject good values?
3. If the fix changes a public contract (return shape, error codes, accepted
   input), that must be called out — silent contract changes are `NEEDS-WORK`.

## Output

`behavior: pass` only if the suite is green and no legitimate path is broken.
Regressions → list them.
