# Verify Check 1 — Test integrity

The security test is the fixer's evidence. First, decide if the evidence is real.

## Ask

1. **Real path?** Does the test call the actual handler/function named in the
   finding, or does it mock away the vulnerable line? A test of a mock proves
   nothing about the real path.
2. **Revert check (the important one).** Reason about the test against the
   *pre-fix* code (read the diff to reconstruct it). Would the test have failed
   before the fix? If you cannot convince yourself it would, the test does not
   actually detect this bug — it is theater. If the operator supplies a
   read-only checkout of the pre-fix state, run the test there and confirm it
   fails; you do not edit code to do this.
3. **Passes for the right reason?** Not skipped, not xfail, not erroring on
   setup, not asserting something trivially true regardless of the fix.

## Fail conditions

- Test mocks the sink or source.
- Test would still pass with the fix reverted.
- Test is skipped/errored/trivial.

Any of these → `test_integrity: fail`, and the overall verdict cannot be PASS.
