# Fix Phase 2 — RED: a test that fails because the bug exists

Goal: a security test that encodes the *safe* expectation and fails today.

## What a good RED test looks like

- **Exercises the real path.** Call the actual handler/function that the finding
  names. Do not mock the vulnerable call away — that tests nothing.
- **Asserts safety, not the exploit.** e.g. "a row with id `1 OR 1=1` is not
  returned", "the shell is never invoked with attacker text", "traversal input
  cannot read outside the allowed dir". The assertion describes correct behavior;
  the vulnerability makes it fail.
- **Minimal, local payload.** Use the smallest input that demonstrates the flaw,
  against the operator's own code in the test harness. Not a portable exploit.
- **Fails for the right reason.** Run it. Read the failure. Confirm it fails
  *because of the vulnerability*, not an import error, fixture typo, or skip.

## Run it deterministically

```
vulnscan-runtest --repo <path> --python "tests/test_security_<id>.py::test_<name>"
# or
vulnscan-runtest --repo <path> --dotnet "FullyQualifiedName~Security_<id>_<name>"
```

The harness returns pass/fail so RED/GREEN aren't a judgment call.

## Gate

Do not go to GREEN until this test **fails as intended**. A RED phase that
passes, errors, or skips means the rest of the run proves nothing.
