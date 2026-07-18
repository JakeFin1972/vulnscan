# Phase 4 — Report: evidence, reproduction, fix

Goal: for each survivor, emit one finding object (schema in SKILL.md) that a
developer can act on without re-doing your analysis.

## For each survivor

1. **Forward-taint argument.** One tight paragraph: how attacker input reaches
   the sink, and why no control on the path stops it. Reference the path hops.
2. **Disproof summary.** State which kill conditions you tried and why each
   failed. This is what makes the finding credible — show your work.
3. **Capability.** Concretely, what the attacker gains (read X, modify Y,
   execute Z). Drives severity, not gut feeling.
4. **Severity + CWE.** Map to CWE. Severity from capability × reachability, not
   from how scary the sink name sounds.
5. **Reproduction — scoped.** The minimum a code owner needs to confirm on
   *their own authorized system*: the exact input shape, the path it travels,
   the observable effect. Not a turnkey exploit for arbitrary targets.
6. **Fix.** Smallest change that closes the path without breaking behavior, plus
   the security test that should now pass (a test that fails today, passes after
   the fix).

## Output rules

- Emit JSON per the SKILL.md schema, one object per survivor.
- Include the Phase 3 kill log as an appendix so reviewers see what was ruled
  out and why.
- **Zero survivors is a valid report.** Say so plainly and attach the kill log.
  An honest empty result beats a padded one — that credibility is the whole
  point of the tool.
