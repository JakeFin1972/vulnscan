# Verify Check 2 — Fix completeness

A fix that closes only the exact input the test used is not a fix.

## Ask

1. **Same sink, other sources.** Do other parameters, headers, body fields, or
   routes reach the same sink unneutralized?
2. **Same pattern, sibling sites.** Grep for the vulnerable pattern elsewhere.
   Were identical holes on the same path left open?
3. **Structural vs. cosmetic.** Did the fix use a robust structural close
   (parameterization, safe API, allow-list) or a blocklist/character filter that
   a different payload evades? Blocklist-only fixes are `NEEDS-WORK`.
4. **Whole path.** Trace source→sink again post-fix. Is the taint genuinely
   broken, or merely narrowed?

## Output

`completeness: pass` only if the taint path is structurally closed and no sibling
site on the same path remains open. Otherwise list the open paths explicitly.
