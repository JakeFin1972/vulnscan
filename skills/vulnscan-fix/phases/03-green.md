# Fix Phase 3 — GREEN: the minimal fix

Goal: close the path with the smallest correct change, and prove it.

## Steps

1. Apply the fix at the point chosen in Phase 1. Typical closes:
   - **Injection** → parameterized queries / prepared statements; never string
     concatenation into the sink. (SQL, OS command, LDAP, template.)
   - **Deserialization** → safe serializer / allow-listed types; never
     deserialize untrusted data with a polymorphic formatter.
   - **Path traversal** → resolve and confirm the final path stays within an
     allow-listed root; reject otherwise.
   - **SSRF** → allow-list destinations; block internal ranges.
   - **XXE** → disable DTD / external entity resolution.
2. Re-run the RED test → it must now **pass**.
3. Run the surrounding suite → **no regressions**. A break means the fix is too
   broad or wrong. Revise the fix; never weaken or delete the failing test to
   make it green.
4. Fix every sibling site noted in Phase 1, or explicitly scope them out with a
   reason. "Closed one of several identical holes" is not done.

## Anti-patterns (reject these)

- Blocklist filtering of "bad characters" — leaks; use structural fixes.
- Catching the exception the exploit throws — hides the bug, doesn't close it.
- Loosening the test until it passes — that is fabricating a GREEN.
