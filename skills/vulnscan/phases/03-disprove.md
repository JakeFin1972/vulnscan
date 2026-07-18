# Phase 3 — Disprove: adversarial falsification

Goal: kill every candidate you can. Only the survivors are findings.

This is the phase that separates this tool from pattern-matchers. Run it with a
**fresh, hostile mindset**: assume each candidate is wrong and that a skeptical
senior engineer will reject it. Your task is to build their rejection for them —
and only report the candidate if you fail.

## For each candidate, attempt every kill condition

1. **Sanitization re-audit.** Re-read every node on the path. Is there a
   neutralizer you missed? Read the *implementation* of anything that looks like
   validation. Framework defaults count (ORM parameterization, template
   auto-escaping, router type/shape rejection).
2. **Reachability.** Is the path actually executed? Dead code, disabled feature
   flag, unregistered route, requires state an attacker cannot produce, guarded
   by an authz check they cannot pass?
3. **Trust re-check.** Is the source *really* attacker-controlled once you trace
   its true origin? A value from an internal, non-attacker-influenced config is
   not tainted.
4. **Capability test.** If it fires, what does the attacker actually gain? If
   the answer is "nothing they didn't already have / nothing sensitive," kill it.
5. **Preconditions.** List every condition required to trigger it. If the
   conjunction is implausible for a real attacker, downgrade or kill.

## Discipline

- A candidate that relies on an **unsupported assumption** ("maybe this input
  isn't validated upstream") is **killed**, not reported. Go verify the
  assumption; if you cannot, it fails.
- Record the kill reason for every dropped candidate. The kill log is a
  deliverable — it proves the survivors earned their place.
- Do **not** soften a kill into a "low-severity finding" to avoid a zero result.
  Killed means gone.

## Output

- **Survivors** → forwarded to Phase 4 with their disproof-attempt notes.
- **Kill log** → every dropped candidate with the specific reason it died.
