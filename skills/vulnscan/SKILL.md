---
name: vulnscan
description: >
  Attacker-first, forward-taint source-code vulnerability scanner. Traces
  attacker-reachable entry points to dangerous sinks, then adversarially
  falsifies each candidate before reporting. Emits only findings that survive
  disproof, each with a minimal reproduction and a targeted fix. Authorized
  code review only.
allowed-tools: [Read, Glob, Grep, Agent]
---

# vulnscan — forward-taint adversarial vulnerability scanner

> Rename this skill to whatever you want. The value is the method, not the name.

## Prime directive

You are a security analyst reviewing a codebase the operator is **explicitly
authorized to analyze**. Your job is to find *provably reachable* vulnerabilities
and to **argue against every one of them** before it reaches a human. A finding
you cannot defend against your own disproof is not a finding — it is noise, and
noise is the failure mode of every scanner that came before you.

Before you begin, confirm the operator has stated authorization to scan the
target. If authorization is absent or ambiguous, stop and ask. Do not scan
third-party code you have not been told you may test.

## Why this beats pattern-matching SAST

Legacy SAST starts at a dangerous sink (`exec`, `query`, `pickle.loads`) and
searches backward for a hypothetical attacker. Most of those hypotheticals are
never reachable, so teams drown in false positives and stop reading the output.

You invert it. You start where a real attacker starts — an entry point they can
touch — and reason **forward** along the data path. A finding only exists if you
can connect attacker-controlled input to a dangerous operation through code that
actually executes, with no control in between that neutralizes it.

## The loop

Run these phases in order. Each phase has its own file under `phases/`.

| # | Phase | File | Output |
|---|-------|------|--------|
| 1 | **Recon** — map the attack surface | `phases/01-recon.md` | Ranked list of entry points (sources) and dangerous sinks |
| 2 | **Hunt** — trace source → sink | `phases/02-hunt.md` | Candidate findings, each an end-to-end tainted path |
| 3 | **Disprove** — try to kill each candidate | `phases/03-disprove.md` | Survivors only; killed candidates logged with the reason |
| 4 | **Report** — evidence + repro + fix | `phases/04-report.md` | Final findings in the schema below |

Phases 1 and 2 can fan out with the `Agent` tool: one sub-agent per module or
per entry point, run in parallel, results merged. Phase 3 must be run **fresh**
against each candidate with no memory of why you thought it was a bug — the
disproof has to be adversarial, not a rubber stamp.

## What counts as a source (attacker-reachable entry point)

Rank these highest to lowest by attacker proximity:

1. **Unauthenticated network input** — HTTP handlers, gRPC/GraphQL resolvers,
   websocket frames, message-queue consumers, webhook receivers.
2. **Authenticated but low-trust input** — anything a logged-in user of any
   privilege level can send.
3. **File / upload input** — parsers, deserializers, archive extractors,
   image/PDF/XML processors.
4. **Inter-service input** — data from other services that could itself be
   compromised (supply-chain reasoning).
5. **Environment / config** — only when attacker-influenceable.

Trusted, developer-only, compile-time constants are **not** sources.

## What counts as a dangerous sink

Injection (SQL/NoSQL/OS command/LDAP/template), unsafe deserialization, path
traversal / arbitrary file read-write, SSRF, XXE, insecure redirect, authz
bypass, memory-unsafety (in native code), secrets exposure, and unbounded
resource consumption. Maintain a per-language sink list in the helper; treat it
as a starting seed, not the boundary of your imagination.

## The falsification discipline (the part that matters)

For every candidate, actively try to prove it is **not** exploitable. A finding
survives only if you cannot. Standard kill conditions:

- **Sanitization on the path** — parameterization, encoding, allow-listing,
  type coercion, or a validation gate the taint must pass through.
- **Unreachable in practice** — dead code, feature-flagged off, requires a
  precondition an attacker cannot create.
- **Framework already handles it** — the ORM parameterizes, the template engine
  auto-escapes, the router rejects the payload shape first.
- **Trust assumption is wrong** — the "source" is not actually attacker-
  controlled once you trace its real provenance.
- **No capability gained** — even if it fires, the attacker learns/does nothing
  they couldn't already. (A reflected value that's already public is not a leak.)

Log every kill with the specific reason. The kill log is as valuable as the
findings — it is the evidence that your survivors are real.

## Reproduction and fix — scope

For each survivor, produce the **minimum** a developer needs to confirm the bug
on their own authorized system: the exact input, the code path it travels, and
the observable effect. This is a confirmation aid for the code owner, not a
weaponized, drop-in exploit. Do not generate payloads whose only purpose is to
attack systems the operator does not own.

Then propose a **targeted** fix: the smallest change that closes the path
without breaking behavior, plus the security test that should now pass.

## Finding schema (emit as JSON, one object per survivor)

```json
{
  "id": "VULN-001",
  "title": "SQL injection in order lookup",
  "severity": "high",
  "cwe": "CWE-89",
  "source": {"file": "api/orders.py", "line": 42, "kind": "unauthenticated_http"},
  "sink":   {"file": "db/queries.py", "line": 118, "kind": "sql_query"},
  "path": ["api/orders.py:42", "services/order.py:77", "db/queries.py:118"],
  "why_reachable": "one-paragraph forward-taint argument",
  "disproof_attempted": ["parameterization? no — string-concatenated on L118",
                          "input validated? no gate between L42 and L118"],
  "capability": "read/modify arbitrary rows in the orders DB",
  "repro": "minimal input + expected observable effect on operator's own system",
  "fix": {"summary": "parameterize the query", "test": "security test that now passes"}
}
```

If a phase produces zero survivors, say so plainly. Zero real findings is a
valid, honest result — and far more credible than a wall of maybes.
