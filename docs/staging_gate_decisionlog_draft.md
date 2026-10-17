# DecisionLog additions — DRAFT for review (2026-10-17)

Paste into `06_Governance/DecisionLog.md` after checking. Nothing here is a result of running the Office
Scripts in Excel: every "run" below used the Python port (`staging_gate`) on a scratch copy of
`Test-version36-17Aug-BoardCyberShield.xlsx`, with a fake H2 output. The scripts' first run in the tenant,
and the Claude panel itself, are still untested.

## Decisions

| # | Date | Decision | Rationale | Status |
|---|---|---|---|---|
| 17 | 2026-10-17 | Python port of the gate (`staging_gate`: lock / apply / import-risks / rollup, H2 and H3 runner) alongside the Office Scripts | Lets the workflow be tested and run outside Excel on the web, and gives a second implementation of the same rules to compare against | Done, untested against a live API |
| 18 | 2026-10-17 | H2 output passes a mechanical ceiling guard before it reaches Staging: score capped by the evidence *types* cited (policy→1, +procedure→2, +config export→3, +test report→4; interview-only max 1; level 5 needs human confirmation); invented EV-IDs removed; unknown rows dropped; scores only ever lowered | The Test 3 failure (a wrong 3) produces a wrong board number; a prompt cannot guarantee the ceiling, code can. Guard changes are written to Staging column J | Done — **open to challenge**: the evidence-type mapping is my reading of the rubric, not CISO-approved |
| 19 | 2026-10-17 | Python port verifies `LOCK_PW` against the sheet's SHA-512 protection hash on unprotect (same scheme Excel uses) | Matches Excel's behaviour: a wrong password is refused. Verified against the baseline's own hashes | Done |
| 20 | 2026-10-17 | `profile_to_docx.js` and `review_to_changes.js` ported to Python (`profile-docx`, `review-extract`, `review-apply`) | Same G1 loop without Node. Output compared to the JS on the dummy profile: stamped markdown byte-identical, Word text identical, extract and apply output identical | Done |
| 21 | 2026-10-17 | `fix-workbook` command: replaces the `Prompts` sheet H3 cell with the spec's v4 system prompt (taken verbatim from the H3 `.md`) and adds `y!` to the Staging approve dropdown; both logged to ChangeLog, idempotent | Closes the stale-H3 and dropdown findings below without hand-editing locked sheets | Done on a scratch copy; apply to the real workbook only after review |

## Test run results (Python port, scratch copy — NOT the Excel scripts)

| Date | Test | Result | What I actually saw | Prompt edit made |
|---|---|---|---|---|
| | 1 Panel reads workbook | **Not run** | — | — |
| | 2 Write boundary holds | **Not run** | Python side only: all 14 live sheets protected; `apply` unlocked and re-locked them; a wrong `LOCK_PW` refused the run and changed nothing | — |
| 2026-10-17 | 3 Scoring discipline | **Partial** — guard only, fake model output | Interview-only rows capped at 1; "no routine testing" 4→3. No live H2 run yet, so the *prompt* is untested | none |
| 2026-10-17 | 4 Script applies approved only | Pass (Python port) | 2 approved rows applied (F, G, S, T, U); ChangeLog line per cell; column O stamped; unapproved row untouched | — |
| 2026-10-17 | 5 Roll-up moves | Pass (Python port + LibreOffice recalculation) | `4. DETECT`!K9 = 1.8 (weights 3 and 2, scores 1 and 3), equal to the Python roll-up; the DETECT category appears at `Reporting`!S7 | — |
| 2026-10-17 | 6 Conflict protection | Pass (Python port) | Hand-typed text in F13 survived; row stamped "partial"; conflict counted | — |
| | 7 Risks end to end | **Not run** (unit tests only) | — | — |

## Findings to resolve

- **`Prompts` sheet H3 is v1.0** (fix: `fix-workbook --h3-prompt`) (panel writes straight into Staging-Risks). The spec and `ImportRisksFromJSON.ts` assume v4 (JSON only). `ApplyApproved.ts` also stamps "H3 v1.0" in ChangeLog.
- **Test 5 in the plan names `Reporting!H7`**, which is `'1.Govern'!K24`. DETECT lands in `Reporting!S7`.
- **`ApplyApproved.ts` starts the ChangeLog scan at row 5** while the header is row 3, so row 4 stays blank (harmless).
- **Staging column A dropdown lists only y,n** (fix: `fix-workbook`); `y!` still works because the error alert is off. Add `y!` to the list if wanted.
- **`Reporting`!E24** averages categories unweighted (already an open item).
- **Saving through openpyxl re-serialises the 6 charts** (counts, formulas, validations, merges all preserved; chart XML differs). Appearance not checked. Keep Excel as the master and use the Python port on copies.
