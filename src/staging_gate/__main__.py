import argparse
import json
import sys
from pathlib import Path

from . import layout as L
from .apply import apply_approved
from .controls import read_controls
from .evidence import load_register
from .guard import guard_h2
from .h2 import write_staging
from .lock import lock
from .risks import import_risks
from .rollup import rollup
from .runner import (DEFAULT_MODEL, call_model, existing_risk_names, extract_system_prompt,
                     first_json, h2_user_prompt, h3_user_prompt)
from .xl import open_wb


def _client():
    import anthropic  # needs ANTHROPIC_API_KEY (or an `ant auth login` profile)
    return anthropic.Anthropic()


def _model_args(s):
    s.add_argument("--prompt", required=True, help="the H2/H3 .md file containing '## System prompt'")
    s.add_argument("--profile", required=True, help="approved Company Profile .md")
    s.add_argument("--model", default=DEFAULT_MODEL)
    s.add_argument("--no-fallbacks", action="store_true")
    s.add_argument("--sheets", nargs="+", metavar="SHEET", help='only these control sheets, e.g. --sheets "4. DETECT"')


def _review_cmds(sub):
    s = sub.add_parser("profile-docx", help="render the profile markdown to a Word review copy (or --stamp IDs)")
    s.add_argument("input")
    s.add_argument("--out"), s.add_argument("--config")
    s.add_argument("--stamp", action="store_true"), s.add_argument("--no-prompt", action="store_true")
    for k in ("ciso-email", "ciso-name", "coordinator-email", "coordinator-name"):
        s.add_argument("--" + k)
    s = sub.add_parser("review-extract", help="turn a commented .docx into ChangeProposals.md")
    s.add_argument("input"), s.add_argument("--profile", required=True), s.add_argument("--out")
    s = sub.add_parser("review-apply", help="apply approved proposals to the master profile .md")
    s.add_argument("input"), s.add_argument("--profile", required=True)
    s.add_argument("--new-version"), s.add_argument("--dry-run", action="store_true")
    s.add_argument("--force", action="store_true")


def main(argv=None):
    p = argparse.ArgumentParser(prog="staging_gate")
    sub = p.add_subparsers(dest="cmd", required=True)
    _review_cmds(sub)
    for name, h in [("lock", "protect all live sheets"), ("apply", "apply approved staging rows"),
                    ("import-risks", f"import JSON from {L.STAGING_RISKS}!{L.RISK_JSON_CELL}"),
                    ("rollup", "print the weighted roll-up for a sheet"),
                    ("h2", "run H2 on sheets 1-6 and write guarded proposals to Staging"),
                    ("h3", "run H3 and write its JSON into Staging-Risks"),
                    ("fix-workbook", "update the Prompts sheet H3 to the spec version; allow y! in the Staging dropdown")]:
        s = sub.add_parser(name, help=h)
        s.add_argument("workbook")
        if name == "rollup":
            s.add_argument("sheet")
        else:
            s.add_argument("-o", "--output", help="save here instead of overwriting (use a scratch copy)")
        if name == "h2":
            _model_args(s)
            s.add_argument("--evidence", required=True, help="Evidence Register (.csv or markdown table)")
        if name == "h3":
            _model_args(s)
        if name == "fix-workbook":
            s.add_argument("--h3-prompt", help="the H3 .md file (its '## System prompt (vX.Y)' block replaces the Prompts sheet cell)")
            s.add_argument("--no-dropdown", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "profile-docx":
        from . import profile_review
        return profile_review.run(vars(a))
    if a.cmd == "review-extract":
        from . import review_changes
        return review_changes.cmd_extract(a.input, a.profile, a.out)
    if a.cmd == "review-apply":
        from . import review_changes
        return review_changes.cmd_apply(a.input, a.profile, a.new_version, a.dry_run, a.force)
    wb = open_wb(a.workbook)
    if a.cmd == "rollup":
        for b in rollup(wb, a.sheet):
            print(f"rows {b['first']}-{b['last']}: {b['value']:.2f} from nr {', '.join(b['rows']) or '-'}"
                  + (f"  [weight 0, excluded: {', '.join(b['zero_weight'])}]" if b["zero_weight"] else ""))
        return 0
    try:
        if a.cmd == "lock":
            locked, missing = lock(wb)
            print(f"Locked {len(locked)} sheet(s)." + (f" Missing (skipped): {', '.join(missing)}." if missing else ""))
        elif a.cmd == "apply":
            print(apply_approved(wb).line())
        elif a.cmd == "import-risks":
            n, rej = import_risks(wb)
            print(f"Risks imported: {n} | rejected: {len(rej)}")
            for why in rej:
                print(f"  - {why}")
        elif a.cmd == "h2":
            profile = Path(a.profile).read_text(encoding="utf-8")
            reg_text = Path(a.evidence).read_text(encoding="utf-8")
            system = extract_system_prompt(Path(a.prompt).read_text(encoding="utf-8"))
            controls = read_controls(wb, a.sheets)
            out = call_model(_client(), system, h2_user_prompt(profile, reg_text, controls),
                             a.model, not a.no_fallbacks)
            result, notes = guard_h2(first_json(out, "{"), controls, load_register(a.evidence))
            n = write_staging(wb, result)
            print(f"{n} proposals written to Staging; {len(result['not_scored'])} not scored; "
                  f"{len(notes)} guard changes")
            for x in notes:
                print("  guard:", x)
        elif a.cmd == "fix-workbook":
            from .fixes import fix_workbook
            md = Path(a.h3_prompt).read_text(encoding="utf-8") if a.h3_prompt else None
            res = fix_workbook(wb, md, not a.no_dropdown)
            for x in res.done:
                print("fixed:", x)
            for x in res.skipped:
                print("skipped:", x)
        elif a.cmd == "h3":
            profile = Path(a.profile).read_text(encoding="utf-8")
            system = extract_system_prompt(Path(a.prompt).read_text(encoding="utf-8"))
            out = call_model(_client(), system, h3_user_prompt(profile, read_controls(wb, a.sheets), existing_risk_names(wb)),
                             a.model, not a.no_fallbacks)
            n, rej = import_risks(wb, json.dumps(first_json(out, "[")))
            print(f"Risks imported: {n} | rejected: {len(rej)}")
            for why in rej:
                print(f"  - {why}")
    except (ValueError, RuntimeError, PermissionError) as e:
        print(e, file=sys.stderr)
        return 1
    wb.save(a.output or a.workbook)
    return 0


sys.exit(main()) if __name__ == "__main__" else None
