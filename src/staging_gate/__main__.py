import argparse
import sys

from . import layout as L
from .apply import apply_approved
from .lock import lock
from .risks import import_risks
from .rollup import rollup
from .xl import open_wb


def main(argv=None):
    p = argparse.ArgumentParser(prog="staging_gate", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, h in [("lock", "protect all live sheets"), ("apply", "apply approved staging rows"),
                    ("import-risks", f"import JSON from {L.STAGING_RISKS}!{L.RISK_JSON_CELL}"),
                    ("rollup", "print the weighted roll-up for a sheet")]:
        s = sub.add_parser(name, help=h)
        s.add_argument("workbook")
        if name == "rollup":
            s.add_argument("sheet")
        else:
            s.add_argument("-o", "--output", help="save here instead of overwriting the input "
                           "(recommended: run on a scratch copy)")
    a = p.parse_args(argv)
    wb = open_wb(a.workbook)
    if a.cmd == "rollup":
        r = rollup(wb[a.sheet])
        print(f"{r['value']:.2f} from rows {', '.join(r['rows']) or '-'}"
              + (f"; excluded (no numeric criticality): {', '.join(r['no_weight'])}" if r["no_weight"] else ""))
        return 0
    if a.cmd == "lock":
        locked, missing = lock(wb)
        print(f"Locked {len(locked)} sheet(s)." + (f" Missing (skipped): {', '.join(missing)}." if missing else ""))
    elif a.cmd == "apply":
        try:
            print(apply_approved(wb).line())
        except ValueError as e:
            print(e, file=sys.stderr)
            return 1
    else:
        try:
            n, rej = import_risks(wb)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 1
        print(f"Risks imported: {n} | rejected: {len(rej)}")
        for why in rej:
            print(f"  - {why}")
    wb.save(a.output or a.workbook)
    return 0


sys.exit(main()) if __name__ == "__main__" else None
