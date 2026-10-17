"""Read-only check of the K9 roll-up (the workbook's own formula remains authoritative).
Column choices are ASSUMED - see layout.py."""
from . import layout as L
from .xl import cell, num, s


def rollup(ws) -> dict:
    tot = den = 0.0
    used, no_weight = [], []
    for r in range(L.FIRST_ROW, L.LAST_ROW + 1):
        nr, m = cell(ws, L.NR_COL, r).value, cell(ws, L.ROLLUP_MATURITY_COL, r).value
        if s(nr) == "" or s(m) == "" or num(m) == 0:
            continue
        w = num(cell(ws, L.CRITICALITY_COL, r).value)
        if not w > 0:
            no_weight.append(s(nr))
            continue
        tot += num(m) * w
        den += w
        used.append(s(nr))
    return {"value": tot / den if den else 0.0, "rows": used, "no_weight": no_weight}
