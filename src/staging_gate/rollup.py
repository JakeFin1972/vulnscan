"""Read-only reproduction of the workbook's category roll-up formula:
   K = SUMPRODUCT(V, S) / SUMPRODUCT(V, --(S>0)), V = weight from Config looked up by column H.
Category blocks start at each row in column K that holds a formula (the merged K9:K13 style anchors).
The Excel formulas remain authoritative; this is for checking and for the CLI."""
from openpyxl.utils import column_index_from_string as ci

from . import layout as L
from .xl import blank_s, cell, num, s


def weights(wb) -> dict[str, float]:
    ws = wb[L.CONFIG_SHEET]
    out = {}
    for r in range(L.CONFIG_FIRST_ROW, L.CONFIG_LAST_ROW + 1):
        name = s(cell(ws, L.CONFIG_NAME_COL, r).value)
        if name:
            out[name] = num(cell(ws, L.CONFIG_WEIGHT_COL, r).value)
    return out


def category_blocks(ws) -> list[tuple[int, int]]:
    last_nr = max((r for r in range(L.FIRST_ROW, L.LAST_ROW + 1)
                   if not blank_s(cell(ws, L.NR_COL, r).value)), default=L.FIRST_ROW - 1)
    starts = [r for r in range(L.FIRST_ROW, last_nr + 1)
              if isinstance(cell(ws, "K", r).value, str) and cell(ws, "K", r).value.startswith("=")]
    return [(st, (starts[i + 1] - 1) if i + 1 < len(starts) else last_nr)
            for i, st in enumerate(starts)]


def rollup(wb, sheet: str, col: str = L.MATURITY_COL) -> list[dict]:
    ws, w = wb[sheet], weights(wb)
    out = []
    for first, last in category_blocks(ws):
        num_, den, used, unweighted = 0.0, 0.0, [], []
        for r in range(first, last + 1):
            m = num(cell(ws, col, r).value)
            if not m == m or m <= 0:  # blank/NaN/0 -> excluded, as --(S>0)
                continue
            wt = w.get(s(cell(ws, L.CRITICALITY_COL, r).value), 0.0)
            if wt == 0:
                unweighted.append(s(cell(ws, L.NR_COL, r).value))  # weight 0: silently excluded in Excel too
            num_ += wt * m
            den += wt * 1
            used.append(s(cell(ws, L.NR_COL, r).value))
        out.append({"first": first, "last": last, "value": num_ / den if den else 0.0,
                    "rows": used, "zero_weight": unweighted})
    return out
