"""Write guarded H2 proposals into Staging (columns per layout.H2_STAGING_COLS)."""
from . import layout as L
from .xl import cell, first_empty_row, s


def write_staging(wb, result: dict) -> int:
    st = wb[L.STAGING]
    r = first_empty_row(st, L.COL_NR, L.STAGING_FIRST_ROW)
    last = L.STAGING_FIRST_ROW + L.STAGING_ROWS - 1
    n = 0
    for p in result.get("proposals", []):
        if r > last:
            raise ValueError(f"Staging is full (row {last}); apply or clear rows first")
        cell(st, L.COL_SHEET, r).value = p["sheet"]
        cell(st, L.COL_NR, r).value = int(p["nr"]) if str(p["nr"]).isdigit() else p["nr"]  # MATCH needs a number
        cols = L.H2_STAGING_COLS
        cell(st, cols["F"], r).value = p.get("F") or None
        cell(st, cols["G"], r).value = p.get("G") or None
        cell(st, cols["S"], r).value = p["S"]
        for k in ("T_proposed", "U_proposed"):
            if p.get(k) is not None:
                cell(st, cols[k], r).value = p[k]
        flags = "; ".join(p.get("flags") or [])
        cell(st, cols["rationale"], r).value = " | ".join(x for x in (s(p.get("S_rationale")), flags) if x) or None
        cell(st, cols["evidence"], r).value = ", ".join(p.get("evidence") or [])
        cell(st, cols["confidence"], r).value = p.get("confidence")
        r += 1
        n += 1
    return n
