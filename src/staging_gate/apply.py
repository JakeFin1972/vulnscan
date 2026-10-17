"""ApplyApproved: write only approved staging rows to live sheets; never silently overwrite."""
from dataclasses import dataclass, field

from . import layout as L
from .lock import relock, unlock
from .xl import blank, cell, log, now


@dataclass
class Result:
    controls_applied: int = 0
    overrides: int = 0
    conflicts: int = 0
    rejected: list = field(default_factory=list)
    risks_applied: int = 0

    def line(self):
        return (f"{self.controls_applied} controls applied, {self.overrides} overrides, "
                f"{self.conflicts} conflicts skipped, {self.risks_applied} risks applied, "
                f"{len(self.rejected)} rejected")


def _find_row(ws, nr):
    from openpyxl.utils import column_index_from_string as ci
    for r in range(L.FIRST_ROW, L.LAST_ROW + 1):
        v = ws.cell(r, ci(L.NR_COL)).value
        if not blank(v) and str(v).strip() == str(nr).strip():
            return r
    return None


def _token(v):
    t = "" if v is None else str(v).strip().lower()
    return t if t in ("y", "y!") else None


def _apply_controls(wb, res):
    st = wb[L.STAGING]
    for r in range(L.STAGING_FIRST_ROW, st.max_row + 1):
        tok = _token(cell(st, L.COL_APPROVE, r).value)
        stamp = cell(st, L.COL_APPLIED, r).value
        # 'y' never reapplies a stamped row; 'y!' may correct an applied row once.
        if not tok or (not blank(stamp) and (tok == "y" or str(stamp).startswith("overridden"))):
            continue
        sheet, nr = cell(st, L.COL_SHEET, r).value, cell(st, L.COL_NR, r).value
        if sheet not in wb.sheetnames or sheet in L.WRITABLE:
            res.rejected.append((r, f"unknown target sheet {sheet!r}"))
            log(wb, sheet, nr, "", "REJECT - bad sheet", src=r)
            continue
        ws = wb[sheet]
        tr = _find_row(ws, nr)
        if tr is None:
            res.rejected.append((r, f"nr {nr!r} not found on {sheet}"))
            log(wb, sheet, nr, "", "REJECT - nr not found", src=r)
            continue
        proposals = {}
        bad = None
        for scol, tcol in L.FIELD_MAP.items():
            v = cell(st, scol, r).value
            if blank(v):
                continue
            if scol == L.MATURITY_STAGING_COL:
                lo, hi = L.MATURITY_RANGE
                if isinstance(v, bool) or not isinstance(v, (int, float)) or v != int(v) \
                        or not lo <= v <= hi:
                    bad = f"maturity {v!r} not an integer {lo}-{hi}"
                    break
                v = int(v)
            proposals[tcol] = v
        if bad:
            res.rejected.append((r, bad))
            log(wb, sheet, nr, "", f"REJECT - {bad}", src=r)
            continue
        unlock(ws)
        wrote = overrode = False
        try:
            for tcol, new in proposals.items():
                c = cell(ws, tcol, tr)
                addr, old = f"{tcol}{tr}", c.value
                if blank(old):
                    c.value = new
                    log(wb, sheet, nr, addr, "APPLIED", "", new, r)
                    wrote = True
                elif old == new:
                    log(wb, sheet, nr, addr, "NO-OP - same value", old, new, r)
                elif tok == "y!":
                    c.value = new
                    log(wb, sheet, nr, addr, "OVERRIDE", old, new, r)
                    wrote = overrode = True
                    res.overrides += 1
                else:
                    log(wb, sheet, nr, addr, "CONFLICT - skipped", old, new, r)
                    res.conflicts += 1
        finally:
            relock(ws)
        if wrote:
            stamp = "overridden" if overrode else "applied"
            cell(st, L.COL_APPLIED, r).value = f"{stamp} {now()}"
            res.controls_applied += 1


def _apply_risks(wb, res):
    st = wb[L.STAGING_RISKS]
    if L.RISKS_SHEET not in wb.sheetnames:
        return
    ws = wb[L.RISKS_SHEET]
    from openpyxl.utils import column_index_from_string as ci
    for r in range(L.RISK_FIRST_ROW, st.max_row + 1):
        if not _token(cell(st, L.RISK_COL_APPROVE, r).value) \
                or not blank(cell(st, L.RISK_COL_APPLIED, r).value):
            continue
        unlock(ws)
        try:
            tr = L.RISK_TARGET_FIRST_ROW
            while not blank(ws.cell(tr, ci(L.RISK_TARGET_KEY_COL)).value):
                tr += 1
            for scol, tcol in L.RISK_TARGET_COLS.items():
                cell(ws, tcol, tr).value = cell(st, scol, r).value
        finally:
            relock(ws)
        log(wb, L.RISKS_SHEET, "", f"row {tr}", "APPLIED (risk)", "", cell(st, "C", r).value, r)
        cell(st, L.RISK_COL_APPLIED, r).value = f"applied {now()}"
        res.risks_applied += 1


def apply_approved(wb) -> Result:
    res = Result()
    _apply_controls(wb, res)
    _apply_risks(wb, res)
    return res
