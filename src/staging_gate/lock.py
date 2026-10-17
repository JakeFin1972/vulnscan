"""Protection helpers; behaviour mirrors LockDown.ts / ApplyApproved.ts setProtection.
Note: openpyxl cannot check a password when unprotecting, unlike Excel."""
from . import layout as L


def _protect(ws):
    ws.protection.set_password(L.LOCK_PW)
    ws.protection.enable()


def set_protection(wb, names, on: bool):
    for name in names:
        if name not in wb.sheetnames:
            continue
        ws = wb[name]
        if on and not ws.protection.sheet:
            _protect(ws)
        elif not on and ws.protection.sheet:
            ws.protection.disable()


def lock(wb):
    """LockDown: open the staging sheets, (re)protect every live sheet. Returns (locked, missing)."""
    missing = [n for n in L.OPEN_SHEETS + L.LOCKED_SHEETS if n not in wb.sheetnames]
    set_protection(wb, L.OPEN_SHEETS, False)
    locked = []
    for name in L.LOCKED_SHEETS:
        if name in wb.sheetnames:
            ws = wb[name]
            ws.protection.disable()
            _protect(ws)
            locked.append(name)
    return locked, missing
