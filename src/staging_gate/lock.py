"""LockDown: password-protect every sheet except the staging sheets."""
from . import layout as L


def lock(wb) -> list[str]:
    locked = []
    for ws in wb.worksheets:
        if ws.title in L.WRITABLE:
            ws.protection.disable()
        else:
            ws.protection.set_password(L.LOCK_PW)
            ws.protection.enable()
            locked.append(ws.title)
    return locked


def unlock(ws):
    ws.protection.disable()


def relock(ws):
    ws.protection.set_password(L.LOCK_PW)
    ws.protection.enable()
