"""Small openpyxl helpers shared by the commands."""
import math
from datetime import datetime, timezone

from openpyxl import load_workbook
from openpyxl.utils import column_index_from_string as ci

from . import layout as L


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def s(v) -> str:
    """String(v).trim() as the Excel scripts see a cell value."""
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip()


def num(v) -> float:
    try:
        return float(s(v))
    except ValueError:
        return math.nan


def blank_s(v) -> bool:
    return s(v) == ""


def cell(ws, col: str, row: int):
    return ws.cell(row=row, column=ci(col))


def first_empty_row(ws, col: str, start: int, span: int = 400) -> int:
    for r in range(start, start + span):
        if s(cell(ws, col, r).value) == "":
            return r
    return start + span


def open_wb(path):
    return load_workbook(path)


class ChangeLog:
    def __init__(self, wb, now: str):
        self.ws = wb[L.CHANGELOG]
        self.row = first_empty_row(self.ws, L.LOG_KEY_COL, L.LOG_FIRST_ROW)
        self.now = now

    def write(self, src, sheet, id_, col, old, new, ev, conf, result):
        vals = [self.now, src, sheet, id_, col, old, new, ev, conf, L.STAMP_SOURCE, result]
        for i, v in enumerate(vals, 1):
            self.ws.cell(self.row, i).value = v
        self.row += 1
