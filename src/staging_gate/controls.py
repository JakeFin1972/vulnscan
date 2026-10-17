"""Read control rows (sheets 1-6) as H2/H3 inputs."""
from . import layout as L
from .xl import cell, s


def nr_str(v) -> str:
    return s(v)


def read_controls(wb) -> list[dict]:
    out = []
    for name in L.CONTROL_SHEETS:
        if name not in wb.sheetnames:
            continue
        ws = wb[name]
        for r in range(L.FIRST_ROW, L.LAST_ROW + 1):
            nr = cell(ws, L.NR_COL, r).value
            if s(nr) == "":
                continue
            out.append({
                "sheet": name, "nr": nr_str(nr),
                "topic": s(cell(ws, L.CTRL_TOPIC_COL, r).value),
                "question": s(cell(ws, L.CTRL_QUESTION_COL, r).value),
                "criticality": s(cell(ws, L.CTRL_CRIT_COL, r).value),
                "nist": s(cell(ws, L.CTRL_NIST_COL, r).value),
                "current_state": s(cell(ws, L.CTRL_CURRENT_STATE_COL, r).value),
                "maturity_S": s(cell(ws, L.ROLLUP_MATURITY_COL, r).value),
            })
    return out
