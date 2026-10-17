"""Evidence Register loading: EV-ID -> evidence type text (lower-cased)."""
import csv
import re
from pathlib import Path


def load_register(path) -> dict[str, str]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    reg: dict[str, str] = {}
    if p.suffix.lower() == ".csv":
        rows = list(csv.reader(text.splitlines()))
        if not rows:
            return reg
        head = [h.strip().lower() for h in rows[0]]
        tcol = next((i for i, h in enumerate(head) if h.startswith("type")), None)
        if tcol is None:
            raise ValueError("Evidence register CSV has no 'Type' column")
        for r in rows[1:]:
            if r and r[0].strip() and len(r) > tcol:
                reg[r[0].strip()] = r[tcol].strip().lower()
        return reg
    for line in text.splitlines():  # markdown table: | EV-01 | doc | type | date |
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and re.fullmatch(r"EV-\d+", cells[0]):
            reg[cells[0]] = cells[2].lower()
    return reg
