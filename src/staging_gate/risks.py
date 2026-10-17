"""ImportRisksFromJSON: port of ImportRisksFromJSON.ts. Columns A and Q are always left empty."""
import json

from . import layout as L
from .xl import cell, first_empty_row, s
from openpyxl.utils import column_index_from_string as ci


def _str(v) -> str:
    return "" if v is None else str(v)


def import_risks(wb, text: str | None = None):
    """Returns (imported, rejected). Raises ValueError on empty/unparseable JSON."""
    sr = wb[L.STAGING_RISKS]
    if text is None:
        text = sr[L.RISK_JSON_CELL].value
    raw = s(text)
    if raw == "":
        raise ValueError(f"{L.STAGING_RISKS}!{L.RISK_JSON_CELL} is empty - paste the H3 JSON array first.")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError("JSON did not parse - check for stray text before/after the array, "
                         f"or a trailing comma. Error: {e}") from e
    items = parsed if isinstance(parsed, list) else [parsed]
    rows, rejected = [], []
    for i, r in enumerate(items):
        r = r if isinstance(r, dict) else {}
        label = f"item {i + 1} ({_str(r.get('C')) or 'unnamed'})"
        if s(r.get("C")) == "":
            rejected.append(f"{label}: missing C (risk name)")
            continue
        bad = next(((k, ok) for k, ok in (("H", L.H_OK), ("I", L.I_OK), ("J", L.J_OK))
                    if r.get(k) not in ok), None)
        if bad:
            rejected.append(f"{label}: bad {bad[0]} value '{r.get(bad[0])}'")
            continue
        sr_rows = r.get("source_rows")
        r["source_rows"] = "; ".join(map(str, sr_rows)) if isinstance(sr_rows, list) else _str(sr_rows)
        basis = _str(r.get("rating_basis")).strip()
        if r.get("rating_evidence"):
            basis += " - " + _str(r["rating_evidence"]).strip()
        r["basis_evidence"] = basis
        rows.append([_str(r.get(k)) if k else "" for k in L.RISK_IMPORT_COLS])
    if rows:
        start = first_empty_row(sr, L.RISK_COL_NAME, L.RISK_STAGING_FIRST_ROW)
        for dr, vals in enumerate(rows):
            for dc, v in enumerate(vals):
                if dc not in (0, len(vals) - 1):
                    sr.cell(start + dr, 1 + dc).value = v
    return len(rows), rejected
