"""ImportRisksFromJSON: load H3's JSON array into Staging-Risks. A/Q left empty."""
import json

from . import layout as L
from .xl import blank, cell


def import_risks(wb, text: str | None = None):
    st = wb[L.STAGING_RISKS]
    if text is None:
        text = cell(st, L.RISK_JSON_CELL[0], int(L.RISK_JSON_CELL[1:])).value
    if blank(text):
        raise ValueError(f"no JSON found in {L.STAGING_RISKS}!{L.RISK_JSON_CELL}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parse error (paste only the array, no prose): {e}") from e
    if not isinstance(data, list):
        raise ValueError("JSON must be an array of risk objects")
    r = L.RISK_FIRST_ROW
    while not blank(cell(st, L.RISK_STAGING_COLS["title"], r).value):
        r += 1
    imported, rejected = 0, []
    lo, hi = L.RISK_SCALE
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            rejected.append((i, "not an object"))
            continue
        missing = [k for k in L.RISK_REQUIRED if blank(item.get(k))]
        if missing:
            rejected.append((i, f"missing {', '.join(missing)}"))
            continue
        bad = [k for k in ("likelihood", "impact") if k in item and not (
            isinstance(item[k], int) and not isinstance(item[k], bool) and lo <= item[k] <= hi)]
        if bad:
            rejected.append((i, f"{', '.join(bad)} not an integer {lo}-{hi}"))
            continue
        for key, col in L.RISK_STAGING_COLS.items():
            cell(st, col, r).value = item.get(key)
        cell(st, L.RISK_COL_BASIS, r).value = (
            f"Basis: {item['rating_basis']}\nEvidence: {item['evidence']}")
        r += 1
        imported += 1
    return imported, rejected
