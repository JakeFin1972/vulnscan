import json

import pytest
from openpyxl import Workbook, load_workbook

from staging_gate import layout as L
from staging_gate.apply import apply_approved
from staging_gate.lock import lock
from staging_gate.risks import import_risks
from staging_gate.rollup import rollup

DETECT = "4. DETECT"


def make_wb():
    wb = Workbook()
    wb.active.title = DETECT
    d = wb[DETECT]
    for i, (nr, crit) in enumerate([("D.1", 3), ("D.2", 1), ("D.3", 2)]):
        d[f"A{9 + i}"], d[f"D{9 + i}"] = nr, crit
    wb.create_sheet(L.RISKS_SHEET)
    st = wb.create_sheet(L.STAGING)
    wb.create_sheet(L.STAGING_RISKS)
    wb.create_sheet(L.CHANGELOG)
    for i, nr in enumerate(["D.1", "D.2", "D.3"]):
        r = 7 + i
        st[f"B{r}"], st[f"C{r}"] = DETECT, nr
        st[f"E{r}"], st[f"F{r}"], st[f"G{r}"], st[f"H{r}"] = "find", "evid", "rec", i + 1
    return wb


def log_rows(wb):
    return [[c.value for c in row] for row in wb[L.CHANGELOG].iter_rows(min_row=2)]


def test_only_approved_rows_apply_and_log():
    wb = make_wb()
    wb[L.STAGING]["A7"], wb[L.STAGING]["A9"] = "y", "Y"
    res = apply_approved(wb)
    d = wb[DETECT]
    assert res.controls_applied == 2
    assert (d["S9"].value, d["S10"].value, d["S11"].value) == (1, None, 3)
    assert d["F10"].value is None
    assert sum(r[4] == "APPLIED" for r in log_rows(wb)) == 8
    assert wb[L.STAGING]["O7"].value.startswith("applied")
    assert wb[L.STAGING]["O8"].value is None
    assert apply_approved(wb).controls_applied == 0  # stamped rows not reapplied


def test_rollup_weighted_and_excludes_zero():
    wb = make_wb()
    wb[L.STAGING]["A7"], wb[L.STAGING]["A9"] = "y", "y"
    apply_approved(wb)
    r = rollup(wb[DETECT])
    assert r["rows"] == ["D.1", "D.3"]
    assert r["value"] == pytest.approx((1 * 3 + 3 * 2) / 5)


def test_conflict_keeps_human_text_and_override_replaces():
    wb = make_wb()
    wb[DETECT]["F9"] = "human text"
    wb[L.STAGING]["A7"] = "y"
    res = apply_approved(wb)
    assert wb[DETECT]["F9"].value == "human text"
    assert res.conflicts == 1
    assert any(r[4] == "CONFLICT - skipped" for r in log_rows(wb))
    wb[L.STAGING]["A7"] = "y!"
    res = apply_approved(wb)
    assert wb[DETECT]["F9"].value == "evid" and res.overrides == 1
    assert any(r[4] == "OVERRIDE" and r[5] == "human text" for r in log_rows(wb))
    assert wb[L.STAGING]["O7"].value.startswith("overridden")


def test_bad_maturity_and_unknown_nr_rejected():
    wb = make_wb()
    st = wb[L.STAGING]
    st["A7"], st["H7"] = "y", 9
    st["A8"], st["C8"] = "y", "ZZ.9"
    res = apply_approved(wb)
    assert len(res.rejected) == 2 and res.controls_applied == 0
    assert wb[DETECT]["S9"].value is None


def test_lock_protects_live_sheets_only_and_apply_relocks():
    wb = make_wb()
    locked = lock(wb)
    assert DETECT in locked and L.STAGING not in locked
    assert wb[DETECT].protection.sheet and not wb[L.STAGING].protection.sheet
    wb[L.STAGING]["A7"] = "y"
    apply_approved(wb)
    assert wb[DETECT]["S9"].value == 1 and wb[DETECT].protection.sheet


def test_risks_import_then_apply(tmp_path):
    wb = make_wb()
    items = [{"source": "D.1", "title": "T", "description": "d", "likelihood": 3, "impact": 4,
              "rating_basis": "b", "evidence": "e"},
             {"title": "no source"}]
    n, rej = import_risks(wb, json.dumps(items))
    st = wb[L.STAGING_RISKS]
    assert n == 1 and len(rej) == 1
    assert st["A7"].value is None and st["Q7"].value is None
    assert "Basis: b" in st["O7"].value and "Evidence: e" in st["O7"].value
    st["A7"] = "y"
    assert apply_approved(wb).risks_applied == 1
    r = wb[L.RISKS_SHEET]
    assert r["B12"].value == "T"
    assert all(r[f"{c}12"].value is None for c in "AKLN")
    p = tmp_path / "t.xlsx"
    wb.save(p)
    assert load_workbook(p)[L.RISKS_SHEET]["B12"].value == "T"


def test_risks_bad_json_message():
    with pytest.raises(ValueError, match="JSON parse error"):
        import_risks(make_wb(), "Here you go: [{}]")
