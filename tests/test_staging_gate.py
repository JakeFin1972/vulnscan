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
    for name in L.LOCKED_SHEETS + L.OPEN_SHEETS:
        if name not in wb.sheetnames:
            wb.create_sheet(name)
    d = wb[DETECT]
    for i, (nr, crit) in enumerate([("D.1", 3), ("D.2", 1), ("D.3", 2)]):
        d[f"A{9 + i}"], d[f"D{9 + i}"] = nr, crit
    st = wb[L.STAGING]
    for i, nr in enumerate(["D.1", "D.2", "D.3"]):
        r = 7 + i
        st[f"B{r}"], st[f"C{r}"] = DETECT, nr
        st[f"E{r}"], st[f"F{r}"], st[f"G{r}"] = "state", "proposal", i + 1
        st[f"H{r}"], st[f"I{r}"], st[f"K{r}"] = 2, 3, "ev"
    return wb


def log_rows(wb):
    ws = wb[L.CHANGELOG]
    return [[c.value for c in row] for row in ws.iter_rows(min_row=5, max_col=11) if row[1].value]


def results(wb):
    return [r[10] for r in log_rows(wb)]


def test_only_approved_rows_apply_and_log():
    wb = make_wb()
    wb[L.STAGING]["A7"], wb[L.STAGING]["A9"] = "y", "Y"
    res = apply_approved(wb)
    d = wb[DETECT]
    assert res.controls == 2
    assert (d["S9"].value, d["S10"].value, d["S11"].value) == (1, None, 3)
    assert d["F10"].value is None and d["T9"].value == 2 and d["U9"].value == 3
    assert results(wb).count("APPLIED") == 10
    assert wb[L.STAGING]["O7"].value.endswith(" applied") and wb[L.STAGING]["O8"].value is None
    assert apply_approved(wb).controls == 0  # stamped rows are not reapplied
    assert log_rows(wb)[0][9] == L.STAMP_SOURCE


def test_conflict_partial_stamp_then_override():
    wb = make_wb()
    wb[DETECT]["F9"] = "human text"
    wb[L.STAGING]["A7"] = "y"
    res = apply_approved(wb)
    assert wb[DETECT]["F9"].value == "human text" and res.conflicts == 1
    assert "CONFLICT - skipped" in results(wb)
    assert wb[L.STAGING]["O7"].value.endswith(" partial") and res.controls == 0
    wb[L.STAGING]["A7"] = "y!"
    res = apply_approved(wb)
    assert wb[DETECT]["F9"].value == "state" and res.overrides == 1
    assert any(r[10] == "OVERRIDE" and r[5] == "human text" for r in log_rows(wb))
    assert wb[L.STAGING]["O7"].value.endswith(" overridden")
    assert apply_approved(wb).overrides == 0  # y! does not re-fire


def test_zero_maturity_is_not_a_conflict_but_nonzero_is():
    wb = make_wb()
    wb[DETECT]["S9"], wb[DETECT]["T9"] = 0, 4
    wb[L.STAGING]["A7"] = "y"
    res = apply_approved(wb)
    assert wb[DETECT]["S9"].value == 1 and wb[DETECT]["T9"].value == 4
    assert res.conflicts == 1


def test_out_of_range_maturity_rejected_per_cell():
    wb = make_wb()
    wb[L.STAGING]["A7"], wb[L.STAGING]["G7"] = "y", 9
    res = apply_approved(wb)
    assert wb[DETECT]["S9"].value is None and wb[DETECT]["T9"].value == 2
    assert "REJECTED - not 0-5" in results(wb)
    assert wb[L.STAGING]["O7"].value.endswith(" partial") and res.controls == 0


def test_unknown_sheet_and_nr_logged_not_stamped():
    wb = make_wb()
    st = wb[L.STAGING]
    st["A7"], st["B7"] = "y", "Nope"
    st["A8"], st["C8"] = "y", "ZZ.9"
    res = apply_approved(wb)
    assert res.not_found == 2 and st["O7"].value is None and st["O8"].value is None
    assert set(results(wb)) == {"SHEET NOT FOUND", "NR NOT FOUND"}


def test_lock_and_apply_relocks():
    wb = make_wb()
    locked, missing = lock(wb)
    assert DETECT in locked and not missing
    assert wb[DETECT].protection.sheet and not wb[L.STAGING].protection.sheet
    wb[L.STAGING]["A7"] = "y"
    apply_approved(wb)
    assert wb[DETECT]["S9"].value == 1
    assert all(wb[n].protection.sheet for n in L.LOCKED_SHEETS)


def test_rollup_weighted_and_excludes_zero():
    wb = make_wb()
    wb[L.STAGING]["A7"], wb[L.STAGING]["A9"] = "y", "y"
    apply_approved(wb)
    r = rollup(wb[DETECT])
    assert r["rows"] == ["D.1", "D.3"] and r["value"] == pytest.approx((1 * 3 + 3 * 2) / 5)


RISK = {"B": "PR.AA", "C": "Weak MFA", "D": "cur", "E": "tgt", "F": "desc", "G": "act",
        "H": "3-HIGH RISK", "I": "3-MEANINGFUL IMPACT", "J": "1-LOW HANGING FRUIT",
        "M": "CISO", "R": "maturity", "S": "H3", "source_rows": ["D.1", "D.2"],
        "rating_basis": "basis", "rating_evidence": "ev", "confidence": "high"}


def test_risks_import_then_apply(tmp_path):
    wb = make_wb()
    n, rej = import_risks(wb, json.dumps([RISK, {**RISK, "H": "bogus"}, {"B": "x"}]))
    sr = wb[L.STAGING_RISKS]
    assert n == 1 and len(rej) == 2 and "bad H value 'bogus'" in rej[0]
    assert sr["A7"].value is None and sr["Q7"].value is None
    assert sr["N7"].value == "D.1; D.2" and sr["O7"].value == "basis - ev" and sr["P7"].value == "high"
    assert (sr["K7"].value, sr["L7"].value, sr["M7"].value) == ("CISO", "maturity", "H3")
    sr["A7"] = "y"
    assert apply_approved(wb).risks == 1
    r = wb[L.RISKS_SHEET]
    assert r["C12"].value == "Weak MFA" and (r["M12"].value, r["R12"].value, r["S12"].value) == ("CISO", "maturity", "H3")
    assert all(r[f"{c}12"].value is None for c in "AKLN")
    assert sr["Q7"].value.endswith(" applied")
    p = tmp_path / "t.xlsx"
    wb.save(p)
    assert load_workbook(p)[L.RISKS_SHEET]["C12"].value == "Weak MFA"


def test_risks_bad_json_and_single_object():
    with pytest.raises(ValueError, match="did not parse"):
        import_risks(make_wb(), "Here you go: [{}]")
    with pytest.raises(ValueError, match="empty"):
        import_risks(make_wb(), "")
    assert import_risks(make_wb(), json.dumps(RISK))[0] == 1
