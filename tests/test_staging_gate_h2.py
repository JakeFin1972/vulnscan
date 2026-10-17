import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from staging_gate import layout as L
from staging_gate.guard import ceiling, guard_h2
from staging_gate.h2 import write_staging
from staging_gate.runner import call_model, extract_system_prompt, first_json
from tests.test_staging_gate import DETECT, make_wb

# evidence types as in the dummy profile's register
REG = {"EV-01": "internal presentation", "EV-02": "policy + procedure",
       "EV-03": "interview", "EV-04": "config export"}
CONTROLS = [{"sheet": DETECT, "nr": n} for n in ("D.1", "D.2", "D.3")]


def prop(nr, s, ev, **kw):
    return {"sheet": DETECT, "nr": nr, "F": "f", "G": "g", "S": s, "evidence": ev,
            "confidence": "high", **kw}


def run(props, not_scored=None):
    return guard_h2({"proposals": props, "not_scored": not_scored or []}, CONTROLS, REG)[0]


def test_three_traps():
    res = run([prop("D.1", 3, ["EV-03"]),              # interview-only "watches routinely"
               prop("D.2", 3, ["EV-03", "EV-01"]),     # licensed SIEM, no coverage evidence
               prop("D.3", 4, ["EV-02", "EV-04"])])    # Defender: policy+procedure+export, no testing
    s = {p["nr"]: p["S"] for p in res["proposals"]}
    assert s == {"D.1": 1, "D.2": 0, "D.3": 3}  # fixture accepts 0-2 for the SIEM
    assert any("interview-only" in f for f in res["proposals"][0]["flags"])
    assert any("routine-test" in f for f in res["proposals"][2]["flags"])


def test_never_raises_a_score():
    assert run([prop("D.3", 2, ["EV-02", "EV-04"])])["proposals"][0]["S"] == 2


def test_fabricated_ev_id_and_no_evidence_become_not_scored():
    res = run([prop("D.1", 3, ["EV-99"]), prop("D.2", 2, ["EV-02", "EV-77"])])
    assert [p["nr"] for p in res["proposals"]] == ["D.2"]
    assert any("EV-77" in f for f in res["proposals"][0]["flags"])
    assert res["not_scored"][0]["nr"] == "D.1" and "no valid EV-ID" in res["not_scored"][0]["reason"]


def test_unknown_row_duplicate_and_bad_score_dropped():
    res = run([prop("ZZ", 1, ["EV-02"]), prop("D.1", 1, ["EV-02"]), prop("D.1", 2, ["EV-02"]),
               prop("D.2", 7, ["EV-02"])])
    assert [p["nr"] for p in res["proposals"]] == ["D.1"]
    assert res["proposals"][0]["S"] == 1 and len(res["guard_notes"]) == 3


def test_level5_capped_and_u5_flagged():
    reg = {**REG, "EV-09": "test report"}
    r, _ = guard_h2({"proposals": [prop("D.1", 5, ["EV-02", "EV-04", "EV-09"], U_proposed=5)]}, CONTROLS, reg)
    p = r["proposals"][0]
    assert p["S"] == 4 and any("U=5" in f for f in p["flags"])
    assert ceiling(["policy"]) [0] == 1 and ceiling([])[0] == 0


def test_write_staging_columns():
    wb = make_wb()
    res = run([prop("D.1", 3, ["EV-02", "EV-04"], S_rationale="why", T_proposed=4, U_proposed=5)])
    assert write_staging(wb, res) == 1
    st = wb[L.STAGING]
    # make_wb pre-fills rows 7-9 in B/C, so the new row lands at row 10
    assert (st["B10"].value, st["C10"].value, st["E10"].value, st["F10"].value) == (DETECT, "D.1", "f", "g")
    assert (st["G10"].value, st["H10"].value, st["I10"].value) == (3, 4, 5)
    assert st["K10"].value == "EV-02, EV-04" and st["L10"].value == "high"
    assert "why" in st["J10"].value and "U=5" in st["J10"].value
    assert st["A10"].value is None and st["O10"].value is None


def test_first_json_and_system_prompt_extraction():
    assert first_json('Sure:\n```json\n{"a": [1]}\n```\nthanks', "{") == {"a": [1]}
    assert first_json('[{"x":1}]\nPaste the array above', "[") == [{"x": 1}]
    with pytest.raises(ValueError):
        first_json("no json", "[")
    md = "# H\n\n## System prompt (v2.0)\n\n```\nYou are H2.\nLine two.\n```\n\n## Next\n```\nx\n```"
    assert extract_system_prompt(md) == "You are H2.\nLine two."


class FakeClient:
    def __init__(self, stop="end_turn", text="OUT"):
        self.calls = []
        self.msg = SimpleNamespace(stop_reason=stop, stop_details=None,
                                   content=[SimpleNamespace(type="thinking"), SimpleNamespace(type="text", text=text)])
        outer = self

        class Messages:
            @contextmanager
            def stream(self, **kw):
                outer.calls.append(kw)
                yield SimpleNamespace(get_final_message=lambda: outer.msg)
        self.beta = SimpleNamespace(messages=Messages())


def test_call_model_request_shape_and_stop_handling():
    c = FakeClient()
    assert call_model(c, "SYS", "USER") == "OUT"
    kw = c.calls[0]
    assert kw["model"] == "claude-opus-5-5" and kw["system"] == "SYS"
    assert kw["betas"] == ["server-side-fallback-2026-07-01"] and kw["extra_body"] == {"fallbacks": "default"}
    assert "thinking" not in kw and "temperature" not in kw
    assert "betas" not in (c2 := FakeClient(), call_model(c2, "s", "u", fallbacks=False), c2.calls[0])[2]
    with pytest.raises(RuntimeError, match="refused"):
        call_model(FakeClient(stop="refusal"), "s", "u")
    with pytest.raises(RuntimeError, match="max_tokens"):
        call_model(FakeClient(stop="max_tokens"), "s", "u")
