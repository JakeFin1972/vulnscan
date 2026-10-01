import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import report, scoring
from app.seed_data import DEFAULT_CONFIG

BASE_ASSESSMENT = {
    "id": 1, "project_name": "Test", "description": "", "countries": "",
    "project_manager": "", "solution_name": "", "solution_owner": "",
    "completed_by": "Alice", "completed_by_email": "alice@example.com",
    "form_date": "", "status": "draft", "bia_status": "draft", "dpia_status": "draft",
}


def _report_for(scope, answers=None):
    assessment = {**BASE_ASSESSMENT, "scope": scope}
    answers = answers or {}
    results = scoring.compute_results(DEFAULT_CONFIG, answers)
    return report.build_report(DEFAULT_CONFIG, assessment, answers, results)


def test_both_scope_includes_protection_and_dpia_needed_and_all_sections():
    r = _report_for("both")
    assert r["protection"]
    assert r["dpia_needed"] is not None
    tool_titles = {s["tool_title"] for s in r["sections"]}
    assert any("Business Impact" in t for t in tool_titles)
    assert any("Data Privacy" in t or "DPIA" in t for t in tool_titles)


def test_bia_only_scope_excludes_dpia_sections():
    r = _report_for("bia")
    assert r["protection"]  # BIA results still shown
    assert r["dpia_needed"] is not None  # still computed from screening answers
    tool_titles = {s["tool_title"] for s in r["sections"]}
    assert not any("Data Privacy" in t for t in tool_titles)


def test_dpia_only_scope_excludes_protection_and_dpia_needed():
    r = _report_for("dpia")
    assert r["protection"] == []
    assert r["dpia_needed"] is None
    tool_titles = {s["tool_title"] for s in r["sections"]}
    assert not any("Business Impact Assessment (BIA)" == t for t in tool_titles)


def test_meta_includes_scope_label_and_relevant_status_only():
    r = _report_for("bia")
    labels = dict(r["meta"])
    assert labels["Assessment scope"] == "BIA only"
    assert "BIA status" in labels
    assert "DPIA status" not in labels

    r_both = _report_for("both")
    labels_both = dict(r_both["meta"])
    assert "BIA status" in labels_both
    assert "DPIA status" in labels_both


def test_answer_value_rendering_handles_lists_and_blanks():
    answers = {"dpia.q2_1": {"value": ["customers", "coworkers"]}}
    r = _report_for("dpia", answers)
    row = next(row for s in r["sections"] for row in s["rows"] if row["id"] == "2.1")
    assert row["answer"] == "Customers, Co-workers / employees"


def test_answer_value_rendering_resolves_other_option_with_specify_text():
    answers = {"dpia.q2_1": {"value": ["other"], "other_text": "Volunteers"}}
    r = _report_for("dpia", answers)
    row = next(row for s in r["sections"] for row in s["rows"] if row["id"] == "2.1")
    assert row["answer"] == "Other, please specify: Volunteers"


def test_risk_fields_only_shown_when_present():
    answers = {"dpia.q6_1": {"value": "shared", "likelihood": 4, "consequence": 5, "risk_owner": "Dana"}}
    r = _report_for("dpia", answers)
    row = next(row for s in r["sections"] for row in s["rows"] if row["id"] == "6.1")
    risk_dict = dict(row["risk"])
    assert risk_dict["Likelihood"] == "4"
    assert risk_dict["Risk owner"] == "Dana"
    assert "Remediation options" not in risk_dict


def test_info_asset_question_supports_multiple_selections():
    answers = {"bia.screening.q1_info_asset": {"value": ["cardholder_data", "marketing"]}}
    r = _report_for("bia", answers)
    row = next(row for s in r["sections"] for row in s["rows"] if row["prompt"].startswith("What are the information assets"))
    assert row["answer"] == "Cardholder data, Marketing"


def test_criticality_section_renders_with_resolved_labels():
    answers = {
        "bia.criticality.q1_rating": {"value": "critical"},
        "bia.criticality.q2_rto": {"value": "near_zero"},
        "bia.criticality.q3_rpo": {"value": "under_15m"},
    }
    r = _report_for("bia", answers)
    section = next(s for s in r["sections"] if s["section_title"] == "Criticality & Recovery Objectives")
    by_prompt = {row["prompt"]: row["answer"] for row in section["rows"]}
    assert by_prompt["What is the overall criticality rating of this asset/service to the organization?"] == "Critical"
    assert by_prompt["What is the Recovery Time Objective (RTO) for this asset/service?"] == "Near-zero (< 15 minutes)"
    assert by_prompt["What is the Recovery Point Objective (RPO) for this asset/service?"] == "Less than 15 minutes"


def test_report_filename_sanitizes_project_name():
    name = report.report_filename({"id": 5, "project_name": "My/Weird: Project!!"}, "csv")
    assert name.startswith("BIA-DPIA-")
    assert name.endswith("-5.csv")
    assert "/" not in name and ":" not in name
