import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import scoring
from app.seed_data import DEFAULT_CONFIG


def test_bia_category_defaults_to_not_applicable_when_unanswered():
    results = scoring.compute_bia_results(DEFAULT_CONFIG, {})
    for category, entry in results.items():
        assert entry["max_value"] == 0
        assert entry["max_label"] == "Not applicable"
        assert entry["answered_count"] == 0


def test_bia_category_takes_the_maximum_of_answered_scenarios():
    answers = {
        "bia.confidentiality.q9": {"value": 3},
        "bia.confidentiality.q10": {"value": 5},
        "bia.confidentiality.q11": {"value": 2},
    }
    results = scoring.compute_bia_results(DEFAULT_CONFIG, answers)
    entry = results["confidentiality"]
    assert entry["max_value"] == 5
    assert entry["max_label"] == "Critical"
    assert entry["answered_count"] == 3


def test_bia_unanswered_scenarios_are_excluded_not_treated_as_zero():
    # Only one scenario answered with a low value -- an unanswered scenario
    # must not silently count as 0 and get excluded from "answered_count".
    answers = {"bia.confidentiality.q9": {"value": 2}}
    results = scoring.compute_bia_results(DEFAULT_CONFIG, answers)
    entry = results["confidentiality"]
    assert entry["max_value"] == 2
    assert entry["answered_count"] == 1
    assert entry["total_questions"] == 5


def test_classification_code_maps_value_to_aspect_letter_plus_level():
    # value 5 (Critical) -> classification 4 -> "C4" for confidentiality
    answers = {"bia.confidentiality.q9": {"value": 5}}
    results = scoring.compute_bia_results(DEFAULT_CONFIG, answers)
    entry = results["confidentiality"]
    assert entry["classification_code"] == "C4"
    assert entry["classification_label"] == "Strictly confidential"

    # value 2 (Minor) -> classification 1 -> "I1" for integrity
    answers = {"bia.integrity.q14": {"value": 2}}
    results = scoring.compute_bia_results(DEFAULT_CONFIG, answers)
    entry = results["integrity"]
    assert entry["classification_code"] == "I1"


def test_non_ci_a_categories_have_no_classification_code():
    answers = {"bia.uniqueness.q23": {"value": 5}}
    results = scoring.compute_bia_results(DEFAULT_CONFIG, answers)
    assert "classification_code" not in results["uniqueness"]


def test_criticality_section_is_informational_and_not_scored():
    # Criticality/RTO/RPO questions carry no "category"/"impact" input_type,
    # so they must never show up as a scored BIA category.
    answers = {
        "bia.criticality.q1_rating": {"value": "critical"},
        "bia.criticality.q2_rto": {"value": "near_zero"},
        "bia.criticality.q3_rpo": {"value": "under_15m"},
    }
    results = scoring.compute_bia_results(DEFAULT_CONFIG, answers)
    assert "criticality" not in results


def test_dpia_needed_triggers_on_profile_count_threshold():
    answers = {"bia.screening.q2_profile_count": {"value": 5000}}
    result = scoring.compute_dpia_needed(DEFAULT_CONFIG, answers)
    assert result["result"] == "Yes"
    assert any("5000" in r for r in result["reasons"])


def test_dpia_needed_no_when_below_threshold_and_no_other_triggers():
    answers = {"bia.screening.q2_profile_count": {"value": 10}}
    result = scoring.compute_dpia_needed(DEFAULT_CONFIG, answers)
    assert result["result"] == "No"
    assert result["reasons"] == []


def test_dpia_needed_triggers_on_cross_border_transfer():
    answers = {"bia.screening.q3_cross_border": {"value": "Yes"}}
    result = scoring.compute_dpia_needed(DEFAULT_CONFIG, answers)
    assert result["result"] == "Yes"


def test_dpia_needed_triggers_on_sensitive_personal_data():
    answers = {"bia.screening.q1b_sensitive_personal_data": {"value": "Yes"}}
    result = scoring.compute_dpia_needed(DEFAULT_CONFIG, answers)
    assert result["result"] == "Yes"


def test_dpia_needed_triggers_on_any_art35_criterion():
    answers = {"dpia0.art35.c1": {"value": "Yes"}}
    result = scoring.compute_dpia_needed(DEFAULT_CONFIG, answers)
    assert result["result"] == "Yes"
    assert len(result["reasons"]) == 1


def test_dpia_needed_respects_custom_threshold():
    config = {**DEFAULT_CONFIG, "settings": {**DEFAULT_CONFIG["settings"], "dpia_profile_threshold": 100}}
    answers = {"bia.screening.q2_profile_count": {"value": 150}}
    result = scoring.compute_dpia_needed(config, answers)
    assert result["result"] == "Yes"


def test_risk_score_buckets_match_source_formula():
    # source: IF(score>20,"Critical",IF(score>12,"High",IF(score>4,"Medium",IF(score>1,"Low",""))))
    cases = [
        (5, 5, "Critical"),   # 25
        (4, 5, "High"),       # 20
        (4, 4, "High"),       # 16 (>12)
        (3, 3, "Medium"),     # 9
        (2, 3, "Medium"),     # 6 (>4)
        (2, 2, "Low"),        # 4 is not >4, but is >1, so Low
        (1, 1, "Not rated"),  # 1
    ]
    for likelihood, consequence, expected in cases:
        answers = {"dpia.q6_1": {"likelihood": likelihood, "consequence": consequence}}
        result = scoring.compute_dpia_risks(DEFAULT_CONFIG, answers)
        entry = result["by_question"]["dpia.q6_1"]
        assert entry["score"] == likelihood * consequence
        assert entry["level"] == expected, f"{likelihood}x{consequence}={likelihood*consequence} expected {expected} got {entry['level']}"


def test_risk_not_computed_without_both_likelihood_and_consequence():
    answers = {"dpia.q6_1": {"likelihood": 5}}
    result = scoring.compute_dpia_risks(DEFAULT_CONFIG, answers)
    assert "dpia.q6_1" not in result["by_question"]


def test_compute_results_bundles_everything():
    result = scoring.compute_results(DEFAULT_CONFIG, {})
    assert "bia_categories" in result
    assert "dpia_needed" in result
    assert "dpia_risks" in result
