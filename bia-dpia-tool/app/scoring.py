"""Replicates the scoring formulas from the source spreadsheet.

- Per BIA category, the maximum impact is MAX() over the numeric value of
  every answered scenario in that category (unanswered rows are excluded;
  if nothing at all has been answered the effective value is 0, i.e.
  "Not applicable" -- this matches the workbook's MAX(IF(ISERROR(...))))
  behaviour of resolving to 0 on an empty range).
- The classification code for Confidentiality/Integrity/Availability is the
  aspect's letter plus the "Classification" number looked up for that
  maximum value in the impact_scale option list (tblImpact in the
  workbook), e.g. value 5 ("Critical") -> classification 4 -> "C4".
- "Is a DPIA needed?" is Yes if: the profile count screening question is at
  or above the configured threshold, OR the cross-border-transfer screening
  question is "Yes", OR the sensitive-personal-data screening question is
  "Yes" (mirrors BIA!D9>=2000 / BIA!D10="Yes" / Protection Level!E16="Yes"
  in the source file), OR any Art. 35(3) GDPR / WP248 criterion applies.
- Per DPIA question, risk score = likelihood x consequence, bucketed into
  Critical/High/Medium/Low using the same >20/>12/>4/>1 thresholds as the
  source sheet's J-column formula.
"""

ASPECT_LETTERS = {
    "confidentiality": "C",
    "integrity": "I",
    "availability": "A",
}


def _impact_scale_lookup(config):
    return {row["value"]: row for row in config["option_lists"]["impact_scale"]}


def _iter_questions(tool):
    for section in tool.get("sections", []):
        for question in section.get("questions", []):
            yield section, question


def compute_bia_results(config, answers):
    scale = _impact_scale_lookup(config)
    categories = {}
    bia_tool = config["tools"]["bia"]

    by_category = {}
    for section, question in _iter_questions(bia_tool):
        category = question.get("category")
        if not category or question.get("input_type") != "impact":
            continue
        by_category.setdefault(category, []).append(question["key"])

    for category, keys in by_category.items():
        values = []
        for key in keys:
            ans = answers.get(key)
            if not ans:
                continue
            val = ans.get("value")
            if val is None or val == "":
                continue
            try:
                values.append(int(val))
            except (TypeError, ValueError):
                continue
        max_value = max(values) if values else 0
        scale_row = scale.get(max_value, {})
        entry = {
            "max_value": max_value,
            "max_label": scale_row.get("label", "Not applicable"),
            "answered_count": len(values),
            "total_questions": len(keys),
        }
        letter = ASPECT_LETTERS.get(category)
        if letter:
            classification = scale_row.get("classification")
            if isinstance(classification, int):
                code = f"{letter}{classification}"
            else:
                code = classification or "<assessment not completed>"
            matrix_row = next(
                (
                    row
                    for row in config.get("classification_matrix", [])
                    if row.get("code", "").split(" ")[0] == code
                ),
                None,
            )
            entry["classification_code"] = code
            entry["classification_label"] = matrix_row["label"] if matrix_row else None
            entry["protection_profile"] = scale_row.get("protection_profile")
            entry["service_level"] = scale_row.get("service_level")
        categories[category] = entry

    return categories


def _find_answer_value(answers, key):
    ans = answers.get(key)
    if not ans:
        return None
    return ans.get("value")


def compute_dpia_needed(config, answers):
    reasons = []
    threshold = config.get("settings", {}).get("dpia_profile_threshold", 2000)

    profile_count = _find_answer_value(answers, "bia.screening.q2_profile_count")
    try:
        if profile_count not in (None, "") and int(profile_count) >= threshold:
            reasons.append(f"{profile_count} individual profiles will be processed (threshold: {threshold}).")
    except (TypeError, ValueError):
        pass

    if _find_answer_value(answers, "bia.screening.q3_cross_border") == "Yes":
        reasons.append("Personal data is transferred across borders, outside the original jurisdiction.")

    if _find_answer_value(answers, "bia.screening.q1b_sensitive_personal_data") == "Yes":
        reasons.append("Special category / sensitive personal data will be processed.")

    dpia0 = config["tools"].get("dpia0", {})
    for section, question in _iter_questions(dpia0):
        if question.get("role") != "art35_criterion":
            continue
        if _find_answer_value(answers, question["key"]) == "Yes":
            reasons.append(f"Art. 35(3) criterion applies: {question['prompt']}")

    return {"result": "Yes" if reasons else "No", "reasons": reasons}


def compute_dpia_risks(config, answers):
    thresholds = config.get("settings", {}).get(
        "dpia_risk_thresholds", {"critical": 20, "high": 12, "medium": 4, "low": 1}
    )
    dpia_tool = config["tools"].get("dpia", {})
    results = {}
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for section, question in _iter_questions(dpia_tool):
        if not question.get("has_risk_register"):
            continue
        ans = answers.get(question["key"]) or {}
        likelihood = ans.get("likelihood")
        consequence = ans.get("consequence")
        try:
            likelihood = int(likelihood)
            consequence = int(consequence)
        except (TypeError, ValueError):
            continue
        score = likelihood * consequence
        if score > thresholds.get("critical", 20):
            level = "Critical"
        elif score > thresholds.get("high", 12):
            level = "High"
        elif score > thresholds.get("medium", 4):
            level = "Medium"
        elif score > thresholds.get("low", 1):
            level = "Low"
        else:
            level = "Not rated"
        if level in counts:
            counts[level] += 1
        results[question["key"]] = {
            "likelihood": likelihood,
            "consequence": consequence,
            "score": score,
            "level": level,
            "question_id": question.get("id"),
            "prompt": question["prompt"],
        }

    return {"by_question": results, "counts": counts}


def compute_results(config, answers):
    bia = compute_bia_results(config, answers)
    dpia_needed = compute_dpia_needed(config, answers)
    dpia_risks = compute_dpia_risks(config, answers)
    return {
        "bia_categories": bia,
        "dpia_needed": dpia_needed,
        "dpia_risks": dpia_risks,
    }
