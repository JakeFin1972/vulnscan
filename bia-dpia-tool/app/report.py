"""Flattens an assessment (config + answers + computed results) into a
plain-data report structure shared by the CSV, Word and PDF exporters.

Kept separate from http_app.py's HTML print view (which has its own
render helper) so a change here can't regress the already-tested print
view, and vice versa.
"""

RISK_FIELD_LABELS = [
    ("risk_identified", "Risk identified"),
    ("remediation", "Remediation options"),
    ("likelihood", "Likelihood"),
    ("consequence", "Consequence"),
    ("impact_brand", "Impact on brand & reputation"),
    ("impact_finance", "Impact on finance (incl. sales)"),
    ("impact_people", "Impact on business & people"),
    ("rationale", "Rationale"),
    ("conclusion", "Conclusion"),
    ("risk_owner", "Risk owner"),
    ("status", "Status"),
    ("due_date", "Due date"),
    ("completion_date", "Completion date"),
    ("risk_comments", "Additional comments"),
]


def _value_text(answer):
    if not answer:
        return ""
    value = answer.get("value")
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value in (None, ""):
        return ""
    return str(value)


SCOPE_LABELS = {"bia": "BIA only", "dpia": "DPIA only", "both": "BIA + DPIA"}
STATUS_LABELS = {"draft": "Draft", "submitted": "Submitted", "not_applicable": "Not applicable (out of scope)"}

# Which tool sections apply for a given scope, in display order.
SCOPE_TOOLS = {"bia": ["bia"], "dpia": ["dpia0", "dpia"], "both": ["bia", "dpia0", "dpia"]}


def build_report(config, assessment, answers, results):
    a = assessment
    scope = a.get("scope", "both")
    include_bia = scope in ("bia", "both")

    meta = [
        ("Project/tool/application name", a["project_name"]),
        ("Description", a["description"]),
        ("Country/countries/business unit", a["countries"]),
        ("Project manager", a["project_manager"]),
        ("Solution name", a["solution_name"]),
        ("Solution owner", a["solution_owner"]),
        ("Completed by", f"{a['completed_by']} ({a['completed_by_email']})".strip()),
        ("Form date", a["form_date"]),
        ("Assessment scope", SCOPE_LABELS.get(scope, scope)),
    ]
    if scope in ("bia", "both"):
        meta.append(("BIA status", STATUS_LABELS.get(a.get("bia_status"), a.get("bia_status"))))
    if scope in ("dpia", "both"):
        meta.append(("DPIA status", STATUS_LABELS.get(a.get("dpia_status"), a.get("dpia_status"))))

    protection = []
    if include_bia:
        for cat, entry in results["bia_categories"].items():
            classification = ""
            if entry.get("classification_code"):
                classification = f"{entry.get('classification_label') or ''} ({entry['classification_code']})".strip()
            protection.append(
                {
                    "aspect": cat.capitalize(),
                    "max_label": entry["max_label"],
                    "classification": classification,
                    "protection_profile": entry.get("protection_profile") or "",
                    "service_level": entry.get("service_level") or "",
                    "answered": f"{entry['answered_count']}/{entry['total_questions']}",
                }
            )

    dpia_needed = results["dpia_needed"] if include_bia else None

    sections = []
    for tool_key in SCOPE_TOOLS.get(scope, SCOPE_TOOLS["both"]):
        tool = config["tools"][tool_key]
        for section in tool["sections"]:
            rows = []
            for q in section["questions"]:
                answer = answers.get(q["key"]) or {}
                risk = []
                if q.get("has_risk_register"):
                    risk = [(label, str(answer.get(field) or "")) for field, label in RISK_FIELD_LABELS if answer.get(field)]
                rows.append(
                    {
                        "id": q.get("id", ""),
                        "prompt": q["prompt"],
                        "answer": _value_text(answer),
                        "comment": answer.get("comment") or "",
                        "risk": risk,
                    }
                )
            sections.append({"tool_title": tool["title"], "section_title": section["title"], "rows": rows})

    return {"scope": scope, "meta": meta, "protection": protection, "dpia_needed": dpia_needed, "sections": sections}


def report_filename(assessment, ext):
    import re

    base = re.sub(r"[^A-Za-z0-9._-]+", "-", assessment["project_name"].strip() or "assessment").strip("-") or "assessment"
    return f"BIA-DPIA-{base}-{assessment['id']}.{ext}"
