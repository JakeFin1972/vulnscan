"""CSV export -- pure stdlib (csv module)."""

import csv
import io


def build_csv(report) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)

    w.writerow(["Business Impact Assessment & DPIA Report"])
    w.writerow([])
    for label, value in report["meta"]:
        w.writerow([label, value])
    w.writerow([])

    if report["protection"]:
        w.writerow(["Protection level"])
        w.writerow(["Aspect", "Maximum impact", "Classification", "Protection profile", "Service level", "Answered"])
        for p in report["protection"]:
            w.writerow([p["aspect"], p["max_label"], p["classification"], p["protection_profile"], p["service_level"], p["answered"]])
        w.writerow([])

    if report["dpia_needed"] is not None:
        w.writerow(["Is a DPIA needed?", report["dpia_needed"]["result"]])
        for reason in report["dpia_needed"]["reasons"]:
            w.writerow(["", reason])
        w.writerow([])

    for section in report["sections"]:
        w.writerow([section["tool_title"], section["section_title"]])
        w.writerow(["ID", "Question", "Answer", "Comment", "Risk & remediation"])
        for row in section["rows"]:
            risk_text = "; ".join(f"{label}: {value}" for label, value in row["risk"])
            w.writerow([row["id"], row["prompt"], row["answer"], row["comment"], risk_text])
        w.writerow([])

    # utf-8-sig so Excel auto-detects UTF-8 (accented text, curly quotes, etc.)
    return buf.getvalue().encode("utf-8-sig")
