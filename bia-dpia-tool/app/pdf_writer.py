"""Minimal, dependency-free PDF writer.

Uses only the 2 standard (non-embedded) Type1 fonts Helvetica and
Helvetica-Bold, which every PDF viewer provides -- so no font file needs to
be embedded. Text is placed with absolute positioning (Tm) rather than
relative (Td) to keep the layout math simple. Word-wrap uses a conservative
average character-width estimate rather than real font metrics: good enough
for a report, not for typesetting-critical output.
"""

import io
import textwrap

PAGE_WIDTH = 612  # US Letter, points
PAGE_HEIGHT = 792
MARGIN = 54
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class SimplePDF:
    def __init__(self):
        self.pages = [[]]
        self.y = PAGE_HEIGHT - MARGIN

    def _ensure_space(self, height):
        if self.y - height < MARGIN:
            self.pages.append([])
            self.y = PAGE_HEIGHT - MARGIN

    def _wrap(self, text, font_size, bold, indent):
        avg_char_width = font_size * (0.62 if bold else 0.52)
        max_chars = max(10, int((CONTENT_WIDTH - indent) / avg_char_width))
        lines = []
        for raw_line in str(text).split("\n"):
            wrapped = textwrap.wrap(raw_line, width=max_chars, break_long_words=True, break_on_hyphens=False)
            lines.extend(wrapped or [""])
        return lines

    def _text_op(self, font, size, x, y, text):
        encoded = _esc(text).encode("cp1252", errors="replace").decode("latin-1")
        return f"BT /{font} {size} Tf 1 0 0 1 {x:.1f} {y:.1f} Tm ({encoded}) Tj ET"

    def add_heading(self, text, level=1):
        size = {1: 18, 2: 14, 3: 12}.get(level, 12)
        self._ensure_space(size + 12)
        self.y -= size
        self.pages[-1].append(self._text_op("F2", size, MARGIN, self.y, text))
        self.y -= 8

    def add_paragraph(self, text, size=9, bold=False, indent=0, space_after=4):
        font = "F2" if bold else "F1"
        line_height = size * 1.35
        for line in self._wrap(text, size, bold, indent):
            self._ensure_space(line_height)
            self.y -= line_height
            self.pages[-1].append(self._text_op(font, size, MARGIN + indent, self.y, line))
        self.y -= space_after

    def add_spacer(self, height=6):
        self._ensure_space(height)
        self.y -= height

    def add_rule(self):
        self._ensure_space(6)
        self.pages[-1].append(f"{MARGIN} {self.y:.1f} m {PAGE_WIDTH - MARGIN} {self.y:.1f} l S")
        self.y -= 8

    def render(self) -> bytes:
        n_pages = len(self.pages)
        font1_id, font2_id = 3, 4
        page_ids = list(range(5, 5 + n_pages * 2, 2))
        content_ids = list(range(6, 6 + n_pages * 2, 2))

        objects = {
            1: "<< /Type /Catalog /Pages 2 0 R >>",
            2: f"<< /Type /Pages /Kids [{' '.join(f'{p} 0 R' for p in page_ids)}] /Count {n_pages} >>",
            font1_id: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            font2_id: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        }
        for i in range(n_pages):
            pid, cid = page_ids[i], content_ids[i]
            objects[pid] = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 {font1_id} 0 R /F2 {font2_id} 0 R >> >> "
                f"/Contents {cid} 0 R >>"
            )
            stream_bytes = "\n".join(self.pages[i]).encode("latin-1", errors="replace")
            objects[cid] = ("stream", stream_bytes)

        buf = bytearray()
        buf += b"%PDF-1.4\n"
        offsets = {}
        max_id = max(objects.keys())
        for obj_id in range(1, max_id + 1):
            if obj_id not in objects:
                continue
            offsets[obj_id] = len(buf)
            val = objects[obj_id]
            if isinstance(val, tuple) and val[0] == "stream":
                data = val[1]
                buf += f"{obj_id} 0 obj\n<< /Length {len(data)} >>\nstream\n".encode("latin-1")
                buf += data
                buf += b"\nendstream\nendobj\n"
            else:
                buf += f"{obj_id} 0 obj\n{val}\nendobj\n".encode("latin-1")

        xref_offset = len(buf)
        buf += f"xref\n0 {max_id + 1}\n".encode("latin-1")
        buf += b"0000000000 65535 f \n"
        for obj_id in range(1, max_id + 1):
            buf += f"{offsets.get(obj_id, 0):010d} 00000 n \n".encode("latin-1")
        buf += (
            f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF"
        ).encode("latin-1")
        return bytes(buf)


def build_pdf(report) -> bytes:
    pdf = SimplePDF()
    pdf.add_heading("Business Impact Assessment & DPIA Report", level=1)
    for label, value in report["meta"]:
        pdf.add_paragraph(f"{label}: {value or ''}", size=9)
    pdf.add_spacer(8)

    pdf.add_heading("Protection level", level=2)
    for p in report["protection"]:
        line = f"{p['aspect']}: {p['max_label']}"
        if p["classification"]:
            line += f" — {p['classification']} (protection profile: {p['protection_profile']}, service level: {p['service_level']})"
        pdf.add_paragraph(line, size=9)
    pdf.add_spacer(8)

    pdf.add_heading("Is a full DPIA needed?", level=2)
    pdf.add_paragraph(report["dpia_needed"]["result"], size=10, bold=True)
    for reason in report["dpia_needed"]["reasons"]:
        pdf.add_paragraph(f"- {reason}", size=9, indent=10)
    pdf.add_spacer(8)

    for section in report["sections"]:
        pdf.add_heading(f"{section['tool_title']} — {section['section_title']}", level=3)
        for row in section["rows"]:
            label = f"{row['id']} {row['prompt']}".strip()
            pdf.add_paragraph(label, size=9, bold=True, space_after=1)
            pdf.add_paragraph(row["answer"] or "(Not answered)", size=9, indent=10, space_after=1)
            if row["comment"]:
                pdf.add_paragraph(f"Comment: {row['comment']}", size=8, indent=10, space_after=1)
            for risk_label, risk_value in row["risk"]:
                pdf.add_paragraph(f"{risk_label}: {risk_value}", size=8, indent=10, space_after=1)
            pdf.add_spacer(6)

    return pdf.render()
