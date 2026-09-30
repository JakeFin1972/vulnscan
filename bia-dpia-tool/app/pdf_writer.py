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
FOOTER_HEIGHT = 26  # reserved band at the bottom of every page

# A restrained, print-friendly palette (0-1 RGB floats for the PDF `rg`/`RG`
# color operators). Navy on white and white on navy both clear the WCAG AA
# 4.5:1 contrast threshold for text.
BLACK = (0.13, 0.13, 0.13)
NAVY = (0.122, 0.220, 0.392)
ACCENT = (0.184, 0.435, 0.620)
MUTED = (0.35, 0.38, 0.42)
BORDER = (0.72, 0.75, 0.78)
ZEBRA = (0.95, 0.96, 0.97)


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class SimplePDF:
    def __init__(self):
        self.pages = [[]]
        self.y = PAGE_HEIGHT - MARGIN
        # MARGIN already reserves room above FOOTER_HEIGHT; the usable floor
        # for content is a bit higher than MARGIN so text never collides
        # with the per-page footer drawn later at render() time.
        self.content_floor = MARGIN + FOOTER_HEIGHT

    def _ensure_space(self, height):
        if self.y - height < self.content_floor:
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

    def _text_op(self, font, size, x, y, text, color=BLACK):
        encoded = _esc(text).encode("cp1252", errors="replace").decode("latin-1")
        r, g, b = color
        return f"{r:.3f} {g:.3f} {b:.3f} rg BT /{font} {size} Tf 1 0 0 1 {x:.1f} {y:.1f} Tm ({encoded}) Tj ET"

    def add_heading(self, text, level=1):
        size = {1: 20, 2: 14, 3: 11.5}.get(level, 12)
        color = {1: NAVY, 2: NAVY, 3: ACCENT}.get(level, NAVY)
        self._ensure_space(size + 16)
        self.y -= size
        self.pages[-1].append(self._text_op("F2", size, MARGIN, self.y, text, color))
        if level == 1:
            self.y -= 6
            self.add_rule(color=NAVY, weight=1.6)
        elif level == 2:
            self.y -= 4
            self.add_rule(color=BORDER, weight=0.8)
        else:
            self.y -= 6

    def add_subtitle(self, text, size=9.5, color=MUTED):
        self._ensure_space(size + 6)
        self.y -= size
        self.pages[-1].append(self._text_op("F1", size, MARGIN, self.y, text, color))
        self.y -= 10

    def add_paragraph(self, text, size=9.5, bold=False, indent=0, color=BLACK, space_after=4):
        font = "F2" if bold else "F1"
        line_height = size * 1.4
        for line in self._wrap(text, size, bold, indent):
            self._ensure_space(line_height)
            self.y -= line_height
            self.pages[-1].append(self._text_op(font, size, MARGIN + indent, self.y, line, color))
        self.y -= space_after

    def add_kv_row(self, label, value, label_width=155, size=9.5):
        """Two-column label/value row (bold navy label, plain value) used for
        the report's metadata block, instead of a single "Label: value"
        run-on line -- lines up into a scannable column like a form."""
        value = value or ""
        line_height = size * 1.4
        value_lines = self._wrap(value, size, False, label_width) or [""]
        self._ensure_space(line_height)
        self.y -= line_height
        self.pages[-1].append(self._text_op("F2", size, MARGIN, self.y, label, NAVY))
        self.pages[-1].append(self._text_op("F1", size, MARGIN + label_width, self.y, value_lines[0], BLACK))
        for extra in value_lines[1:]:
            self._ensure_space(line_height)
            self.y -= line_height
            self.pages[-1].append(self._text_op("F1", size, MARGIN + label_width, self.y, extra, BLACK))
        self.y -= 2

    def add_spacer(self, height=6):
        self._ensure_space(height)
        self.y -= height

    def add_rule(self, color=BORDER, weight=0.75):
        self._ensure_space(6)
        r, g, b = color
        self.pages[-1].append(
            f"{r:.3f} {g:.3f} {b:.3f} RG {weight} w {MARGIN} {self.y:.1f} m {PAGE_WIDTH - MARGIN} {self.y:.1f} l S"
        )
        self.y -= 8

    def add_fill_rect(self, x, y, w, h, color):
        r, g, b = color
        self.pages[-1].append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

    def _add_footers(self, title):
        """Adds a "title -- Page X of Y" footer to every page, drawn last
        (after all content flowed) since the total page count is only known
        once the whole report has been laid out."""
        n_pages = len(self.pages)
        rule_y = MARGIN
        text_y = MARGIN - 16
        r, g, b = BORDER
        for i, page in enumerate(self.pages):
            page.append(f"{r:.3f} {g:.3f} {b:.3f} RG 0.75 w {MARGIN} {rule_y:.1f} m {PAGE_WIDTH - MARGIN} {rule_y:.1f} l S")
            if title:
                page.append(self._text_op("F1", 8, MARGIN, text_y, title, MUTED))
            page_text = f"Page {i + 1} of {n_pages}"
            est_width = len(page_text) * (8 * 0.52)
            page.append(self._text_op("F1", 8, PAGE_WIDTH - MARGIN - est_width, text_y, page_text, MUTED))

    def render(self, footer_title="") -> bytes:
        self._add_footers(footer_title)
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
    subtitle = " · ".join(p for p in [report.get("org_name"), f"Generated {report.get('generated_at')}"] if p)
    if subtitle:
        pdf.add_subtitle(subtitle)
    pdf.add_spacer(4)
    for label, value in report["meta"]:
        pdf.add_kv_row(label, value)
    pdf.add_spacer(10)

    if report["protection"]:
        pdf.add_heading("Protection level", level=2)
        for p in report["protection"]:
            line = f"{p['aspect']}: {p['max_label']}"
            if p["classification"]:
                line += f" — {p['classification']} (protection profile: {p['protection_profile']}, service level: {p['service_level']})"
            pdf.add_paragraph(line, size=9.5)
        pdf.add_spacer(8)

    if report["dpia_needed"] is not None:
        pdf.add_heading("Is a full DPIA needed?", level=2)
        pdf.add_paragraph(report["dpia_needed"]["result"], size=11, bold=True, color=ACCENT)
        for reason in report["dpia_needed"]["reasons"]:
            pdf.add_paragraph(f"- {reason}", size=9.5, indent=10)
        pdf.add_spacer(8)

    for section in report["sections"]:
        pdf.add_heading(f"{section['tool_title']} — {section['section_title']}", level=3)
        for row in section["rows"]:
            label = f"{row['id']} {row['prompt']}".strip()
            pdf.add_paragraph(label, size=9.5, bold=True, color=NAVY, space_after=1)
            pdf.add_paragraph(row["answer"] or "(Not answered)", size=9.5, indent=10, space_after=1)
            if row["comment"]:
                pdf.add_paragraph(f"Comment: {row['comment']}", size=8.5, indent=10, color=MUTED, space_after=1)
            for risk_label, risk_value in row["risk"]:
                pdf.add_paragraph(f"{risk_label}: {risk_value}", size=8.5, indent=10, color=MUTED, space_after=1)
            pdf.add_spacer(4)
            pdf.add_rule(color=BORDER, weight=0.5)

    return pdf.render(footer_title=report.get("project_name") or "BIA/DPIA Report")
