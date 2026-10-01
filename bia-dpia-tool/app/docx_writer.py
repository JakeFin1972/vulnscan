"""Minimal, dependency-free .docx (Word OOXML) writer.

A .docx file is a zip package with a handful of XML parts. This writer
produces the smallest valid package Word/LibreOffice/Google Docs will open:
no styles.xml, no theme, no embedded fonts -- headings and tables use direct
run formatting instead of named styles, which every OOXML-compliant reader
supports without a styles part present.
"""

import io
import zipfile
from xml.sax.saxutils import escape

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

# A restrained, print-friendly palette (hex, no leading #): dark navy for
# headings/accents, a muted blue-gray for secondary text, light gray for
# zebra striping and borders. Navy-on-white and white-on-navy both clear the
# WCAG AA 4.5:1 contrast threshold for body text.
NAVY = "1F3864"
ACCENT = "2F6F9F"
MUTED = "595959"
BORDER = "AAAAAA"
ZEBRA = "F2F5F8"
FONT = "Calibri"

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

DOCUMENT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
</Relationships>"""


def _footer_xml(title):
    """A slim footer: report title on the left, "Page X of Y" on the right,
    separated by a top border -- the running context a multi-page report
    needs so a printed page never loses track of what it belongs to."""
    page_field = (
        '<w:fldSimple w:instr=" PAGE "><w:r><w:t>1</w:t></w:r></w:fldSimple>'
        '<w:r><w:t xml:space="preserve"> of </w:t></w:r>'
        '<w:fldSimple w:instr=" NUMPAGES "><w:r><w:t>1</w:t></w:r></w:fldSimple>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:ftr xmlns:w="{W_NS}">'
        '<w:p><w:pPr><w:pBdr><w:top w:val="single" w:sz="4" w:space="1" w:color="' + BORDER + '"/></w:pBdr>'
        '<w:tabs><w:tab w:val="right" w:pos="9360"/></w:tabs>'
        f'<w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}"/><w:color w:val="{MUTED}"/><w:sz w:val="16"/></w:rPr></w:pPr>'
        f'<w:r><w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}"/><w:color w:val="{MUTED}"/><w:sz w:val="16"/></w:rPr>'
        f'<w:t xml:space="preserve">{escape(title)}</w:t></w:r>'
        f'<w:r><w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}"/><w:color w:val="{MUTED}"/><w:sz w:val="16"/></w:rPr><w:tab/></w:r>'
        f'<w:r><w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}"/><w:color w:val="{MUTED}"/><w:sz w:val="16"/></w:rPr>{page_field}</w:r>'
        "</w:p></w:ftr>"
    )


class SimpleDocx:
    def __init__(self):
        self.body_parts = []

    def _run(self, text, bold=False, size=None, color=None, italic=False):
        inner = f'<w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}"/>'
        if bold:
            inner += "<w:b/>"
        if italic:
            inner += "<w:i/>"
        if size:
            inner += f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>'
        if color:
            inner += f'<w:color w:val="{color}"/>'
        props = f"<w:rPr>{inner}</w:rPr>"
        return f'<w:r>{props}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'

    def add_paragraph(self, text="", bold=False, size=None, italic=False, color=None, space_after=100):
        pPr = f'<w:pPr><w:spacing w:after="{space_after}"/></w:pPr>'
        lines = text.split("\n") if text else [""]
        for line in lines:
            run = self._run(line, bold=bold, size=size, italic=italic, color=color) if line else ""
            self.body_parts.append(f"<w:p>{pPr}{run}</w:p>")

    def add_heading(self, text, level=1):
        size = {1: 40, 2: 26, 3: 22}.get(level, 22)
        color = NAVY if level in (1, 2) else ACCENT
        border = ""
        if level == 1:
            border = f'<w:pBdr><w:bottom w:val="single" w:sz="18" w:space="8" w:color="{NAVY}"/></w:pBdr>'
        elif level == 2:
            border = f'<w:pBdr><w:bottom w:val="single" w:sz="6" w:space="4" w:color="{BORDER}"/></w:pBdr>'
        self.body_parts.append(
            f'<w:p><w:pPr>{border}<w:spacing w:before="360" w:after="160"/></w:pPr>'
            f'{self._run(text, bold=True, size=size, color=color)}</w:p>'
        )

    def add_subtitle(self, text, color=MUTED):
        self.body_parts.append(
            f'<w:p><w:pPr><w:spacing w:before="0" w:after="320"/></w:pPr>'
            f'{self._run(text, size=20, color=color)}</w:p>'
        )

    def add_table(self, rows, header=True, zebra=True):
        tbl = [
            "<w:tbl><w:tblPr>"
            '<w:tblW w:w="0" w:type="auto"/>'
            "<w:tblBorders>"
            f'<w:top w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"/>'
            f'<w:left w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"/>'
            f'<w:bottom w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"/>'
            f'<w:right w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"/>'
            f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"/>'
            f'<w:insideV w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"/>'
            "</w:tblBorders></w:tblPr>"
        ]
        for ridx, row in enumerate(rows):
            is_header = header and ridx == 0
            is_zebra = zebra and not is_header and (ridx % 2 == 0)
            cells = []
            for cell_text in row:
                lines = str(cell_text).split("\n") if cell_text else [""]
                text_color = "FFFFFF" if is_header else None
                paras = "".join(
                    f"<w:p>{self._run(line, bold=is_header, size=18, color=text_color)}</w:p>" for line in lines
                )
                if is_header:
                    shading = f'<w:shd w:val="clear" w:fill="{NAVY}"/>'
                elif is_zebra:
                    shading = f'<w:shd w:val="clear" w:fill="{ZEBRA}"/>'
                else:
                    shading = ""
                cells.append(f"<w:tc><w:tcPr>{shading}</w:tcPr>{paras}</w:tc>")
            tbl.append(f"<w:tr>{''.join(cells)}</w:tr>")
        tbl.append("</w:tbl><w:p/>")
        self.body_parts.append("".join(tbl))

    def render(self, footer_title="") -> bytes:
        document_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:body>'
            + "".join(self.body_parts)
            + '<w:sectPr><w:footerReference w:type="default" r:id="rId1"/>'
            '<w:pgSz w:w="12240" w:h="15840"/>'
            '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/></w:sectPr>'
            + "</w:body></w:document>"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", CONTENT_TYPES)
            z.writestr("_rels/.rels", ROOT_RELS)
            z.writestr("word/_rels/document.xml.rels", DOCUMENT_RELS)
            z.writestr("word/document.xml", document_xml)
            z.writestr("word/footer1.xml", _footer_xml(footer_title))
        return buf.getvalue()


def build_docx(report) -> bytes:
    doc = SimpleDocx()
    doc.add_heading("Business Impact Assessment & DPIA Report", level=1)
    subtitle = " · ".join(p for p in [report.get("org_name"), f"Generated {report.get('generated_at')}"] if p)
    if subtitle:
        doc.add_subtitle(subtitle)

    doc.add_table([["Field", "Value"]] + [[label, value or ""] for label, value in report["meta"]])

    if report["protection"]:
        doc.add_heading("Protection level", level=2)
        doc.add_table(
            [["Aspect", "Maximum impact", "Classification", "Protection profile", "Service level", "Answered"]]
            + [
                [p["aspect"], p["max_label"], p["classification"], p["protection_profile"], p["service_level"], p["answered"]]
                for p in report["protection"]
            ]
        )

    if report["dpia_needed"] is not None:
        doc.add_heading("Is a full DPIA needed?", level=2)
        doc.add_paragraph(report["dpia_needed"]["result"], bold=True, color=ACCENT)
        for reason in report["dpia_needed"]["reasons"]:
            doc.add_paragraph(f"• {reason}")

    for section in report["sections"]:
        doc.add_heading(f"{section['tool_title']} — {section['section_title']}", level=2)
        for row in section["rows"]:
            label = f"{row['id']} {row['prompt']}".strip()
            doc.add_paragraph(label, bold=True, color=NAVY, space_after=40)
            doc.add_paragraph(row["answer"] or "(Not answered)", space_after=40)
            if row["comment"]:
                doc.add_paragraph(f"Comment: {row['comment']}", italic=True, color=MUTED, space_after=40)
            for risk_label, risk_value in row["risk"]:
                doc.add_paragraph(f"{risk_label}: {risk_value}", italic=True, color=MUTED, space_after=40)
            doc.add_paragraph("", space_after=120)

    return doc.render(footer_title=f"{report.get('project_name') or 'BIA/DPIA Report'}")
