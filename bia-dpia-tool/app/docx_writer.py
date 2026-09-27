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

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""


class SimpleDocx:
    def __init__(self):
        self.body_parts = []

    def _run(self, text, bold=False, size=None, color=None, italic=False):
        inner = ""
        if bold:
            inner += "<w:b/>"
        if italic:
            inner += "<w:i/>"
        if size:
            inner += f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>'
        if color:
            inner += f'<w:color w:val="{color}"/>'
        props = f"<w:rPr>{inner}</w:rPr>" if inner else ""
        return f'<w:r>{props}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'

    def add_paragraph(self, text="", bold=False, size=None, italic=False, space_after=100):
        pPr = f'<w:pPr><w:spacing w:after="{space_after}"/></w:pPr>'
        lines = text.split("\n") if text else [""]
        for line in lines:
            run = self._run(line, bold=bold, size=size, italic=italic) if line else ""
            self.body_parts.append(f"<w:p>{pPr}{run}</w:p>")

    def add_heading(self, text, level=1):
        size = {1: 32, 2: 26, 3: 22}.get(level, 22)
        self.body_parts.append(
            f'<w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>{self._run(text, bold=True, size=size)}</w:p>'
        )

    def add_table(self, rows, header=True):
        tbl = [
            "<w:tbl><w:tblPr>"
            '<w:tblW w:w="0" w:type="auto"/>'
            "<w:tblBorders>"
            '<w:top w:val="single" w:sz="4" w:space="0" w:color="AAAAAA"/>'
            '<w:left w:val="single" w:sz="4" w:space="0" w:color="AAAAAA"/>'
            '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="AAAAAA"/>'
            '<w:right w:val="single" w:sz="4" w:space="0" w:color="AAAAAA"/>'
            '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="AAAAAA"/>'
            '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="AAAAAA"/>'
            "</w:tblBorders></w:tblPr>"
        ]
        for ridx, row in enumerate(rows):
            is_header = header and ridx == 0
            cells = []
            for cell_text in row:
                lines = str(cell_text).split("\n") if cell_text else [""]
                paras = "".join(f"<w:p>{self._run(line, bold=is_header, size=18)}</w:p>" for line in lines)
                shading = '<w:shd w:val="clear" w:fill="EFEFEF"/>' if is_header else ""
                cells.append(f"<w:tc><w:tcPr>{shading}</w:tcPr>{paras}</w:tc>")
            tbl.append(f"<w:tr>{''.join(cells)}</w:tr>")
        tbl.append("</w:tbl><w:p/>")
        self.body_parts.append("".join(tbl))

    def render(self) -> bytes:
        document_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:document xmlns:w="{W_NS}"><w:body>'
            + "".join(self.body_parts)
            + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
            '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/></w:sectPr>'
            + "</w:body></w:document>"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", CONTENT_TYPES)
            z.writestr("_rels/.rels", ROOT_RELS)
            z.writestr("word/document.xml", document_xml)
        return buf.getvalue()


def build_docx(report) -> bytes:
    doc = SimpleDocx()
    doc.add_heading("Business Impact Assessment & DPIA Report", level=1)

    doc.add_table([["Field", "Value"]] + [[label, value or ""] for label, value in report["meta"]])

    doc.add_heading("Protection level", level=2)
    doc.add_table(
        [["Aspect", "Maximum impact", "Classification", "Protection profile", "Service level", "Answered"]]
        + [
            [p["aspect"], p["max_label"], p["classification"], p["protection_profile"], p["service_level"], p["answered"]]
            for p in report["protection"]
        ]
    )

    doc.add_heading("Is a full DPIA needed?", level=2)
    doc.add_paragraph(report["dpia_needed"]["result"], bold=True)
    for reason in report["dpia_needed"]["reasons"]:
        doc.add_paragraph(f"• {reason}")

    for section in report["sections"]:
        doc.add_heading(f"{section['tool_title']} — {section['section_title']}", level=2)
        for row in section["rows"]:
            label = f"{row['id']} {row['prompt']}".strip()
            doc.add_paragraph(label, bold=True, space_after=40)
            doc.add_paragraph(row["answer"] or "(Not answered)", space_after=40)
            if row["comment"]:
                doc.add_paragraph(f"Comment: {row['comment']}", italic=True, space_after=40)
            for risk_label, risk_value in row["risk"]:
                doc.add_paragraph(f"{risk_label}: {risk_value}", italic=True, space_after=40)
            doc.add_paragraph("", space_after=120)

    return doc.render()
