#!/usr/bin/env python3
"""Minimal Markdown -> PDF renderer (reportlab).

Handles: ATX headings (#..######), pipe tables (with header separator),
bullet lists (-/*), ordered lists, bold (**x**), inline `code`, horizontal
rules (---), blockquotes (>), and paragraphs. Tailored for tzar-bot reports —
not a general CommonMark engine. Requires reportlab (tools/.venv).

Usage: md-to-pdf.py <input.md> <output.pdf>
"""
import re, sys, html

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, ListFlowable, ListItem)

ACCENT = colors.HexColor("#1F4E79")
SURFACE = colors.HexColor("#EAF0F6")
BORDER = colors.HexColor("#B9C4D0")

def styles():
    ss = getSampleStyleSheet()
    S = {}
    S["body"] = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica",
                               fontSize=9.5, leading=13, spaceAfter=4)
    S["h1"] = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                             fontSize=15, textColor=ACCENT, spaceBefore=10, spaceAfter=6)
    S["h2"] = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                             fontSize=12, textColor=ACCENT, spaceBefore=8, spaceAfter=4)
    S["h3"] = ParagraphStyle("h3", parent=ss["Heading3"], fontName="Helvetica-Bold",
                             fontSize=10.5, textColor=colors.HexColor("#33475B"),
                             spaceBefore=6, spaceAfter=3)
    S["cell"] = ParagraphStyle("cell", parent=S["body"], fontSize=8, leading=10, spaceAfter=0)
    S["cellh"] = ParagraphStyle("cellh", parent=S["cell"], fontName="Helvetica-Bold",
                                textColor=colors.white)
    S["quote"] = ParagraphStyle("quote", parent=S["body"], fontSize=9, leading=12,
                                textColor=colors.HexColor("#555555"), leftIndent=8,
                                fontName="Helvetica-Oblique")
    return S

def inline(text):
    """Convert **bold**/`code` to reportlab markup; escape the rest."""
    out, i = [], 0
    for m in re.finditer(r"\*\*(.+?)\*\*|`([^`]+)`", text):
        out.append(html.escape(text[i:m.start()]))
        if m.group(1) is not None:
            out.append("<b>" + html.escape(m.group(1)) + "</b>")
        else:
            out.append('<font face="Courier">' + html.escape(m.group(2)) + "</font>")
        i = m.end()
    out.append(html.escape(text[i:]))
    return "".join(out)

def is_sep(line):
    return bool(re.match(r"^\s*\|?\s*:?-{2,}.*$", line)) and set(line.strip()) <= set("|-: ")

def parse_row(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]

def main(md_path, pdf_path):
    S = styles()
    lines = open(md_path, encoding="utf-8").read().split("\n")
    story, i, n = [], 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            story.append(Spacer(1, 3)); i += 1; continue
        if re.match(r"^\s*---+\s*$", line):
            story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER,
                                    spaceBefore=3, spaceAfter=3)); i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            lvl = len(m.group(1)); key = "h1" if lvl == 1 else "h2" if lvl == 2 else "h3"
            story.append(Paragraph(inline(m.group(2).strip()), S[key])); i += 1; continue
        # table
        if "|" in line and i + 1 < n and is_sep(lines[i + 1]):
            header = parse_row(line); i += 2; rows = []
            while i < n and "|" in lines[i] and lines[i].strip():
                rows.append(parse_row(lines[i])); i += 1
            ncol = len(header)
            data = [[Paragraph(inline(c), S["cellh"]) for c in header]]
            for r in rows:
                data.append([Paragraph(inline(r[c] if c < len(r) else ""), S["cell"])
                             for c in range(ncol)])
            avail = 170 * mm
            w = [avail / ncol] * ncol
            t = Table(data, colWidths=w, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t); story.append(Spacer(1, 4)); continue
        if line.lstrip().startswith(">"):
            story.append(Paragraph(inline(line.lstrip()[1:].strip()), S["quote"]))
            i += 1; continue
        mo = re.match(r"^(\s*)\d+\.\s+(.*)$", line)
        if mo:
            items = []
            while i < n and re.match(r"^(\s*)\d+\.\s+(.*)$", lines[i]):
                items.append(ListItem(Paragraph(inline(re.match(r"^\s*\d+\.\s+(.*)$", lines[i]).group(1)), S["body"])))
                i += 1
            story.append(ListFlowable(items, bulletType="1", leftIndent=14)); continue
        mb = re.match(r"^(\s*)[-*]\s+(.*)$", line)
        if mb:
            items = []
            while i < n and re.match(r"^(\s*)[-*]\s+(.*)$", lines[i]):
                items.append(ListItem(Paragraph(inline(re.match(r"^\s*[-*]\s+(.*)$", lines[i]).group(1)), S["body"])))
                i += 1
            story.append(ListFlowable(items, bulletType="bullet", leftIndent=14)); continue
        story.append(Paragraph(inline(line.strip()), S["body"])); i += 1

    doc = SimpleDocTemplate(pdf_path, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                            leftMargin=20 * mm, rightMargin=20 * mm,
                            title="VA & PT Report")
    doc.build(story)
    print(f"wrote {pdf_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: md-to-pdf.py <input.md> <output.pdf>"); sys.exit(2)
    main(sys.argv[1], sys.argv[2])
