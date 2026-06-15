# tzar-bot Report Design System

PDF generation using Python ReportLab. Read this before generating any pentest report.

## Install

```bash
pip install reportlab pillow 2>/dev/null || pip3 install reportlab pillow
```

## Color Palette (Dark Theme)

```python
from reportlab.lib.colors import HexColor

COLORS = {
    "background":   HexColor("#0d1117"),
    "surface":      HexColor("#161b22"),
    "border":       HexColor("#30363d"),
    "text_primary": HexColor("#e6edf3"),
    "text_muted":   HexColor("#8b949e"),
    "accent":       HexColor("#58a6ff"),
    "critical":     HexColor("#f85149"),
    "high":         HexColor("#e3b341"),
    "medium":       HexColor("#3fb950"),
    "low":          HexColor("#58a6ff"),
    "info":         HexColor("#8b949e"),
    "white":        HexColor("#ffffff"),
}

SEVERITY_COLOR = {
    "Critical":      COLORS["critical"],
    "High":          COLORS["high"],
    "Medium":        COLORS["medium"],
    "Low":           COLORS["low"],
    "Informational": COLORS["info"],
}
```

## Typography

```python
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# Register fonts (or use built-ins)
FONT_MONO = "Courier"       # code blocks, CVE IDs, vectors
FONT_SANS = "Helvetica"     # body text
FONT_BOLD = "Helvetica-Bold"

STYLES = {
    "h1": ParagraphStyle("H1", fontName=FONT_BOLD, fontSize=24, textColor=COLORS["text_primary"]),
    "h2": ParagraphStyle("H2", fontName=FONT_BOLD, fontSize=16, textColor=COLORS["accent"]),
    "h3": ParagraphStyle("H3", fontName=FONT_BOLD, fontSize=12, textColor=COLORS["text_primary"]),
    "body": ParagraphStyle("Body", fontName=FONT_SANS, fontSize=10, textColor=COLORS["text_primary"], leading=16),
    "code": ParagraphStyle("Code", fontName=FONT_MONO, fontSize=9, textColor=COLORS["text_primary"],
                           backColor=COLORS["surface"], leftIndent=12, rightIndent=12),
    "muted": ParagraphStyle("Muted", fontName=FONT_SANS, fontSize=9, textColor=COLORS["text_muted"]),
}
```

## Page Layout

```python
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Spacer
from reportlab.lib.units import mm

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 20 * mm

def build_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN,
        title="Penetration Test Report",
        author="tzar-bot",
    )
    # Set background color via canvas callback
    def on_page(canvas, doc):
        canvas.setFillColor(COLORS["background"])
        canvas.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, fill=True, stroke=False)
    
    story = []
    # Build story elements...
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
```

## Severity Badge

```python
from reportlab.platypus import Table, TableStyle

def severity_badge(severity):
    color = SEVERITY_COLOR.get(severity, COLORS["info"])
    data = [[severity]]
    t = Table(data, colWidths=[70])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TEXTCOLOR",  (0, 0), (-1, -1), COLORS["white"]),
        ("FONTNAME",   (0, 0), (-1, -1), FONT_BOLD),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [color]),
        ("ROUNDEDCORNERS", [3]),
    ]))
    return t
```

## Required Report Sections (in order)

1. **Cover Page** — logo, title, client name, engagement date, classification label
2. **Disclaimer** — standard engagement disclaimer, authorization statement
3. **Executive Summary** — risk posture, finding counts by severity, top 3 most critical issues
4. **Findings Overview Table** — clickable table of all findings with ID, title, severity, CVSS
5. **Individual Findings** — one page per finding (see finding card layout below)
6. **Remediation Roadmap** — prioritized action plan grouped by effort (quick wins vs long-term)
7. **Methodology** — phases run, tools used, scope
8. **Appendix** — evidence index, raw tool outputs (optional)

## Finding Card Layout (per finding)

```
┌─────────────────────────────────────────────────────────┐
│ F-004  [CRITICAL]  SQL Injection in /api/products        │
├─────────────────────────────────────────────────────────┤
│ CVSS Score: 9.8   CWE: CWE-89   OWASP: A03:2021        │
│ Affected: https://target.com/api/products?id=           │
├─────────────────────────────────────────────────────────┤
│ Description                                              │
│ [paragraph]                                              │
├─────────────────────────────────────────────────────────┤
│ Steps to Reproduce                                       │
│ 1. Navigate to...                                        │
│ 2. Submit payload...                                     │
├─────────────────────────────────────────────────────────┤
│ Evidence                                                 │
│ [embedded screenshot or request/response block]          │
├─────────────────────────────────────────────────────────┤
│ Business Impact                                          │
│ [paragraph]                                              │
├─────────────────────────────────────────────────────────┤
│ Remediation                                              │
│ [paragraph with code example]                            │
└─────────────────────────────────────────────────────────┘
```

## Cover Page Required Elements

- "CONFIDENTIAL — PENETRATION TEST REPORT" (top, small caps)
- Client name (large, centered)
- "Prepared by tzar-bot" 
- Engagement date
- Report version (e.g., v1.0 — Initial)
- Classification: CONFIDENTIAL / RESTRICTED
- tzar-bot logo placeholder (or text logo)
