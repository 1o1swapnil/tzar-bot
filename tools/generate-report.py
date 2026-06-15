#!/usr/bin/env python3
"""
generate-report.py — tzar-bot-style PDF pentest report generator.

Usage:
    python3 tools/generate-report.py <OUTPUT_DIR> [options]
    python3 tools/generate-report.py <pentest-report.json> <reports_dir>  (JSON mode)

Options:
    --client NAME          Client / organisation name (default: extracted from attack-chain.md)
    --target URL           Target URL
    --tester NAME          Tester name (default: Swapnil Khandekar)
    --mode MODE            blackbox | graybox | whitebox (default: blackbox)
    --compliance FRAMEWORKS  Generate compliance mapping appendix. Comma-separated:
                             owasp,pci,iso,nist,hipaa  or  'all'
                             Examples:
                               --compliance pci,iso
                               --compliance all

Reads:
    OUTPUT_DIR/findings/*/description.md   — individual finding files
    OUTPUT_DIR/attack-chain.md             — engagement metadata
    OUTPUT_DIR/artifacts/pentest-report.json  — pre-built JSON (if present)

Writes:
    OUTPUT_DIR/reports/Penetration-Test-Report.pdf
    OUTPUT_DIR/artifacts/pentest-report.json  (always regenerated from findings)
"""

import os, sys, re, json, subprocess, textwrap
from pathlib import Path
from datetime import date

# ── Self-bootstrap: ensure reportlab is importable ─────────────────────────
_HERE = Path(__file__).parent.resolve()
_VENV_PY = _HERE / ".venv" / "bin" / "python3"

def _bootstrap_venv():
    import venv, urllib.request
    venv_dir = _HERE / ".venv"
    print(f"[setup] Building tools/.venv with reportlab …", flush=True)
    venv.create(str(venv_dir), with_pip=False)
    pip_script = Path("/tmp/tzar-get-pip.py")
    urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", pip_script)
    subprocess.run([str(_VENV_PY), str(pip_script)], check=True, capture_output=True)
    subprocess.run([str(_VENV_PY), "-m", "pip", "install",
                    "reportlab", "pillow", "-q"], check=True, capture_output=True)
    print("[setup] Done. Restarting …", flush=True)
    os.execv(str(_VENV_PY), [str(_VENV_PY)] + sys.argv)

try:
    import reportlab
except ImportError:
    if _VENV_PY.exists():
        os.execv(str(_VENV_PY), [str(_VENV_PY)] + sys.argv)
    else:
        _bootstrap_venv()

# ── ReportLab imports ──────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, Color
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether, Preformatted
)
from reportlab.platypus.flowables import Flowable

# ── Design tokens ──────────────────────────────────────────────────────────
C = {
    "bg":       HexColor("#0d1117"),
    "surface":  HexColor("#161b22"),
    "border":   HexColor("#30363d"),
    "primary":  HexColor("#e6edf3"),
    "muted":    HexColor("#8b949e"),
    "accent":   HexColor("#58a6ff"),
    "critical": HexColor("#f85149"),
    "high":     HexColor("#e3b341"),
    "medium":   HexColor("#3fb950"),
    "low":      HexColor("#58a6ff"),
    "info":     HexColor("#8b949e"),
    "white":    HexColor("#ffffff"),
    "red_dark": HexColor("#3d0f0e"),
}

SEV_COLOR = {
    "Critical":      C["critical"],
    "High":          C["high"],
    "Medium":        C["medium"],
    "Low":           C["low"],
    "Informational": C["info"],
    "Info":          C["info"],
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

FONT_BOLD = "Helvetica-Bold"
FONT_SANS = "Helvetica"
FONT_MONO = "Courier"

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


def _s(name, **kw):
    defaults = dict(fontName=FONT_SANS, fontSize=10, textColor=C["primary"],
                    leading=15, spaceAfter=4)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)


ST = {
    "cover_class": _s("cc", fontName=FONT_BOLD, fontSize=8, textColor=C["muted"],
                      alignment=TA_CENTER, spaceAfter=0),
    "cover_title": _s("ct", fontName=FONT_BOLD, fontSize=30, textColor=C["white"],
                      alignment=TA_CENTER, leading=36, spaceAfter=8),
    "cover_sub":   _s("cs", fontName=FONT_SANS, fontSize=13, textColor=C["accent"],
                      alignment=TA_CENTER, spaceAfter=6),
    "cover_meta":  _s("cm", fontName=FONT_SANS, fontSize=9, textColor=C["muted"],
                      alignment=TA_CENTER, spaceAfter=4),
    "h1":          _s("h1", fontName=FONT_BOLD, fontSize=18, textColor=C["accent"],
                      leading=22, spaceAfter=10, spaceBefore=6),
    "h2":          _s("h2", fontName=FONT_BOLD, fontSize=13, textColor=C["primary"],
                      leading=16, spaceAfter=6, spaceBefore=10),
    "h3":          _s("h3", fontName=FONT_BOLD, fontSize=10, textColor=C["accent"],
                      leading=14, spaceAfter=4, spaceBefore=6),
    "body":        _s("body"),
    "body_muted":  _s("bm", textColor=C["muted"], fontSize=9),
    "code":        _s("code", fontName=FONT_MONO, fontSize=8, textColor=C["primary"],
                      backColor=C["surface"], leading=12, leftIndent=8, rightIndent=8,
                      spaceAfter=6),
    "bullet":      _s("blt", leftIndent=14, firstLineIndent=-10, spaceAfter=3),
    "label":       _s("lbl", fontName=FONT_BOLD, fontSize=9, textColor=C["muted"],
                      spaceAfter=0),
    "finding_id":  _s("fid", fontName=FONT_BOLD, fontSize=11, textColor=C["white"],
                      spaceAfter=0),
    "disclaimer":  _s("disc", fontSize=9, textColor=C["muted"], leading=13),
}


# ── Canvas background callback ─────────────────────────────────────────────
def _bg(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C["bg"])
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=True, stroke=False)
    # Footer
    canvas.setFont(FONT_SANS, 7)
    canvas.setFillColor(C["muted"])
    canvas.drawString(MARGIN, 8 * mm, "CONFIDENTIAL — tzar-bot")
    canvas.drawRightString(PAGE_W - MARGIN, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


# ── Flowable helpers ───────────────────────────────────────────────────────
def sp(h=4):
    return Spacer(1, h * mm)

def hr():
    return HRFlowable(width="100%", thickness=0.5, color=C["border"],
                      spaceAfter=4 * mm, spaceBefore=2 * mm)

def p(text, style="body"):
    s = ST[style] if isinstance(style, str) else style
    safe = _escape(str(text))
    return Paragraph(safe, s)

def _escape(t):
    return (t.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))

def severity_badge(severity):
    color = SEV_COLOR.get(severity, C["info"])
    t = Table([[severity]], colWidths=[55])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TEXTCOLOR",  (0, 0), (-1, -1), C["white"]),
        ("FONTNAME",   (0, 0), (-1, -1), FONT_BOLD),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


# ── Markdown finding parser ────────────────────────────────────────────────
def _field(text, *keys):
    """Extract a bold-field value: **Key:** value"""
    for key in keys:
        m = re.search(rf'\*\*{re.escape(key)}[:\s]*\*\*\s*(.+)', text, re.IGNORECASE)
        if m:
            return m.group(1).strip().rstrip("  ").strip()
    return ""

def _table_field(text, *keys):
    """Extract a markdown table field: | Key | Value |"""
    for key in keys:
        m = re.search(rf'\|\s*{re.escape(key)}\s*\|\s*(.+?)\s*\|', text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""

def _section(text, header):
    """Extract text under a ## Section header."""
    pattern = rf'##\s+{re.escape(header)}\s*\n(.*?)(?=\n##\s|\Z)'
    m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return ""

def _cvss_score(text):
    """Pull score from CVSS string or Score: X.X notation."""
    m = re.search(r'Score[:\s]+(\d+\.\d+)', text, re.IGNORECASE)
    if m:
        return float(m.group(1))
    m = re.search(r'(\d+\.\d+)\s*$', text.split("—")[-1])
    if m:
        return float(m.group(1))
    m = re.search(r'\b(\d+\.\d+)\b', text)
    if m:
        return float(m.group(1))
    return 0.0

def parse_finding_md(path):
    """Parse a description.md into a finding dict. Handles both formats."""
    text = Path(path).read_text(encoding="utf-8")

    # Title from first # heading
    title_m = re.match(r'#\s+Finding[:\s\d—-]*(.+)', text)
    title = title_m.group(1).strip() if title_m else Path(path).parent.name

    # Try table format first, fall back to bold-field
    sev = _table_field(text, "Severity") or _field(text, "Severity") or "Informational"
    cvss_raw = (_table_field(text, "CVSS Score", "CVSS") or
                _field(text, "CVSS v3.1", "CVSS v3", "CVSS Score", "CVSS"))
    cvss_vec = (_table_field(text, "CVSS Vector") or
                re.search(r'CVSS:3\.1/\S+', text) and
                re.search(r'CVSS:3\.1/\S+', text).group(0) or "")
    cwe  = (_table_field(text, "CWE") or _field(text, "CWE") or "")
    owasp = (_table_field(text, "OWASP") or _field(text, "OWASP") or "")
    affected = (_table_field(text, "Affected Component", "Affected URL", "Affected") or
                _field(text, "Affected Component", "Affected URL", "File") or "")

    # Extract CVSS score float
    cvss_score = _cvss_score(cvss_raw) if cvss_raw else 0.0

    # Sections
    desc   = _section(text, "Description")
    steps  = _section(text, "Steps to Reproduce") or _section(text, "Proof of Concept")
    impact = _section(text, "Business Impact") or _section(text, "Impact")
    remed  = _section(text, "Remediation") or _section(text, "Fix") or _section(text, "Remediation")
    evid   = _section(text, "Evidence")

    # Normalise severity
    sev = sev.strip().title()
    if sev not in SEV_COLOR:
        sev = "Informational"

    return {
        "id":               Path(path).parent.name.upper().replace("FINDING-", "F-").replace("FINDING_", "F-"),
        "title":            title,
        "severity":         sev,
        "cvss_score":       cvss_score,
        "cvss_vector":      cvss_vec,
        "cwe":              cwe,
        "owasp":            owasp,
        "affected_component": affected,
        "description":      desc,
        "steps_to_reproduce": steps,
        "business_impact":  impact,
        "remediation":      remed,
        "evidence_text":    evid,
    }


def load_findings(output_dir):
    """Discover and parse all finding description.md files, sorted by severity."""
    findings_dir = output_dir / "findings"
    if not findings_dir.exists():
        return []
    paths = sorted(findings_dir.glob("*/description.md"))
    findings = [parse_finding_md(p) for p in paths]
    findings.sort(key=lambda f: SEV_ORDER.index(f["severity"])
                  if f["severity"] in SEV_ORDER else len(SEV_ORDER))
    return findings


def load_metadata(output_dir, cli_args):
    """Pull engagement metadata from attack-chain.md + CLI args."""
    meta = {
        "client":   cli_args.get("client", ""),
        "target":   cli_args.get("target", ""),
        "tester":   cli_args.get("tester", "Swapnil Khandekar"),
        "mode":     cli_args.get("mode", "blackbox"),
        "org":      "tzar-bot",
        "date":     date.today().isoformat(),
    }
    chain = output_dir / "attack-chain.md"
    if chain.exists():
        text = chain.read_text(encoding="utf-8")
        if not meta["target"]:
            m = re.search(r'(?:Target|URL)[:\s]+([https://]\S+)', text, re.IGNORECASE)
            if m:
                meta["target"] = m.group(1)
        if not meta["client"]:
            m = re.search(r'(?:Client|Project|Engagement)[:\s]+(.+)', text, re.IGNORECASE)
            if m:
                meta["client"] = m.group(1).strip()
    if not meta["client"] and meta["target"]:
        from urllib.parse import urlparse
        meta["client"] = urlparse(meta["target"]).netloc or meta["target"]
    if not meta["client"]:
        meta["client"] = output_dir.parent.name.replace("-", " ").title()
    return meta


# ── PDF builder ────────────────────────────────────────────────────────────
def build_cover(meta):
    story = []
    story.append(sp(30))
    story.append(p("CONFIDENTIAL — PENETRATION TEST REPORT", "cover_class"))
    story.append(sp(8))

    # Title bar
    title_table = Table(
        [[Paragraph(_escape(meta["client"]), ST["cover_title"])]],
        colWidths=[PAGE_W - 2 * MARGIN],
    )
    title_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C["surface"]),
        ("BOX",        (0, 0), (-1, -1), 1, C["accent"]),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
    ]))
    story.append(title_table)
    story.append(sp(6))

    story.append(p("Web Application / API Penetration Test", "cover_sub"))
    story.append(sp(16))
    story.append(p(f"Target: {meta['target']}", "cover_meta"))
    story.append(p(f"Engagement Mode: {meta['mode'].title()}", "cover_meta"))
    story.append(sp(4))
    story.append(p(f"Prepared by: {meta['tester']}, {meta['org']}", "cover_meta"))
    story.append(p(f"Report Date: {meta['date']}", "cover_meta"))
    story.append(p("Report Version: 1.0 — Initial", "cover_meta"))
    story.append(sp(20))

    # Classification strip
    cls_table = Table([["CLASSIFICATION: CONFIDENTIAL"]], colWidths=[PAGE_W - 2 * MARGIN])
    cls_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C["red_dark"]),
        ("TEXTCOLOR",  (0, 0), (-1, -1), C["critical"]),
        ("FONTNAME",   (0, 0), (-1, -1), FONT_BOLD),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(cls_table)
    story.append(PageBreak())
    return story


def build_disclaimer():
    story = [p("Disclaimer", "h1"), hr()]
    text = (
        "This report and all its contents are prepared exclusively for the named client "
        "organisation. It is classified CONFIDENTIAL and must not be shared, distributed, "
        "or published without written authorisation from tzar-bot.<br/><br/>"
        "All testing activities were conducted under explicit written authorisation from "
        "the client. Tests were performed in a non-destructive manner and confined to the "
        "declared scope. tzar-bot accepts no liability for issues discovered "
        "outside the declared scope or for any service disruption caused by third parties "
        "during the assessment window.<br/><br/>"
        "This report reflects the security posture of the target at the time of testing. "
        "The absence of a finding does not guarantee the absence of a vulnerability."
    )
    story.append(p(text, "disclaimer"))
    story.append(PageBreak())
    return story


def build_exec_summary(findings, meta):
    story = [p("Executive Summary", "h1"), hr()]
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    intro = (
        f"tzar-bot conducted a <b>{meta['mode']}</b> penetration test "
        f"against <b>{_escape(meta['target'])}</b> on {meta['date']}. "
        f"The assessment identified <b>{len(findings)}</b> "
        f"vulnerabilit{'y' if len(findings) == 1 else 'ies'}."
    )
    story.append(Paragraph(intro, ST["body"]))
    story.append(sp(4))

    # Risk overview table
    sev_rows = [
        [Paragraph("<b>Severity</b>", ST["body"]),
         Paragraph("<b>Count</b>", ST["body"]),
         Paragraph("<b>Remediation SLA</b>", ST["body"])]
    ]
    slas = {
        "Critical":      "Immediate (24–48 h)",
        "High":          "Within 7 days",
        "Medium":        "Within 30 days",
        "Low":           "Next release cycle",
        "Informational": "Advisory",
    }
    for sev in SEV_ORDER:
        sev_rows.append([
            Paragraph(sev, ST["body"]),
            Paragraph(str(counts[sev]), ST["body"]),
            Paragraph(slas[sev], ST["body_muted"]),
        ])
    t = Table(sev_rows, colWidths=[80, 50, 200])
    styles = [
        ("BACKGROUND", (0, 0), (-1, 0), C["surface"]),
        ("TEXTCOLOR",  (0, 0), (-1, 0), C["accent"]),
        ("FONTNAME",   (0, 0), (-1, 0), FONT_BOLD),
        ("GRID",       (0, 0), (-1, -1), 0.4, C["border"]),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C["bg"], C["surface"]]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]
    for i, sev in enumerate(SEV_ORDER, 1):
        if counts[sev] > 0:
            styles.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLOR[sev]))
            styles.append(("FONTNAME",  (0, i), (0, i), FONT_BOLD))
    t.setStyle(TableStyle(styles))
    story.append(t)
    story.append(sp(6))

    # Top findings
    critical_high = [f for f in findings if f["severity"] in ("Critical", "High")][:3]
    if critical_high:
        story.append(p("Top Issues Requiring Immediate Attention", "h2"))
        for i, f in enumerate(critical_high, 1):
            story.append(p(f"{i}. [{f['severity']}] {f['title']} — CVSS {f['cvss_score']}", "body"))

    # Compliance posture paragraph (injected when --compliance is used)
    if meta.get("_compliance_frameworks"):
        posture = _compliance_posture_text(findings, meta["_compliance_frameworks"])
        if posture:
            story.append(sp(4))
            story.append(p("Compliance Impact", "h2"))
            story.append(Paragraph(posture, ST["body"]))

    story.append(PageBreak())
    return story


def build_findings_table(findings):
    story = [p("Findings Overview", "h1"), hr()]
    rows = [[
        Paragraph("<b>ID</b>",       ST["body"]),
        Paragraph("<b>Title</b>",    ST["body"]),
        Paragraph("<b>Severity</b>", ST["body"]),
        Paragraph("<b>CVSS</b>",     ST["body"]),
        Paragraph("<b>CWE</b>",      ST["body"]),
    ]]
    for f in findings:
        rows.append([
            Paragraph(f["id"],    ST["body_muted"]),
            Paragraph(_escape(f["title"]), ST["body"]),
            Paragraph(f["severity"], _s("sv", fontName=FONT_BOLD, fontSize=9,
                                        textColor=SEV_COLOR.get(f["severity"], C["info"]))),
            Paragraph(str(f["cvss_score"]), ST["body"]),
            Paragraph(_escape(f["cwe"][:25] if f["cwe"] else "—"), ST["body_muted"]),
        ])
    t = Table(rows, colWidths=[38, 215, 58, 38, 85])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C["surface"]),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C["accent"]),
        ("FONTNAME",      (0, 0), (-1, 0), FONT_BOLD),
        ("GRID",          (0, 0), (-1, -1), 0.4, C["border"]),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C["bg"], C["surface"]]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(PageBreak())
    return story


def _md_to_paragraphs(text, base_style="body"):
    """Convert simple markdown text into a list of Paragraph/Preformatted flowables."""
    if not text:
        return []
    items = []
    in_code = False
    code_lines = []
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            if in_code:
                items.append(Preformatted("\n".join(code_lines), ST["code"]))
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        stripped = line.strip()
        if not stripped:
            continue
        # Numbered list
        m = re.match(r'^(\d+)\.\s+(.+)', stripped)
        if m:
            items.append(p(f"{m.group(1)}. {m.group(2)}", base_style))
            continue
        # Bullet
        if stripped.startswith(("- ", "* ", "• ")):
            items.append(p("• " + stripped[2:], "bullet"))
            continue
        # Inline code: replace backtick with monospace spans
        safe = _escape(stripped)
        safe = re.sub(r'`([^`]+)`', r'<font name="Courier" size="8">\1</font>', safe)
        # Bold
        safe = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', safe)
        items.append(Paragraph(safe, ST[base_style]))
    if in_code and code_lines:
        items.append(Preformatted("\n".join(code_lines), ST["code"]))
    return items


def build_finding_card(f, idx):
    """Render one finding as a bordered card."""
    story = []
    sev_color = SEV_COLOR.get(f["severity"], C["info"])

    # Header row: ID + severity badge + title
    header_inner = Table(
        [[Paragraph(f["id"], ST["finding_id"]),
          severity_badge(f["severity"]),
          Paragraph(_escape(f["title"]), ST["finding_id"])]],
        colWidths=[42, 60, PAGE_W - 2 * MARGIN - 42 - 60 - 24],
    )
    header_inner.setStyle(TableStyle([
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",(0, 0), (-1, -1), 4),
    ]))
    header_row = Table([[header_inner]], colWidths=[PAGE_W - 2 * MARGIN])
    header_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["surface"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("LINEBELOW",     (0, 0), (-1, -1), 2, sev_color),
    ]))

    # Metadata row
    meta_parts = []
    if f["cvss_score"]:
        meta_parts.append(f"CVSS: {f['cvss_score']}")
    if f["cwe"]:
        meta_parts.append(f"CWE: {f['cwe'][:40]}")
    if f["owasp"]:
        meta_parts.append(f"OWASP: {f['owasp'][:30]}")
    meta_text = "    |    ".join(meta_parts) if meta_parts else "—"
    meta_row = Table(
        [[Paragraph(_escape(meta_text), ST["body_muted"])]],
        colWidths=[PAGE_W - 2 * MARGIN],
    )
    meta_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["bg"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.4, C["border"]),
    ]))

    card_rows = [[header_row], [meta_row]]

    def _detail_row(label, content_flowables):
        label_cell = Paragraph(label, ST["label"])
        content_cell = content_flowables
        inner = Table(
            [[label_cell, content_cell]],
            colWidths=[90, PAGE_W - 2 * MARGIN - 90 - 20],
        )
        inner.setStyle(TableStyle([
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",  (0, 0), (0, -1), 10),
            ("LEFTPADDING",  (1, 0), (1, -1), 6),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("LINEBELOW",    (0, 0), (-1, -1), 0.4, C["border"]),
        ]))
        row = Table([[inner]], colWidths=[PAGE_W - 2 * MARGIN])
        row.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C["bg"]),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.4, C["border"]),
        ]))
        return row

    if f["affected_component"]:
        card_rows.append([_detail_row(
            "Affected Component",
            [Paragraph(_escape(f["affected_component"]), ST["code"])]
        )])

    if f["description"]:
        card_rows.append([_detail_row("Description",
                                       _md_to_paragraphs(f["description"]) or [p("—")])])

    if f["steps_to_reproduce"]:
        card_rows.append([_detail_row("Steps to Reproduce",
                                       _md_to_paragraphs(f["steps_to_reproduce"]) or [p("—")])])

    if f["business_impact"]:
        card_rows.append([_detail_row("Business Impact",
                                       _md_to_paragraphs(f["business_impact"]) or [p("—")])])

    if f["remediation"]:
        card_rows.append([_detail_row("Remediation",
                                       _md_to_paragraphs(f["remediation"]) or [p("—")])])

    # Wrap entire card in a bordered outer table
    card = Table(card_rows, colWidths=[PAGE_W - 2 * MARGIN])
    card.setStyle(TableStyle([
        ("BOX",     (0, 0), (-1, -1), 1, C["border"]),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))
    story.append(card)
    story.append(sp(8))
    return story


def build_remediation_roadmap(findings):
    story = [p("Remediation Roadmap", "h1"), hr()]
    buckets = {
        "Immediate (0–48 h)":   [f for f in findings if f["severity"] == "Critical"],
        "Short-term (7 days)":  [f for f in findings if f["severity"] == "High"],
        "Medium-term (30 days)":[f for f in findings if f["severity"] == "Medium"],
        "Next release cycle":   [f for f in findings if f["severity"] == "Low"],
        "Advisory":             [f for f in findings if f["severity"] == "Informational"],
    }
    for label, items in buckets.items():
        if not items:
            continue
        story.append(p(label, "h2"))
        for f in items:
            story.append(p(f"• {f['id']} — {f['title']}", "bullet"))
            if f["remediation"]:
                first_line = f["remediation"].split("\n")[0].strip()[:200]
                story.append(p(f"  Fix: {first_line}", "body_muted"))
        story.append(sp(3))
    story.append(PageBreak())
    return story


def build_methodology():
    story = [p("Methodology", "h1"), hr()]
    story.append(p("Assessment Phases", "h2"))
    phases = [
        ("Phase 1", "Passive & Active Reconnaissance",
         "subfinder, amass, dnsx, httpx, nmap, gobuster, ffuf, katana"),
        ("Phase 2", "Source Code Review (conditional)",
         "semgrep, bandit, trufflehog"),
        ("Phase 3", "Authentication Testing",
         "Manual + Burp Suite"),
        ("Phase 4", "Injection & Server-Side",
         "sqlmap, manual SSTI/SSRF/XXE testing"),
        ("Phase 5", "Client-Side & API Security",
         "Manual XSS, CORS, parameter analysis, OpenAPI fuzzing"),
        ("Phase 6", "Business Logic",
         "Manual workflow analysis"),
    ]
    rows = [[
        Paragraph("<b>Phase</b>",       ST["body"]),
        Paragraph("<b>Description</b>", ST["body"]),
        Paragraph("<b>Tools</b>",       ST["body"]),
    ]]
    for ph, desc, tools in phases:
        rows.append([p(ph), p(desc), Paragraph(_escape(tools), ST["body_muted"])])
    t = Table(rows, colWidths=[50, 160, 224])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C["surface"]),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C["accent"]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C["border"]),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C["bg"], C["surface"]]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(PageBreak())
    return story


# ── Compliance mapping ─────────────────────────────────────────────────────
# Maps CWE numeric IDs to control references across five frameworks.
# Keys are integers; values are dicts with keys: owasp, pci, iso, nist, hipaa.
COMPLIANCE_MAP = {
    # Injection family
    79:   {"owasp":"A03:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-10, SA-11","hipaa":"§164.312(c)(1)"},
    89:   {"owasp":"A03:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-10, SA-11","hipaa":"§164.312(c)(1)"},
    94:   {"owasp":"A03:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-10","hipaa":"§164.312(c)(1)"},
    611:  {"owasp":"A03:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-10","hipaa":"§164.312(c)(1)"},
    918:  {"owasp":"A10:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SC-7, SI-10","hipaa":"§164.312(e)(1)"},
    1336: {"owasp":"A03:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-10","hipaa":"§164.312(c)(1)"},
    # Access control
    22:   {"owasp":"A01:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-10","hipaa":"§164.312(a)(2)(iv)"},
    285:  {"owasp":"A01:2021","pci":"Req 7.2","iso":"A.5.15","nist":"AC-3, AC-6","hipaa":"§164.312(a)(1)"},
    601:  {"owasp":"A01:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SA-11","hipaa":"§164.312(b)"},
    639:  {"owasp":"A01:2021","pci":"Req 7.1","iso":"A.5.15","nist":"AC-3","hipaa":"§164.312(a)(1)"},
    732:  {"owasp":"A01:2021","pci":"Req 7.1, 7.2","iso":"A.5.15, A.8.3","nist":"AC-3, AC-6","hipaa":"§164.312(a)(1)"},
    # Authentication
    287:  {"owasp":"A07:2021","pci":"Req 8.2, 8.3","iso":"A.5.17, A.8.5","nist":"IA-2, IA-5","hipaa":"§164.312(d)"},
    306:  {"owasp":"A07:2021","pci":"Req 7.1, 8.2","iso":"A.5.15, A.8.5","nist":"IA-2, AC-3","hipaa":"§164.312(d)"},
    307:  {"owasp":"A07:2021","pci":"Req 8.3.4","iso":"A.8.5","nist":"AC-7, IA-5","hipaa":"§164.312(d)"},
    352:  {"owasp":"A01:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SC-8, SA-11","hipaa":"§164.312(c)(1)"},
    384:  {"owasp":"A07:2021","pci":"Req 8.2","iso":"A.8.5","nist":"IA-2, SC-23","hipaa":"§164.312(d)"},
    798:  {"owasp":"A07:2021","pci":"Req 2.2.7, 8.2.2","iso":"A.5.17","nist":"IA-5","hipaa":"§164.312(d)"},
    # Cryptographic failures
    295:  {"owasp":"A02:2021","pci":"Req 4.2","iso":"A.8.24","nist":"SC-8, IA-5","hipaa":"§164.312(e)(2)(ii)"},
    311:  {"owasp":"A02:2021","pci":"Req 3.4, 4.2","iso":"A.8.24","nist":"SC-8, SC-28","hipaa":"§164.312(e)(2)(ii)"},
    312:  {"owasp":"A02:2021","pci":"Req 3.4","iso":"A.8.11, A.8.24","nist":"SC-28","hipaa":"§164.312(e)(2)(ii)"},
    327:  {"owasp":"A02:2021","pci":"Req 4.2, 3.6","iso":"A.8.24","nist":"SC-8, SC-13","hipaa":"§164.312(e)(2)(ii)"},
    # Information exposure
    200:  {"owasp":"A02:2021","pci":"Req 3.4","iso":"A.5.12, A.8.11","nist":"SC-8, SC-28","hipaa":"§164.312(e)(2)(ii)"},
    359:  {"owasp":"A02:2021","pci":"Req 3.4","iso":"A.5.12","nist":"SC-28","hipaa":"§164.312(e)(2)(ii)"},
    # Software integrity & deserialization
    434:  {"owasp":"A04:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-3, SI-10","hipaa":"§164.312(c)(1)"},
    502:  {"owasp":"A08:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SI-10, SA-11","hipaa":"§164.312(c)(1)"},
    # Design / race conditions
    362:  {"owasp":"A04:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SA-11","hipaa":"§164.312(c)(1)"},
    400:  {"owasp":"A04:2021","pci":"Req 6.2.4","iso":"A.8.28","nist":"SC-5","hipaa":"§164.312(c)(1)"},
}

FRAMEWORK_LABELS = {
    "owasp": "OWASP A0X:2021",
    "pci":   "PCI-DSS v4",
    "iso":   "ISO 27001:2022",
    "nist":  "NIST 800-53",
    "hipaa": "HIPAA Safeguard",
}


def _cwe_number(cwe_str: str) -> int | None:
    """Extract CWE numeric ID from strings like 'CWE-79', 'CWE-79: XSS', '79'."""
    m = re.search(r'(\d+)', cwe_str or "")
    return int(m.group(1)) if m else None


def _compliance_for_finding(finding: dict) -> dict:
    """Return compliance mapping dict for a finding, or {} if CWE unknown."""
    cwe_num = _cwe_number(finding.get("cwe", ""))
    return COMPLIANCE_MAP.get(cwe_num, {})


def build_compliance_appendix(findings, frameworks: list[str]):
    """
    Build a compliance mapping appendix section.
    frameworks: list of keys from FRAMEWORK_LABELS, e.g. ['pci', 'iso'] or all keys.
    """
    story = [p("Compliance Mapping", "h1"), hr()]

    # Intro paragraph
    fw_names = ", ".join(FRAMEWORK_LABELS[k] for k in frameworks if k in FRAMEWORK_LABELS)
    story.append(p(
        f"The following table maps each finding to applicable control references across: "
        f"<b>{fw_names}</b>. Findings with unknown or non-standard CWE IDs appear with "
        f"'—' where no direct mapping exists.",
        "body"
    ))
    story.append(sp(4))

    # Determine column widths based on number of frameworks
    PAGE_AVAIL = PAGE_W - 2 * MARGIN
    base_cols = {"id": 35, "sev": 48, "cwe": 55, "owasp_col": 88}
    extra_keys = [k for k in frameworks if k != "owasp" and k in FRAMEWORK_LABELS]
    extra_count = len(extra_keys)
    owasp_in = "owasp" in frameworks

    # Distribute remaining width across framework columns
    used = sum(base_cols.values()) if owasp_in else (base_cols["id"] + base_cols["sev"] + base_cols["cwe"])
    if not owasp_in:
        used += base_cols["owasp_col"]  # OWASP always shown even if not in extras
    remaining = PAGE_AVAIL - used
    fw_col_w  = int(remaining / max(extra_count, 1)) if extra_count else 0

    col_widths = [base_cols["id"], base_cols["sev"], base_cols["cwe"]]
    if owasp_in or True:  # OWASP always included as baseline
        col_widths.append(base_cols["owasp_col"])
    for _ in extra_keys:
        col_widths.append(fw_col_w)

    # Header row
    hdr = [
        Paragraph("<b>ID</b>",         ST["body_muted"]),
        Paragraph("<b>Severity</b>",   ST["body_muted"]),
        Paragraph("<b>CWE</b>",        ST["body_muted"]),
        Paragraph("<b>OWASP 2021</b>", ST["body_muted"]),
    ]
    for k in extra_keys:
        hdr.append(Paragraph(f"<b>{FRAMEWORK_LABELS[k]}</b>", ST["body_muted"]))

    rows = [hdr]
    small = _s("sm7", fontSize=7, leading=9, textColor=C["primary"])
    muted_sm = _s("ms7", fontSize=7, leading=9, textColor=C["muted"])

    for f in findings:
        cm = _compliance_for_finding(f)
        sev_color = SEV_COLOR.get(f["severity"], C["info"])
        row = [
            Paragraph(f["id"],         muted_sm),
            Paragraph(f["severity"],   _s("sv7", fontSize=7, leading=9,
                                          fontName=FONT_BOLD, textColor=sev_color)),
            Paragraph(_escape(f["cwe"][:30] if f["cwe"] else "—"), muted_sm),
            Paragraph(_escape(cm.get("owasp", "—")), small),
        ]
        for k in extra_keys:
            row.append(Paragraph(_escape(cm.get(k, "—")), small))
        rows.append(row)

    t = Table(rows, colWidths=col_widths)
    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C["surface"]),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C["accent"]),
        ("FONTNAME",      (0, 0), (-1, 0), FONT_BOLD),
        ("GRID",          (0, 0), (-1, -1), 0.3, C["border"]),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C["bg"], C["surface"]]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])
    t.setStyle(ts)
    story.append(t)
    story.append(sp(6))

    # Control coverage summary per framework
    story.append(p("Control Coverage Summary", "h2"))
    for k in ["owasp"] + extra_keys:
        label = FRAMEWORK_LABELS.get(k, k)
        refs  = set()
        for f in findings:
            cm = _compliance_for_finding(f)
            val = cm.get(k, "")
            if val and val != "—":
                for part in re.split(r',\s*', val):
                    refs.add(part.strip())
        if refs:
            story.append(p(
                f"<b>{label}:</b> {len(refs)} distinct control(s) — "
                f"{', '.join(sorted(refs)[:10])}" +
                (f" (+{len(refs)-10} more)" if len(refs) > 10 else ""),
                "body_muted"
            ))
    return story


def _compliance_posture_text(findings, frameworks: list[str]) -> str:
    """Generate an executive-level compliance posture sentence."""
    if not findings or not frameworks:
        return ""
    criticals = sum(1 for f in findings if f["severity"] == "Critical")
    highs     = sum(1 for f in findings if f["severity"] == "High")

    ref_counts = {}
    for k in frameworks:
        refs = set()
        for f in findings:
            cm = _compliance_for_finding(f)
            val = cm.get(k, "")
            for part in re.split(r',\s*', val):
                if part.strip() and part.strip() != "—":
                    refs.add(part.strip())
        if refs:
            ref_counts[FRAMEWORK_LABELS.get(k, k)] = len(refs)

    if not ref_counts:
        return ""

    impacts = "; ".join(f"{fw}: {n} control(s)" for fw, n in ref_counts.items())
    urgency = ""
    if criticals:
        urgency = (f" <b>{criticals} Critical finding(s)</b> represent immediate compliance "
                   f"violations requiring remediation within 24–48 hours.")
    elif highs:
        urgency = (f" <b>{highs} High finding(s)</b> require remediation within 7 days "
                   f"to maintain compliance posture.")

    return (
        f"The findings identified in this assessment impact the following regulatory "
        f"frameworks: <b>{impacts}</b>.{urgency} "
        f"A detailed control-to-finding mapping is provided in the Compliance Mapping appendix."
    )


def build_appendix(findings, output_dir):
    story = [p("Appendix", "h1"), hr()]
    story.append(p("Evidence Index", "h2"))
    for f in findings:
        evidence_dir = output_dir / "findings" / f["id"].lower().replace("f-", "finding-") / "evidence"
        files = list(evidence_dir.glob("*")) if evidence_dir.exists() else []
        story.append(p(f"{f['id']} — {f['title']}", "h3"))
        if files:
            for ef in sorted(files):
                story.append(p(f"• {ef.name}", "bullet"))
        else:
            story.append(p("No evidence files attached.", "body_muted"))
        story.append(sp(2))
    story.append(sp(4))
    story.append(p("CVSS Scoring", "h2"))
    story.append(p(
        "All vulnerabilities are scored using the Common Vulnerability Scoring System "
        "v3.1 (CVSS 3.1). Scores reflect the inherent risk without mitigating controls.",
        "body_muted"
    ))
    return story


def write_json(findings, meta, output_dir):
    summary = {s.lower(): sum(1 for f in findings if f["severity"] == s)
               for s in SEV_ORDER}
    summary["total"] = len(findings)
    data = {
        "engagement": {
            "client":       meta["client"],
            "target":       meta["target"],
            "mode":         meta["mode"],
            "report_date":  meta["date"],
            "tester":       meta["tester"],
            "organization": meta["org"],
        },
        "findings":   findings,
        "summary":    summary,
    }
    out = output_dir / "artifacts" / "pentest-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return out


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output_dir",
                    help="Engagement OUTPUT_DIR (or path to pentest-report.json)")
    ap.add_argument("reports_dir", nargs="?",
                    help="Override reports output directory")
    ap.add_argument("--client",  default="", help="Client name")
    ap.add_argument("--target",  default="", help="Target URL")
    ap.add_argument("--tester",  default="Swapnil Khandekar", help="Tester name")
    ap.add_argument("--mode",       default="blackbox",
                    choices=["blackbox", "graybox", "whitebox"])
    ap.add_argument("--compliance", default="",
                    help=(
                        "Generate compliance mapping appendix. Comma-separated frameworks: "
                        "owasp,pci,iso,nist,hipaa  or  'all'  (default: none)"
                    ))
    args = ap.parse_args()

    output_dir = Path(args.output_dir).resolve()

    # Legacy JSON mode: python3 generate-report.py findings.json reports/
    if output_dir.suffix == ".json":
        print("[ERROR] This tool builds the canonical PDF from an OUTPUT_DIR.\n"
              "        For offline JSON/HTML export (no reportlab, no network), use:\n"
              "          python3 tools/report-export.py \"$OUTPUT_DIR\" --format both")
        sys.exit(1)

    if not output_dir.exists():
        print(f"[ERROR] OUTPUT_DIR not found: {output_dir}")
        sys.exit(1)

    reports_dir = Path(args.reports_dir).resolve() if args.reports_dir \
                  else output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = reports_dir / "Penetration-Test-Report.pdf"

    # Parse compliance frameworks
    all_fw = list(FRAMEWORK_LABELS.keys())
    if args.compliance.strip().lower() == "all":
        compliance_fws = all_fw
    elif args.compliance.strip():
        compliance_fws = [f.strip().lower() for f in args.compliance.split(",")
                          if f.strip().lower() in FRAMEWORK_LABELS]
    else:
        compliance_fws = []

    cli_args = dict(client=args.client, target=args.target,
                    tester=args.tester, mode=args.mode,
                    _compliance_frameworks=compliance_fws)
    meta     = load_metadata(output_dir, cli_args)
    meta["_compliance_frameworks"] = compliance_fws
    findings = load_findings(output_dir)

    if not findings:
        print("[WARN] No findings found in findings/*/description.md — report will be empty.")

    print(f"[*] Engagement: {meta['client']}")
    print(f"[*] Target:     {meta['target']}")
    print(f"[*] Findings:   {len(findings)}")
    for f in findings:
        print(f"    {f['id']:8s} [{f['severity']:<13}] CVSS {f['cvss_score']:.1f}  {f['title'][:60]}")

    # Build story
    story = []
    story += build_cover(meta)
    story += build_disclaimer()
    story += build_exec_summary(findings, meta)
    story += build_findings_table(findings)

    story.append(p("Findings Detail", "h1"))
    story.append(hr())
    for i, f in enumerate(findings):
        story += build_finding_card(f, i)

    story.append(PageBreak())
    story += build_remediation_roadmap(findings)
    story += build_methodology()
    story += build_appendix(findings, output_dir)

    # Optional compliance appendix
    if compliance_fws:
        story.append(PageBreak())
        story += build_compliance_appendix(findings, compliance_fws)
        print(f"[*] Compliance frameworks: {', '.join(FRAMEWORK_LABELS[k] for k in compliance_fws)}")

    # Generate PDF
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=15 * mm,
        title=f"Penetration Test Report — {meta['client']}",
        author=f"{meta['tester']}, {meta['org']}",
        subject="Penetration Test Report",
    )
    doc.build(story, onFirstPage=_bg, onLaterPages=_bg)

    # Write JSON
    json_path = write_json(findings, meta, output_dir)

    print(f"\n[+] PDF  → {pdf_path}")
    print(f"[+] JSON → {json_path}")


if __name__ == "__main__":
    main()
