#!/usr/bin/env python3
"""
report-export.py — offline JSON + HTML report export (no reportlab, no network).

generate-report.py produces the canonical PDF but self-bootstraps a reportlab venv
(downloads on first run). This tool emits a structured JSON and a self-contained
HTML report from the same engagement data using only the standard library, so it
works on an air-gapped box, in CI, or as a quick preview before the full PDF.

Source of findings (first that applies):
    OUTPUT_DIR/artifacts/pentest-report.json   (richer; written by generate-report)
    OUTPUT_DIR/findings/*/description.md        (parsed directly)

Usage:
    python3 tools/report-export.py <OUTPUT_DIR> [--format json|html|both]
                                   [--client NAME] [--target URL] [--out-dir DIR]

Writes (under OUTPUT_DIR/reports/ by default):
    report.json   and/or   report.html
"""

import re
import sys
import json
import html
import argparse
from pathlib import Path
from datetime import date

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
SEV_COLOR = {"critical": "#f85149", "high": "#ff7b72", "medium": "#d29922",
             "low": "#3fb950", "info": "#58a6ff", "informational": "#58a6ff"}


def _field(text, key):
    m = re.search(rf"\|\s*{re.escape(key)}\s*\|\s*(.+?)\s*\|", text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _cvss(raw):
    m = re.search(r"\b(\d+\.\d+)\b", raw or "")
    return float(m.group(1)) if m else 0.0


def parse_findings_dir(output_dir: Path):
    findings = []
    fdir = output_dir / "findings"
    if not fdir.exists():
        return findings
    for d in sorted(fdir.iterdir()):
        desc = d / "description.md"
        if not d.is_dir() or not desc.exists():
            continue
        text = desc.read_text(encoding="utf-8", errors="replace")
        tm = re.match(r"#\s+Finding[:\s\d—-]*(.+)", text)
        title = tm.group(1).strip() if tm else d.name
        findings.append({
            "id": d.name,
            "title": title,
            "severity": (_field(text, "Severity") or "info").lower(),
            "cvss_score": _cvss(_field(text, "CVSS Score")),
            "affected": (_field(text, "Affected Component") or _field(text, "Affected URL")
                         or _field(text, "Affected")),
            "body": text,
        })
    return findings


def load_findings(output_dir: Path):
    pj = output_dir / "artifacts" / "pentest-report.json"
    if pj.exists():
        try:
            data = json.loads(pj.read_text())
            fl = data.get("findings", data if isinstance(data, list) else [])
            norm = []
            for f in fl:
                norm.append({
                    "id": f.get("id", f.get("finding_id", "")),
                    "title": f.get("title", ""),
                    "severity": str(f.get("severity", "info")).lower(),
                    "cvss_score": float(f.get("cvss_score", f.get("cvss", 0)) or 0),
                    "affected": f.get("affected", f.get("affected_component", "")),
                    "body": f.get("description", f.get("body", "")),
                })
            if norm:
                return norm
        except (ValueError, OSError):
            pass
    return parse_findings_dir(output_dir)


def load_meta(output_dir: Path, client, target):
    meta = {"client": client, "target": target, "type": "", "mode": "", "scope": ""}
    ej = output_dir / "engagement.json"
    if ej.exists():
        try:
            e = json.loads(ej.read_text())
            meta["client"] = client or e.get("project", "")
            meta["target"] = target or e.get("target", "")
            meta["type"] = e.get("type", "")
            meta["mode"] = e.get("mode", "")
            scope = e.get("in_scope") or e.get("scope") or ""
            meta["scope"] = ", ".join(scope) if isinstance(scope, list) else str(scope)
        except (ValueError, OSError):
            pass
    meta["client"] = meta["client"] or "Client"
    meta["target"] = meta["target"] or "—"
    return meta


def sev_counts(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def build_json(findings, meta):
    return {
        "engagement": meta,
        "generated": date.today().isoformat(),
        "summary": {"total": len(findings), "by_severity": sev_counts(findings)},
        "findings": sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                                    -f["cvss_score"])),
    }


def build_html(findings, meta):
    ordered = sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), -f["cvss_score"]))
    counts = sev_counts(findings)
    esc = html.escape

    chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR.get(s, "#444")}22;'
        f'border-color:{SEV_COLOR.get(s, "#444")}">{esc(s)}: {n}</span>'
        for s, n in sorted(counts.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))
    ) or '<span class="chip">no findings</span>'

    cards = []
    for f in ordered:
        col = SEV_COLOR.get(f["severity"], "#8b949e")
        cards.append(f"""
        <div class="card" style="border-left:4px solid {col}">
          <div class="card-h">
            <span class="sev" style="color:{col}">{esc(f['severity'].upper())}</span>
            <span class="cvss">CVSS {f['cvss_score']:.1f}</span>
            <span class="fid">{esc(f['id'])}</span>
          </div>
          <h3>{esc(f['title'] or f['id'])}</h3>
          {f'<div class="aff">Affected: <code>{esc(f["affected"])}</code></div>' if f['affected'] else ''}
          <pre>{esc(f['body'])}</pre>
        </div>""")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Penetration Test Report — {esc(meta['client'])}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#c9d1d9; font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;
          margin:0; padding:0 0 64px; }}
  header {{ background:#161b22; border-bottom:1px solid #30363d; padding:28px 40px; }}
  header h1 {{ margin:0 0 4px; font-size:24px; }}
  header .meta {{ color:#8b949e; font-size:13px; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:0 40px; }}
  .summary {{ margin:28px 0; }}
  .chip {{ display:inline-block; border:1px solid #30363d; border-radius:999px;
           padding:3px 12px; margin:4px 6px 4px 0; font-size:13px; text-transform:capitalize; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
           padding:18px 20px; margin:16px 0; }}
  .card-h {{ display:flex; gap:14px; align-items:center; font-size:12px; }}
  .sev {{ font-weight:700; letter-spacing:.5px; }}
  .cvss {{ color:#8b949e; }} .fid {{ color:#6e7681; margin-left:auto; }}
  .card h3 {{ margin:8px 0 6px; font-size:17px; color:#e6edf3; }}
  .aff {{ color:#8b949e; font-size:13px; margin-bottom:8px; }}
  code {{ background:#0d1117; border:1px solid #30363d; border-radius:4px; padding:1px 5px; }}
  pre {{ background:#0d1117; border:1px solid #21262d; border-radius:6px; padding:14px;
         overflow:auto; font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap; }}
  footer {{ color:#6e7681; font-size:12px; text-align:center; margin-top:36px; }}
</style></head>
<body>
<header>
  <h1>Penetration Test Report</h1>
  <div class="meta">{esc(meta['client'])} &nbsp;·&nbsp; Target: {esc(meta['target'])}
    {f"&nbsp;·&nbsp; {esc(meta['type'])}" if meta['type'] else ""}
    {f"/{esc(meta['mode'])}" if meta['mode'] else ""}
    &nbsp;·&nbsp; {date.today().isoformat()}</div>
</header>
<div class="wrap">
  <div class="summary">
    <h2>Summary — {len(findings)} finding(s)</h2>
    {chips}
    {f'<div class="aff" style="margin-top:8px">Scope: <code>{esc(meta["scope"])}</code></div>' if meta['scope'] else ''}
  </div>
  {''.join(cards) if cards else '<p>No findings recorded.</p>'}
  <footer>Generated offline by tools/report-export.py · not a substitute for the signed PDF.</footer>
</div>
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Offline JSON/HTML report export (no reportlab).")
    ap.add_argument("output_dir", help="Engagement OUTPUT_DIR")
    ap.add_argument("--format", choices=["json", "html", "both"], default="both")
    ap.add_argument("--client", default="")
    ap.add_argument("--target", default="")
    ap.add_argument("--out-dir", default="", help="Output dir (default: OUTPUT_DIR/reports)")
    a = ap.parse_args()

    output_dir = Path(a.output_dir).resolve()
    if not output_dir.exists():
        print(f"[ERROR] OUTPUT_DIR not found: {output_dir}", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(output_dir)
    meta = load_meta(output_dir, a.client, a.target)
    out_dir = Path(a.out_dir).resolve() if a.out_dir else (output_dir / "reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    written = []
    if a.format in ("json", "both"):
        p = out_dir / "report.json"
        p.write_text(json.dumps(build_json(findings, meta), indent=2) + "\n")
        written.append(p)
    if a.format in ("html", "both"):
        p = out_dir / "report.html"
        p.write_text(build_html(findings, meta))
        written.append(p)

    print(f"[*] {meta['client']} | target {meta['target']} | {len(findings)} finding(s)")
    for p in written:
        print(f"[+] {p}")


if __name__ == "__main__":
    main()
