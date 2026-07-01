#!/usr/bin/env python3
"""
validate-finding.py — Run the 5-check validation protocol on a finding directory.

Usage:
    python3 tools/validate-finding.py <OUTPUT_DIR/findings/finding-NNN>
    python3 tools/validate-finding.py <OUTPUT_DIR/findings/finding-NNN> --strict
    python3 tools/validate-finding.py <OUTPUT_DIR>  --all     # validate every finding

Checks:
    1  CVSS Consistency  — score range matches severity label; vector is well-formed
    2  Evidence Exists   — evidence/ has at least one non-empty recognised file
    3  PoC Validity      — poc.py/poc.sh parses; targets the stated affected component
    4  Claims vs Evidence— affected component appears in at least one evidence file
    5  Log Corroboration — OUTPUT_DIR/logs/ has an entry referencing this target

Exit: 0 = all pass,  1 = one or more fail,  2 = usage error
"""

import os
import re
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone


# ── CVSS 3.x severity bands ──────────────────────────────────────────────────
SEVERITY_BANDS = {
    "critical":      (9.0, 10.0),
    "high":          (7.0,  8.9),
    "medium":        (4.0,  6.9),
    "low":           (0.1,  3.9),
    "informational": (0.0,  0.0),
    "info":          (0.0,  0.0),
    "none":          (0.0,  0.0),
}
CVSS_TOLERANCE = 0.5

EVIDENCE_FILENAMES = {
    "request.txt", "response.txt", "screenshot.png",
    "screenshot.jpg", "screenshot.jpeg",
    "output.txt", "tool-output.txt", "raw.txt",
}

RESULT = {
    "pass":    "pass",
    "fail":    "fail",
    "warn":    "warn",   # non-blocking advisory
    "skip":    "skip",   # file absent, check not applicable
}


# ── Markdown helpers ──────────────────────────────────────────────────────────
def _field(text, *keys):
    for key in keys:
        m = re.search(rf'\*\*{re.escape(key)}[:\s]*\*\*\s*(.+)', text, re.IGNORECASE)
        if m:
            return m.group(1).strip().rstrip("  ").strip()
    return ""

def _table_field(text, *keys):
    for key in keys:
        m = re.search(rf'\|\s*{re.escape(key)}\s*\|\s*(.+?)\s*\|', text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""

def _section(text, header):
    m = re.search(rf'##\s+{re.escape(header)}\s*\n(.*?)(?=\n##\s|\Z)',
                  text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""

def parse_description(desc_path):
    text = Path(desc_path).read_text(encoding="utf-8", errors="replace")

    title_m = re.match(r'#\s+Finding[:\s\d—-]*(.+)', text)
    title = title_m.group(1).strip() if title_m else Path(desc_path).parent.name

    severity = (_table_field(text, "Severity") or _field(text, "Severity") or "").strip().title()
    cvss_raw  = (_table_field(text, "CVSS Score", "CVSS") or
                 _field(text, "CVSS v3.1", "CVSS v3", "CVSS Score", "CVSS") or "")
    affected  = (_table_field(text, "Affected Component", "Affected URL", "Affected") or
                 _field(text, "Affected Component", "Affected URL", "File") or "")

    # Extract numeric score
    score = None
    m = re.search(r'Score[:\s]+(\d+(?:\.\d+)?)', cvss_raw, re.IGNORECASE)
    if m:
        score = float(m.group(1))
    else:
        m = re.search(r'(\d+\.\d+)\s*$', cvss_raw.split("—")[-1])
        if m:
            score = float(m.group(1))
        else:
            m = re.search(r'\b(\d+\.\d+)\b', cvss_raw)
            if m:
                score = float(m.group(1))

    # Extract CVSS vector
    vec_m = re.search(r'CVSS:3\.\d/\S+', text)
    cvss_vector = vec_m.group(0) if vec_m else ""

    return {
        "title":        title,
        "severity":     severity,
        "cvss_score":   score,
        "cvss_vector":  cvss_vector,
        "cvss_raw":     cvss_raw,
        "affected":     affected,
        "full_text":    text,
    }


# ── Check 1: CVSS Consistency ─────────────────────────────────────────────────
def check_cvss_consistency(info):
    score    = info["cvss_score"]
    severity = info["severity"].lower()

    if score is None:
        return RESULT["fail"], "No CVSS score found in description.md"

    band = SEVERITY_BANDS.get(severity)
    if band is None:
        return RESULT["fail"], f"Unrecognised severity label: '{info['severity']}'"

    lo, hi = band
    # Informational/None is special — score 0.0 or absent
    if severity in ("informational", "info", "none"):
        if score <= 0.0:
            return RESULT["pass"], f"Score {score} consistent with {info['severity']}"
        return RESULT["fail"], (
            f"Score {score} is non-zero but severity is {info['severity']}"
        )

    if not (lo - CVSS_TOLERANCE <= score <= hi + CVSS_TOLERANCE):
        # Find what severity the score actually belongs to
        expected = next(
            (k.title() for k, (l, h) in SEVERITY_BANDS.items()
             if l <= score <= h and k not in ("info", "none")), "unknown"
        )
        return RESULT["fail"], (
            f"Score {score} is outside the {info['severity']} band "
            f"({lo}–{hi} ±{CVSS_TOLERANCE}). Expected severity: {expected}"
        )

    # Validate CVSS vector format if present
    vec = info["cvss_vector"]
    if vec:
        required_metrics = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        present = set(re.findall(r'([A-Z]+):', vec))
        missing = required_metrics - present
        if missing:
            return RESULT["warn"], (
                f"Score/severity consistent but CVSS vector missing metrics: "
                f"{', '.join(sorted(missing))}"
            )

    return RESULT["pass"], (
        f"Score {score} is within the {info['severity']} band ({lo}–{hi})"
    )


# ── Check 2: Evidence Exists ──────────────────────────────────────────────────
def check_evidence_exists(finding_dir):
    evidence_dir = finding_dir / "evidence"

    if not evidence_dir.exists():
        return RESULT["fail"], (
            "evidence/ directory is missing. "
            "At least one of request.txt / response.txt / screenshot.png is required."
        )

    found = []
    for f in evidence_dir.iterdir():
        if f.is_file() and f.stat().st_size > 0:
            found.append(f.name)

    if not found:
        return RESULT["fail"], (
            "evidence/ directory exists but all files are empty or absent."
        )

    recognised = [f for f in found if f.lower() in EVIDENCE_FILENAMES]
    if not recognised:
        return RESULT["warn"], (
            f"evidence/ has files ({', '.join(found)}) but none match the "
            f"expected names (request.txt, response.txt, screenshot.png, …). "
            f"Treating as present — rename files if this is a false positive."
        )

    return RESULT["pass"], f"Evidence files present: {', '.join(sorted(recognised))}"


# ── Check 3: PoC Validity ─────────────────────────────────────────────────────
def check_poc_validity(finding_dir, info):
    poc_py = finding_dir / "poc.py"
    poc_sh = finding_dir / "poc.sh"

    if not poc_py.exists() and not poc_sh.exists():
        return RESULT["fail"], "No poc.py or poc.sh found in finding directory."

    poc_file = poc_py if poc_py.exists() else poc_sh
    poc_text = poc_file.read_text(encoding="utf-8", errors="replace")

    # Syntax check
    if poc_file.suffix == ".py":
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(poc_file)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return RESULT["fail"], (
                f"poc.py failed syntax check: {result.stderr.strip()}"
            )

    # Check PoC references the affected component
    affected = info["affected"]
    if affected:
        # Extract meaningful tokens from the affected component URL/path
        # Use the hostname or a distinctive path segment
        tokens = re.findall(r'[\w.-]{6,}', affected)
        meaningful = [t for t in tokens if len(t) >= 6 and t not in
                      ("https", "http", "example", "localhost", "script", "target")][:3]

        matched = any(tok.lower() in poc_text.lower() for tok in meaningful)
        if not matched and meaningful:
            return RESULT["warn"], (
                f"{poc_file.name} syntax is valid but none of the affected-component "
                f"tokens ({', '.join(meaningful)}) appear in the PoC. "
                f"Verify the PoC targets the right endpoint."
            )

    return RESULT["pass"], f"{poc_file.name} syntax valid and references affected component"


# ── Check 4: Claims vs Evidence ───────────────────────────────────────────────
def check_claims_vs_evidence(finding_dir, info):
    evidence_dir = finding_dir / "evidence"
    affected = info["affected"].strip()

    if not evidence_dir.exists() or not any(evidence_dir.iterdir()):
        return RESULT["fail"], (
            "Cannot verify claims — evidence/ is empty or absent (see Check 2)."
        )

    # Gather all evidence text
    evidence_text = ""
    for f in evidence_dir.iterdir():
        if f.is_file() and f.stat().st_size < 1_000_000:
            try:
                evidence_text += f.read_text(encoding="utf-8", errors="replace") + "\n"
            except OSError:
                pass

    if not evidence_text.strip():
        return RESULT["fail"], "Evidence files are present but unreadable or empty."

    # Check: affected component appears somewhere in evidence
    if affected:
        tokens = re.findall(r'[\w.-]{6,}', affected)
        meaningful = [t for t in tokens if len(t) >= 6 and
                      t not in ("https", "http", "example")][:3]
        if meaningful and not any(tok.lower() in evidence_text.lower() for tok in meaningful):
            return RESULT["warn"], (
                f"Affected component tokens ({', '.join(meaningful)}) not found in "
                f"evidence files. Confirm evidence targets the correct endpoint."
            )

    return RESULT["pass"], "Evidence text present and references the affected component"


# ── Check 5: Log Corroboration ────────────────────────────────────────────────
def check_log_corroboration(finding_dir, output_dir, info):
    logs_dir = output_dir / "logs"
    affected  = info["affected"]

    if not logs_dir.exists():
        return RESULT["fail"], (
            f"logs/ directory not found at {logs_dir}. "
            "Executor activity logs are required to corroborate this finding."
        )

    log_files = list(logs_dir.glob("*.ndjson")) + \
                list(logs_dir.glob("*.json"))  + \
                list(logs_dir.glob("*.txt"))   + \
                list(logs_dir.glob("*.log"))

    if not log_files:
        return RESULT["fail"], (
            "logs/ directory exists but contains no log files."
        )

    # Build search tokens from affected component + finding title keywords
    tokens = set(re.findall(r'[\w.-]{5,}', affected)) if affected else set()
    # Add title keywords
    title_words = [w for w in re.findall(r'\b[a-zA-Z]{5,}\b', info["title"])
                   if w.lower() not in ("finding", "bypass", "injection", "unvalidated")]
    tokens.update(title_words[:4])
    tokens = {t for t in tokens if t not in ("https", "http", "example")}

    for lf in log_files:
        try:
            content = lf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(tok.lower() in content.lower() for tok in tokens):
            return RESULT["pass"], f"Corroborating log entry found in {lf.name}"

    return RESULT["fail"], (
        f"No log entry found referencing this finding's target "
        f"(searched {len(log_files)} log file(s) for: "
        f"{', '.join(sorted(tokens)[:5])}). "
        "The finding may not have been actively tested — check executor logs."
    )


# ── Runner ────────────────────────────────────────────────────────────────────
ICONS = {RESULT["pass"]: "✓", RESULT["fail"]: "✗",
         RESULT["warn"]: "⚠", RESULT["skip"]: "–"}
LABELS = {RESULT["pass"]: "PASS", RESULT["fail"]: "FAIL",
          RESULT["warn"]: "WARN", RESULT["skip"]: "SKIP"}

def run_checks(finding_dir, strict=False):
    """Run all 5 checks. Returns (overall_pass, results_dict)."""
    finding_dir = Path(finding_dir).resolve()
    desc_path   = finding_dir / "description.md"

    if not finding_dir.exists():
        print(f"[ERROR] Finding directory not found: {finding_dir}", file=sys.stderr)
        sys.exit(2)
    if not desc_path.exists():
        print(f"[ERROR] description.md not found in {finding_dir}", file=sys.stderr)
        sys.exit(2)

    # Infer OUTPUT_DIR: finding_dir → findings/ → OUTPUT_DIR
    output_dir = finding_dir.parent.parent

    info    = parse_description(desc_path)
    fid     = finding_dir.name
    width   = 68

    print(f"\n{'─' * width}")
    print(f"  Validating: {fid}")
    print(f"  Title:      {info['title'][:60]}")
    print(f"  Severity:   {info['severity']}   CVSS: {info['cvss_score']}")
    print(f"{'─' * width}")

    checks = [
        ("cvss_consistency",  "CVSS Consistency",
         lambda: check_cvss_consistency(info)),
        ("evidence_exists",   "Evidence Exists",
         lambda: check_evidence_exists(finding_dir)),
        ("poc_validity",      "PoC Validity",
         lambda: check_poc_validity(finding_dir, info)),
        ("claims_vs_evidence","Claims vs Evidence",
         lambda: check_claims_vs_evidence(finding_dir, info)),
        ("log_corroboration", "Log Corroboration",
         lambda: check_log_corroboration(finding_dir, output_dir, info)),
    ]

    results = {}
    for i, (key, label, fn) in enumerate(checks, 1):
        outcome, reason = fn()
        results[key] = {"result": outcome, "reason": reason}
        icon = ICONS[outcome]
        tag  = LABELS[outcome]
        print(f"  {icon} Check {i}: {label:<22}  [{tag}]")
        # Show reason for non-pass outcomes
        if outcome != RESULT["pass"]:
            wrapped = re.sub(r'(.{1,62})(\s|$)', r'    \1\n', reason).rstrip()
            print(wrapped)

    print(f"{'─' * width}")

    # Overall: warn counts as pass unless --strict
    failures = [k for k, v in results.items()
                if v["result"] == RESULT["fail"] or
                   (strict and v["result"] == RESULT["warn"])]

    overall_pass = len(failures) == 0
    status_label = "VALIDATED" if overall_pass else "REJECTED"
    status_icon  = "✓" if overall_pass else "✗"
    print(f"  {status_icon} Overall: {status_label}"
          + (f"  (failed: {', '.join(failures)})" if failures else ""))
    print(f"{'─' * width}\n")

    return overall_pass, results, info


def write_result(finding_dir, overall_pass, results, info):
    output_dir = Path(finding_dir).resolve().parent.parent
    fid        = Path(finding_dir).name

    payload = {
        "finding_id": fid,
        "title":      info["title"],
        "severity":   info["severity"],
        "cvss_score": info["cvss_score"],
        "validated":  overall_pass,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "checks": {k: v["result"] for k, v in results.items()},
        "notes":  {k: v["reason"]  for k, v in results.items()
                   if v["result"] != RESULT["pass"]},
    }

    if overall_pass:
        out_dir  = output_dir / "artifacts" / "validated"
        out_file = out_dir / f"{fid}.json"
    else:
        out_dir  = output_dir / "artifacts" / "false-positives"
        failed   = next(k for k, v in results.items()
                        if v["result"] == RESULT["fail"])
        payload["failed_check"] = failed
        payload["reason"]       = results[failed]["reason"]
        out_file = out_dir / f"{fid}-rejected.json"

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(payload, indent=2))
    tag = "validated" if overall_pass else "false-positives"
    print(f"  → Written to artifacts/{tag}/{out_file.name}")

    return out_file


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    args   = sys.argv[1:]
    strict = "--strict" in args
    run_all = "--all" in args
    # Extract --output-dir VALUE / --output-dir=VALUE (alternative to the positional dir).
    od_flag, cleaned, i = "", [], 0
    while i < len(args):
        a = args[i]
        if a == "--output-dir" and i + 1 < len(args):
            od_flag = args[i + 1]; i += 2; continue
        if a.startswith("--output-dir="):
            od_flag = a.split("=", 1)[1]; i += 1; continue
        cleaned.append(a); i += 1
    paths = [a for a in cleaned if not a.startswith("--")]

    # Resolve target: --output-dir flag → positional → $OUTPUT_DIR env.
    target_str = od_flag or (paths[0] if paths else "") or os.environ.get("OUTPUT_DIR", "")
    if not target_str:
        print(__doc__)
        sys.exit(2)

    target = Path(target_str).resolve()

    if run_all:
        # Validate every finding under OUTPUT_DIR/findings/
        findings_dir = target / "findings"
        if not findings_dir.exists():
            print(f"[ERROR] No findings/ directory under {target}", file=sys.stderr)
            sys.exit(2)
        dirs = sorted(d for d in findings_dir.iterdir()
                      if d.is_dir() and (d / "description.md").exists())
        if not dirs:
            print(f"[INFO] No findings with description.md found in {findings_dir}")
            sys.exit(0)

        all_pass = True
        for d in dirs:
            ok, results, info = run_checks(d, strict=strict)
            write_result(d, ok, results, info)
            if not ok:
                all_pass = False

        print(f"\n{'═' * 68}")
        total = len(dirs)
        passed = sum(1 for d in dirs
                     if (target / "artifacts" / "validated" / f"{d.name}.json").exists())
        print(f"  Results: {passed}/{total} findings validated")
        print(f"{'═' * 68}\n")
        sys.exit(0 if all_pass else 1)

    else:
        # Single finding
        ok, results, info = run_checks(target, strict=strict)
        write_result(target, ok, results, info)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
