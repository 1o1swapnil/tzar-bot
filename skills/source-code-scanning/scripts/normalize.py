#!/usr/bin/env python3
"""
normalize.py — Convert heterogeneous scanner outputs into canonical Finding JSONL.

Supports (extend as needed):
  - SARIF 2.1.0 (CodeQL, Semgrep, Snyk Code, Sonar export, gosec, Bandit-SARIF, ...)
  - SonarQube native JSON
  - Semgrep native JSON
  - OWASP Dependency-Check JSON
  - Trivy JSON
  - Grype JSON
  - Snyk Open Source JSON
  - Gitleaks JSON
  - ZAP JSON
  - Burp XML
  - CycloneDX SBOM (for components inventory only — no findings)

Usage:
    python normalize.py <inputs_dir_or_file> [--out findings.jsonl]

Output: one JSON object per line, schema as documented in SKILL.md §3 Phase 3.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ----------------------------- canonical schema ------------------------------

CANONICAL_FIELDS = [
    "finding_id", "source_tool", "source_tool_version", "source_rule_id",
    "title", "description", "cwe", "owasp_top10_2021", "owasp_asvs_4_0_3",
    "owasp_llm_top10", "cvss_v3_1", "cvss_v4_0", "severity_raw",
    "severity_normalized", "likelihood", "impact", "exploitability",
    "asset", "component_purl", "component_version", "fixed_in_version",
    "language", "location_file", "location_start_line", "location_end_line",
    "location_url", "data_flow", "evidence", "introduced_at",
    "first_seen", "last_seen", "status", "fp_reasoning",
    "remediation", "remediation_effort", "owner_role", "tags",
    "severity_adjustments", "mapping_source",
]


def fid(*parts: Any) -> str:
    """Deterministic finding id."""
    h = hashlib.sha256("".join(str(p or "") for p in parts).encode("utf-8"))
    return h.hexdigest()[:16]


def empty() -> dict[str, Any]:
    base = {k: None for k in CANONICAL_FIELDS}
    base["cwe"] = []
    base["owasp_top10_2021"] = []
    base["owasp_asvs_4_0_3"] = []
    base["owasp_llm_top10"] = []
    base["data_flow"] = []
    base["severity_adjustments"] = []
    base["tags"] = []
    base["status"] = "new"
    base["first_seen"] = base["last_seen"] = datetime.now(tz=timezone.utc).isoformat()
    return base


# ----------------------------- severity mapping ------------------------------

CVSS_BANDS = [
    (9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "Info"),
]


def cvss_to_canonical(score: float | None) -> str | None:
    if score is None:
        return None
    for floor, name in CVSS_BANDS:
        if score >= floor:
            return name
    return "Info"


SEVERITY_TABLE = {
    "critical": "Critical", "blocker": "Critical", "very high": "Critical",
    "high": "High", "error": "High",
    "medium": "Medium", "moderate": "Medium", "major": "Medium", "warning": "Medium",
    "low": "Low", "minor": "Low",
    "info": "Info", "informational": "Info", "note": "Info", "unknown": "Info",
}


def vendor_to_canonical(level: str | None) -> str | None:
    if level is None:
        return None
    return SEVERITY_TABLE.get(level.strip().lower())


# ----------------------------- helpers ----------------------------------------

CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def extract_cwes(*texts: str | None) -> list[str]:
    found: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in CWE_RE.finditer(t):
            found.add(f"CWE-{m.group(1)}")
    return sorted(found)


def load_json(p: Path) -> Any:
    with p.open("r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


# ----------------------------- SARIF parser ----------------------------------

def parse_sarif(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    for run in data.get("runs", []):
        tool = (run.get("tool") or {}).get("driver") or {}
        tool_name = tool.get("name") or "SARIF"
        tool_ver = tool.get("version") or tool.get("semanticVersion")
        rules_by_id: dict[str, dict[str, Any]] = {r.get("id"): r for r in tool.get("rules", []) if r.get("id")}

        for r in run.get("results", []):
            f = empty()
            rule_id = r.get("ruleId") or (r.get("rule") or {}).get("id")
            rule = rules_by_id.get(rule_id, {})

            msg = r.get("message") or {}
            title = (rule.get("shortDescription") or {}).get("text") or rule.get("name") or rule_id or "Untitled"
            description = (msg.get("text") or (rule.get("fullDescription") or {}).get("text") or "")

            locs = r.get("locations") or []
            phys = (locs[0].get("physicalLocation") if locs else {}) or {}
            artifact = (phys.get("artifactLocation") or {}).get("uri")
            region = phys.get("region") or {}

            sev_raw = (r.get("level")
                       or (rule.get("defaultConfiguration") or {}).get("level")
                       or (rule.get("properties") or {}).get("security-severity"))
            # SARIF "security-severity" is a CVSS string
            cvss = None
            try:
                cvss = float((rule.get("properties") or {}).get("security-severity")) if rule else None
            except (TypeError, ValueError):
                cvss = None

            cwes = extract_cwes(
                title, description,
                json.dumps(rule.get("properties") or {}, default=str),
                json.dumps((r.get("properties") or {}), default=str),
            )

            f.update({
                "source_tool": tool_name,
                "source_tool_version": tool_ver,
                "source_rule_id": rule_id,
                "title": title,
                "description": description,
                "cwe": cwes,
                "cvss_v3_1": cvss,
                "severity_raw": sev_raw,
                "severity_normalized": cvss_to_canonical(cvss) or vendor_to_canonical(sev_raw),
                "location_file": artifact,
                "location_start_line": region.get("startLine"),
                "location_end_line": region.get("endLine"),
                "evidence": (region.get("snippet") or {}).get("text"),
            })
            f["finding_id"] = fid(tool_name, rule_id, artifact, region.get("startLine"), title)
            yield f


# ----------------------------- Semgrep native --------------------------------

def parse_semgrep(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    for r in data.get("results", []):
        f = empty()
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        f.update({
            "source_tool": "Semgrep",
            "source_rule_id": r.get("check_id"),
            "title": meta.get("shortlink") or r.get("check_id"),
            "description": extra.get("message"),
            "cwe": extract_cwes(json.dumps(meta), extra.get("message")),
            "severity_raw": extra.get("severity"),
            "severity_normalized": vendor_to_canonical(extra.get("severity")),
            "location_file": r.get("path"),
            "location_start_line": (r.get("start") or {}).get("line"),
            "location_end_line": (r.get("end") or {}).get("line"),
            "evidence": extra.get("lines"),
        })
        f["finding_id"] = fid("Semgrep", r.get("check_id"), r.get("path"),
                              (r.get("start") or {}).get("line"))
        yield f


# ----------------------------- Sonar native ----------------------------------

def parse_sonar(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    issues = data.get("issues") or data.get("hotspots") or []
    for r in issues:
        f = empty()
        rule = r.get("rule") or r.get("ruleKey")
        f.update({
            "source_tool": "SonarQube",
            "source_rule_id": rule,
            "title": r.get("message") or rule,
            "description": r.get("message"),
            "cwe": extract_cwes(r.get("message"), json.dumps(r.get("tags") or [])),
            "severity_raw": r.get("severity"),
            "severity_normalized": vendor_to_canonical(r.get("severity")),
            "location_file": r.get("component"),
            "location_start_line": (r.get("textRange") or {}).get("startLine"),
            "location_end_line": (r.get("textRange") or {}).get("endLine"),
        })
        f["finding_id"] = fid("SonarQube", rule, r.get("component"),
                              (r.get("textRange") or {}).get("startLine"))
        yield f


# ----------------------------- OWASP Dependency-Check ------------------------

def parse_owasp_dc(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    for dep in data.get("dependencies", []):
        purl = None
        for ident in dep.get("packages") or []:
            if (ident.get("id") or "").startswith("pkg:"):
                purl = ident["id"]
                break
        for vuln in dep.get("vulnerabilities", []) or []:
            cvss = ((vuln.get("cvssv3") or {}).get("baseScore")
                    or (vuln.get("cvssv2") or {}).get("score"))
            f = empty()
            f.update({
                "source_tool": "OWASP Dependency-Check",
                "source_rule_id": vuln.get("name"),
                "title": f"{vuln.get('name')} in {dep.get('fileName')}",
                "description": vuln.get("description"),
                "cwe": [c for c in (vuln.get("cwes") or []) if c.startswith("CWE-")],
                "cvss_v3_1": cvss,
                "severity_raw": vuln.get("severity"),
                "severity_normalized": cvss_to_canonical(cvss) or vendor_to_canonical(vuln.get("severity")),
                "asset": dep.get("fileName"),
                "component_purl": purl,
                "tags": ["sca"],
            })
            f["finding_id"] = fid("OWASP-DC", vuln.get("name"), purl or dep.get("fileName"))
            yield f


# ----------------------------- Trivy -----------------------------------------

def parse_trivy(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            f = empty()
            cvss = None
            for vendor, payload in (v.get("CVSS") or {}).items():
                if payload.get("V3Score"):
                    cvss = payload["V3Score"]
                    break
            f.update({
                "source_tool": "Trivy",
                "source_rule_id": v.get("VulnerabilityID"),
                "title": v.get("Title") or v.get("VulnerabilityID"),
                "description": v.get("Description"),
                "cwe": v.get("CweIDs") or [],
                "cvss_v3_1": cvss,
                "severity_raw": v.get("Severity"),
                "severity_normalized": cvss_to_canonical(cvss) or vendor_to_canonical(v.get("Severity")),
                "asset": res.get("Target"),
                "component_purl": v.get("PkgIdentifier", {}).get("PURL"),
                "component_version": v.get("InstalledVersion"),
                "fixed_in_version": v.get("FixedVersion"),
                "tags": ["sca", res.get("Type") or ""],
            })
            f["finding_id"] = fid("Trivy", v.get("VulnerabilityID"),
                                  v.get("PkgName"), v.get("InstalledVersion"))
            yield f


# ----------------------------- Grype -----------------------------------------

def parse_grype(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    for m in data.get("matches", []) or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        cvss = None
        for c in v.get("cvss") or []:
            if c.get("version", "").startswith("3"):
                cvss = (c.get("metrics") or {}).get("baseScore")
                break
        f = empty()
        f.update({
            "source_tool": "Grype",
            "source_rule_id": v.get("id"),
            "title": v.get("id"),
            "description": v.get("description"),
            "cvss_v3_1": cvss,
            "severity_raw": v.get("severity"),
            "severity_normalized": cvss_to_canonical(cvss) or vendor_to_canonical(v.get("severity")),
            "component_purl": a.get("purl"),
            "component_version": a.get("version"),
            "fixed_in_version": ",".join((v.get("fix") or {}).get("versions") or []) or None,
            "tags": ["sca"],
        })
        f["finding_id"] = fid("Grype", v.get("id"), a.get("purl"))
        yield f


# ----------------------------- Snyk Open Source ------------------------------

def parse_snyk_oss(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    items = data.get("vulnerabilities") if isinstance(data, dict) else []
    for v in items or []:
        cvss = v.get("cvssScore")
        f = empty()
        f.update({
            "source_tool": "Snyk Open Source",
            "source_rule_id": v.get("id"),
            "title": v.get("title"),
            "description": v.get("description"),
            "cwe": [c for c in (v.get("identifiers", {}).get("CWE") or []) if c.startswith("CWE-")],
            "cvss_v3_1": cvss,
            "severity_raw": v.get("severity"),
            "severity_normalized": cvss_to_canonical(cvss) or vendor_to_canonical(v.get("severity")),
            "component_purl": v.get("packageName") and f"pkg:{v.get('packageManager')}/{v['packageName']}@{v.get('version')}",
            "component_version": v.get("version"),
            "fixed_in_version": ",".join(v.get("fixedIn") or []) or None,
            "tags": ["sca"],
        })
        f["finding_id"] = fid("Snyk", v.get("id"), v.get("packageName"), v.get("version"))
        yield f


# ----------------------------- Gitleaks --------------------------------------

def parse_gitleaks(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    items = data if isinstance(data, list) else data.get("findings") or []
    for r in items:
        secret = r.get("Secret") or r.get("secret") or ""
        masked = (secret[:4] + "*" * max(0, len(secret) - 4)) if secret else None
        f = empty()
        f.update({
            "source_tool": "Gitleaks",
            "source_rule_id": r.get("RuleID") or r.get("rule_id"),
            "title": f"Secret detected: {r.get('RuleID') or r.get('rule_id')}",
            "description": r.get("Description") or r.get("description"),
            "cwe": ["CWE-798"],
            "severity_raw": "High",
            "severity_normalized": "High",
            "location_file": r.get("File") or r.get("file"),
            "location_start_line": r.get("StartLine") or r.get("startLine"),
            "evidence": masked,
            "tags": ["secret"],
        })
        f["finding_id"] = fid("Gitleaks", r.get("RuleID"), r.get("File"), r.get("StartLine"))
        yield f


# ----------------------------- ZAP -------------------------------------------

def parse_zap(p: Path) -> Iterable[dict[str, Any]]:
    data = load_json(p)
    risk_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            sev = risk_map.get(str(a.get("riskcode")), "Info")
            urls = [(i.get("uri"), i.get("evidence")) for i in (a.get("instances") or [])]
            f = empty()
            f.update({
                "source_tool": "OWASP ZAP",
                "source_rule_id": str(a.get("pluginid")),
                "title": a.get("name"),
                "description": a.get("desc"),
                "cwe": extract_cwes(a.get("cweid") and f"CWE-{a['cweid']}"),
                "severity_raw": a.get("riskdesc"),
                "severity_normalized": sev,
                "location_url": urls[0][0] if urls else None,
                "evidence": urls[0][1] if urls else None,
                "tags": ["dast"],
            })
            f["finding_id"] = fid("ZAP", a.get("pluginid"), site.get("@name"), urls[0][0] if urls else None)
            yield f


# ----------------------------- Burp XML --------------------------------------

def parse_burp_xml(p: Path) -> Iterable[dict[str, Any]]:
    tree = ET.parse(p)
    root = tree.getroot()
    for issue in root.findall(".//issue"):
        sev = (issue.findtext("severity") or "").strip()
        f = empty()
        f.update({
            "source_tool": "Burp Suite",
            "source_rule_id": issue.findtext("type"),
            "title": issue.findtext("name"),
            "description": (issue.findtext("issueDetail") or issue.findtext("issueBackground") or ""),
            "cwe": extract_cwes(issue.findtext("issueBackground") or "",
                                 issue.findtext("issueDetail") or ""),
            "severity_raw": sev,
            "severity_normalized": vendor_to_canonical(sev),
            "location_url": issue.findtext("host") and (issue.findtext("host") + (issue.findtext("path") or "")),
            "tags": ["dast"],
        })
        f["finding_id"] = fid("Burp", issue.findtext("type"), issue.findtext("host"),
                              issue.findtext("path"))
        yield f


# ----------------------------- dispatcher ------------------------------------

def looks_like_sarif(obj: Any) -> bool:
    return isinstance(obj, dict) and "runs" in obj and any(
        "tool" in r and "results" in r for r in (obj.get("runs") or [])
    )


def dispatch(path: Path) -> Iterable[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".sarif"}:
        yield from parse_sarif(path); return
    if suffix == ".json":
        try:
            data = load_json(path)
        except Exception as e:
            print(f"[warn] could not parse JSON: {path}: {e}", file=sys.stderr)
            return
        if looks_like_sarif(data):
            yield from parse_sarif(path); return
        if isinstance(data, dict):
            if "results" in data and any("check_id" in r for r in data.get("results", []) if isinstance(r, dict)):
                yield from parse_semgrep(path); return
            if "issues" in data and "components" in data:
                yield from parse_sonar(path); return
            if "dependencies" in data and "reportSchema" in data:
                yield from parse_owasp_dc(path); return
            if "Results" in data and any("Vulnerabilities" in r for r in data.get("Results", []) if isinstance(r, dict)):
                yield from parse_trivy(path); return
            if "matches" in data and isinstance(data["matches"], list):
                yield from parse_grype(path); return
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list) \
                    and data["vulnerabilities"] and "packageName" in data["vulnerabilities"][0]:
                yield from parse_snyk_oss(path); return
            if "site" in data and isinstance(data["site"], list):
                yield from parse_zap(path); return
            if "findings" in data and isinstance(data["findings"], list):
                yield from parse_gitleaks(path); return
        if isinstance(data, list) and data and isinstance(data[0], dict) and "RuleID" in data[0]:
            yield from parse_gitleaks(path); return
        print(f"[warn] unrecognized JSON: {path}", file=sys.stderr)
        return
    if suffix == ".xml":
        # Best-effort: Burp
        try:
            yield from parse_burp_xml(path); return
        except Exception as e:
            print(f"[warn] XML not Burp ({path}): {e}", file=sys.stderr)
            return
    print(f"[skip] unsupported suffix: {path}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", help="File or directory of scanner outputs")
    ap.add_argument("--out", default="-", help="Output JSONL path (default stdout)")
    args = ap.parse_args()

    src = Path(args.inputs)
    files: list[Path] = []
    if src.is_dir():
        files = sorted(p for p in src.rglob("*") if p.is_file())
    elif src.is_file():
        files = [src]
    else:
        print(f"[error] not found: {src}", file=sys.stderr); return 2

    out = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    count = 0
    for fp in files:
        for finding in dispatch(fp):
            out.write(json.dumps(finding, default=str) + "\n")
            count += 1
    if out is not sys.stdout:
        out.close()
    print(f"[ok] wrote {count} findings", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
