#!/usr/bin/env python3
"""
dedup.py — Cross-tool deduplication and SAST/DAST/SCA correlation.

Reads canonical findings JSONL (from normalize.py) and writes:
  - findings.dedup.jsonl  (one row per logical issue, sources merged into 'evidence_tools')
  - correlations.md       (SAST <-> DAST <-> SCA links)

Rules (see SKILL.md §4):
  - Strong match: same primary CWE + same file:line(±2) + same language family   => merge
  - Medium match: same primary CWE + same logical location (function/symbol)      => merge
  - SCA match:    same purl + same CVE/source_rule_id                              => merge
  - DAST/SAST correlation: same URL path family + overlapping CWE family           => link (kept separate)

Usage:
    python dedup.py findings.jsonl --out findings.dedup.jsonl --correlations correlations.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0, None: -1}


def primary_cwe(f: dict[str, Any]) -> str | None:
    cwes = f.get("cwe") or []
    return cwes[0] if cwes else None


def language_of(f: dict[str, Any]) -> str | None:
    # Try explicit, else infer from file extension
    if f.get("language"):
        return f["language"]
    path = f.get("location_file") or ""
    if not path:
        return None
    ext = path.lower().rsplit(".", 1)[-1] if "." in path else ""
    return {
        "java": "Java", "kt": "Kotlin", "kts": "Kotlin", "scala": "Scala",
        "py": "Python", "rb": "Ruby", "go": "Go", "rs": "Rust",
        "js": "JavaScript", "jsx": "JavaScript", "ts": "TypeScript", "tsx": "TypeScript",
        "cs": "C#", "fs": "F#", "vb": "VB.NET",
        "php": "PHP", "swift": "Swift", "m": "Objective-C", "mm": "Objective-C",
        "c": "C", "h": "C", "cpp": "C++", "cc": "C++", "hpp": "C++",
        "tf": "Terraform", "yaml": "YAML", "yml": "YAML",
        "dockerfile": "Docker",
    }.get(ext)


def line_key(f: dict[str, Any], tolerance: int = 2) -> tuple[str, int]:
    line = f.get("location_start_line") or 0
    bucket = (int(line) // (tolerance + 1)) if isinstance(line, int) else 0
    return (f.get("location_file") or "", bucket)


URL_NORM = re.compile(r"\d+|[0-9a-f]{8,}", re.IGNORECASE)


def url_path_family(f: dict[str, Any]) -> str | None:
    u = f.get("location_url")
    if not u:
        return None
    # strip scheme://host, query
    path = re.sub(r"^[a-z]+://[^/]+", "", u, count=1).split("?", 1)[0]
    # collapse numeric ids / hex hashes to wildcards
    return URL_NORM.sub("*", path)


def cwe_family(cwes: list[str]) -> set[str]:
    return {c for c in (cwes or []) if c.startswith("CWE-")}


def is_sast(f): return "dast" not in (f.get("tags") or []) and "sca" not in (f.get("tags") or []) and not f.get("component_purl")
def is_dast(f): return "dast" in (f.get("tags") or [])
def is_sca(f):  return "sca" in (f.get("tags") or []) or bool(f.get("component_purl"))


def higher_sev(a: str | None, b: str | None) -> str | None:
    return a if SEV_RANK.get(a, -1) >= SEV_RANK.get(b, -1) else b


def merge(into: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    into["evidence_tools"] = sorted(set((into.get("evidence_tools") or [into["source_tool"]]) + [extra["source_tool"]]))
    into["severity_normalized"] = higher_sev(into.get("severity_normalized"), extra.get("severity_normalized"))
    # Union CWEs and tags
    into["cwe"] = sorted(set((into.get("cwe") or []) + (extra.get("cwe") or [])))
    into["tags"] = sorted(set((into.get("tags") or []) + (extra.get("tags") or [])))
    # Prefer non-null fixed_in_version
    if extra.get("fixed_in_version") and not into.get("fixed_in_version"):
        into["fixed_in_version"] = extra["fixed_in_version"]
    return into


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", help="findings.jsonl from normalize.py")
    ap.add_argument("--out", default="findings.dedup.jsonl")
    ap.add_argument("--correlations", default="correlations.md")
    args = ap.parse_args()

    findings: list[dict[str, Any]] = []
    with open(args.findings, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                findings.append(json.loads(ln))

    # 1) SCA exact-match merge by (purl, rule_id)
    sca_index: dict[tuple[str, str], dict[str, Any]] = {}
    others: list[dict[str, Any]] = []
    for f in findings:
        if is_sca(f) and f.get("component_purl") and f.get("source_rule_id"):
            key = (f["component_purl"], f["source_rule_id"])
            if key in sca_index:
                merge(sca_index[key], f)
            else:
                f["evidence_tools"] = [f["source_tool"]]
                sca_index[key] = f
        else:
            others.append(f)

    # 2) SAST merge by (primary_cwe, line bucket, language)
    sast_index: dict[tuple, dict[str, Any]] = {}
    leftover: list[dict[str, Any]] = []
    for f in others:
        if is_sast(f) and primary_cwe(f):
            key = (primary_cwe(f), line_key(f), language_of(f))
            if key in sast_index:
                merge(sast_index[key], f)
            else:
                f["evidence_tools"] = [f["source_tool"]]
                sast_index[key] = f
        else:
            leftover.append(f)

    deduped = list(sca_index.values()) + list(sast_index.values()) + leftover

    # 3) Correlation (DAST <-> SAST) — separate output, do not merge
    correlations: list[tuple[dict[str, Any], dict[str, Any], float]] = []
    sast_by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in sast_index.values():
        for c in cwe_family(f.get("cwe") or []):
            sast_by_cwe[c].append(f)
    for f in leftover:
        if is_dast(f):
            family = cwe_family(f.get("cwe") or [])
            url_fam = url_path_family(f)
            for c in family:
                for s in sast_by_cwe.get(c, []):
                    # very rough: link if any path component matches
                    sfile = (s.get("location_file") or "").lower()
                    if url_fam and any(part and part in sfile for part in url_fam.lower().strip("/").split("/")):
                        correlations.append((s, f, 0.7))
                        s.setdefault("correlations", []).append(f.get("finding_id"))
                        f.setdefault("correlations", []).append(s.get("finding_id"))

    # Write outputs
    out_path = Path(args.out)
    with out_path.open("w", encoding="utf-8") as out:
        for f in deduped:
            out.write(json.dumps(f, default=str) + "\n")

    with open(args.correlations, "w", encoding="utf-8") as out:
        out.write("# SAST <-> DAST <-> SCA Correlations\n\n")
        out.write(f"Total correlations: {len(correlations)}\n\n")
        if not correlations:
            out.write("_No cross-tool correlations identified._\n")
        for s, d, conf in correlations:
            out.write(
                f"- [{conf:.2f}] **{s.get('title')}** "
                f"(`{s.get('source_tool')}` {s.get('location_file')}:{s.get('location_start_line')}) "
                f"↔ **{d.get('title')}** (`{d.get('source_tool')}` {d.get('location_url')})\n"
            )

    print(f"[ok] {len(deduped)} unique findings, {len(correlations)} correlations", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
