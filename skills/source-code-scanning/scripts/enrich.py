#!/usr/bin/env python3
"""
enrich.py — Optional enrichment for SCA findings.

Network use REQUIRES explicit user authorization. By default this script runs
offline and only re-reads local copies of KEV / EPSS if present.

Sources:
  - CISA KEV catalog:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - FIRST EPSS:        https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY

Usage:
    python enrich.py findings.dedup.jsonl --kev kev.json --epss epss.csv --out enriched.jsonl
    # or with --allow-network to fetch live (you must say yes)
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any
from urllib.request import urlopen

CVE_RE = __import__("re").compile(r"CVE-\d{4}-\d+", __import__("re").IGNORECASE)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH_URL = "https://api.first.org/data/v1/epss?cve={}"


def load_kev(path: Path | None, allow_network: bool) -> set[str]:
    if path and path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
    if not allow_network:
        return set()
    with urlopen(KEV_URL, timeout=30) as r:
        data = json.loads(r.read())
    return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}


def load_epss(path: Path | None) -> dict[str, float]:
    """Load FIRST EPSS CSV (cve,epss,percentile,date)."""
    out: dict[str, float] = {}
    if not path or not path.exists():
        return out
    with path.open("r", encoding="utf-8") as f:
        rdr = csv.reader(f)
        for row in rdr:
            if not row or row[0].startswith("#") or row[0] == "cve":
                continue
            try:
                out[row[0].upper()] = float(row[1])
            except (IndexError, ValueError):
                continue
    return out


def fetch_epss(cves: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for i in range(0, len(cves), 100):
        batch = ",".join(cves[i:i + 100])
        try:
            with urlopen(EPSS_BATCH_URL.format(batch), timeout=30) as r:
                data = json.loads(r.read())
            for d in data.get("data", []):
                out[d["cve"].upper()] = float(d.get("epss", 0))
        except Exception as e:
            print(f"[warn] EPSS fetch failed: {e}", file=sys.stderr)
    return out


def adjust_severity(current: str | None, kev: bool, epss: float | None) -> tuple[str | None, list[str]]:
    order = ["Info", "Low", "Medium", "High", "Critical"]
    if not current or current not in order:
        return current, []
    idx = order.index(current)
    adjustments: list[str] = []
    if kev:
        idx = max(idx, order.index("Critical"))
        adjustments.append("KEV: floor=Critical")
    if epss is not None and epss >= 0.7:
        idx = min(idx + 1, order.index("Critical"))
        adjustments.append(f"EPSS>=0.7 ({epss:.2f}): +1")
    return order[idx], adjustments


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--kev", type=Path)
    ap.add_argument("--epss", type=Path)
    ap.add_argument("--allow-network", action="store_true")
    ap.add_argument("--out", default="enriched.jsonl")
    args = ap.parse_args()

    findings = [json.loads(ln) for ln in Path(args.findings).read_text(encoding="utf-8").splitlines() if ln.strip()]

    cves: set[str] = set()
    for f in findings:
        rid = f.get("source_rule_id") or ""
        for m in CVE_RE.findall(rid):
            cves.add(m.upper())
        for c in f.get("cwe") or []:
            pass
        for m in CVE_RE.findall(f.get("title") or ""):
            cves.add(m.upper())

    kev_set = load_kev(args.kev, args.allow_network)
    epss_map = load_epss(args.epss)
    if args.allow_network and cves - set(epss_map.keys()):
        epss_map.update(fetch_epss(sorted(cves - set(epss_map.keys()))))

    with open(args.out, "w", encoding="utf-8") as out:
        for f in findings:
            rid = f.get("source_rule_id") or ""
            cve_match = (CVE_RE.search(rid) or CVE_RE.search(f.get("title") or ""))
            cve = cve_match.group(0).upper() if cve_match else None
            kev = bool(cve and cve in kev_set)
            epss = epss_map.get(cve) if cve else None
            f["kev_listed"] = kev
            f["epss"] = epss
            new_sev, adj = adjust_severity(f.get("severity_normalized"), kev, epss)
            if new_sev != f.get("severity_normalized") or adj:
                f["severity_adjustments"] = (f.get("severity_adjustments") or []) + adj
                f["severity_normalized"] = new_sev
            out.write(json.dumps(f, default=str) + "\n")

    print(f"[ok] enriched {len(findings)} findings, KEV={len(kev_set)}, EPSS={len(epss_map)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
