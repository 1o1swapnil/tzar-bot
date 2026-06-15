#!/usr/bin/env python3
"""
continuous-scan.py — Continuous / scheduled scanning orchestration for tzar-bot.

Manages recurring delta scans against monitored targets. The actual scanning is
performed by Claude Code coordinator/executor agents — this tool handles the
metadata: preparing new scan directories, computing finding deltas, and recording
scan history in memory.db.

Usage (coordinator calls these; also callable from /schedule):

    # 1. See what needs scanning
    python3 tools/continuous-scan.py list [--overdue-hours 24]

    # 2. Before scanning: prepare a new OUTPUT_DIR for the rescan
    python3 tools/continuous-scan.py prepare WAPT/acme/20260603_143022
    # → prints: export OUTPUT_DIR='WAPT/acme/20260604_090000'  (new timestamped dir)

    # 3. After scanning: compute which findings are NEW vs prior runs
    python3 tools/continuous-scan.py delta NEW_OUTPUT_DIR BASE_OUTPUT_DIR

    # 4. Record the completed scan
    python3 tools/continuous-scan.py record NEW_OUTPUT_DIR --findings 2 --type delta

    # 5. View history for a target
    python3 tools/continuous-scan.py history BASE_OUTPUT_DIR
"""

import sys
import os
import re
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timezone

REPO_DIR   = Path(__file__).parent.parent.resolve()
PYTHON     = sys.executable
MEM_TOOL   = str(REPO_DIR / "tools" / "session-memory.py")
INIT_TOOL  = str(REPO_DIR / "tools" / "init-engagement.py")


# ── helpers ──────────────────────────────────────────────────────────────────

def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_DIR)
    return r.stdout, r.stderr, r.returncode


def _load_engagement_json(output_dir: Path) -> dict:
    p = output_dir / "engagement.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _validated_findings(output_dir: Path) -> list[dict]:
    """Return all validated findings from OUTPUT_DIR/artifacts/validated/*.json"""
    val_dir = output_dir / "artifacts" / "validated"
    findings = []
    if not val_dir.exists():
        return findings
    for f in sorted(val_dir.glob("*.json")):
        try:
            findings.append(json.loads(f.read_text()))
        except Exception:
            pass
    return findings


def _all_findings_in_dir(output_dir: Path) -> list[dict]:
    """Parse finding title + affected from every findings/finding-NNN/description.md"""
    findings_dir = output_dir / "findings"
    results = []
    if not findings_dir.exists():
        return results
    for d in sorted(findings_dir.iterdir()):
        desc = d / "description.md"
        if not d.is_dir() or not desc.exists():
            continue
        text = desc.read_text(encoding="utf-8", errors="replace")
        title_m = re.match(r'#\s+Finding[:\s\d—-]*(.+)', text)
        title = title_m.group(1).strip() if title_m else d.name

        def tf(key):
            m = re.search(rf'\|\s*{re.escape(key)}\s*\|\s*(.+?)\s*\|', text, re.I)
            return m.group(1).strip() if m else ""

        results.append({
            "finding_id": d.name,
            "title":      title,
            "severity":   tf("Severity"),
            "affected":   tf("Affected Component") or tf("Affected URL") or tf("Affected"),
        })
    return results


def _fingerprint(finding: dict) -> str:
    """Normalise title + affected into a dedup key."""
    title    = re.sub(r'\s+', ' ', (finding.get("title") or "")).strip().lower()
    affected = re.sub(r'https?://[^/]+', '', (finding.get("affected") or "")).strip().lower()
    return f"{title}|{affected}"


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_list(args):
    """Proxy to session-memory.py targets with optional --overdue-hours."""
    cmd = [PYTHON, MEM_TOOL, "targets"] + args
    out, err, _ = _run(cmd)
    print(out, end="")
    if err:
        print(err, end="", file=sys.stderr)


def cmd_prepare(base_output_dir_str: str):
    """
    Create a new timestamped OUTPUT_DIR for a delta rescan of an existing engagement.
    Copies engagement metadata, writes a delta attack-chain.md, registers in memory.db.
    Prints the shell export line so coordinators can eval it.
    """
    base = Path(base_output_dir_str).resolve()
    if not base.exists():
        print(f"[!] Base OUTPUT_DIR not found: {base}", file=sys.stderr)
        sys.exit(1)

    meta = _load_engagement_json(base)
    if not meta:
        print(f"[!] No engagement.json found in: {base}", file=sys.stderr)
        sys.exit(1)

    # Build new OUTPUT_DIR: same type/project, new timestamp
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    eng_type  = meta.get("type", "WAPT")
    project   = meta.get("project", "unknown")
    new_dir   = REPO_DIR / eng_type / project / ts

    subdirs = [
        "recon", "findings", "logs",
        "artifacts/validated", "artifacts/false-positives",
        "tools", "reports", "evidence", "screenshots",
    ]
    for sub in subdirs:
        (new_dir / sub).mkdir(parents=True, exist_ok=True)

    # Write engagement.json (same target/scope, new timestamp, type=delta)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    new_meta = dict(meta)
    new_meta["output_dir"]  = str(new_dir)
    new_meta["started"]     = now_str
    new_meta["scan_type"]   = "delta"
    new_meta["base_run"]    = str(base)
    (new_dir / "engagement.json").write_text(json.dumps(new_meta, indent=2))

    # Write minimal attack-chain.md for the delta run
    prior_validated = _validated_findings(base)
    (new_dir / "attack-chain.md").write_text(f"""\
# Delta Scan — {meta.get('target', 'TARGET')}

## Engagement
- **Type:** {eng_type} (DELTA RESCAN)
- **Target:** {meta.get('target', '?')}
- **Scope:** {meta.get('scope', '?')}
- **Started:** {now_str}
- **Base Run:** {base}
- **OUTPUT_DIR:** {new_dir}

## Prior Validated Findings ({len(prior_validated)} known)
{chr(10).join(f"- [{f.get('severity','?')}] {f.get('title','?')} — {f.get('finding_id','')}" for f in prior_validated) or "- None"}

## Delta Scan Phases
Run only phases likely to surface NEW findings:
- Phase 1 — Recon diff: new subdomains, ports, endpoints since last scan
- Phase 4 — Injection: re-probe known endpoints + any new ones
- Nuclei: full template scan against current tech stack
- CVE reactive: check for new CVEs affecting detected versions

## New Findings (populate after scan)
| ID | Title | Severity | New? |
|----|-------|----------|------|
| — | (none yet) | — | — |

## Next Steps
- [ ] Spawn recon-diff executor
- [ ] Spawn nuclei-rescan executor
- [ ] Run: python3 tools/continuous-scan.py delta {new_dir} {base}
- [ ] Run: python3 tools/continuous-scan.py record {new_dir} --findings N
""")

    # Register in memory.db (reuse same project/target record via save)
    _run([PYTHON, MEM_TOOL, "save", str(new_dir)])

    print(f"[+] Delta scan directory prepared")
    print(f"    Base run      : {base}")
    print(f"    New scan dir  : {new_dir}")
    print(f"    Prior findings: {len(prior_validated)}")
    print()
    print(f"export OUTPUT_DIR='{new_dir}'")


def cmd_delta(new_dir_str: str, base_dir_str: str):
    """
    Compare findings in NEW_DIR against all prior validated findings in BASE_DIR
    (and its scan_history siblings). Print only genuinely NEW findings.
    """
    new_dir  = Path(new_dir_str).resolve()
    base_dir = Path(base_dir_str).resolve()

    # Collect known fingerprints from ALL prior validated runs under this project
    known: set[str] = set()

    # From base_dir validated
    for f in _validated_findings(base_dir):
        known.add(_fingerprint(f))

    # From any sibling scan dirs (same project dir)
    project_dir = base_dir.parent
    for sibling in sorted(project_dir.iterdir()):
        if sibling == base_dir or sibling == new_dir or not sibling.is_dir():
            continue
        for f in _validated_findings(sibling):
            known.add(_fingerprint(f))

    # New findings from current scan
    new_findings = _all_findings_in_dir(new_dir)
    fresh = [f for f in new_findings if _fingerprint(f) not in known]
    dupes = [f for f in new_findings if _fingerprint(f) in known]

    sep = "═" * 68
    print(sep)
    print(f"  DELTA REPORT — {new_dir.name}")
    print(f"  Base: {base_dir.name}")
    print(sep)
    print(f"  Total findings this scan : {len(new_findings)}")
    print(f"  Already known (skip)     : {len(dupes)}")
    print(f"  NEW findings             : {len(fresh)}")
    print()

    if fresh:
        print("  NEW FINDINGS (validate and report these):")
        for f in fresh:
            sev  = f.get("severity", "?")
            fid  = f.get("finding_id", "?")
            title = f.get("title", "?")
            aff   = f.get("affected", "")
            print(f"    [{sev:8s}] {fid} — {title}")
            if aff:
                print(f"             → {aff}")
        print()
    else:
        print("  No new findings — target posture unchanged since last scan.")

    if dupes:
        print(f"  KNOWN (already reported, skip): {', '.join(d['finding_id'] for d in dupes)}")

    print(sep)
    # Machine-readable for MCP / programmatic use
    result = {
        "new_count":  len(fresh),
        "known_count": len(dupes),
        "new_findings": fresh,
    }
    print()
    print("JSON_DELTA:", json.dumps(result))


def cmd_record(output_dir_str: str, extra: list[str]):
    """Proxy to session-memory.py record-scan."""
    cmd = [PYTHON, MEM_TOOL, "record-scan", output_dir_str] + extra
    out, err, rc = _run(cmd)
    print(out, end="")
    if err:
        print(err, end="", file=sys.stderr)
    sys.exit(rc)


def cmd_history(output_dir_str: str):
    """Proxy to session-memory.py scan-history."""
    out, err, _ = _run([PYTHON, MEM_TOOL, "scan-history", output_dir_str])
    print(out, end="")
    if err:
        print(err, end="", file=sys.stderr)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    cmd = args[0]

    if cmd == "list":
        cmd_list(args[1:])
    elif cmd == "prepare" and len(args) >= 2:
        cmd_prepare(args[1])
    elif cmd == "delta" and len(args) >= 3:
        cmd_delta(args[1], args[2])
    elif cmd == "record" and len(args) >= 2:
        cmd_record(args[1], args[2:])
    elif cmd == "history" and len(args) >= 2:
        cmd_history(args[1])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
