#!/usr/bin/env python3
"""
session-memory.py — SQLite-backed cross-session memory for tzar-bot engagements.

Parses attack-chain.md + findings/ + engagement.json into a structured database
so coordinator context survives conversation resets.

DB location: REPO_DIR/memory.db   (add to .gitignore — may contain sensitive intel)

Commands:
    save         <output_dir>              Parse attack-chain.md + findings/ and upsert to DB
    load         <output_dir>              Print a coordinator resume briefing to stdout
    list         [--type T] [--status S]  List all known engagements (active/completed/abandoned)
    search       <query>                   Full-text search across all engagements
    note         <output_dir> <text>       Append a freeform note to an engagement
    status       <output_dir> <new_status> Update engagement status (active/completed/abandoned)
    targets      [--overdue-hours N]       List monitored targets ready for a rescan
    record-scan  <output_dir> [--type TYPE] [--findings N] [--status STATUS]
                                           Record a completed scan run in scan_history
    scan-history <output_dir>              Show scan run history for an engagement
"""

import sys
import os
import re
import json
import sqlite3
import textwrap
from pathlib import Path
from datetime import datetime, timezone

REPO_DIR = Path(__file__).parent.parent.resolve()
DB_PATH  = REPO_DIR / "memory.db"


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    output_dir   TEXT    UNIQUE NOT NULL,
    target       TEXT,
    type         TEXT,
    project      TEXT,
    mode         TEXT,
    scope        TEXT,
    started      TEXT,
    last_updated TEXT,
    status       TEXT DEFAULT 'active',
    tech_stack   TEXT   -- JSON blob: {framework, database, waf, auth}
);

CREATE TABLE IF NOT EXISTS phases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    phase         TEXT,
    status        TEXT,
    agents        TEXT,
    findings      TEXT,
    UNIQUE(engagement_id, phase)
);

CREATE TABLE IF NOT EXISTS services (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    port          TEXT,
    service       TEXT,
    version       TEXT,
    notes         TEXT,
    UNIQUE(engagement_id, port, service)
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    finding_id    TEXT,
    title         TEXT,
    severity      TEXT,
    status        TEXT,
    cvss_score    REAL,
    affected      TEXT,
    UNIQUE(engagement_id, finding_id)
);

CREATE TABLE IF NOT EXISTS vectors (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    vector        TEXT,
    endpoint      TEXT,
    result        TEXT,
    notes         TEXT,
    UNIQUE(engagement_id, vector, endpoint)
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    text          TEXT,
    status        TEXT DEFAULT 'active',
    UNIQUE(engagement_id, text)
);

CREATE TABLE IF NOT EXISTS next_steps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    step          TEXT,
    done          INTEGER DEFAULT 0,
    UNIQUE(engagement_id, step)
);

CREATE TABLE IF NOT EXISTS notes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    note          TEXT,
    created_at    TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
    target, type, project, scope, finding_titles, vector_endpoints, notes_text,
    content='',
    tokenize='porter unicode61'
);

CREATE TABLE IF NOT EXISTS scan_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    scan_dir      TEXT,                       -- OUTPUT_DIR of this specific scan run
    scan_type     TEXT DEFAULT 'delta',       -- full | delta | nuclei | recon
    started_at    TEXT,
    completed_at  TEXT,
    new_findings  INTEGER DEFAULT 0,
    status        TEXT DEFAULT 'running'      -- running | completed | failed
);
"""


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# ── Markdown parsers ──────────────────────────────────────────────────────────

def _table_rows(text, header_pattern):
    """Extract rows from a markdown table following a ## header matching pattern."""
    m = re.search(rf'##\s+{re.escape(header_pattern)}\s*\n(.*?)(?=\n##\s|\Z)',
                  text, re.DOTALL | re.IGNORECASE)
    if not m:
        return []
    block = m.group(1)
    rows = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith('|') or re.match(r'\|[-| ]+\|', line):
            continue
        cells = [c.strip() for c in line.strip('|').split('|')]
        if any(c and c != '—' and 'populated after' not in c for c in cells):
            rows.append(cells)
    return rows[1:]  # skip header row


def _kv_section(text, header):
    """Extract key: value pairs from a ## section."""
    m = re.search(rf'##\s+{re.escape(header)}\s*\n(.*?)(?=\n##\s|\Z)',
                  text, re.DOTALL | re.IGNORECASE)
    if not m:
        return {}
    kv = {}
    for line in m.group(1).splitlines():
        mv = re.match(r'\*\*(.+?)\*\*[:\s]+(.+)', line.strip())
        if mv:
            kv[mv.group(1).lower()] = mv.group(2).strip()
    return kv


def _list_items(text, header):
    """Extract numbered/bullet list items from a ## section."""
    m = re.search(rf'##\s+{re.escape(header)}\s*\n(.*?)(?=\n##\s|\Z)',
                  text, re.DOTALL | re.IGNORECASE)
    if not m:
        return []
    items = []
    for line in m.group(1).splitlines():
        mv = re.match(r'[\d]+\.\s+(.+)', line.strip())
        if mv and 'none yet' not in mv.group(1):
            items.append(mv.group(1).strip())
        mb = re.match(r'[-*]\s+\[[ x]\]\s+(.+)', line.strip())
        if mb:
            done = '[x]' in line
            items.append((mb.group(1).strip(), done))
    return items


def parse_attack_chain(output_dir):
    """Parse attack-chain.md and return a structured dict."""
    chain_path = Path(output_dir) / "attack-chain.md"
    if not chain_path.exists():
        return None
    text = chain_path.read_text(encoding="utf-8", errors="replace")

    # Phase progress
    phases = []
    for row in _table_rows(text, "Phase Progress"):
        if len(row) >= 4:
            phases.append({
                "phase": row[0], "status": row[1],
                "agents": row[2], "findings": row[3]
            })

    # Discovered services
    services = []
    for row in _table_rows(text, "Discovered Services"):
        if len(row) >= 4:
            services.append({
                "port": row[0], "service": row[1],
                "version": row[2], "notes": row[3]
            })

    # Tech stack
    tech = _kv_section(text, "Tech Stack")

    # Findings summary
    findings = []
    for row in _table_rows(text, "Findings Summary"):
        if len(row) >= 4:
            findings.append({
                "finding_id": row[0], "title": row[1],
                "severity": row[2], "status": row[3]
            })

    # Tested vectors
    vectors = []
    for row in _table_rows(text, "Tested Vectors"):
        if len(row) >= 4:
            vectors.append({
                "vector": row[0], "endpoint": row[1],
                "result": row[2], "notes": row[3]
            })

    # Active hypotheses
    hypotheses = []
    for item in _list_items(text, "Active Hypotheses"):
        if isinstance(item, str):
            hypotheses.append(item)

    # Next steps
    next_steps = []
    for item in _list_items(text, "Next Steps"):
        if isinstance(item, tuple):
            next_steps.append(item)

    return {
        "phases": phases, "services": services, "tech": tech,
        "findings": findings, "vectors": vectors,
        "hypotheses": hypotheses, "next_steps": next_steps,
    }


def scan_findings_dir(output_dir):
    """Scan OUTPUT_DIR/findings/ for description.md files and extract metadata."""
    findings_dir = Path(output_dir) / "findings"
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
            m = re.search(rf'\|\s*{re.escape(key)}\s*\|\s*(.+?)\s*\|', text, re.IGNORECASE)
            return m.group(1).strip() if m else ""

        severity   = tf("Severity")
        cvss_raw   = tf("CVSS Score")
        affected   = tf("Affected Component") or tf("Affected URL") or tf("Affected")
        cvss_score = None
        cm = re.search(r'\b(\d+\.\d+)\b', cvss_raw)
        if cm:
            cvss_score = float(cm.group(1))

        # Check validated status
        validated_dir = Path(output_dir) / "artifacts" / "validated" / f"{d.name}.json"
        fp_dir        = Path(output_dir) / "artifacts" / "false-positives" / f"{d.name}-rejected.json"
        if validated_dir.exists():
            status = "validated"
        elif fp_dir.exists():
            status = "false-positive"
        else:
            status = "pending"

        results.append({
            "finding_id": d.name, "title": title, "severity": severity,
            "status": status, "cvss_score": cvss_score, "affected": affected
        })
    return results


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_save(output_dir):
    output_dir = str(Path(output_dir).resolve())
    conn = connect()

    # Load engagement.json
    meta = {}
    meta_path = Path(output_dir) / "engagement.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())

    now = datetime.now(timezone.utc).isoformat()

    # Upsert engagement row
    conn.execute("""
        INSERT INTO engagements (output_dir, target, type, project, mode, scope, started, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(output_dir) DO UPDATE SET
            target=excluded.target, type=excluded.type, project=excluded.project,
            mode=excluded.mode, scope=excluded.scope, last_updated=excluded.last_updated
    """, (output_dir, meta.get("target"), meta.get("type"), meta.get("project"),
          meta.get("mode"), str(meta.get("scope", "")), meta.get("started"), now))

    eng_id = conn.execute(
        "SELECT id FROM engagements WHERE output_dir=?", (output_dir,)
    ).fetchone()["id"]

    # Parse attack-chain.md
    chain = parse_attack_chain(output_dir)
    if chain:
        # Tech stack
        if chain["tech"]:
            conn.execute(
                "UPDATE engagements SET tech_stack=? WHERE id=?",
                (json.dumps(chain["tech"]), eng_id)
            )

        # Phases
        for p in chain["phases"]:
            conn.execute("""
                INSERT INTO phases (engagement_id, phase, status, agents, findings)
                VALUES (?,?,?,?,?)
                ON CONFLICT(engagement_id, phase) DO UPDATE SET
                    status=excluded.status, agents=excluded.agents, findings=excluded.findings
            """, (eng_id, p["phase"], p["status"], p["agents"], p["findings"]))

        # Services
        for s in chain["services"]:
            conn.execute("""
                INSERT OR IGNORE INTO services (engagement_id, port, service, version, notes)
                VALUES (?,?,?,?,?)
            """, (eng_id, s["port"], s["service"], s["version"], s["notes"]))

        # Vectors
        for v in chain["vectors"]:
            conn.execute("""
                INSERT INTO vectors (engagement_id, vector, endpoint, result, notes)
                VALUES (?,?,?,?,?)
                ON CONFLICT(engagement_id, vector, endpoint) DO UPDATE SET
                    result=excluded.result, notes=excluded.notes
            """, (eng_id, v["vector"], v["endpoint"], v["result"], v["notes"]))

        # Hypotheses
        for h in chain["hypotheses"]:
            conn.execute("""
                INSERT OR IGNORE INTO hypotheses (engagement_id, text) VALUES (?,?)
            """, (eng_id, h))

        # Next steps
        for item in chain["next_steps"]:
            if isinstance(item, tuple):
                step, done = item
                conn.execute("""
                    INSERT INTO next_steps (engagement_id, step, done) VALUES (?,?,?)
                    ON CONFLICT(engagement_id, step) DO UPDATE SET done=excluded.done
                """, (eng_id, step, int(done)))

    # Scan findings directory (ground truth over attack-chain summary)
    for f in scan_findings_dir(output_dir):
        conn.execute("""
            INSERT INTO findings
                (engagement_id, finding_id, title, severity, status, cvss_score, affected)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(engagement_id, finding_id) DO UPDATE SET
                title=excluded.title, severity=excluded.severity, status=excluded.status,
                cvss_score=excluded.cvss_score, affected=excluded.affected
        """, (eng_id, f["finding_id"], f["title"], f["severity"],
              f["status"], f["cvss_score"], f["affected"]))

    conn.commit()
    conn.close()
    print(f"[+] Saved engagement: {output_dir}")
    print(f"    Target: {meta.get('target','?')} | Type: {meta.get('type','?')} | Status: active")


def cmd_load(output_dir):
    output_dir = str(Path(output_dir).resolve())
    conn = connect()

    row = conn.execute(
        "SELECT * FROM engagements WHERE output_dir=?", (output_dir,)
    ).fetchone()
    if not row:
        print(f"[!] No saved memory for: {output_dir}", file=sys.stderr)
        print(f"    Run: python3 tools/session-memory.py save {output_dir}", file=sys.stderr)
        sys.exit(1)

    eng_id = row["id"]
    tech = json.loads(row["tech_stack"]) if row["tech_stack"] else {}

    phases     = conn.execute("SELECT * FROM phases     WHERE engagement_id=?", (eng_id,)).fetchall()
    services   = conn.execute("SELECT * FROM services   WHERE engagement_id=?", (eng_id,)).fetchall()
    findings   = conn.execute("SELECT * FROM findings   WHERE engagement_id=? ORDER BY severity DESC", (eng_id,)).fetchall()
    vectors    = conn.execute("SELECT * FROM vectors    WHERE engagement_id=?", (eng_id,)).fetchall()
    hypotheses = conn.execute("SELECT * FROM hypotheses WHERE engagement_id=? AND status='active'", (eng_id,)).fetchall()
    next_steps = conn.execute("SELECT * FROM next_steps WHERE engagement_id=? AND done=0", (eng_id,)).fetchall()
    notes_rows = conn.execute("SELECT * FROM notes      WHERE engagement_id=? ORDER BY id DESC LIMIT 10", (eng_id,)).fetchall()

    conn.close()

    sep = "═" * 68
    print(sep)
    print(f"  ENGAGEMENT RESUME BRIEFING")
    print(sep)
    print(f"  Target      : {row['target']}")
    print(f"  Type        : {row['type']}  |  Mode: {row['mode']}")
    print(f"  Project     : {row['project']}")
    print(f"  Scope       : {row['scope']}")
    print(f"  Started     : {row['started']}")
    print(f"  Last saved  : {row['last_updated']}")
    print(f"  Status      : {row['status']}")
    print(f"  OUTPUT_DIR  : {row['output_dir']}")
    print(sep)

    if tech:
        print("\n  TECH STACK")
        for k, v in tech.items():
            print(f"    {k:20s}: {v}")

    if services:
        print("\n  DISCOVERED SERVICES")
        for s in services:
            print(f"    {s['port']:8s} {s['service']:15s} {s['version']:20s} {s['notes'] or ''}")

    if phases:
        print("\n  PHASE PROGRESS")
        for p in phases:
            icon = "✓" if p["status"] == "completed" else ("→" if p["status"] == "in-progress" else " ")
            print(f"    {icon} {p['phase']:35s} [{p['status']}]")

    if findings:
        print("\n  FINDINGS")
        for f in findings:
            sev = f['severity'] or '?'
            score = f"CVSS {f['cvss_score']}" if f['cvss_score'] else ""
            print(f"    [{f['status']:13s}] {sev:8s} {score:10s} {f['title']}")
            if f['affected']:
                print(f"                          → {f['affected']}")

    if vectors:
        tested = [v for v in vectors if v['result'] not in ('pending', '—', '')]
        if tested:
            print(f"\n  TESTED VECTORS ({len(tested)} completed, {len(vectors)-len(tested)} pending)")
            for v in tested[:15]:
                result_icon = "✓" if "vuln" in (v['result'] or '').lower() else "✗"
                print(f"    {result_icon} {v['vector']:20s} {v['endpoint'][:35]:35s} [{v['result']}]")
            if len(tested) > 15:
                print(f"    ... and {len(tested)-15} more")

    if hypotheses:
        print("\n  ACTIVE HYPOTHESES")
        for h in hypotheses:
            print(f"    • {h['text']}")

    if next_steps:
        print("\n  OPEN NEXT STEPS")
        for n in next_steps:
            print(f"    [ ] {n['step']}")

    if notes_rows:
        print("\n  RECENT NOTES")
        for n in notes_rows:
            print(f"    [{n['created_at'][:16]}] {n['note']}")

    print(f"\n{sep}")
    print(f"  export OUTPUT_DIR='{output_dir}'")
    print(sep)


def cmd_list(args):
    filter_type   = None
    filter_status = None
    i = 0
    while i < len(args):
        if args[i] == "--type"   and i+1 < len(args): filter_type   = args[i+1]; i += 2
        elif args[i] == "--status" and i+1 < len(args): filter_status = args[i+1]; i += 2
        else: i += 1

    conn = connect()
    q    = "SELECT * FROM engagements WHERE 1=1"
    params = []
    if filter_type:
        q += " AND type=?"; params.append(filter_type)
    if filter_status:
        q += " AND status=?"; params.append(filter_status)
    q += " ORDER BY last_updated DESC"

    rows = conn.execute(q, params).fetchall()
    conn.close()

    if not rows:
        print("No engagements found.")
        return

    sep = "─" * 80
    print(f"\n{'Target':30s} {'Type':10s} {'Status':12s} {'Last Updated':20s} {'Project'}")
    print(sep)
    for r in rows:
        updated = (r["last_updated"] or "")[:16]
        print(f"{(r['target'] or '?')[:30]:30s} {(r['type'] or '?'):10s} "
              f"{(r['status'] or '?'):12s} {updated:20s} {r['project'] or ''}")
    print(sep)
    print(f"  Total: {len(rows)} engagement(s)")


def cmd_search(query):
    conn = connect()
    # Simple LIKE search across key text columns
    like = f"%{query}%"
    rows = conn.execute("""
        SELECT DISTINCT e.output_dir, e.target, e.type, e.project, e.last_updated
        FROM engagements e
        LEFT JOIN findings    f ON f.engagement_id = e.id
        LEFT JOIN vectors     v ON v.engagement_id = e.id
        LEFT JOIN notes       n ON n.engagement_id = e.id
        LEFT JOIN hypotheses  h ON h.engagement_id = e.id
        WHERE e.target LIKE ? OR e.scope LIKE ?
           OR f.title  LIKE ? OR f.affected LIKE ?
           OR v.vector LIKE ? OR v.endpoint LIKE ?
           OR n.note   LIKE ? OR h.text     LIKE ?
        ORDER BY e.last_updated DESC
    """, (like,)*8).fetchall()
    conn.close()

    if not rows:
        print(f"No results for: {query}")
        return
    print(f"\n  Search results for '{query}':")
    for r in rows:
        print(f"    {(r['target'] or '?'):30s} [{r['type']}] — {r['output_dir']}")


def cmd_note(output_dir, text):
    output_dir = str(Path(output_dir).resolve())
    conn = connect()
    row = conn.execute(
        "SELECT id FROM engagements WHERE output_dir=?", (output_dir,)
    ).fetchone()
    if not row:
        print(f"[!] Engagement not found: {output_dir}\n    Run save first.", file=sys.stderr)
        sys.exit(1)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO notes (engagement_id, note, created_at) VALUES (?,?,?)",
        (row["id"], text, now)
    )
    conn.commit()
    conn.close()
    print(f"[+] Note saved.")


def cmd_status(output_dir, new_status):
    valid = ("active", "monitored", "completed", "abandoned")
    if new_status not in valid:
        print(f"[!] Status must be one of: {', '.join(valid)}", file=sys.stderr)
        sys.exit(1)
    output_dir = str(Path(output_dir).resolve())
    conn = connect()
    conn.execute(
        "UPDATE engagements SET status=? WHERE output_dir=?", (new_status, output_dir)
    )
    if conn.total_changes == 0:
        print(f"[!] Engagement not found: {output_dir}", file=sys.stderr)
        sys.exit(1)
    conn.commit()
    conn.close()
    print(f"[+] Status updated to: {new_status}")


def cmd_targets(args):
    """List monitored/active engagements ready for a rescan."""
    overdue_hours = 24
    i = 0
    while i < len(args):
        if args[i] == "--overdue-hours" and i + 1 < len(args):
            overdue_hours = int(args[i + 1]); i += 2
        else:
            i += 1

    conn = connect()
    rows = conn.execute(
        "SELECT e.*, MAX(s.completed_at) AS last_scan "
        "FROM engagements e "
        "LEFT JOIN scan_history s ON s.engagement_id = e.id AND s.status='completed' "
        "WHERE e.status IN ('active','monitored') "
        "GROUP BY e.id ORDER BY last_scan ASC NULLS FIRST"
    ).fetchall()
    conn.close()

    if not rows:
        print("No active or monitored engagements found.")
        return

    from datetime import timezone as _tz
    now = datetime.now(_tz.utc)
    sep = "─" * 90
    print(f"\n{'Target':30s} {'Type':8s} {'Status':10s} {'Last Scan':20s} {'Overdue':8s} {'OUTPUT_DIR'}")
    print(sep)
    for r in rows:
        last = r["last_scan"]
        if last:
            from datetime import datetime as _dt
            try:
                last_dt = _dt.fromisoformat(last.replace("Z", "+00:00"))
                hours_ago = (now - last_dt).total_seconds() / 3600
                overdue = "YES" if hours_ago >= overdue_hours else f"{hours_ago:.0f}h ago"
                last_str = last[:16]
            except Exception:
                overdue = "YES"; last_str = last[:16]
        else:
            overdue = "NEVER"; last_str = "never"
        print(f"{(r['target'] or '?')[:30]:30s} {(r['type'] or '?'):8s} "
              f"{(r['status'] or '?'):10s} {last_str:20s} {overdue:8s} {r['output_dir']}")
    print(sep)
    print(f"  {len(rows)} target(s) | overdue threshold: {overdue_hours}h")


def cmd_record_scan(output_dir, extra_args):
    """Record a completed scan run in scan_history."""
    scan_type   = "delta"
    new_findings = 0
    status       = "completed"
    i = 0
    while i < len(extra_args):
        if extra_args[i] == "--type"     and i+1 < len(extra_args): scan_type    = extra_args[i+1]; i += 2
        elif extra_args[i] == "--findings" and i+1 < len(extra_args): new_findings = int(extra_args[i+1]); i += 2
        elif extra_args[i] == "--status"   and i+1 < len(extra_args): status       = extra_args[i+1]; i += 2
        else: i += 1

    output_dir = str(Path(output_dir).resolve())
    conn = connect()
    row = conn.execute(
        "SELECT id FROM engagements WHERE output_dir=?", (output_dir,)
    ).fetchone()
    if not row:
        # Try to find by project+target (scan_dir might differ from base)
        print(f"[!] Engagement not found for: {output_dir}", file=sys.stderr)
        print(f"    Run: python3 tools/session-memory.py save {output_dir}", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO scan_history (engagement_id, scan_dir, scan_type, started_at, completed_at, new_findings, status) "
        "VALUES (?,?,?,?,?,?,?)",
        (row["id"], output_dir, scan_type, now, now, new_findings, status)
    )
    # Also update engagement status to 'monitored' if it was 'active' and this is a delta scan
    if scan_type == "delta":
        conn.execute(
            "UPDATE engagements SET status='monitored', last_updated=? "
            "WHERE id=? AND status='active'",
            (now, row["id"])
        )
    conn.commit()
    conn.close()
    print(f"[+] Scan recorded: {scan_type} | findings: {new_findings} | status: {status}")


def cmd_scan_history(output_dir):
    """Show scan run history for an engagement."""
    output_dir = str(Path(output_dir).resolve())
    conn = connect()
    row = conn.execute(
        "SELECT id, target, type FROM engagements WHERE output_dir=?", (output_dir,)
    ).fetchone()
    if not row:
        print(f"[!] Engagement not found: {output_dir}", file=sys.stderr)
        sys.exit(1)

    scans = conn.execute(
        "SELECT * FROM scan_history WHERE engagement_id=? ORDER BY id DESC LIMIT 20",
        (row["id"],)
    ).fetchall()
    conn.close()

    sep = "─" * 72
    print(f"\n  Scan history: {row['target']} [{row['type']}]")
    print(sep)
    if not scans:
        print("  No scan runs recorded yet.")
    else:
        print(f"  {'#':4s} {'Type':8s} {'Status':12s} {'New Findings':13s} {'Completed':20s}")
        print(sep)
        for i, s in enumerate(scans, 1):
            completed = (s["completed_at"] or "")[:16]
            print(f"  {i:<4d} {(s['scan_type'] or '?'):8s} {(s['status'] or '?'):12s} "
                  f"{s['new_findings']:<13d} {completed}")
    print(sep)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    cmd = args[0]

    if cmd == "save" and len(args) >= 2:
        cmd_save(args[1])
    elif cmd == "load" and len(args) >= 2:
        cmd_load(args[1])
    elif cmd == "list":
        cmd_list(args[1:])
    elif cmd == "search" and len(args) >= 2:
        cmd_search(" ".join(args[1:]))
    elif cmd == "note" and len(args) >= 3:
        cmd_note(args[1], " ".join(args[2:]))
    elif cmd == "status" and len(args) >= 3:
        cmd_status(args[1], args[2])
    elif cmd == "targets":
        cmd_targets(args[1:])
    elif cmd == "record-scan" and len(args) >= 2:
        cmd_record_scan(args[1], args[2:])
    elif cmd == "scan-history" and len(args) >= 2:
        cmd_scan_history(args[1])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
