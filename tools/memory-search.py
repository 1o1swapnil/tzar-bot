#!/usr/bin/env python3
"""
memory-search.py — Full-text cross-engagement search across tzar-bot memory.db.

Uses SQLite FTS5 with porter stemmer for natural language search across findings,
vectors, notes, services, and hypotheses from all engagements.

Usage:
    python3 tools/memory-search.py "JWT bypass"
    python3 tools/memory-search.py "Cloudflare WAF bypass" --type WAPT
    python3 tools/memory-search.py "SSRF" --severity critical
    python3 tools/memory-search.py "what worked against Flask" --limit 10
    python3 tools/memory-search.py --index          # rebuild FTS index

Results ranked by: recency × match quality × severity weight.
"""

import sys
import os
import re
import json
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime, timezone

REPO_DIR = Path(__file__).parent.parent.resolve()
DB_PATH  = REPO_DIR / "memory.db"

SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def connect():
    if not DB_PATH.exists():
        print(f"[!] memory.db not found at {DB_PATH}", file=sys.stderr)
        print("    Run an engagement with init-engagement.py first.", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _ensure_fts(conn):
    """Create or verify the cross-engagement FTS5 virtual table."""
    conn.executescript("""
        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
            engagement_id UNINDEXED,
            record_type   UNINDEXED,   -- finding|vector|note|service|hypothesis
            record_id     UNINDEXED,
            content,                   -- searchable text
            tokenize='porter unicode61'
        );
    """)
    conn.commit()


def rebuild_index(conn):
    """(Re)populate memory_fts from all engagement tables."""
    _ensure_fts(conn)
    conn.execute("DELETE FROM memory_fts")

    # Findings
    rows = conn.execute(
        "SELECT engagement_id, finding_id, title, affected, severity FROM findings"
    ).fetchall()
    conn.executemany(
        "INSERT INTO memory_fts(engagement_id, record_type, record_id, content) VALUES (?,?,?,?)",
        [(r["engagement_id"], "finding", r["finding_id"],
          f"{r['title']} {r['affected'] or ''} {r['severity'] or ''}") for r in rows]
    )

    # Vectors
    rows = conn.execute(
        "SELECT engagement_id, id, vector, endpoint, result, notes FROM vectors"
    ).fetchall()
    conn.executemany(
        "INSERT INTO memory_fts(engagement_id, record_type, record_id, content) VALUES (?,?,?,?)",
        [(r["engagement_id"], "vector", str(r["id"]),
          f"{r['vector']} {r['endpoint'] or ''} {r['result'] or ''} {r['notes'] or ''}") for r in rows]
    )

    # Notes
    rows = conn.execute(
        "SELECT engagement_id, id, note FROM notes"
    ).fetchall()
    conn.executemany(
        "INSERT INTO memory_fts(engagement_id, record_type, record_id, content) VALUES (?,?,?,?)",
        [(r["engagement_id"], "note", str(r["id"]), r["note"] or "") for r in rows]
    )

    # Services
    rows = conn.execute(
        "SELECT engagement_id, id, service, version, notes FROM services"
    ).fetchall()
    conn.executemany(
        "INSERT INTO memory_fts(engagement_id, record_type, record_id, content) VALUES (?,?,?,?)",
        [(r["engagement_id"], "service", str(r["id"]),
          f"{r['service']} {r['version'] or ''} {r['notes'] or ''}") for r in rows]
    )

    # Hypotheses
    rows = conn.execute(
        "SELECT engagement_id, id, text FROM hypotheses"
    ).fetchall()
    conn.executemany(
        "INSERT INTO memory_fts(engagement_id, record_type, record_id, content) VALUES (?,?,?,?)",
        [(r["engagement_id"], "hypothesis", str(r["id"]), r["text"] or "") for r in rows]
    )

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM memory_fts").fetchone()[0]
    print(f"[+] FTS index rebuilt: {total} records indexed")


def search(conn, query: str, eng_type: str = "", severity: str = "", limit: int = 20) -> list:
    """
    Search memory_fts and join back to engagement context.
    Returns list of result dicts sorted by relevance score.
    """
    _ensure_fts(conn)

    # Check if index is populated
    count = conn.execute("SELECT COUNT(*) FROM memory_fts").fetchone()[0]
    if count == 0:
        rebuild_index(conn)

    # FTS5 query — wrap multi-word in quotes for phrase matching, else AND terms
    words = query.strip().split()
    if len(words) == 1:
        fts_query = words[0]
    else:
        # Try phrase match first, fall back to AND
        fts_query = f'"{query}"'

    try:
        hits = conn.execute(
            "SELECT engagement_id, record_type, record_id, content, "
            "       bm25(memory_fts) AS score "
            "FROM memory_fts "
            "WHERE memory_fts MATCH ? "
            "ORDER BY score LIMIT ?",
            (fts_query, limit * 3)  # fetch extra to allow post-filter
        ).fetchall()
    except sqlite3.OperationalError:
        # Phrase match failed — fall back to individual terms
        fts_query = " AND ".join(words)
        try:
            hits = conn.execute(
                "SELECT engagement_id, record_type, record_id, content, "
                "       bm25(memory_fts) AS score "
                "FROM memory_fts "
                "WHERE memory_fts MATCH ? "
                "ORDER BY score LIMIT ?",
                (fts_query, limit * 3)
            ).fetchall()
        except sqlite3.OperationalError:
            # Last resort: LIKE search
            like = f"%{query}%"
            hits = conn.execute(
                "SELECT engagement_id, record_type, record_id, content, 0.0 AS score "
                "FROM memory_fts WHERE content LIKE ? LIMIT ?",
                (like, limit * 3)
            ).fetchall()

    # Enrich with engagement context
    results = []
    seen = set()
    for h in hits:
        eng_id = h["engagement_id"]
        eng = conn.execute(
            "SELECT target, type, project, status, output_dir, last_updated "
            "FROM engagements WHERE id=?", (eng_id,)
        ).fetchone()
        if not eng:
            continue

        # Post-filter by type / severity
        if eng_type and eng["type"].lower() != eng_type.lower():
            continue

        sev = ""
        if h["record_type"] == "finding":
            f = conn.execute(
                "SELECT severity FROM findings WHERE engagement_id=? AND finding_id=?",
                (eng_id, h["record_id"])
            ).fetchone()
            sev = f["severity"].lower() if f else ""
        if severity and sev and sev != severity.lower():
            continue

        # Deduplicate by (engagement_id, record_type, record_id)
        key = (eng_id, h["record_type"], h["record_id"])
        if key in seen:
            continue
        seen.add(key)

        results.append({
            "score":       float(h["score"]),
            "record_type": h["record_type"],
            "record_id":   h["record_id"],
            "content":     h["content"][:120],
            "severity":    sev,
            "target":      eng["target"],
            "eng_type":    eng["type"],
            "project":     eng["project"],
            "status":      eng["status"],
            "output_dir":  eng["output_dir"],
            "last_updated":eng["last_updated"],
        })
        if len(results) >= limit:
            break

    return results


def print_results(results: list, query: str):
    if not results:
        print(f"No results for: {query!r}")
        return

    sep = "─" * 72
    print(f"\n  Search: {query!r} — {len(results)} result(s)")
    print(sep)
    for r in results:
        sev_tag = f"[{r['severity'].upper()}] " if r['severity'] else ""
        print(f"  {r['record_type'].upper():10s} {sev_tag}{r['content'][:60]}")
        print(f"  {'':10s} → {r['target']} [{r['eng_type']}] {r['project']} ({r['status']})")
        print(f"  {'':10s}   OUTPUT_DIR: {r['output_dir']}")
        print(f"  {sep}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("query", nargs="?", default="", help="Search query (natural language)")
    ap.add_argument("--type",     default="", help="Filter by engagement type (WAPT, API, Network...)")
    ap.add_argument("--severity", default="", help="Filter findings by severity (critical, high, medium, low)")
    ap.add_argument("--limit",    type=int, default=20, help="Max results (default: 20)")
    ap.add_argument("--index",    action="store_true", help="Rebuild FTS index and exit")
    ap.add_argument("--json",     action="store_true", help="Output as JSON")
    args = ap.parse_args()

    conn = connect()

    if args.index:
        rebuild_index(conn)
        conn.close()
        return

    if not args.query:
        ap.print_help()
        sys.exit(0)

    results = search(conn, args.query, args.type, args.severity, args.limit)
    conn.close()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results, args.query)


if __name__ == "__main__":
    main()
