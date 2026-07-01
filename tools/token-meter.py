#!/usr/bin/env python3
"""
token-meter.py — token accounting & cost telemetry for tzar-bot engagements.

The tzar-bot architecture is fan-out (1 coordinator → N executors → M validators),
so token spend multiplies fast and is otherwise invisible. This tool records actual
per-agent token usage into memory.db, estimates token cost of content before you load
it, and reports a per-role / per-phase / per-model breakdown with USD cost and an
optional budget guard.

DB location: REPO_DIR/memory.db  (shared with session-memory.py; tables are additive)

Commands:
    record  <output_dir> [flags]    Record one token-usage event for an agent batch
    ingest  <output_dir> [--keep]   Record every usage.json an engagement produced (semi-auto)
    report  <output_dir>            Per-role/phase/agent/model breakdown + totals + cost
    budget  <output_dir> [--set N]  Show, or set, a token/USD budget for the engagement
    estimate <file|->               Approximate tokens + cost for a file or stdin (pre-flight)
    list                            Token + cost totals across ALL engagements
    pricing                         Print the model pricing table

Semi-auto capture: an executor drops a usage.json (its API usage object plus
optional role/agent/phase/model) anywhere under OUTPUT_DIR; the coordinator then
runs `ingest` once to record them all. Ingested files are renamed *.recorded so a
re-run never double-counts.

record flags:
    --role  coordinator|executor|validator|other   (default: executor)
    --agent NAME            Free-text agent label (e.g. "recon-1", "sqli-validator")
    --phase NAME            Phase/group label (e.g. "recon", "hunt", "report")
    --model MODEL_ID        Model used (default: claude-opus-4-8). Aliases accepted.
    --in    N               Input (prompt) tokens                       [required]
    --out   N               Output (completion) tokens                  [required]
    --cache-read  N         Cache-read input tokens   (billed ~0.1x input)
    --cache-write N         Cache-write input tokens  (billed 1.25x / 2x input)
    --cache-ttl   5m|1h     TTL for cache-write pricing (default: 5m)
    --label TEXT            Optional note for this event

budget flags:
    --set-tokens N          Set a token ceiling for this engagement
    --set-usd     N         Set a USD ceiling for this engagement

Token figures come straight from the API `usage` object
(input_tokens / output_tokens / cache_read_input_tokens / cache_creation_input_tokens).
The `estimate` command is a heuristic pre-flight gauge only — the authoritative count is
the API's count_tokens endpoint; never trust tiktoken for Claude.
"""

import os
import sys
import json
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

REPO_DIR = Path(__file__).parent.parent.resolve()
# Default to the shared engagement DB; override with TZAR_MEMORY_DB (used by tests).
DB_PATH  = Path(os.environ.get("TZAR_MEMORY_DB") or (REPO_DIR / "memory.db"))


# ── Pricing (USD per 1,000,000 tokens) ────────────────────────────────────────
# Source: claude-api skill model catalogue (cached 2026-05-26).
# Cache reads ≈ 0.1x input; cache writes = 1.25x input (5m TTL) or 2x input (1h TTL).
# Opus tiers carry a 1M context window at standard pricing — no long-context premium.

_FAMILY_RATES = {
    "opus":   {"in": 5.0, "out": 25.0},
    "sonnet": {"in": 3.0, "out": 15.0},
    "haiku":  {"in": 1.0, "out":  5.0},
}


def _family(model: str) -> str:
    """Map a model id/alias to its pricing family."""
    m = (model or "").lower()
    if "opus" in m:
        return "opus"
    if "sonnet" in m:
        return "sonnet"
    if "haiku" in m:
        return "haiku"
    # Unknown → price as opus (most expensive) so estimates never under-report.
    return "opus"


def rates_for(model: str) -> dict:
    """Full per-MTok rate card for a model, including derived cache rates."""
    base = _FAMILY_RATES[_family(model)]
    return {
        "in":        base["in"],
        "out":       base["out"],
        "cache_read":   round(base["in"] * 0.1, 4),
        "cache_write_5m": round(base["in"] * 1.25, 4),
        "cache_write_1h": round(base["in"] * 2.0, 4),
    }


def cost_usd(model, in_tok=0, out_tok=0, cache_read=0, cache_write=0, cache_ttl="5m") -> float:
    """Compute USD cost for a single usage event."""
    r = rates_for(model)
    cw_rate = r["cache_write_1h"] if cache_ttl == "1h" else r["cache_write_5m"]
    total = (
        (in_tok     or 0) * r["in"] +
        (out_tok    or 0) * r["out"] +
        (cache_read or 0) * r["cache_read"] +
        (cache_write or 0) * cw_rate
    )
    return round(total / 1_000_000, 6)


# ── DB ────────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS token_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    output_dir      TEXT NOT NULL,
    engagement_id   INTEGER,
    ts              TEXT,
    role            TEXT,
    agent           TEXT,
    phase           TEXT,
    model           TEXT,
    input_tokens        INTEGER DEFAULT 0,
    output_tokens       INTEGER DEFAULT 0,
    cache_read_tokens   INTEGER DEFAULT 0,
    cache_write_tokens  INTEGER DEFAULT 0,
    cache_ttl       TEXT DEFAULT '5m',
    cost_usd        REAL DEFAULT 0,
    label           TEXT
);
CREATE INDEX IF NOT EXISTS idx_token_events_dir ON token_events(output_dir);

CREATE TABLE IF NOT EXISTS token_budgets (
    output_dir      TEXT PRIMARY KEY,
    budget_tokens   INTEGER,
    budget_usd      REAL,
    set_at          TEXT
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


def _lookup_engagement_id(conn, output_dir):
    """Best-effort link to an existing engagements row (session-memory.py owns it)."""
    try:
        row = conn.execute(
            "SELECT id FROM engagements WHERE output_dir=?", (output_dir,)
        ).fetchone()
        return row["id"] if row else None
    except sqlite3.OperationalError:
        return None  # engagements table not created yet


def _now():
    return datetime.now(timezone.utc).isoformat()


def _fmt_tok(n):
    n = n or 0
    if n >= 1_000_000:
        return f"{n/1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}k"
    return str(n)


# ── Heuristic estimator ───────────────────────────────────────────────────────

def estimate_tokens(text: str) -> int:
    """
    Approximate Claude token count WITHOUT an API call.
    Blends a chars/4 estimate with a words*1.33 estimate and takes the larger
    (conservative). Real counts: client.messages.count_tokens(). Never tiktoken.
    """
    chars = len(text)
    words = len(text.split())
    by_chars = chars / 4.0
    by_words = words * 1.33
    return int(round(max(by_chars, by_words)))


# ── Commands ──────────────────────────────────────────────────────────────────

def _insert_event(conn, output_dir, *, role="executor", agent=None, phase=None,
                  model="claude-opus-4-8", input_tokens=0, output_tokens=0,
                  cache_read=0, cache_write=0, cache_ttl="5m", label=None):
    """Insert one usage event and return its USD cost. Shared by record + ingest."""
    cost = cost_usd(model, input_tokens, output_tokens, cache_read, cache_write, cache_ttl)
    eng_id = _lookup_engagement_id(conn, output_dir)
    conn.execute(
        """INSERT INTO token_events
           (output_dir, engagement_id, ts, role, agent, phase, model,
            input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
            cache_ttl, cost_usd, label)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (output_dir, eng_id, _now(), role, agent, phase, model,
         input_tokens, output_tokens, cache_read, cache_write, cache_ttl, cost, label),
    )
    return cost


def _normalize_usage(obj):
    """
    Accept either tzar fields or a raw API usage object (possibly nested under
    'usage'), returning the kwargs _insert_event expects.
    """
    u = obj.get("usage", obj) if isinstance(obj, dict) else {}
    def pick(*keys, default=0):
        for src in (obj, u):
            for k in keys:
                if isinstance(src, dict) and src.get(k) is not None:
                    return src[k]
        return default
    return dict(
        role=obj.get("role", "executor"),
        agent=obj.get("agent"),
        phase=obj.get("phase"),
        model=obj.get("model", "claude-opus-4-8"),
        input_tokens=int(pick("input_tokens") or 0),
        output_tokens=int(pick("output_tokens") or 0),
        cache_read=int(pick("cache_read", "cache_read_input_tokens") or 0),
        cache_write=int(pick("cache_write", "cache_creation_input_tokens") or 0),
        cache_ttl=obj.get("cache_ttl", "5m"),
        label=obj.get("label"),
    )


def cmd_record(a):
    output_dir = str(Path(a.output_dir).resolve())
    conn = connect()
    cost = _insert_event(conn, output_dir, role=a.role, agent=a.agent, phase=a.phase,
                         model=a.model, input_tokens=a.in_tokens, output_tokens=a.out_tokens,
                         cache_read=a.cache_read, cache_write=a.cache_write,
                         cache_ttl=a.cache_ttl, label=a.label)
    conn.commit()

    total_tok = a.in_tokens + a.out_tokens + a.cache_read + a.cache_write
    print(f"[+] Recorded {a.role} event"
          + (f" ({a.agent})" if a.agent else "")
          + (f" [{a.phase}]" if a.phase else ""))
    print(f"    model {a.model} | in {_fmt_tok(a.in_tokens)} out {_fmt_tok(a.out_tokens)}"
          f" cache-r {_fmt_tok(a.cache_read)} cache-w {_fmt_tok(a.cache_write)}"
          f" | total {_fmt_tok(total_tok)} | ${cost:.4f}")

    _budget_warn(conn, output_dir)
    conn.close()


def _engagement_totals(conn, output_dir):
    row = conn.execute(
        """SELECT
             COALESCE(SUM(input_tokens),0)       AS in_tok,
             COALESCE(SUM(output_tokens),0)      AS out_tok,
             COALESCE(SUM(cache_read_tokens),0)  AS cr_tok,
             COALESCE(SUM(cache_write_tokens),0) AS cw_tok,
             COALESCE(SUM(cost_usd),0)           AS usd,
             COUNT(*)                            AS events
           FROM token_events WHERE output_dir=?""",
        (output_dir,),
    ).fetchone()
    total = row["in_tok"] + row["out_tok"] + row["cr_tok"] + row["cw_tok"]
    return row, total


def _budget_warn(conn, output_dir):
    b = conn.execute("SELECT * FROM token_budgets WHERE output_dir=?", (output_dir,)).fetchone()
    if not b:
        return
    row, total = _engagement_totals(conn, output_dir)
    if b["budget_tokens"]:
        pct = 100 * total / b["budget_tokens"] if b["budget_tokens"] else 0
        if pct >= 80:
            flag = "OVER" if pct >= 100 else "WARN"
            print(f"    [{flag}] tokens {_fmt_tok(total)} / {_fmt_tok(b['budget_tokens'])}"
                  f" ({pct:.0f}% of budget)")
    if b["budget_usd"]:
        pct = 100 * row["usd"] / b["budget_usd"] if b["budget_usd"] else 0
        if pct >= 80:
            flag = "OVER" if pct >= 100 else "WARN"
            print(f"    [{flag}] cost ${row['usd']:.2f} / ${b['budget_usd']:.2f}"
                  f" ({pct:.0f}% of budget)")


def _group_table(conn, output_dir, column, title):
    rows = conn.execute(
        f"""SELECT COALESCE({column},'(none)') AS k,
                   SUM(input_tokens+output_tokens+cache_read_tokens+cache_write_tokens) AS tok,
                   SUM(cost_usd) AS usd, COUNT(*) AS n
            FROM token_events WHERE output_dir=?
            GROUP BY k ORDER BY tok DESC""",
        (output_dir,),
    ).fetchall()
    if not rows:
        return
    print(f"\n  BY {title}")
    print(f"    {'name':22s} {'events':>7s} {'tokens':>10s} {'cost':>11s}")
    print(f"    {'-'*22} {'-'*7} {'-'*10} {'-'*11}")
    for r in rows:
        print(f"    {str(r['k'])[:22]:22s} {r['n']:>7d} {_fmt_tok(r['tok']):>10s} ${r['usd']:>9.4f}")


def cmd_report(a):
    output_dir = str(Path(a.output_dir).resolve())
    conn = connect()
    row, total = _engagement_totals(conn, output_dir)
    if row["events"] == 0:
        print(f"[!] No token events recorded for: {output_dir}", file=sys.stderr)
        print("    Record with: python3 tools/token-meter.py record \"$OUTPUT_DIR\" "
              "--role executor --in N --out N", file=sys.stderr)
        conn.close()
        sys.exit(1)

    sep = "═" * 66
    print(sep)
    print("  TOKEN UTILIZATION REPORT")
    print(sep)
    print(f"  OUTPUT_DIR : {output_dir}")
    print(f"  Events     : {row['events']}")
    print(f"  Input      : {_fmt_tok(row['in_tok']):>10s}")
    print(f"  Output     : {_fmt_tok(row['out_tok']):>10s}")
    print(f"  Cache read : {_fmt_tok(row['cr_tok']):>10s}")
    print(f"  Cache write: {_fmt_tok(row['cw_tok']):>10s}")
    print(f"  TOTAL      : {_fmt_tok(total):>10s} tokens")
    print(f"  COST       : ${row['usd']:.4f}")

    _group_table(conn, output_dir, "role",  "ROLE")
    _group_table(conn, output_dir, "phase", "PHASE")
    _group_table(conn, output_dir, "agent", "AGENT")
    _group_table(conn, output_dir, "model", "MODEL")

    b = conn.execute("SELECT * FROM token_budgets WHERE output_dir=?", (output_dir,)).fetchone()
    if b:
        print("\n  BUDGET")
        if b["budget_tokens"]:
            pct = 100 * total / b["budget_tokens"]
            print(f"    tokens {_fmt_tok(total)} / {_fmt_tok(b['budget_tokens'])} ({pct:.0f}%)")
        if b["budget_usd"]:
            pct = 100 * row["usd"] / b["budget_usd"]
            print(f"    cost   ${row['usd']:.2f} / ${b['budget_usd']:.2f} ({pct:.0f}%)")

    print(f"\n{sep}")
    conn.close()


def cmd_budget(a):
    output_dir = str(Path(a.output_dir).resolve())
    conn = connect()
    if a.set_tokens is not None or a.set_usd is not None:
        existing = conn.execute(
            "SELECT * FROM token_budgets WHERE output_dir=?", (output_dir,)).fetchone()
        bt = a.set_tokens if a.set_tokens is not None else (existing["budget_tokens"] if existing else None)
        bu = a.set_usd    if a.set_usd    is not None else (existing["budget_usd"]    if existing else None)
        conn.execute(
            """INSERT INTO token_budgets (output_dir, budget_tokens, budget_usd, set_at)
               VALUES (?,?,?,?)
               ON CONFLICT(output_dir) DO UPDATE SET
                 budget_tokens=excluded.budget_tokens,
                 budget_usd=excluded.budget_usd,
                 set_at=excluded.set_at""",
            (output_dir, bt, bu, _now()),
        )
        conn.commit()
        tok_str = _fmt_tok(bt) if bt else "none"
        usd_str = f"${bu:.2f}" if bu else "none"
        print(f"[+] Budget set — tokens: {tok_str} | usd: {usd_str}")

    b = conn.execute("SELECT * FROM token_budgets WHERE output_dir=?", (output_dir,)).fetchone()
    if not b:
        print(f"No budget set for {output_dir}.")
        print("Set one: python3 tools/token-meter.py budget \"$OUTPUT_DIR\" "
              "--set-tokens 2000000 --set-usd 25")
        conn.close()
        return
    row, total = _engagement_totals(conn, output_dir)
    print(f"  Budget for {output_dir}")
    if b["budget_tokens"]:
        pct = 100 * total / b["budget_tokens"]
        print(f"    tokens : {_fmt_tok(total)} / {_fmt_tok(b['budget_tokens'])} ({pct:.0f}%)")
    if b["budget_usd"]:
        pct = 100 * row["usd"] / b["budget_usd"]
        print(f"    cost   : ${row['usd']:.2f} / ${b['budget_usd']:.2f} ({pct:.0f}%)")
    conn.close()


def cmd_estimate(a):
    src = a.source
    if src == "-":
        text = sys.stdin.read()
        name = "<stdin>"
    else:
        p = Path(src)
        if not p.exists():
            print(f"[!] Not found: {src}", file=sys.stderr)
            sys.exit(2)
        text = p.read_text(encoding="utf-8", errors="replace")
        name = str(p)
    tok = estimate_tokens(text)
    print(f"  Source : {name}")
    print(f"  Chars  : {len(text):,}   Words: {len(text.split()):,}")
    print(f"  ~Tokens: {tok:,}   (heuristic — confirm with count_tokens API)")
    print(f"\n  Approx cost if loaded as INPUT once, per model:")
    for mid in ("claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"):
        c = cost_usd(mid, in_tok=tok)
        print(f"    {mid:20s} ${c:.4f}")


def cmd_list(a):
    conn = connect()
    rows = conn.execute(
        """SELECT output_dir,
                  SUM(input_tokens+output_tokens+cache_read_tokens+cache_write_tokens) AS tok,
                  SUM(cost_usd) AS usd, COUNT(*) AS n
           FROM token_events GROUP BY output_dir ORDER BY tok DESC""",
    ).fetchall()
    conn.close()
    if not rows:
        print("No token events recorded yet.")
        return
    print(f"\n  {'tokens':>10s} {'cost':>11s} {'events':>7s}  engagement")
    print(f"  {'-'*10} {'-'*11} {'-'*7}  {'-'*30}")
    gt = gu = 0
    for r in rows:
        gt += r["tok"] or 0
        gu += r["usd"] or 0
        print(f"  {_fmt_tok(r['tok']):>10s} ${r['usd']:>9.2f} {r['n']:>7d}  {r['output_dir']}")
    print(f"  {'-'*10} {'-'*11} {'-'*7}")
    print(f"  {_fmt_tok(gt):>10s} ${gu:>9.2f}  ALL ENGAGEMENTS")


def cmd_ingest(a):
    """
    Semi-auto capture: scan OUTPUT_DIR for usage.json files (executors drop these
    on return) and record each as a token event, then mark the file .recorded so a
    re-run never double-counts. A file may hold one event object or a list of them.
    """
    output_dir = str(Path(a.output_dir).resolve())
    base = Path(output_dir)
    files = sorted(set(base.glob("**/usage.json")) | set(base.glob("**/*.usage.json")))
    files = [f for f in files if not f.name.endswith(".recorded")]
    if not files:
        print(f"[i] No usage.json files under {output_dir}")
        return

    conn = connect()
    n_events = n_files = 0
    tot_cost = tot_tok = 0
    for f in files:
        try:
            obj = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError) as e:
            print(f"    [skip] {f}: {e}")
            continue
        events = obj if isinstance(obj, list) else [obj]
        for ev in events:
            fields = _normalize_usage(ev)
            tot_cost += _insert_event(conn, output_dir, **fields)
            tot_tok += (fields["input_tokens"] + fields["output_tokens"]
                        + fields["cache_read"] + fields["cache_write"])
            n_events += 1
        n_files += 1
        if not a.keep:
            f.rename(f.with_name(f.name + ".recorded"))
    conn.commit()
    print(f"[+] Ingested {n_events} event(s) from {n_files} file(s) | "
          f"{_fmt_tok(tot_tok)} tokens | ${tot_cost:.4f}")
    _budget_warn(conn, output_dir)
    conn.close()


def cmd_pricing(a):
    print("  Model pricing — USD per 1,000,000 tokens (cached 2026-05-26)")
    print(f"\n  {'model':20s} {'input':>8s} {'output':>8s} {'cache-r':>9s} "
          f"{'cache-w5m':>10s} {'cache-w1h':>10s}")
    print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*9} {'-'*10} {'-'*10}")
    for mid in ("claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"):
        r = rates_for(mid)
        print(f"  {mid:20s} {r['in']:>8.2f} {r['out']:>8.2f} {r['cache_read']:>9.2f} "
              f"{r['cache_write_5m']:>10.2f} {r['cache_write_1h']:>10.2f}")
    print("\n  Opus tiers include a 1M-token context window at standard pricing"
          " (no long-context premium).")
    print("  Batches API applies a 50% discount to all token usage.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="token-meter.py",
        description="Token accounting & cost telemetry for tzar-bot engagements.",
    )
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("record", help="Record one token-usage event")
    r.add_argument("output_dir", nargs="?")
    r.add_argument("--output-dir", dest="output_dir_opt", default="")
    r.add_argument("--role", default="executor",
                   choices=["coordinator", "executor", "validator", "other"])
    r.add_argument("--agent", default=None)
    r.add_argument("--phase", default=None)
    r.add_argument("--model", default="claude-opus-4-8")
    r.add_argument("--in", dest="in_tokens", type=int, required=True)
    r.add_argument("--out", dest="out_tokens", type=int, required=True)
    r.add_argument("--cache-read", dest="cache_read", type=int, default=0)
    r.add_argument("--cache-write", dest="cache_write", type=int, default=0)
    r.add_argument("--cache-ttl", dest="cache_ttl", default="5m", choices=["5m", "1h"])
    r.add_argument("--label", default=None)
    r.set_defaults(func=cmd_record)

    rp = sub.add_parser("report", help="Per-role/phase/agent/model breakdown")
    rp.add_argument("output_dir", nargs="?")
    rp.add_argument("--output-dir", dest="output_dir_opt", default="")
    rp.set_defaults(func=cmd_report)

    b = sub.add_parser("budget", help="Show or set an engagement token/USD budget")
    b.add_argument("output_dir", nargs="?")
    b.add_argument("--output-dir", dest="output_dir_opt", default="")
    b.add_argument("--set-tokens", dest="set_tokens", type=int, default=None)
    b.add_argument("--set-usd", dest="set_usd", type=float, default=None)
    b.set_defaults(func=cmd_budget)

    e = sub.add_parser("estimate", help="Heuristic token+cost for a file or stdin")
    e.add_argument("source", help="Path to a file, or '-' for stdin")
    e.set_defaults(func=cmd_estimate)

    ing = sub.add_parser("ingest", help="Record all usage.json files an engagement produced")
    ing.add_argument("output_dir")
    ing.add_argument("--keep", action="store_true",
                     help="Don't rename processed files to .recorded (allows re-ingest)")
    ing.set_defaults(func=cmd_ingest)

    l = sub.add_parser("list", help="Token + cost totals across all engagements")
    l.set_defaults(func=cmd_list)

    pr = sub.add_parser("pricing", help="Print the model pricing table")
    pr.set_defaults(func=cmd_pricing)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        sys.exit(0)
    # Unify engagement dir: --output-dir flag → positional → $OUTPUT_DIR env.
    if hasattr(args, "output_dir"):
        args.output_dir = (getattr(args, "output_dir_opt", "") or args.output_dir
                           or os.environ.get("OUTPUT_DIR", ""))
        if not args.output_dir:
            parser.error("engagement dir required (positional, --output-dir, or $OUTPUT_DIR)")
    args.func(args)


if __name__ == "__main__":
    main()
