#!/usr/bin/env python3
"""
tzar-bot MCP server — exposes tools/ as MCP tools for Claude Code, Cursor,
and any MCP-compatible client.

Transport: stdio (newline-delimited JSON-RPC 2.0, per the MCP stdio spec)

Start manually:
    python3 tools/mcp-server.py

Registered automatically via .claude/settings.json mcpServers block.
"""

import sys
import os
import re
import json
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).parent.resolve()
REPO_DIR  = TOOLS_DIR.parent
PYTHON    = sys.executable

sys.path.insert(0, str(TOOLS_DIR))
from pathguard import within_allowed_roots  # noqa: E402  — contain caller-supplied output paths

# Reject anything that is not a well-formed CVE id before it reaches a child
# script as an argument (also neutralises option-injection via leading '-').
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{3,}$", re.IGNORECASE)


# ── stdio framing ────────────────────────────────────────────────────────────

def read_message():
    """Read one newline-delimited JSON-RPC message from stdin (MCP stdio transport)."""
    while True:
        raw = sys.stdin.buffer.readline()
        if not raw:
            return None
        line = raw.strip()
        if not line:
            continue  # skip blank lines between messages
        try:
            return json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # A malformed line must not crash the server — skip and keep serving.
            sys.stderr.write("[mcp] skipping malformed JSON-RPC line\n")
            sys.stderr.flush()
            continue


def send_message(obj):
    """Write one newline-delimited JSON-RPC message to stdout (MCP stdio transport)."""
    body = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(body + b"\n")
    sys.stdout.buffer.flush()


# ── subprocess helper ────────────────────────────────────────────────────────

TOOL_TIMEOUT = 120  # seconds — a hung child must never freeze the single-threaded server


def run(cmd, stdin=None, env=None, timeout=TOOL_TIMEOUT):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_DIR,
                           input=stdin, env=env, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"tool timed out after {timeout}s", 124


# ── tool schemas ─────────────────────────────────────────────────────────────

TOOL_DEFS = [
    {
        "name": "nvd_lookup",
        "description": (
            "Fetch CVE details (CVSS score, severity, description, published date) "
            "from the NVD 2.0 API. Uses NVD_API_KEY from .env automatically."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id":  {"type": "string", "description": "e.g. CVE-2024-12345"},
                "api_key": {"type": "string", "description": "Optional NVD API key (overrides .env)"},
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "mitre_lookup",
        "description": (
            "Look up / search / map MITRE ATT&CK techniques across the Enterprise, "
            "Mobile and ICS (OT) matrices from a local offline index. Use 'map' to get "
            "candidate technique IDs for a finding description, 'lookup' for a technique "
            "by ID (Txxxx[.yyy]), 'search' for keywords, 'tactic' to list a tactic's "
            "techniques, 'stats' for index coverage."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["lookup", "search", "map", "tactic", "tactics", "stats"],
                           "description": "Operation to run"},
                "query":  {"type": "string", "description": "Technique ID (lookup), keywords (search), finding text (map), or tactic name (tactic)"},
                "matrix": {"type": "string", "enum": ["all", "enterprise", "mobile", "ics"], "default": "all"},
                "limit":  {"type": "integer", "description": "Max results for search/map", "default": 8},
            },
            "required": ["action"],
        },
    },
    {
        "name": "atomic_red",
        "description": (
            "Look up Red Canary Atomic Red Team detection-validation tests, keyed by MITRE "
            "ATT&CK technique, from a local offline index. action 'lookup' lists tests for a "
            "technique ID, 'search' finds tests by keyword, 'show' returns one test's full "
            "command+cleanup, 'map' maps a finding description to techniques then to "
            "atomic tests, 'stats' shows coverage. READ-ONLY: returns test definitions/commands; "
            "it never executes them (run atomics only in an authorized lab via Invoke-AtomicRedTeam)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action":   {"type": "string", "enum": ["lookup", "search", "show", "map", "stats"]},
                "query":    {"type": "string", "description": "Technique ID (lookup/show), keywords (search), or finding text (map)"},
                "platform": {"type": "string", "enum": ["windows", "linux", "macos"], "description": "Optional platform filter"},
                "test":     {"type": "integer", "description": "show: 1-based test number"},
                "guid":     {"type": "string", "description": "show: select test by GUID"},
                "limit":    {"type": "integer", "default": 20},
            },
            "required": ["action"],
        },
    },
    {
        "name": "validate_finding",
        "description": (
            "Run the 5-check validation protocol on a single finding directory: "
            "CVSS consistency, evidence exists, PoC validity, claims vs evidence, "
            "log corroboration. Writes JSON result to artifacts/validated/ or "
            "artifacts/false-positives/."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_dir": {"type": "string", "description": "Absolute path to OUTPUT_DIR/findings/finding-NNN"},
                "strict":      {"type": "boolean", "description": "Treat WARN as failure", "default": False},
            },
            "required": ["finding_dir"],
        },
    },
    {
        "name": "validate_all_findings",
        "description": (
            "Validate every finding under OUTPUT_DIR/findings/ in one call. "
            "Run before generating the final PDF report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string", "description": "Absolute path to the engagement OUTPUT_DIR"},
                "strict":     {"type": "boolean", "description": "Treat WARN as failure", "default": False},
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "init_engagement",
        "description": (
            "Initialise a new engagement OUTPUT_DIR: creates the full directory tree, "
            "writes attack-chain.md and engagement.json, prints the coordinator checklist, "
            "and returns the shell export command."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Client/project name"},
                "target":  {"type": "string", "description": "Primary target URL or IP"},
                "type": {
                    "type": "string",
                    "enum": ["WAPT","MAPT","API","Network","CodeReview","Cloud","RedTeam","DFIR","BugBounty"],
                    "description": "Engagement type (auto-detected from target if omitted)",
                },
                "mode":  {"type": "string", "enum": ["blackbox","graybox","whitebox"], "default": "blackbox"},
                "scope": {"type": "string", "description": "Comma-separated in-scope domains/IPs"},
            },
            "required": ["project", "target"],
        },
    },
    {
        "name": "scrub_web_content",
        "description": (
            "Strip prompt injection patterns from web-sourced content before embedding "
            "it in agent prompts. Returns scrubbed text with [SCRUBBED:label] markers "
            "where injections were removed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content":     {"type": "string", "description": "Raw web content (HTTP body, HTML, JSON, etc.)"},
                "json_report": {"type": "boolean", "description": "Return JSON with injections_found, hits, scrubbed fields", "default": False},
            },
            "required": ["content"],
        },
    },
    {
        "name": "gen_nuclei_template",
        "description": (
            "Generate a Nuclei v3 YAML detection template from CVE metadata. "
            "If OUTPUT_DIR/tools/CVE-ID/nvd.json exists (written by nvd_lookup), "
            "CVSS/CWE fields are auto-filled from it."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id":      {"type": "string", "description": "e.g. CVE-2024-12345"},
                "description": {"type": "string", "description": "Short vulnerability description"},
                "path":        {"type": "string", "description": "Vulnerable URL path, e.g. /api/v1/exec"},
                "severity":    {"type": "string", "enum": ["critical","high","medium","low","info"], "default": "medium"},
                "method":      {"type": "string", "enum": ["GET","POST","PUT","PATCH","DELETE"], "default": "GET"},
                "body":        {"type": "string", "description": "Request body for POST/PUT"},
                "match_words": {"type": "array",  "items": {"type": "string"}, "description": "Words to match in response body"},
                "match_regex": {"type": "array",  "items": {"type": "string"}, "description": "Regex patterns to match in response body"},
                "match_status":{"type": "integer","description": "Expected HTTP status", "default": 200},
                "cvss":        {"type": "string", "description": "CVSS v3.1 vector string"},
                "cvss_score":  {"type": "number", "description": "CVSS base score"},
                "cwe":         {"type": "string", "description": "CWE identifier, e.g. CWE-78"},
                "tags":        {"type": "string", "description": "Comma-separated Nuclei tags"},
                "output_path": {"type": "string", "description": "File path to write the template (stdout if omitted)"},
                "output_dir":  {"type": "string", "description": "Engagement OUTPUT_DIR for nvd.json auto-fill"},
            },
            "required": ["cve_id", "description", "path"],
        },
    },
    {
        "name": "read_env",
        "description": (
            "Read environment variables from the project .env file. "
            "The only approved method for accessing credentials (HTB_TOKEN, NVD_API_KEY, etc.)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vars": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Variable names to read, e.g. [\"HTB_TOKEN\", \"NVD_API_KEY\"]",
                },
            },
            "required": ["vars"],
        },
    },
    {
        "name": "scope_check",
        "description": (
            "Check whether a Bash command targets in-scope hosts before running it. "
            "Returns 'ALLOWED' or 'BLOCKED: <reason>'. "
            "Use before any command that touches a target host when OUTPUT_DIR is set."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command":    {"type": "string", "description": "The Bash command to check"},
                "output_dir": {"type": "string", "description": "Engagement OUTPUT_DIR (reads scope from engagement.json)"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "session_memory",
        "description": (
            "Cross-session SQLite memory for engagements. "
            "save: parse attack-chain.md + findings/ into memory.db. "
            "load: get a full coordinator resume briefing for a prior engagement. "
            "list: show all known engagements. "
            "search: find engagements by target/finding/vector/note. "
            "note: append a freeform note. "
            "status: mark an engagement active/completed/abandoned."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["save", "load", "list", "search", "note", "status"],
                    "description": "Subcommand to run",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Absolute path to the engagement OUTPUT_DIR (required for save/load/note/status)",
                },
                "query": {
                    "type": "string",
                    "description": "Search query (required for search)",
                },
                "text": {
                    "type": "string",
                    "description": "Note text (required for note) or new status value (required for status: active/completed/abandoned)",
                },
                "filter_type": {
                    "type": "string",
                    "description": "Filter by engagement type for list (e.g. WAPT, API, Network)",
                },
                "filter_status": {
                    "type": "string",
                    "description": "Filter by status for list (active/completed/abandoned)",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "memory_search",
        "description": (
            "Full-text cross-engagement search using SQLite FTS5 (porter stemmer). "
            "Searches findings, vectors, notes, services, and hypotheses across ALL "
            "engagements in memory.db. Natural language queries supported. "
            "Use --index to rebuild the index after bulk saves."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":    {"type": "string", "description": "Natural language search query, e.g. 'JWT bypass cloudflare'"},
                "type":     {"type": "string", "description": "Filter by engagement type: WAPT, API, Network, Cloud, etc."},
                "severity": {"type": "string", "description": "Filter findings by severity: critical, high, medium, low"},
                "limit":    {"type": "integer", "description": "Max results (default 20)", "default": 20},
                "rebuild":  {"type": "boolean", "description": "Rebuild FTS index before searching (default false)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "continuous_scan",
        "description": (
            "Continuous / scheduled delta scanning orchestration. "
            "list: show monitored targets overdue for a rescan. "
            "prepare: create a new timestamped OUTPUT_DIR for a delta rescan of an existing engagement. "
            "delta: compare new findings against all prior validated findings — returns only NEW ones. "
            "record: log a completed scan run in scan_history and mark engagement as monitored. "
            "history: show scan run history for an engagement."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["list", "prepare", "delta", "record", "history"],
                    "description": "Subcommand to run",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Engagement OUTPUT_DIR (required for prepare/delta/record/history)",
                },
                "base_dir": {
                    "type": "string",
                    "description": "Base (prior) OUTPUT_DIR (required for delta)",
                },
                "new_findings": {
                    "type": "integer",
                    "description": "Number of new findings discovered (for record)",
                },
                "scan_type": {
                    "type": "string",
                    "description": "Scan type for record: full | delta | nuclei | recon",
                    "default": "delta",
                },
                "overdue_hours": {
                    "type": "integer",
                    "description": "Hours threshold for 'overdue' in list (default 24)",
                    "default": 24,
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "token_meter",
        "description": (
            "Token accounting & cost telemetry for the fan-out (coordinator->executors->validators) "
            "architecture. record: log one agent batch's API usage (feed it the usage object) and warn "
            "at >=80%/100% of budget. ingest: record every usage.json an engagement produced (semi-auto). "
            "report: per-role/phase/agent/model breakdown + totals + USD cost. "
            "budget: set/show a token or USD ceiling. estimate: heuristic token+cost for content or a file "
            "BEFORE loading it (gauge only; count_tokens is authoritative). list: totals across all "
            "engagements. pricing: model rate card."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["record", "ingest", "report", "budget", "estimate", "list", "pricing"],
                    "description": "Subcommand to run",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Engagement OUTPUT_DIR (required for record/ingest/report/budget)",
                },
                "keep": {"type": "boolean", "description": "ingest: don't rename processed usage.json to .recorded"},
                "role": {
                    "type": "string",
                    "enum": ["coordinator", "executor", "validator", "other"],
                    "description": "Agent role for record (default executor)",
                },
                "agent": {"type": "string", "description": "Free-text agent label for record, e.g. 'recon-1'"},
                "phase": {"type": "string", "description": "Phase/group label for record, e.g. 'recon'"},
                "model": {"type": "string", "description": "Model id for record (default claude-opus-4-8)"},
                "input_tokens":  {"type": "integer", "description": "Input/prompt tokens (record) — API usage.input_tokens"},
                "output_tokens": {"type": "integer", "description": "Output tokens (record) — API usage.output_tokens"},
                "cache_read":  {"type": "integer", "description": "Cache-read input tokens (record) — usage.cache_read_input_tokens"},
                "cache_write": {"type": "integer", "description": "Cache-write input tokens (record) — usage.cache_creation_input_tokens"},
                "cache_ttl":   {"type": "string", "enum": ["5m", "1h"], "description": "TTL for cache-write pricing (default 5m)"},
                "label":       {"type": "string", "description": "Optional note for the event"},
                "set_tokens":  {"type": "integer", "description": "Token ceiling to set (budget)"},
                "set_usd":     {"type": "number",  "description": "USD ceiling to set (budget)"},
                "source":      {"type": "string", "description": "File path to estimate (estimate)"},
                "content":     {"type": "string", "description": "Inline text to estimate (estimate) — takes precedence over source"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "report_export",
        "description": (
            "Offline JSON + HTML report export — stdlib only, no reportlab, no network "
            "(air-gapped box / CI / quick preview before the full PDF). Reads "
            "artifacts/pentest-report.json if present, else parses findings/*/description.md. "
            "Writes reports/report.json and/or reports/report.html."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string", "description": "Engagement OUTPUT_DIR"},
                "format":     {"type": "string", "enum": ["json", "html", "both"], "default": "both"},
                "client":     {"type": "string", "description": "Client name (default: engagement.json project)"},
                "target":     {"type": "string", "description": "Target URL (default: engagement.json target)"},
                "out_dir":    {"type": "string", "description": "Output dir (default: OUTPUT_DIR/reports)"},
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "rate_limiter",
        "description": (
            "Per-host request pacing (token bucket) so parallel executors don't trip a WAF "
            "or get the source IP banned. acquire: consume a slot. status: show the bucket. "
            "State persists per host under OUTPUT_DIR/.ratelimit/. NOTE: this MCP wrapper "
            "defaults acquire to non-blocking (reports THROTTLED instead of sleeping); for "
            "true blocking pacing call rate-limiter.py via Bash."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command":   {"type": "string", "enum": ["acquire", "status"], "description": "Subcommand"},
                "key":       {"type": "string", "description": "Bucket key, usually the target host"},
                "rps":       {"type": "number", "description": "Requests/sec refill rate (acquire)", "default": 5},
                "burst":     {"type": "number", "description": "Bucket capacity (acquire; default max(1, rps))"},
                "no_wait":   {"type": "boolean", "description": "Report throttle instead of blocking (default true in MCP)", "default": True},
                "state_dir": {"type": "string", "description": "Override bucket state directory"},
            },
            "required": ["command", "key"],
        },
    },
    {
        "name": "engagement_state",
        "description": (
            "Resumable, scope-guarded engagement ledger (state.json). "
            "summary: counts + phase. set-phase: advance phase. add-surface: add discovered "
            "items (out-of-scope dropped in code). worklist: impact-ranked untested surface "
            "(optionally claim-aware via agent). mark-tested: record a tested vector. "
            "claim/release/claims: executor work-claim dedup so two agents don't re-test the "
            "same surface (claim returns isError when denied)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["summary", "set-phase", "add-surface", "worklist",
                             "mark-tested", "claim", "release", "claims"],
                    "description": "Subcommand to run",
                },
                "output_dir": {"type": "string", "description": "Engagement OUTPUT_DIR (default: $OUTPUT_DIR)"},
                "phase":      {"type": "string", "description": "Phase name (set-phase)"},
                "items":      {"type": "array", "items": {"type": "object"},
                               "description": "Surface items (add-surface): [{url, param, vuln_class}]"},
                "url":        {"type": "string", "description": "Target URL (mark-tested/claim/release)"},
                "param":      {"type": "string", "description": "Parameter name"},
                "vuln_class": {"type": "string", "description": "Vulnerability class, e.g. idor, sqli"},
                "agent":      {"type": "string", "description": "Agent id (claim/release; worklist claim filter)"},
                "top":        {"type": "integer", "description": "Limit worklist size"},
            },
            "required": ["command"],
        },
    },
]


# ── tool handlers ─────────────────────────────────────────────────────────────

def tool_nvd_lookup(args):
    cve = args["cve_id"]
    if not _CVE_RE.match(cve or ""):
        return f"Invalid CVE id: {cve!r} (expected CVE-YYYY-NNNN…)", True
    cmd = [PYTHON, str(TOOLS_DIR / "nvd-lookup.py")]
    if args.get("api_key"):
        cmd += ["--api-key", args["api_key"]]
    cmd += ["--", cve]   # end-of-options: a leading-dash value can't become a flag
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc != 0 else "")).strip(), rc != 0


def tool_mitre_lookup(args):
    action = args.get("action")
    if action not in {"lookup", "search", "map", "tactic", "tactics", "stats"}:
        return f"Invalid action: {action!r}", True
    cmd = [PYTHON, str(TOOLS_DIR / "mitre-lookup.py"), action]
    needs_query = action in {"lookup", "search", "map", "tactic"}
    if needs_query:
        q = (args.get("query") or "").strip()
        if not q:
            return f"action '{action}' requires 'query'", True
    if action in {"search", "map"} and args.get("limit"):
        cmd += ["--limit", str(int(args["limit"]))]
    if args.get("matrix"):
        cmd += ["--matrix", args["matrix"]]
    if action != "update":
        cmd.append("--json")
    if needs_query:
        cmd += ["--", q]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc != 0 else "")).strip(), rc != 0


def tool_atomic_red(args):
    action = args.get("action")
    if action not in {"lookup", "search", "show", "map", "stats"}:
        return f"Invalid action: {action!r}", True
    cmd = [PYTHON, str(TOOLS_DIR / "atomic-red.py"), action]
    needs_query = action in {"lookup", "search", "show", "map"}
    q = (args.get("query") or "").strip()
    if needs_query and not q:
        return f"action '{action}' requires 'query'", True
    if args.get("platform") and action != "stats":
        cmd += ["--platform", args["platform"]]
    if action in {"search", "map"} and args.get("limit"):
        cmd += ["--limit", str(int(args["limit"]))]
    if action == "show":
        if args.get("guid"):
            cmd += ["--guid", str(args["guid"])]
        elif args.get("test"):
            cmd += ["--test", str(int(args["test"]))]
    cmd.append("--json")
    if needs_query:
        cmd += ["--", q]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc != 0 else "")).strip(), rc != 0


def tool_validate_finding(args):
    cmd = [PYTHON, str(TOOLS_DIR / "validate-finding.py")]
    if args.get("strict"):
        cmd.append("--strict")
    cmd += ["--", args["finding_dir"]]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err else "")).strip(), rc == 2


def tool_validate_all(args):
    cmd = [PYTHON, str(TOOLS_DIR / "validate-finding.py"), "--all"]
    if args.get("strict"):
        cmd.append("--strict")
    cmd += ["--", args["output_dir"]]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err else "")).strip(), rc == 2


def tool_init_engagement(args):
    cmd = [PYTHON, str(TOOLS_DIR / "init-engagement.py"),
           "--project", args["project"], "--target", args["target"]]
    if args.get("type"):
        cmd += ["--type", args["type"]]
    if args.get("mode"):
        cmd += ["--mode", args["mode"]]
    if args.get("scope"):
        cmd += ["--scope", args["scope"]]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc != 0 else "")).strip(), rc != 0


def tool_scrub_web_content(args):
    cmd = [PYTHON, str(TOOLS_DIR / "scrub-web-content.py"), "--text", args["content"]]
    if args.get("json_report"):
        cmd.append("--json")
    out, err, _ = run(cmd)
    parts = [out]
    if err:
        parts.append(f"[scrubber log]: {err}")
    return "\n".join(p for p in parts if p).strip(), False


def tool_gen_nuclei_template(args):
    cve = args["cve_id"]
    if not _CVE_RE.match(cve or ""):
        return f"Invalid CVE id: {cve!r} (expected CVE-YYYY-NNNN…)", True
    out_path = args.get("output_path")
    if out_path and not within_allowed_roots(out_path):
        return f"BLOCKED (path): output_path {out_path!r} is outside the engagement sandbox", True
    cmd = [PYTHON, str(TOOLS_DIR / "gen-nuclei-template.py"),
           "--cve", cve,
           "--description", args.get("description", ""),
           "--path", args.get("path", "/")]
    for flag, key in [("--severity","severity"), ("--method","method"),
                      ("--body","body"), ("--cvss","cvss"), ("--cwe","cwe"), ("--tags","tags"),
                      ("--output","output_path"), ("--output-dir","output_dir")]:
        if args.get(key):
            cmd += [flag, str(args[key])]
    if args.get("cvss_score") is not None:
        cmd += ["--cvss-score", str(args["cvss_score"])]
    if args.get("match_status"):
        cmd += ["--match-status", str(args["match_status"])]
    for w in args.get("match_words", []):
        cmd += ["--match-word", w]
    for r in args.get("match_regex", []):
        cmd += ["--match-regex", r]
    out, err, rc = run(cmd)
    return (out + (f"\n[info]: {err}" if err else "")).strip(), rc != 0


def tool_read_env(args):
    cmd = [PYTHON, str(TOOLS_DIR / "env-reader.py")] + args["vars"]
    out, _, rc = run(cmd)
    return out.strip(), rc != 0


def tool_scope_check(args):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": args["command"]}})
    env = dict(os.environ)
    if args.get("output_dir"):
        env["OUTPUT_DIR"] = args["output_dir"]
    out, err, rc = run([PYTHON, str(TOOLS_DIR / "scope-check.py")], stdin=payload, env=env)
    if rc == 2:
        return f"BLOCKED: {err.strip()}", True  # is_error=True signals the command was rejected
    return "ALLOWED", False


def tool_memory_search(args):
    cmd = [PYTHON, str(TOOLS_DIR / "memory-search.py")]
    if args.get("type"):     cmd += ["--type",     args["type"]]
    if args.get("severity"): cmd += ["--severity", args["severity"]]
    if args.get("limit"):    cmd += ["--limit",     str(args["limit"])]
    if args.get("rebuild"):  cmd.append("--index")
    cmd.append("--json")
    cmd += ["--", args["query"]]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc != 0 else "")).strip(), rc != 0


def tool_continuous_scan(args):
    cmd_name = args.get("command", "list")
    cmd = [PYTHON, str(TOOLS_DIR / "continuous-scan.py"), cmd_name]
    if cmd_name == "list" and args.get("overdue_hours"):
        cmd += ["--overdue-hours", str(args["overdue_hours"])]
    elif cmd_name == "prepare" and args.get("output_dir"):
        cmd.append(args["output_dir"])
    elif cmd_name == "delta" and args.get("output_dir") and args.get("base_dir"):
        cmd += [args["output_dir"], args["base_dir"]]
    elif cmd_name == "record" and args.get("output_dir"):
        cmd.append(args["output_dir"])
        if args.get("scan_type"):
            cmd += ["--type", args["scan_type"]]
        if args.get("new_findings") is not None:
            cmd += ["--findings", str(args["new_findings"])]
    elif cmd_name == "history" and args.get("output_dir"):
        cmd.append(args["output_dir"])
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc not in (0, 1) else "")).strip(), rc > 1


def tool_session_memory(args):
    cmd_name = args.get("command", "list")
    cmd = [PYTHON, str(TOOLS_DIR / "session-memory.py"), cmd_name]
    if cmd_name in ("save", "load") and args.get("output_dir"):
        cmd.append(args["output_dir"])
    elif cmd_name == "search" and args.get("query"):
        cmd.append(args["query"])
    elif cmd_name == "note" and args.get("output_dir") and args.get("text"):
        cmd += [args["output_dir"], args["text"]]
    elif cmd_name == "status" and args.get("output_dir") and args.get("text"):
        cmd += [args["output_dir"], args["text"]]
    elif cmd_name == "list":
        if args.get("filter_type"):
            cmd += ["--type", args["filter_type"]]
        if args.get("filter_status"):
            cmd += ["--status", args["filter_status"]]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc not in (0, 1) else "")).strip(), rc == 2  # exit 2 = usage error; 0=ok, 1=no results


def tool_token_meter(args):
    cmd_name = args.get("command", "report")
    cmd = [PYTHON, str(TOOLS_DIR / "token-meter.py"), cmd_name]
    stdin_input = None
    if cmd_name == "record":
        cmd.append(args["output_dir"])
        if args.get("role"):  cmd += ["--role",  args["role"]]
        if args.get("agent"): cmd += ["--agent", args["agent"]]
        if args.get("phase"): cmd += ["--phase", args["phase"]]
        if args.get("model"): cmd += ["--model", args["model"]]
        cmd += ["--in",  str(args.get("input_tokens", 0))]
        cmd += ["--out", str(args.get("output_tokens", 0))]
        if args.get("cache_read"):  cmd += ["--cache-read",  str(args["cache_read"])]
        if args.get("cache_write"): cmd += ["--cache-write", str(args["cache_write"])]
        if args.get("cache_ttl"):   cmd += ["--cache-ttl",   args["cache_ttl"]]
        if args.get("label"):       cmd += ["--label",       args["label"]]
    elif cmd_name == "ingest":
        cmd.append(args["output_dir"])
        if args.get("keep"):
            cmd.append("--keep")
    elif cmd_name in ("report",):
        cmd.append(args["output_dir"])
    elif cmd_name == "budget":
        cmd.append(args["output_dir"])
        if args.get("set_tokens") is not None: cmd += ["--set-tokens", str(args["set_tokens"])]
        if args.get("set_usd")    is not None: cmd += ["--set-usd",    str(args["set_usd"])]
    elif cmd_name == "estimate":
        if args.get("content") is not None:
            cmd.append("-")
            stdin_input = args["content"]
        else:
            cmd.append(args.get("source", "-"))
    # list / pricing take no extra args
    out, err, rc = run(cmd, stdin=stdin_input)
    return (out + (f"\n{err}" if err and rc != 0 else "")).strip(), rc != 0


def tool_report_export(args):
    cmd = [PYTHON, str(TOOLS_DIR / "report-export.py")]
    if args.get("format"):  cmd += ["--format",  args["format"]]
    if args.get("client"):  cmd += ["--client",  args["client"]]
    if args.get("target"):  cmd += ["--target",  args["target"]]
    if args.get("out_dir"): cmd += ["--out-dir", args["out_dir"]]
    cmd += ["--", args["output_dir"]]
    out, err, rc = run(cmd)
    return (out + (f"\n{err}" if err and rc != 0 else "")).strip(), rc != 0


def tool_rate_limiter(args):
    cmd_name = args.get("command", "status")
    cmd = [PYTHON, str(TOOLS_DIR / "rate-limiter.py"), cmd_name, "--key", args["key"]]
    if cmd_name == "acquire":
        if args.get("rps") is not None:
            cmd += ["--rps", str(args["rps"])]
        if args.get("burst") is not None:
            cmd += ["--burst", str(args["burst"])]
        # default to non-blocking in MCP so the JSON-RPC call never hangs the server
        if args.get("no_wait", True):
            cmd.append("--no-wait")
    if args.get("state_dir"):
        cmd += ["--state-dir", args["state_dir"]]
    out, err, rc = run(cmd)
    # rc 1 = THROTTLED (informational, not an error); rc 2 = usage error
    return (out + (f"\n{err}" if err and rc > 1 else "")).strip(), rc > 1


def tool_engagement_state(args):
    cmd_name = args.get("command", "summary")
    cmd = [PYTHON, str(TOOLS_DIR / "engagement-state.py")]
    if args.get("output_dir"):
        cmd += ["--output-dir", args["output_dir"]]
    cmd.append(cmd_name)
    if cmd_name == "set-phase":
        cmd.append(args.get("phase", ""))
    elif cmd_name == "add-surface":
        cmd += ["--json", json.dumps(args.get("items", []))]
    elif cmd_name == "worklist":
        if args.get("top") is not None:
            cmd += ["--top", str(args["top"])]
        if args.get("agent"):
            cmd += ["--agent", args["agent"]]
    elif cmd_name == "mark-tested":
        cmd += ["--url", args.get("url", "")]
        if args.get("param"):      cmd += ["--param", args["param"]]
        if args.get("vuln_class"): cmd += ["--vuln-class", args["vuln_class"]]
    elif cmd_name in ("claim", "release"):
        cmd += ["--url", args.get("url", ""), "--agent", args.get("agent", "")]
        if args.get("param"):      cmd += ["--param", args["param"]]
        if args.get("vuln_class"): cmd += ["--vuln-class", args["vuln_class"]]
    # summary / claims take no extra args
    out, err, rc = run(cmd)
    # rc 1 = claim denied (informational); rc 2 = usage/no-OUTPUT_DIR error
    return (out + (f"\n{err}" if err and rc > 1 else "")).strip(), rc > 1


HANDLERS = {
    "nvd_lookup":            tool_nvd_lookup,
    "mitre_lookup":          tool_mitre_lookup,
    "atomic_red":            tool_atomic_red,
    "validate_finding":      tool_validate_finding,
    "validate_all_findings": tool_validate_all,
    "init_engagement":       tool_init_engagement,
    "scrub_web_content":     tool_scrub_web_content,
    "gen_nuclei_template":   tool_gen_nuclei_template,
    "read_env":              tool_read_env,
    "scope_check":           tool_scope_check,
    "memory_search":         tool_memory_search,
    "continuous_scan":       tool_continuous_scan,
    "session_memory":        tool_session_memory,
    "token_meter":           tool_token_meter,
    "report_export":         tool_report_export,
    "rate_limiter":          tool_rate_limiter,
    "engagement_state":      tool_engagement_state,
}


# ── JSON-RPC dispatch ─────────────────────────────────────────────────────────

def dispatch(msg):
    method = msg.get("method", "")
    msg_id = msg.get("id")
    params = msg.get("params", {})

    if msg_id is None:
        return None  # notification — no response

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tzar-bot", "version": "1.0.0"},
        }}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOL_DEFS}}

    if method == "tools/call":
        name    = params.get("name", "")
        handler = HANDLERS.get(name)
        if not handler:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
        try:
            text, is_error = handler(params.get("arguments", {}))
        except Exception as exc:
            text, is_error = f"Tool execution error: {exc}", True
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }}

    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main():
    while True:
        msg = read_message()
        if msg is None:
            break
        response = dispatch(msg)
        if response is not None:
            send_message(response)


if __name__ == "__main__":
    main()
