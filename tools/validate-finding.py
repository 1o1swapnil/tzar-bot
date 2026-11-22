#!/usr/bin/env python3
"""
validate-finding.py — validate a finding by reproducing it, not by checking its format.

Usage:
    python3 tools/validate-finding.py <OUTPUT_DIR/findings/finding-NNN>
    python3 tools/validate-finding.py <OUTPUT_DIR> --all          # every finding
      --strict          warnings count as failures
      --no-replay       skip check 6 (result can then be UNVERIFIED at best)
      --replay-writes   allow replaying state-changing requests (the scope hook turns this
                        into an operator approval prompt)

Checks:
    1  CVSS Consistency  — score range matches severity label; vector is well-formed
    2  Evidence Exists   — evidence/ has at least one non-empty recognised file
    3  PoC Validity      — poc.py/poc.sh parses; targets the stated affected component
    4  Claims vs Evidence— affected component appears in at least one evidence file
    5  Log Corroboration — the hook-written, hash-chained tool ledger
                           (logs/tool-ledger.ndjson) shows a real tool call to the target.
                           Agent-written logs alone are only a warning (legacy engagements).
    6  Independent Replay— re-sends the requests in replay.json (in scope, through the write
                           gate) and checks each response against its oracle; the fresh
                           transcript is saved to evidence/replay-<UTC>.txt.

Verdicts (exactly one result file per finding; stale ones are removed):
    VALIDATED   all checks pass and the replay reproduced it → artifacts/validated/
    UNVERIFIED  nothing failed, but it could not be reproduced (no replay.json, weak oracle,
                authz finding without a control request, write not approved, expired
                credentials, network error) → artifacts/unverified/
    REJECTED    any check failed, including a replay that did not reproduce
                → artifacts/false-positives/

replay.json (written by the executor next to description.md):
    {"requests": [
       {"name": "exploit", "method": "GET", "url": "https://api.acme.com/v1/users/2",
        "headers": {"Authorization": "Bearer {{env:ACME_USER_A_TOKEN}}"},
        "expect": {"status": [200], "body_contains": ["\"email\":\"victim@"]}},
       {"name": "control", "role": "control", "method": "GET",
        "url": "https://api.acme.com/v1/users/2",
        "expect": {"status": [401, 403]}}]}
    expect keys: status, body_contains, body_not_contains, body_regex, headers_contain.
    {{env:NAME}} is resolved through tools/env-reader.py; secrets are redacted in evidence.

Exit: 0 = validated, 1 = unverified or rejected, 2 = usage error
"""

import hashlib
import importlib.util
import os
import re
import ssl
import sys
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit

TOOLS_DIR = Path(__file__).resolve().parent
REPO_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))
from scope import Scope  # noqa: E402
import write_gate  # noqa: E402


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


# ── Check 5: Log Corroboration (hook-written ledger) ──────────────────────────
def _ledger():
    spec = importlib.util.spec_from_file_location("tool_ledger", TOOLS_DIR / "tool-ledger.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _corroboration_needles(info, replay_spec):
    """Host + first distinctive path segment of the affected component / replay URLs."""
    urls = []
    if replay_spec:
        urls += [r.get("url", "") for r in replay_spec.get("requests", []) if isinstance(r, dict)]
    urls += re.findall(r"https?://[^\s|`)>\]]+", info.get("affected", ""))
    if not urls:        # no Affected Component line: fall back to URLs in the write-up
        urls += re.findall(r"https?://[^\s|`)>\]'\"]+", info.get("full_text", ""))[:5]
    pairs = []
    for u in urls:
        try:
            parts = urlsplit(u)
        except ValueError:
            continue
        if not parts.hostname:
            continue
        segs = [s for s in parts.path.split("/") if s and not re.fullmatch(r"\{.*\}|\d+|[0-9a-f-]{16,}", s)]
        pairs.append((parts.hostname.lower(), segs[0].lower() if segs else ""))
    return list(dict.fromkeys(pairs))


def check_log_corroboration(finding_dir, output_dir, info, replay_spec=None):
    ledger = _ledger()
    ok, msg, entries = ledger.verify(output_dir)
    if entries:
        if not ok:
            return RESULT["fail"], (f"tool ledger failed verification: {msg}. Hook-written "
                                    f"evidence was edited — treat the engagement logs as untrusted.")
        needles = _corroboration_needles(info, replay_spec)
        if not needles:
            return RESULT["fail"], ("No URL in 'Affected Component' or replay.json to look for "
                                    "in the tool ledger.")
        for host, seg in needles:
            hits = ledger.search(output_dir, [host, seg] if seg else [host])
            if hits:
                h = hits[0]
                return RESULT["pass"], (f"tool ledger #{h['seq']} ({h['ts']}, {h['tool']}) "
                                        f"recorded traffic to {host}/{seg} — {msg}")
        shown = ", ".join(f"{h}/{s}" for h, s in needles[:3])
        return RESULT["fail"], (f"No hook-recorded tool call touched {shown} ({msg}). The "
                                f"finding was not tested by any recorded tool call.")

    # Legacy engagement (no ledger): agent-written logs only — never a clean pass.
    logs_dir = output_dir / "logs"
    log_files = [p for ext in ("*.ndjson", "*.json", "*.txt", "*.log")
                 for p in logs_dir.glob(ext)] if logs_dir.exists() else []
    tokens = set(re.findall(r'[\w.-]{5,}', info.get("affected", "")))
    tokens.update([w for w in re.findall(r'\b[a-zA-Z]{5,}\b', info.get("title", ""))
                   if w.lower() not in ("finding", "bypass", "injection", "unvalidated")][:4])
    tokens = {t for t in tokens if t not in ("https", "http", "example")}
    for lf in log_files:
        try:
            content = lf.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if tokens and any(t.lower() in content for t in tokens):
            return RESULT["warn"], (f"No tool ledger (pre-ledger engagement); only agent-written "
                                    f"log {lf.name} mentions the target. Not independent evidence.")
    return RESULT["fail"], "No tool ledger and no log entry references this finding's target."


# ── Check 6: Independent Replay ───────────────────────────────────────────────
AUTHZ_HINTS = re.compile(
    r"(?i)\b(idor|bola|bfla|broken (?:object|function)|access control|authori[sz]ation|"
    r"privilege|unauthenticated|without authentication|cwe-(?:284|285|639|862|863|566|425))\b")
SENSITIVE_HEADERS = re.compile(r"(?i)^(authorization|cookie|x-api-key|x-auth-token|api-key|"
                               r"x-csrf-token|proxy-authorization)$")
PLACEHOLDER = re.compile(r"\{\{env:([A-Za-z_][A-Za-z0-9_]*)\}\}")
MAX_BODY = 2_000_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _resolve_env(names):
    """Credentials only via tools/env-reader.py (project rule)."""
    if not names:
        return {}
    r = subprocess.run([sys.executable, str(TOOLS_DIR / "env-reader.py"), *sorted(names)],
                       capture_output=True, text=True, cwd=str(REPO_DIR), timeout=30)
    vals = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        if k in names and v != "NOT_SET":
            vals[k] = v
    return vals


def _fill(value, env):
    if not isinstance(value, str):
        return value
    return PLACEHOLDER.sub(lambda m: env.get(m.group(1), m.group(0)), value)


def _send(req, env, timeout):
    url = _fill(req["url"], env)
    headers = {k: _fill(v, env) for k, v in (req.get("headers") or {}).items()}
    body = req.get("body")
    data = None
    if body is not None:
        data = (json.dumps(body) if isinstance(body, (dict, list)) else _fill(str(body), env)).encode()
    r = urllib.request.Request(url, data=data, method=req.get("method", "GET").upper(),
                               headers=headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        resp = opener.open(r, timeout=timeout)
        status, rheaders, rbody = resp.status, dict(resp.headers), resp.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        status, rheaders, rbody = e.code, dict(e.headers or {}), (e.read(MAX_BODY) if e.fp else b"")
    return status, rheaders, rbody.decode("utf-8", "replace")


def _evaluate(expect, status, headers, body):
    """Return list of failed assertions (empty = pass)."""
    fails = []
    want = expect.get("status")
    if want is not None:
        want = want if isinstance(want, list) else [want]
        if status not in want:
            fails.append(f"status {status} not in {want}")
    for s in expect.get("body_contains", []):
        if s not in body:
            fails.append(f"body lacks {s!r}")
    for s in expect.get("body_not_contains", []):
        if s in body:
            fails.append(f"body contains {s!r}")
    for rx in expect.get("body_regex", []):
        if not re.search(rx, body):
            fails.append(f"body doesn't match /{rx}/")
    low = {k.lower(): v for k, v in headers.items()}
    for k, v in (expect.get("headers_contain") or {}).items():
        if v.lower() not in str(low.get(k.lower(), "")).lower():
            fails.append(f"header {k} lacks {v!r}")
    return fails


def _strong_oracle(expect):
    return any(expect.get(k) for k in ("body_contains", "body_regex", "headers_contain",
                                       "body_not_contains"))


def _redact(headers, env_values):
    out = {}
    for k, v in headers.items():
        out[k] = "<redacted>" if SENSITIVE_HEADERS.match(k) else v
    return out


def check_replay(finding_dir, output_dir, info, replay_spec, opts):
    """
    Re-send the finding's requests from replay.json and check the response oracle.
    pass = reproduced now · fail = sent but did not reproduce / out of scope ·
    skip = could not be replayed safely (→ UNVERIFIED).
    """
    if opts.get("no_replay"):
        return RESULT["skip"], "replay disabled (--no-replay)", {}
    if replay_spec is None:
        return RESULT["skip"], ("no replay.json — the finding can't be reproduced "
                                "independently (see executor-role.md for the format)"), {}
    if isinstance(replay_spec, str):
        return RESULT["fail"], f"replay.json is invalid: {replay_spec}", {}
    reqs = replay_spec.get("requests") or []
    if not reqs or not all(isinstance(r, dict) and r.get("url") and isinstance(r.get("expect"), dict)
                           for r in reqs):
        return RESULT["fail"], "replay.json needs requests[] each with url and expect{}", {}
    if not any(_strong_oracle(r["expect"]) for r in reqs):
        return RESULT["skip"], ("oracle too weak: at least one request must assert on the body "
                                "or headers, not just the status code"), {}
    text = info.get("full_text", "") + " " + info.get("title", "")
    if AUTHZ_HINTS.search(text) and not any(r.get("role") == "control" for r in reqs):
        return RESULT["skip"], ("authorization finding without a control request (e.g. the same "
                                "call unauthenticated or as the owner) — a 200 alone doesn't prove "
                                "the access was unauthorised"), {}

    meta_path = output_dir / "engagement.json"
    if not meta_path.exists():
        return RESULT["skip"], "no engagement.json — scope unknown, not replaying", {}
    meta = json.loads(meta_path.read_text())
    scope = Scope.from_engagement(meta)
    for r in reqs:
        reason = scope.reject_reason(r["url"])
        if reason:
            return RESULT["fail"], f"replay URL out of scope: {r['url']} ({reason})", {}
        op = write_gate.classify(r.get("method", "GET"), r["url"],
                                 json.dumps(r.get("body")) if r.get("body") is not None else None,
                                 "replay")
        if op and not (meta.get("write_policy") == "allow"
                       or write_gate.preapproved(op, meta.get("write_allow"))
                       or opts.get("replay_writes")):
            return RESULT["skip"], (f"replay needs a write ({op.label()}); rerun with "
                                    f"--replay-writes (the hook asks the operator) or pre-approve it "
                                    f"with tools/write_gate.py allow"), {}

    names = {m for r in reqs for v in [r["url"], json.dumps(r.get("headers") or {}),
                                       json.dumps(r.get("body"))]
             for m in PLACEHOLDER.findall(v)}
    env = _resolve_env(names)
    missing = names - set(env)
    if missing:
        return RESULT["skip"], (f"credentials not set in .env: {', '.join(sorted(missing))} "
                                f"(refresh the token and rerun)"), {}

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    transcript, results, fails = [], [], []
    for i, r in enumerate(reqs, 1):
        name = r.get("name") or f"request-{i}"
        try:
            status, headers, body = _send(r, env, opts.get("timeout", 20))
        except Exception as e:                      # network error → can't conclude
            return RESULT["skip"], f"{name}: request failed ({type(e).__name__}: {e})", {}
        bad = _evaluate(r["expect"], status, headers, body)
        results.append({"name": name, "role": r.get("role", "exploit"), "status": status,
                        "passed": not bad, "failures": bad,
                        "body_sha256": hashlib.sha256(body.encode()).hexdigest()})
        if bad:
            fails.append(f"{name}: " + "; ".join(bad))
        transcript.append(
            f"### {name} ({r.get('role', 'exploit')})\n"
            f"{r.get('method', 'GET').upper()} {r['url']}\n"
            + "".join(f"{k}: {v}\n" for k, v in _redact(r.get("headers") or {}, env).items())
            + (f"\n{r['body'] if isinstance(r.get('body'), str) else json.dumps(r.get('body'))}\n"
               if r.get("body") is not None else "")
            + f"\n--- response: HTTP {status}\n"
            + "".join(f"{k}: {v}\n" for k, v in _redact(headers, env).items())
            + f"\n{body[:20000]}\n"
            + f"--- assertions: {'PASS' if not bad else 'FAIL: ' + '; '.join(bad)}\n\n")
        time.sleep(opts.get("delay", 0.5))

    ev = finding_dir / "evidence" / f"replay-{ts}.txt"
    ev.parent.mkdir(exist_ok=True)
    ev.write_text(f"# Independent replay by validate-finding.py at {ts}\n\n" + "".join(transcript))
    detail = {"time": ts, "evidence": str(ev.relative_to(finding_dir)), "requests": results}
    if fails:
        return RESULT["fail"], "did not reproduce: " + " | ".join(fails), detail
    return RESULT["pass"], (f"reproduced: {len(results)} request(s) matched their oracle "
                            f"→ evidence/{ev.name}"), detail


def load_replay(finding_dir):
    p = finding_dir / "replay.json"
    if not p.exists():
        return None
    try:
        spec = json.loads(p.read_text())
        return spec if isinstance(spec, dict) else "top level must be an object"
    except ValueError as e:
        return str(e)


# ── Runner ────────────────────────────────────────────────────────────────────
ICONS = {RESULT["pass"]: "✓", RESULT["fail"]: "✗",
         RESULT["warn"]: "⚠", RESULT["skip"]: "–"}
LABELS = {RESULT["pass"]: "PASS", RESULT["fail"]: "FAIL",
          RESULT["warn"]: "WARN", RESULT["skip"]: "SKIP"}
VERDICTS = ("validated", "unverified", "rejected")


def run_checks(finding_dir, strict=False, opts=None):
    """Run all checks. Returns (verdict, results, info, replay_detail)."""
    opts = opts or {}
    finding_dir = Path(finding_dir).resolve()
    desc_path = finding_dir / "description.md"
    if not finding_dir.exists():
        print(f"[ERROR] Finding directory not found: {finding_dir}", file=sys.stderr)
        sys.exit(2)
    if not desc_path.exists():
        print(f"[ERROR] description.md not found in {finding_dir}", file=sys.stderr)
        sys.exit(2)

    output_dir = finding_dir.parent.parent
    info = parse_description(desc_path)
    replay_spec = load_replay(finding_dir)
    fid, width = finding_dir.name, 68
    print(f"\n{'─' * width}")
    print(f"  Validating: {fid}")
    print(f"  Title:      {info['title'][:60]}")
    print(f"  Severity:   {info['severity']}   CVSS: {info['cvss_score']}")
    print(f"{'─' * width}")

    replay_detail = {}

    def _replay():
        outcome, reason, detail = check_replay(finding_dir, output_dir, info, replay_spec, opts)
        replay_detail.update(detail)
        return outcome, reason

    checks = [
        ("cvss_consistency", "CVSS Consistency", lambda: check_cvss_consistency(info)),
        ("evidence_exists", "Evidence Exists", lambda: check_evidence_exists(finding_dir)),
        ("poc_validity", "PoC Validity", lambda: check_poc_validity(finding_dir, info)),
        ("claims_vs_evidence", "Claims vs Evidence",
         lambda: check_claims_vs_evidence(finding_dir, info)),
        ("log_corroboration", "Log Corroboration",
         lambda: check_log_corroboration(finding_dir, output_dir, info,
                                         replay_spec if isinstance(replay_spec, dict) else None)),
        ("replay", "Independent Replay", _replay),
    ]
    results = {}
    for i, (key, label, fn) in enumerate(checks, 1):
        outcome, reason = fn()
        results[key] = {"result": outcome, "reason": reason}
        print(f"  {ICONS[outcome]} Check {i}: {label:<22}  [{LABELS[outcome]}]")
        if outcome != RESULT["pass"]:
            print(re.sub(r'(.{1,62})(\s|$)', r'    \1\n', reason).rstrip())
    print(f"{'─' * width}")

    failures = [k for k, v in results.items()
                if v["result"] == RESULT["fail"] or (strict and v["result"] == RESULT["warn"])]
    if failures:
        verdict = "rejected"
    elif results["replay"]["result"] != RESULT["pass"]:
        verdict = "unverified"
    else:
        verdict = "validated"
    icon = {"validated": "✓", "unverified": "?", "rejected": "✗"}[verdict]
    extra = f"  (failed: {', '.join(failures)})" if failures else \
        ("  (format checks pass, but the finding was not reproduced)" if verdict == "unverified" else "")
    print(f"  {icon} Overall: {verdict.upper()}{extra}")
    print(f"{'─' * width}\n")
    return verdict, results, info, replay_detail


def write_result(finding_dir, verdict, results, info, replay_detail=None):
    finding_dir = Path(finding_dir).resolve()
    output_dir, fid = finding_dir.parent.parent, finding_dir.name
    payload = {
        "finding_id": fid,
        "title": info["title"],
        "severity": info["severity"],
        "cvss_score": info["cvss_score"],
        "verdict": verdict,
        "validated": verdict == "validated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {k: v["result"] for k, v in results.items()},
        "notes": {k: v["reason"] for k, v in results.items() if v["result"] != RESULT["pass"]},
        "replay": replay_detail or None,
    }
    if verdict == "rejected":
        failed = next(k for k, v in results.items() if v["result"] in (RESULT["fail"], RESULT["warn"]))
        payload["failed_check"] = failed
        payload["reason"] = results[failed]["reason"]

    targets = {
        "validated": output_dir / "artifacts" / "validated" / f"{fid}.json",
        "unverified": output_dir / "artifacts" / "unverified" / f"{fid}.json",
        "rejected": output_dir / "artifacts" / "false-positives" / f"{fid}-rejected.json",
    }
    # Exactly one current verdict per finding: remove stale results from earlier runs.
    for v, path in targets.items():
        if v != verdict and path.exists():
            path.unlink()
    out = targets[verdict]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    print(f"  → Written to {out.relative_to(output_dir)}")
    return out


def read_verdicts(output_dir):
    """Map finding_id → verdict from artifacts/ (legacy validated files without replay → unverified)."""
    output_dir = Path(output_dir)
    out = {}
    for sub, verdict in (("false-positives", "rejected"), ("unverified", "unverified"),
                         ("validated", "validated")):
        for p in sorted((output_dir / "artifacts" / sub).glob("*.json")):
            try:
                d = json.loads(p.read_text())
            except ValueError:
                continue
            fid = d.get("finding_id") or p.stem.replace("-rejected", "")
            v = d.get("verdict") or verdict
            if v == "validated" and not (d.get("replay") or {}).get("requests"):
                v = "unverified"                 # pre-replay "validated" = format checks only
            out[fid] = v
    return out


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    args = sys.argv[1:]
    strict, run_all = "--strict" in args, "--all" in args
    opts = {"no_replay": "--no-replay" in args, "replay_writes": "--replay-writes" in args}
    paths = [a for a in args if not a.startswith("--")]
    if not paths:
        print(__doc__)
        sys.exit(2)
    target = Path(paths[0]).resolve()

    if run_all:
        findings_dir = target / "findings"
        if not findings_dir.exists():
            print(f"[ERROR] No findings/ directory under {target}", file=sys.stderr)
            sys.exit(2)
        dirs = sorted(d for d in findings_dir.iterdir()
                      if d.is_dir() and (d / "description.md").exists())
        if not dirs:
            print(f"[INFO] No findings with description.md found in {findings_dir}")
            sys.exit(0)
        counts = {v: 0 for v in VERDICTS}
        for d in dirs:
            verdict, results, info, detail = run_checks(d, strict=strict, opts=opts)
            write_result(d, verdict, results, info, detail)
            counts[verdict] += 1
        print(f"\n{'═' * 68}")
        print(f"  Results: {counts['validated']} validated (reproduced) · "
              f"{counts['unverified']} unverified · {counts['rejected']} rejected  "
              f"of {len(dirs)}")
        if counts["unverified"]:
            print("  Unverified findings are excluded from the report unless you pass "
                  "--include-unverified to generate-report.py.")
        print(f"{'═' * 68}\n")
        sys.exit(0 if counts["validated"] == len(dirs) else 1)

    verdict, results, info, detail = run_checks(target, strict=strict, opts=opts)
    write_result(target, verdict, results, info, detail)
    sys.exit(0 if verdict == "validated" else 1)


if __name__ == "__main__":
    main()
