#!/usr/bin/env python3
"""
engagement-runner.py — MVP autonomous engagement runner (Level-3).

A manual agentic loop on the Claude API that OWNS the loop so every tool call is
gated through the code-enforced controls BEFORE it executes ("AI decides, code
enforces"). See docs/autonomous-engagement-runner.md for the full architecture.

This MVP wires up:
  - a COORDINATOR loop (Opus 4.8, adaptive thinking, prompt-cached system prompt)
  - a TOOL GATE that runs every tool call through scope.py + pathguard +
    an executable allowlist + an append-only audit log + an output-token budget
  - three gated tools: run_scanner, http_request, write_finding

The TOOL GATE is the safety-critical part and is fully exercised by --selftest
WITHOUT the Anthropic SDK, an API key, network, or a live target. The live loop
(`run`) needs `pip install anthropic`, ANTHROPIC_API_KEY in .env, and a target
you are authorized to test; it executes scanners only with --live.

Usage:
  python3 tools/engagement-runner.py --selftest
  python3 tools/engagement-runner.py run --output-dir "$OUTPUT_DIR" --dry-run
  python3 tools/engagement-runner.py run --output-dir "$OUTPUT_DIR" --live
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
REPO_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

from scope import Scope, host_of          # noqa: E402  — code-enforced scope authority
from pathguard import safe_output_path     # noqa: E402  — write containment

MODEL_COORDINATOR = "claude-opus-4-8"

# Scanners the executor is permitted to run. The model can only ask for these by
# name; a raw shell string is never executed. (These are the executor's tools —
# the coordinator-boundary rule forbids them *inline*, which the runner is not.)
SCANNER_ALLOWLIST = {
    "nmap", "httpx", "ffuf", "gobuster", "feroxbuster", "nuclei",
    "nikto", "whatweb", "katana", "subfinder", "curl", "wafw00f",
}
# Web-only schemes for http_request / scanner targets.
ALLOWED_SCHEMES = {"http", "https"}
# Always-denied substrings — destructive actions are blocked regardless of intent.
DESTRUCTIVE = ("rm -rf", "drop table", "drop database", "delete from",
               "mkfs", "dd if=", ":(){", "shutdown", "reboot")


# ── credentials (per CLAUDE.md: read env only via env-reader.py) ──────────────

def read_env_key(var="ANTHROPIC_API_KEY"):
    r = subprocess.run([sys.executable, str(TOOLS_DIR / "env-reader.py"), var],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith(f"{var}="):
            val = line.split("=", 1)[1].strip()
            if val and val not in ("NOT_SET", "DENIED"):
                return val
    return None


# ── audit log (append-only; a safety + enterprise artifact) ───────────────────

class AuditLog:
    def __init__(self, output_dir):
        self.path = Path(output_dir) / "audit.log" if output_dir else None

    def write(self, decision, tool, detail):
        line = json.dumps({"decision": decision, "tool": tool, "detail": detail})
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        sys.stderr.write(f"[gate] {decision.upper()} {tool}: {detail}\n")


# ── the tool gate — every model tool call passes through here ─────────────────

class ToolGate:
    """Enforce scope / path / allowlist / budget on every tool call.

    dispatch() returns (result_text, is_error). is_error=True hands the denial
    back to the model so it re-plans, exactly like a failed tool result.
    """

    def __init__(self, scope: Scope, output_dir, live=False, audit=None):
        self.scope = scope
        self.output_dir = output_dir
        self.live = live
        self.audit = audit or AuditLog(output_dir)

    # --- shared guards ---------------------------------------------------------
    def _scope_ok(self, target, tool):
        scheme = (target.split("://", 1)[0].lower() if "://" in target else "")
        if scheme and scheme not in ALLOWED_SCHEMES:
            return f"scheme '{scheme}:' is blocked (only http/https)"
        if self.scope.active:
            reason = self.scope.reject_reason(target)
            if reason:
                return reason
        elif not host_of(target):
            return "could not parse a host from target"
        return None

    def _deny(self, tool, reason):
        self.audit.write("deny", tool, reason)
        return f"BLOCKED by gate: {reason}", True

    def _allow(self, tool, detail, result):
        self.audit.write("allow", tool, detail)
        return result, False

    # --- tool handlers ---------------------------------------------------------
    def run_scanner(self, args):
        tool = args.get("tool", "")
        target = args.get("target", "")
        extra = args.get("args", [])
        if tool not in SCANNER_ALLOWLIST:
            return self._deny("run_scanner", f"scanner {tool!r} not in allowlist")
        joined = " ".join([tool, target, *map(str, extra)]).lower()
        if any(bad in joined for bad in DESTRUCTIVE):
            return self._deny("run_scanner", "destructive pattern in command")
        reason = self._scope_ok(target, "run_scanner")
        if reason:
            return self._deny("run_scanner", reason)
        cmd = [tool, *map(str, extra), target]
        if not self.live:
            return self._allow("run_scanner", f"DRY-RUN would execute: {' '.join(cmd)}",
                               f"[dry-run] in-scope; would run: {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            out = (r.stdout + ("\n" + r.stderr if r.returncode != 0 else "")).strip()
        except FileNotFoundError:
            return self._deny("run_scanner", f"{tool} not installed")
        except subprocess.TimeoutExpired:
            out = f"[{tool} timed out after 300s]"
        return self._allow("run_scanner", f"ran {tool} against {host_of(target)}",
                           _scrub(out)[:12000])

    def http_request(self, args):
        url = args.get("url", "")
        method = args.get("method", "GET").upper()
        reason = self._scope_ok(url, "http_request")
        if reason:
            return self._deny("http_request", reason)
        if not self.live:
            return self._allow("http_request", f"DRY-RUN {method} {url}",
                               f"[dry-run] in-scope; would {method} {url}")
        try:
            req = urllib.request.Request(url, method=method,
                                         data=(args.get("body") or "").encode() or None,
                                         headers=args.get("headers", {}))
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (scope-gated)
                body = resp.read(200_000).decode("utf-8", "replace")
                status = resp.status
        except Exception as exc:  # network errors are normal tool results
            return self._allow("http_request", f"{method} {url} errored",
                               f"request error: {exc}")
        return self._allow("http_request", f"{method} {url} -> {status}",
                           f"HTTP {status}\n\n{_scrub(body)[:12000]}")

    def write_finding(self, args):
        name = args.get("name", "finding")
        content = args.get("content", "")
        try:
            path = safe_output_path(self.output_dir or str(REPO_DIR),
                                    "findings", name, "description.md")
        except ValueError as e:
            return self._deny("write_finding", str(e))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return self._allow("write_finding", f"wrote {path}", f"finding written: {path}")

    def dispatch(self, name, args):
        handler = getattr(self, name, None)
        if handler is None or name not in ("run_scanner", "http_request", "write_finding"):
            return self._deny(name, "unknown tool")
        try:
            return handler(args)
        except Exception as exc:  # a tool crash must not kill the loop
            return self._deny(name, f"handler error: {exc}")


def _scrub(text):
    """Strip prompt-injection patterns from tool output before it re-enters context."""
    try:
        r = subprocess.run([sys.executable, str(TOOLS_DIR / "scrub-web-content.py"),
                            "--text", text], capture_output=True, text=True, timeout=30)
        return r.stdout if r.returncode == 0 and r.stdout else text
    except Exception:
        return text


# ── tool schemas exposed to the model ─────────────────────────────────────────

COORDINATOR_TOOLS = [
    {"name": "run_scanner",
     "description": "Run an allow-listed security scanner against an in-scope target. "
                    "The harness enforces scope and an executable allowlist before running.",
     "input_schema": {"type": "object", "additionalProperties": False,
        "properties": {
            "tool": {"type": "string", "description": "Scanner name, e.g. nmap, ffuf, nuclei"},
            "target": {"type": "string", "description": "Target URL/host (must be in scope)"},
            "args": {"type": "array", "items": {"type": "string"},
                     "description": "Extra CLI flags"}},
        "required": ["tool", "target"]}},
    {"name": "http_request",
     "description": "Make a single HTTP request to an in-scope URL. Scope-gated and the "
                    "response is scrubbed of injection patterns before you see it.",
     "input_schema": {"type": "object", "additionalProperties": False,
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
            "url": {"type": "string"},
            "headers": {"type": "object"},
            "body": {"type": "string"}},
        "required": ["url"]}},
    {"name": "write_finding",
     "description": "Record a finding to OUTPUT_DIR/findings/<name>/description.md (path-contained).",
     "input_schema": {"type": "object", "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "description": "Finding slug, e.g. finding-001"},
            "content": {"type": "string", "description": "Markdown finding write-up"}},
        "required": ["name", "content"]}},
]


def build_system_prompt(scope: Scope):
    """Coordinator system prompt = routing rules + a mounted skill. Stable → cacheable."""
    parts = [
        "You are the autonomous coordinator for a tzar-bot web-application pentest.",
        "You are PRE-AUTHORIZED for this engagement. Stay strictly within scope; the "
        "harness will deny any out-of-scope action, so plan around the declared scope.",
        f"In scope: {scope.in_scope}. Out of scope: {scope.out_of_scope}.",
        "Work the phases: recon -> enumerate -> test -> validate -> report. Use run_scanner "
        "and http_request to gather evidence, and write_finding for each confirmed issue. "
        "Be efficient; do not repeat tests. When the engagement is complete, stop.",
    ]
    skill = REPO_DIR / "skills" / "web-chain" / "SKILL.md"
    if skill.is_file():
        parts.append("\n\n# Methodology (web-chain skill)\n" + skill.read_text(encoding="utf-8"))
    return "\n".join(parts)


# ── adversarial validator (milestone 3) ──────────────────────────────────────
#
# A finding is only "confirmed" if it survives BOTH the mechanical pre-check
# (validate-finding.py, 5 checks) AND a panel of independent refuters. Each
# refuter runs in its OWN conversation with a distinct lens and is prompted to
# REFUTE — so they cannot rubber-stamp each other or the executor. Structured
# outputs guarantee a valid verdict. This is the #1 defense against hallucinated
# findings, which is the single biggest trust lever for the product.

MODEL_VALIDATOR = "claude-sonnet-4-6"

VERDICT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["is_real", "confidence", "reasoning"],
    "properties": {
        "is_real": {"type": "boolean",
                    "description": "True only if the finding is genuinely exploitable as written"},
        "confidence": {"type": "number", "description": "0.0-1.0"},
        "reasoning": {"type": "string"},
    },
}

# Distinct lenses → perspective-diverse verification (not N identical refuters).
LENSES = ["correctness", "reproducibility", "impact", "false-positive-likelihood"]


class Validator:
    """Mechanical pre-check + adversarial refuter panel → validated | false-positive.

    judge_fn(finding_text, lens) -> verdict dict   and   mechanical_fn(finding_dir)
    -> (passed, output) are injectable so the vote/routing logic is testable with
    no SDK, key, or network.
    """

    def __init__(self, output_dir, votes=3, judge_fn=None, mechanical_fn=None,
                 model=MODEL_VALIDATOR):
        self.output_dir = output_dir
        self.votes = max(1, votes)
        self.model = model
        self.judge_fn = judge_fn or self._api_judge
        self.mechanical_fn = mechanical_fn or self._default_mechanical
        self._client = None

    def _default_mechanical(self, finding_dir):
        r = subprocess.run([sys.executable, str(TOOLS_DIR / "validate-finding.py"),
                            "--", str(finding_dir)], capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()

    def _api_judge(self, finding_text, lens):
        import anthropic
        if self._client is None:
            self._client = anthropic.Anthropic(api_key=read_env_key())
        prompt = (
            f"You are an adversarial security reviewer. Try to REFUTE the finding below "
            f"through the '{lens}' lens. Default to is_real=false if you are uncertain or "
            f"if the evidence does not clearly prove exploitability.\n\n--- FINDING ---\n"
            f"{_scrub(finding_text)[:12000]}")
        resp = self._client.messages.create(
            model=self.model, max_tokens=2000,
            output_config={"format": {"type": "json_schema", "schema": VERDICT_SCHEMA}},
            messages=[{"role": "user", "content": prompt}])
        text = next((b.text for b in resp.content if b.type == "text"), "{}")
        return json.loads(text)

    def validate(self, finding_dir):
        finding_dir = Path(finding_dir)
        name = finding_dir.name or "finding"
        desc = finding_dir / "description.md"
        text = desc.read_text(encoding="utf-8") if desc.is_file() else ""

        mech_ok, mech_out = self.mechanical_fn(finding_dir)
        lenses = [LENSES[i % len(LENSES)] for i in range(self.votes)]
        verdicts = [self.judge_fn(text, lens) for lens in lenses]
        real_votes = sum(1 for v in verdicts if v.get("is_real"))
        majority = real_votes > len(verdicts) // 2          # strict majority
        confirmed = bool(mech_ok and majority)
        route = "validated" if confirmed else "false-positives"

        record = {"finding": name, "confirmed": confirmed,
                  "mechanical_passed": mech_ok, "real_votes": real_votes,
                  "total_votes": len(verdicts),
                  "verdicts": [dict(lens=l, **v) for l, v in zip(lenses, verdicts)],
                  "mechanical_output": mech_out}
        try:
            path = safe_output_path(self.output_dir or str(REPO_DIR),
                                    "artifacts", route, f"{name}.json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            record["written_to"] = str(path)
        except ValueError as e:
            record["write_error"] = str(e)
        return confirmed, record

    def validate_all(self):
        findings = sorted((Path(self.output_dir) / "findings").glob("*/")) \
            if self.output_dir else []
        return [self.validate(d) for d in findings if (d / "description.md").is_file()]


# ── the coordinator loop (live; needs the SDK + API key) ──────────────────────

def run_coordinator(scope, output_dir, target, live, budget_out_tokens):
    try:
        import anthropic
    except ImportError:
        print("error: `pip install anthropic` to run the live loop.", file=sys.stderr)
        return 1
    api_key = read_env_key()
    if not api_key:
        print("error: ANTHROPIC_API_KEY not available via env-reader (.env + allowlist).",
              file=sys.stderr)
        return 1

    client = anthropic.Anthropic(api_key=api_key)
    gate = ToolGate(scope, output_dir, live=live)
    system = build_system_prompt(scope)
    messages = [{"role": "user", "content":
                 f"Begin the autonomous pentest of {target}. Start with recon."}]
    spent = 0

    while True:
        resp = client.messages.create(
            model=MODEL_COORDINATOR,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=COORDINATOR_TOOLS,
            messages=messages,
        )
        spent += resp.usage.output_tokens
        if resp.stop_reason == "refusal":
            print("coordinator refused; stopping.", file=sys.stderr)
            break
        if resp.stop_reason == "end_turn":
            print("coordinator finished the engagement.")
            break
        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for block in resp.content:
            if block.type == "tool_use":
                text, is_error = gate.dispatch(block.name, block.input)
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": text, "is_error": is_error})
        if results:
            messages.append({"role": "user", "content": results})
        if spent >= budget_out_tokens:
            print(f"output-token budget reached ({spent}/{budget_out_tokens}); stopping.")
            break
    return 0


# ── selftest (no SDK / key / network / target required) ───────────────────────

def selftest():
    import tempfile
    out = tempfile.mkdtemp()
    os.environ["TZAR_ENGAGEMENT_ROOTS"] = out   # permit the sandbox dir for write_finding
    sc = Scope(in_scope=["acme.com"], out_of_scope=["admin.acme.com"])
    gate = ToolGate(sc, out, live=False)

    # in-scope scanner in dry-run -> allowed, not executed
    txt, err = gate.dispatch("run_scanner", {"tool": "nmap", "target": "https://acme.com"})
    assert not err and "dry-run" in txt.lower()
    # out-of-scope target -> denied
    _, err = gate.dispatch("run_scanner", {"tool": "nmap", "target": "https://evil.com"})
    assert err
    # deny-wins out-of-scope subdomain
    _, err = gate.dispatch("http_request", {"url": "https://admin.acme.com/x"})
    assert err
    # non-allowlisted scanner -> denied
    _, err = gate.dispatch("run_scanner", {"tool": "metasploit", "target": "https://acme.com"})
    assert err
    # destructive pattern -> denied even in scope
    _, err = gate.dispatch("run_scanner",
                           {"tool": "curl", "target": "https://acme.com", "args": ["rm -rf /"]})
    assert err
    # non-web scheme -> denied
    _, err = gate.dispatch("http_request", {"url": "file:///etc/passwd"})
    assert err
    # unknown tool -> denied
    _, err = gate.dispatch("exfiltrate", {})
    assert err
    # write_finding path containment: traversal denied, in-sandbox allowed
    _, err = gate.dispatch("write_finding", {"name": "../../etc/x", "content": "x"})
    assert err
    txt, err = gate.dispatch("write_finding", {"name": "finding-001", "content": "poc"})
    assert not err and (Path(out) / "findings" / "finding-001" / "description.md").is_file()
    # audit log recorded decisions
    assert (Path(out) / "audit.log").is_file()

    # --- adversarial validator (injected judge + mechanical, no SDK) -----------
    real = lambda txt, lens: {"is_real": True, "confidence": 0.9, "reasoning": lens}
    fake = lambda txt, lens: {"is_real": False, "confidence": 0.9, "reasoning": lens}
    mech_pass = lambda d: (True, "ok")
    mech_fail = lambda d: (False, "check 2 failed")

    # majority real + mechanical pass -> confirmed -> validated/
    ok, rec = Validator(out, votes=3, judge_fn=real, mechanical_fn=mech_pass).validate(
        Path(out) / "findings" / "finding-001")
    assert ok and rec["confirmed"] and "validated" in rec["written_to"]
    assert (Path(out) / "artifacts" / "validated" / "finding-001.json").is_file()
    # majority refuted -> false positive even if mechanical passes
    ok, rec = Validator(out, votes=3, judge_fn=fake, mechanical_fn=mech_pass).validate(
        Path(out) / "findings" / "finding-001")
    assert (not ok) and "false-positives" in rec["written_to"]
    # mechanical fail gates it out even if the panel believes it
    ok, _ = Validator(out, votes=3, judge_fn=real, mechanical_fn=mech_fail).validate(
        Path(out) / "findings" / "finding-001")
    assert not ok
    # split vote (1 of 3 real) is NOT a majority -> false positive
    flip = [real, fake, fake]
    ok, _ = Validator(out, votes=3, mechanical_fn=mech_pass,
                      judge_fn=lambda t, l: flip.pop(0)(t, l)).validate(
        Path(out) / "findings" / "finding-001")
    assert not ok

    print("engagement-runner selftest: PASS")


def main():
    ap = argparse.ArgumentParser(description="Autonomous engagement runner (MVP).")
    ap.add_argument("command", nargs="?", default="run",
                    choices=["run", "selftest", "validate"])
    ap.add_argument("--selftest", action="store_true", help="alias for the selftest command")
    ap.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR", ""))
    ap.add_argument("--finding", default="", help="finding dir to validate (validate command)")
    ap.add_argument("--votes", type=int, default=3, help="refuter panel size (validate)")
    ap.add_argument("--target", default="")
    ap.add_argument("--in-scope", default=None, help="comma-separated in-scope rules (override)")
    ap.add_argument("--out-of-scope", default=None)
    ap.add_argument("--live", action="store_true", help="actually execute scanners/requests")
    ap.add_argument("--dry-run", action="store_true", help="gate only; never execute (default)")
    ap.add_argument("--budget", type=int, default=200000, help="output-token budget")
    a = ap.parse_args()

    if a.selftest or a.command == "selftest":
        selftest()
        return 0

    if a.command == "validate":
        v = Validator(a.output_dir, votes=a.votes)
        results = [v.validate(a.finding)] if a.finding else v.validate_all()
        if not results:
            print("no findings to validate.", file=sys.stderr)
            return 1
        for confirmed, rec in results:
            verdict = "CONFIRMED" if confirmed else "FALSE POSITIVE"
            print(f"{verdict:14} {rec['finding']}  "
                  f"({rec['real_votes']}/{rec['total_votes']} votes, "
                  f"mechanical={'pass' if rec['mechanical_passed'] else 'fail'})")
        return 0

    # Build scope from engagement.json (preferred) or explicit flags.
    scope = Scope()
    meta = Path(a.output_dir) / "engagement.json" if a.output_dir else None
    if meta and meta.exists():
        scope = Scope.load(meta)
    if a.in_scope or a.out_of_scope:
        scope = Scope(in_scope=a.in_scope, out_of_scope=a.out_of_scope)
    if not scope.active:
        print("error: no active scope (need OUTPUT_DIR/engagement.json or --in-scope).",
              file=sys.stderr)
        return 2

    target = a.target or (scope.in_scope[0] if scope.in_scope else "")
    if not target.startswith("http"):
        target = "https://" + target
    return run_coordinator(scope, a.output_dir, target,
                           live=a.live and not a.dry_run, budget_out_tokens=a.budget)


if __name__ == "__main__":
    sys.exit(main())
