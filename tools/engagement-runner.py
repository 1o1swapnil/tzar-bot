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
from concurrency import safe_workers, safe_fanout  # noqa: E402  — bounded parallelism

# Shared agent registry helper (used by both the inline coordinator and this runner).
_SUPERVISOR = TOOLS_DIR / "agent-supervisor.py"

def _supervisor_register(output_dir, name, url):
    """Record a delegated executor in the shared <output-dir>/.agents registry so the
    autonomous runner and the inline coordinator use one lifecycle ledger. Best-effort."""
    if not (output_dir and _SUPERVISOR.exists()):
        return
    try:
        subprocess.run([sys.executable, str(_SUPERVISOR), "register",
                        "--output-dir", str(output_dir), "--name", name,
                        "--pid", str(os.getpid()), "--owns", url or "-"],
                       capture_output=True, timeout=10)
    except Exception:
        pass

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
        # Bound scanner concurrency the same way the inline path does: tzar-aware
        # scanners read $TZAR_WORKERS to size their pools and avoid resource kills.
        env = {**os.environ, "TZAR_WORKERS": str(safe_workers())}
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
            out = (r.stdout + ("\n" + r.stderr if r.returncode != 0 else "")).strip()
        except FileNotFoundError:
            return self._deny("run_scanner", f"{tool} not installed")
        except subprocess.TimeoutExpired:
            out = f"[{tool} timed out after 300s]"
        return self._allow("run_scanner", f"ran {tool} against {host_of(target)} "
                           f"(workers<={env['TZAR_WORKERS']})", _scrub(out)[:12000])

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

# Leaf tools — executor sub-agents use these; every call is gated by ToolGate.
LEAF_TOOLS = [
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


# Orchestration tools — the COORDINATOR uses only these. It plans and delegates;
# it never scans inline (the CLAUDE.md coordinator hard-boundary, enforced in code
# by simply not giving it the leaf tools). Executors do the gated scanning.
COORDINATOR_TOOLS = [
    {"name": "add_surface",
     "description": "Record discovered attack surface so executors can test it. "
                    "Out-of-scope items are dropped by the harness.",
     "input_schema": {"type": "object", "additionalProperties": False,
        "properties": {"items": {"type": "array", "items": {
            "type": "object", "properties": {
                "url": {"type": "string"}, "param": {"type": "string"},
                "vuln_class": {"type": "string", "description": "e.g. idor, sqli, xss, ssrf"}},
            "required": ["url", "vuln_class"]}}},
        "required": ["items"]}},
    {"name": "get_worklist",
     "description": "Return the impact-ranked, still-untested attack surface.",
     "input_schema": {"type": "object", "additionalProperties": False,
        "properties": {"top": {"type": "integer", "description": "max items"}}}},
    {"name": "delegate",
     "description": "Delegate ONE surface item to an executor sub-agent. The executor "
                    "claims the item (so no two executors test the same surface), runs the "
                    "gated scanners, writes findings, and returns a summary.",
     "input_schema": {"type": "object", "additionalProperties": False,
        "properties": {"url": {"type": "string"}, "param": {"type": "string"},
                       "vuln_class": {"type": "string"}},
        "required": ["url", "vuln_class"]}},
]


def build_system_prompt(scope: Scope):
    """Coordinator system prompt = routing rules + a mounted skill. Stable → cacheable."""
    parts = [
        "You are the autonomous COORDINATOR for a tzar-bot web-application pentest.",
        "You are PRE-AUTHORIZED for this engagement. Stay strictly within scope; the "
        "harness denies any out-of-scope action, so plan around the declared scope.",
        f"In scope: {scope.in_scope}. Out of scope: {scope.out_of_scope}.",
        "HARD RULE: you never scan or send requests yourself. You PLAN and DELEGATE. "
        "Use add_surface to record discovered surface, get_worklist to see what is "
        "untested, and delegate to hand one item at a time to an executor sub-agent "
        "(which does the gated scanning and reports back). Work the phases recon -> "
        "enumerate -> test -> report; do not re-delegate an item already tested. When "
        "the worklist is exhausted and findings are recorded, stop.",
    ]
    skill = REPO_DIR / "skills" / "web-chain" / "SKILL.md"
    if skill.is_file():
        parts.append("\n\n# Methodology (web-chain skill)\n" + skill.read_text(encoding="utf-8"))
    return "\n".join(parts)


def build_executor_prompt(scope: Scope, item):
    """Executor system prompt — one focused surface item, the gated leaf tools."""
    return (
        "You are a tzar-bot EXECUTOR. You have been delegated ONE attack-surface item to "
        "test. You are PRE-AUTHORIZED and strictly scope-bound; the harness denies any "
        "out-of-scope or destructive action.\n"
        f"In scope: {scope.in_scope}. Out of scope: {scope.out_of_scope}.\n"
        f"Test exactly this item: {json.dumps(item)}\n"
        "Use run_scanner / http_request to gather evidence; if you confirm a real, "
        "exploitable issue, call write_finding with a clear PoC and impact. Do not test "
        "anything outside this item. When done, stop with a one-line summary of the result."
    )


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


# ── engagement state (worklist + work-claim dedup, milestone 2) ───────────────

class EngagementState:
    """Thin wrapper over engagement-state.py — the shared worklist + claims ledger
    that lets executors fan out without two of them testing the same surface."""

    def __init__(self, output_dir):
        self.output_dir = output_dir

    def _run(self, *args):
        cmd = [sys.executable, str(TOOLS_DIR / "engagement-state.py")]
        if self.output_dir:
            cmd += ["--output-dir", str(self.output_dir)]
        cmd += list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def add_surface(self, items):
        return self._run("add-surface", "--json", json.dumps(items)).stdout.strip()

    def worklist(self, top=None, agent=None):
        args = ["worklist"]
        if top is not None:
            args += ["--top", str(top)]
        if agent:
            args += ["--agent", agent]
        return self._run(*args).stdout.strip() or "(worklist empty)"

    def claim(self, url, agent, param="", vuln_class=""):
        r = self._run("claim", "--url", url, "--agent", agent,
                      "--param", param, "--vuln-class", vuln_class)
        return r.returncode == 0          # exit 0 = claimed, 1 = denied (held by another)

    def release(self, url, agent, param="", vuln_class=""):
        self._run("release", "--url", url, "--agent", agent,
                  "--param", param, "--vuln-class", vuln_class)

    def mark_tested(self, url, param="", vuln_class=""):
        self._run("mark-tested", "--url", url, "--param", param, "--vuln-class", vuln_class)


# ── executor sub-agent (milestone 2) ──────────────────────────────────────────

class Executor:
    """Tests ONE claimed surface item with the gated leaf tools, then marks it
    tested and releases the claim. loop_fn(item) is injectable so the fan-out /
    claim / dedup logic is testable with no SDK/network."""

    def __init__(self, gate, state, scope, agent_id, client=None, live=False,
                 loop_fn=None, budget_out_tokens=60000):
        self.gate, self.state, self.scope = gate, state, scope
        self.agent_id, self.client, self.live = agent_id, client, live
        self.loop_fn = loop_fn or self._api_loop
        self.budget = budget_out_tokens

    def run(self, item):
        url = item.get("url", "")
        if not self.state.claim(url, self.agent_id, item.get("param", ""),
                                item.get("vuln_class", "")):
            return {"status": "skipped-claimed", "agent": self.agent_id, "item": item}
        try:
            summary = self.loop_fn(item)
        finally:
            self.state.mark_tested(url, item.get("param", ""), item.get("vuln_class", ""))
            self.state.release(url, self.agent_id, item.get("param", ""),
                               item.get("vuln_class", ""))
        return {"status": "done", "agent": self.agent_id, "item": item, "summary": summary}

    def _api_loop(self, item):
        system = build_executor_prompt(self.scope, item)
        messages = [{"role": "user", "content": "Test the delegated item now."}]
        spent, last_text = 0, ""
        while True:
            resp = self.client.messages.create(
                model=MODEL_EXECUTOR, max_tokens=8000,
                thinking={"type": "adaptive"}, output_config={"effort": "medium"},
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                tools=LEAF_TOOLS, messages=messages)
            spent += resp.usage.output_tokens
            last_text = next((b.text for b in resp.content if b.type == "text"), last_text)
            if resp.stop_reason in ("end_turn", "refusal") or spent >= self.budget:
                break
            messages.append({"role": "assistant", "content": resp.content})
            results = [{"type": "tool_result", "tool_use_id": b.id,
                        "content": (r := self.gate.dispatch(b.name, b.input))[0],
                        "is_error": r[1]}
                       for b in resp.content if b.type == "tool_use"]
            if results:
                messages.append({"role": "user", "content": results})
        return last_text


MODEL_EXECUTOR = "claude-sonnet-4-6"


# ── the coordinator orchestrator (live; needs the SDK + API key) ──────────────

class Engagement:
    """Owns the coordinator loop. Routes leaf tools to the gate and orchestration
    tools (add_surface / get_worklist / delegate) to itself; delegate spawns a
    claiming Executor sub-agent."""

    def __init__(self, scope, output_dir, client, live, budget_out_tokens):
        self.scope, self.output_dir = scope, output_dir
        self.client, self.live, self.budget = client, live, budget_out_tokens
        self.gate = ToolGate(scope, output_dir, live=live)
        self.state = EngagementState(output_dir)
        self._exec_n = 0

    def _coordinate_tool(self, name, args):
        if name == "add_surface":
            return self.state.add_surface(args.get("items", [])), False
        if name == "get_worklist":
            wl = self.state.worklist(top=args.get("top"))
            fan = safe_fanout(args.get("top") or 8)
            return (f"{wl}\n[runner] safe parallel fan-out: delegate at most {fan} "
                    f"item(s) concurrently (cpu-bounded)."), False
        if name == "delegate":
            return json.dumps(self._spawn_executor(args)), False
        return f"BLOCKED by gate: unknown coordinator tool {name!r}", True

    def _spawn_executor(self, item, loop_fn=None):
        """Create a claiming executor, register it in the shared agent registry, run it.
        loop_fn is injectable so the full orchestration is testable without the SDK."""
        self._exec_n += 1
        agent_id = f"exec-{self._exec_n}"
        _supervisor_register(self.output_dir, agent_id, item.get("url", ""))
        ex = Executor(self.gate, self.state, self.scope, agent_id=agent_id,
                      client=self.client, live=self.live, loop_fn=loop_fn)
        return ex.run(item)

    def dispatch(self, name, args):
        if name in ("add_surface", "get_worklist", "delegate"):
            return self._coordinate_tool(name, args)
        return self.gate.dispatch(name, args)   # leaf tools (defensive; coordinator shouldn't call)

    def run(self, target):
        system = build_system_prompt(self.scope)
        messages = [{"role": "user", "content":
                     f"Begin the autonomous pentest of {target}. Start with recon."}]
        spent = 0
        while True:
            resp = self.client.messages.create(
                model=MODEL_COORDINATOR, max_tokens=16000,
                thinking={"type": "adaptive"}, output_config={"effort": "high"},
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                tools=COORDINATOR_TOOLS, messages=messages)
            spent += resp.usage.output_tokens
            if resp.stop_reason == "refusal":
                print("coordinator refused; stopping.", file=sys.stderr); break
            if resp.stop_reason == "end_turn":
                print("coordinator finished the engagement."); break
            messages.append({"role": "assistant", "content": resp.content})
            results = [{"type": "tool_result", "tool_use_id": b.id,
                        "content": (r := self.dispatch(b.name, b.input))[0], "is_error": r[1]}
                       for b in resp.content if b.type == "tool_use"]
            if results:
                messages.append({"role": "user", "content": results})
            if spent >= self.budget:
                print(f"output-token budget reached ({spent}/{self.budget}); stopping."); break
        return 0


def run_coordinator(scope, output_dir, target, live, budget_out_tokens):
    try:
        import anthropic
    except ImportError:
        print("error: `pip install anthropic` (or .[runner]) to run the live loop.",
              file=sys.stderr)
        return 1
    api_key = read_env_key()
    if not api_key:
        print("error: ANTHROPIC_API_KEY not available via env-reader (.env + allowlist).",
              file=sys.stderr)
        return 1
    client = anthropic.Anthropic(api_key=api_key)
    return Engagement(scope, output_dir, client, live, budget_out_tokens).run(target)


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

    # --- milestone 2: worklist + claim dedup + executor fan-out ----------------
    (Path(out) / "engagement.json").write_text(
        json.dumps({"project": "t", "scope": ["acme.com"]}), encoding="utf-8")
    state = EngagementState(out)
    item = {"url": "https://api.acme.com/x?id=1", "param": "id", "vuln_class": "idor"}
    state.add_surface([item])
    assert "acme.com" in state.worklist()
    # the safety property: two executors can't hold the same item at once
    assert state.claim(item["url"], "exec-1", item["param"], item["vuln_class"])
    assert not state.claim(item["url"], "exec-2", item["param"], item["vuln_class"])  # dedup
    state.release(item["url"], "exec-1", item["param"], item["vuln_class"])
    assert state.claim(item["url"], "exec-2", item["param"], item["vuln_class"])
    state.release(item["url"], "exec-2", item["param"], item["vuln_class"])
    # executor fan-out: one tests the item; another skips it while it's held
    assert state.claim(item["url"], "holder", item["param"], item["vuln_class"])
    rec_b = Executor(gate, state, sc, "exec-B", loop_fn=lambda it: "x").run(item)
    assert rec_b["status"] == "skipped-claimed"
    state.release(item["url"], "holder", item["param"], item["vuln_class"])
    seen = []
    rec_a = Executor(gate, state, sc, "exec-A",
                     loop_fn=lambda it: seen.append(it) or "tested").run(item)
    assert rec_a["status"] == "done" and seen == [item]

    # --- end-to-end orchestration (SDK-free): surface -> delegate -> finding ->
    #     shared registry -> validate. Exercises the converged primitives. ----------
    eng = Engagement(sc, out, client=None, live=False, budget_out_tokens=1000)
    # get_worklist now carries the concurrency fan-out hint (converged with concurrency.py)
    wl_txt, _ = eng._coordinate_tool("get_worklist", {"top": 50})
    assert "fan-out" in wl_txt
    e2e_item = {"url": "https://acme.com/e2e?id=9", "param": "id", "vuln_class": "idor"}
    eng.state.add_surface([e2e_item])
    # a delegated executor writes a finding via the gate; _spawn_executor registers it
    # in the shared <out>/.agents ledger (converged with agent-supervisor.py)
    rec = eng._spawn_executor(
        e2e_item,
        loop_fn=lambda it: (eng.gate.dispatch(
            "write_finding", {"name": "finding-e2e", "content": "# Finding: e2e\n\npoc"}),
            "wrote")[1])
    assert rec["status"] == "done"
    assert (Path(out) / "findings" / "finding-e2e" / "description.md").is_file()
    reg = json.loads((Path(out) / ".agents" / "registry.json").read_text())
    assert any(a.get("owns") == e2e_item["url"] for a in reg["agents"].values()), \
        "delegated executor not in shared registry"
    # validate the e2e finding through the adversarial panel -> validated/
    okay, vrec = Validator(out, votes=3, judge_fn=real, mechanical_fn=mech_pass).validate(
        Path(out) / "findings" / "finding-e2e")
    assert okay and vrec["confirmed"]
    assert (Path(out) / "artifacts" / "validated" / "finding-e2e.json").is_file()

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
