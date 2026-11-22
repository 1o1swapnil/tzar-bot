"""
Tests for the write-request gate (tools/write_gate.py + its wiring in scope-check.py).

WRITE cases must reach a human (permissionDecision "ask") under the default policy.
READ cases must pass silently, so routine testing — logins, GraphQL queries,
searches, low-risk sqlmap — doesn't flood the operator with prompts.
The first WRITE case is a real past incident: a POST that swapped a client's live plan.
"""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))
from scope import Scope  # noqa: E402
import write_gate  # noqa: E402

_spec = importlib.util.spec_from_file_location("scope_check_wg", TOOLS / "scope-check.py")
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)

SCOPE = Scope(in_scope=["target.com"], out_of_scope=["admin.target.com"])


def scan(cmd, cwd="."):
    c = sc.Checker(SCOPE, cwd=cwd, env={}, safe_prefixes=(), allowed_hosts=sc.INFRA_HOSTS)
    c.check_command(cmd)
    assert c.problems == [], c.problems          # every case here is in scope
    return c


WRITES = [
    "curl -s -X POST https://api.target.com/tid/7/subscriptions/create/ "
    "-H 'Authorization: Bearer x' --json '{\"subscription_plan_id\":\"31b5\"}'",
    "curl -X DELETE https://api.target.com/users/5",
    "curl -XPUT https://target.com/api/profile -d '{}'",
    "curl -d 'plan=1' https://api.target.com/billing",
    "curl -F file=@x.svg https://target.com/api/logo",
    "curl -T shell.php https://target.com/uploads/",
    "curl -s 'https://target.com/account/delete?id=5'",
    "curl -s https://target.com/api/users/5/deactivate",
    "curl -d '{\"query\":\"mutation { deleteUser(id: 1) { ok } }\"}' https://target.com/graphql",
    "wget --post-data 'a=b' https://target.com/api/x",
    "http POST https://target.com/api/x a=b",
    "http https://target.com/api/x name=bob",
    "ffuf -u https://target.com/api/FUZZ -X POST -d 'x=1' -w w.txt",
    "sqlmap -u 'https://target.com/i?id=1' --risk 3 --batch",
    "sqlmap -u 'https://target.com/i?id=1' --batch --os-shell",
    "sqlmap -u 'https://target.com/i?id=1' --technique=BEUSTQ --batch",
    "python3 -c \"import requests; requests.post('https://api.target.com/x', json={})\"",
    "python3 -c \"import requests; requests.delete('https://api.target.com/x/1')\"",
    "python3 -c \"import requests; s=requests.Session(); s.request('PATCH', 'https://target.com/a')\"",
    "node -e \"fetch('https://target.com/x', {method: 'POST'})\"",
    "python3 - <<'EOF'\nimport requests\nrequests.put('https://target.com/api/me', json={'role': 'admin'})\nEOF",
]

READS = [
    "curl -s https://target.com/",
    "curl -sI https://target.com/",
    "curl -X OPTIONS -i https://target.com/api/x",
    "curl -d 'user=a&pass=b' https://target.com/login",
    "curl -X POST https://target.com/oauth/token -d 'grant_type=password'",
    "curl -s -X POST https://target.com/api/v1/auth -d '{}'",
    "curl -d '{\"query\":\"{ me { id email } }\"}' https://target.com/graphql",
    "curl -G -d 'q=shoes' https://target.com/search",
    "curl -d 'q=1' https://target.com/api/search",
    "sqlmap -u 'https://target.com/i?id=1' --batch --level 2 --risk 1",
    "nuclei -u https://target.com -severity critical,high",
    "ffuf -u https://target.com/FUZZ -w words.txt -mc 200",
    "python3 -c \"import requests; print(requests.get('https://target.com').status_code)\"",
    "http https://target.com/api/x q==1",
]


@pytest.mark.parametrize("cmd", WRITES)
def test_write_detected(cmd):
    c = scan(cmd)
    assert c.writes, f"write NOT detected: {cmd!r}"
    decision, pending = write_gate.decide(c.writes, {})
    assert decision == "ask" and pending


@pytest.mark.parametrize("cmd", READS)
def test_read_passes(cmd):
    c = scan(cmd)
    assert c.writes == [], f"false write: {cmd!r} → {[o.label() for o in c.writes]}"


def test_incident_is_flagged_and_policy_modes():
    c = scan(WRITES[0])
    assert write_gate.decide(c.writes, {"write_policy": "deny"})[0] == "deny"
    assert write_gate.decide(c.writes, {"write_policy": "allow"})[0] == "allow"
    assert write_gate.decide(c.writes, {"write_policy": "bogus"})[0] == "ask"   # unknown → ask


def test_preapproval_glob():
    c = scan("curl -X POST https://api.target.com/v1/comments -d 'x=1'")
    rules = [{"rule": "POST https://api.target.com/v1/comments*", "reason": "test acct"}]
    assert write_gate.decide(c.writes, {"write_allow": rules})[0] == "allow"
    assert write_gate.decide(c.writes, {"write_allow": ["PUT https://api.target.com/*"]})[0] == "ask"
    c2 = scan("curl -X DELETE https://api.target.com/v1/comments/9")
    assert write_gate.decide(c2.writes, {"write_allow": rules})[0] == "ask"


def test_destructive_flag():
    assert write_gate.classify("DELETE", "https://t.com/x").destructive
    assert write_gate.classify("GET", "https://t.com/api/purge-cache").destructive
    assert not write_gate.classify("POST", "https://t.com/api/comments").destructive


# ── trust anchors ────────────────────────────────────────────────────────────

GUARDED = [
    "eval $(python3 tools/init-engagement.py --type WAPT --project x --target https://t.com "
    "--scope t.com --write-policy allow)",
    "python3 tools/scope.py --activate WAPT/x/1",
    "python3 tools/write_gate.py allow 'POST https://t.com/*' --reason r",
    "python3 tools/write_gate.py policy allow",
    "sed -i 's/ask/allow/' WAPT/x/1/engagement.json",
    "echo '{}' > WAPT/x/1/engagement.json",
    "jq '.write_policy=\"allow\"' e/engagement.json > t && mv t e/engagement.json",
    "python3 -c \"import json; json.dump({}, open('WAPT/x/engagement.json', 'w'))\"",
    "python3 - <<'EOF'\nfrom pathlib import Path\nPath('tools/scope-check.py').write_text('')\nEOF",
    "cp /tmp/x .claude/settings.json",
    "echo evil.com >> config/allowed-hosts.txt",
    "rm .tzar/active-engagement",
    "git checkout -- tools/write_gate.py",
    "python3 tools/validate-finding.py WAPT/x/1 --all --replay-writes",
    "echo '{}' >> WAPT/x/1/logs/tool-ledger.ndjson",
    "sed -i 1d WAPT/x/1/logs/tool-ledger.ndjson",
    "cp /tmp/v.py tools/validate-finding.py",
]

UNGUARDED = [
    "cat WAPT/x/1/engagement.json",
    "jq .in_scope WAPT/x/1/engagement.json",
    "grep scope WAPT/x/1/engagement.json > /tmp/out.txt",
    "python3 tools/write_gate.py status",
    "python3 tools/scope.py --active",
    "git diff tools/scope-check.py",
    "python3 -c \"import json; print(json.load(open('WAPT/x/engagement.json')))\"",
    "python3 -m pytest tools/tests/test_write_gate.py -q",
    "python3 tools/validate-finding.py WAPT/x/1 --all",
    "python3 tools/tool-ledger.py verify WAPT/x/1",
    "tail -5 WAPT/x/1/logs/tool-ledger.ndjson",
]


@pytest.mark.parametrize("cmd", GUARDED)
def test_policy_change_needs_human(cmd):
    c = sc.Checker(SCOPE, cwd=".", env={}, safe_prefixes=(), allowed_hosts=sc.INFRA_HOSTS)
    c.check_command(cmd)
    assert c.guards, f"policy change NOT guarded: {cmd!r}"


@pytest.mark.parametrize("cmd", UNGUARDED)
def test_reads_of_policy_files_pass(cmd):
    c = sc.Checker(SCOPE, cwd=".", env={}, safe_prefixes=(), allowed_hosts=sc.INFRA_HOSTS)
    c.check_command(cmd)
    assert c.guards == [], f"false guard: {cmd!r} → {c.guards}"


# ── MCP ──────────────────────────────────────────────────────────────────────

def mcp_writes(name, ti):
    c = sc.Checker(SCOPE, cwd=".", env={}, safe_prefixes=(), allowed_hosts=sc.INFRA_HOSTS)
    c.check_mcp(name, ti)
    return c.writes


def burp1(req):
    return {"content": req, "targetHostname": "api.target.com", "targetPort": 443, "usesHttps": True}


def test_burp_writes():
    post = "POST /tid/7/subscriptions/create/ HTTP/1.1\r\nHost: api.target.com\r\n\r\n{\"id\":1}"
    assert mcp_writes("mcp__burp__send_http1_request", burp1(post))
    get = "GET /tid/7/subscriptions/ HTTP/1.1\r\nHost: api.target.com\r\n\r\n"
    assert mcp_writes("mcp__burp__send_http1_request", burp1(get)) == []
    login = "POST /api/login HTTP/1.1\r\nHost: api.target.com\r\n\r\nu=a&p=b"
    assert mcp_writes("mcp__burp__send_http1_request", burp1(login)) == []
    h2 = {"targetHostname": "api.target.com", "targetPort": 443, "usesHttps": True,
          "pseudoHeaders": {":method": "DELETE", ":path": "/api/users/3"}, "headers": {},
          "requestBody": ""}
    assert mcp_writes("mcp__burp__send_http2_request", h2)[0].destructive
    assert mcp_writes("mcp__burp__create_repeater_tab", burp1(post)) == []   # doesn't send
    assert mcp_writes("mcp__burp__set_task_execution_engine_state", {"running": True})


def test_playwright_ui_writes():
    assert mcp_writes("mcp__playwright__browser_click", {"selector": "text=Delete account"})
    assert mcp_writes("mcp__playwright__browser_click", {"selector": "button:has-text('Next')"}) == []
    assert mcp_writes("mcp__playwright__browser_evaluate",
                      {"script": "fetch('https://target.com/api/x', {method:'DELETE'})"})


# ── end-to-end through the hook ──────────────────────────────────────────────

def _env(tmp_path, policy):
    eng = tmp_path / "eng"
    eng.mkdir(exist_ok=True)
    (eng / "engagement.json").write_text(json.dumps(
        {"in_scope": ["target.com"], "out_of_scope": [], "write_policy": policy, "write_allow": []}))
    env = {k: v for k, v in os.environ.items() if k != "OUTPUT_DIR"}
    env.update(OUTPUT_DIR=str(eng), TZAR_ACTIVE_POINTER=str(tmp_path / "ptr"),
               TZAR_MEMORY_DB=str(tmp_path / "none.db"))
    return env


def _hook(payload, env):
    return subprocess.run([sys.executable, str(TOOLS / "scope-check.py")],
                          input=json.dumps(payload), capture_output=True, text=True,
                          env=env, timeout=30)


def test_hook_asks_for_writes(tmp_path):
    r = _hook({"tool_name": "Bash", "tool_input": {
        "command": "curl -X DELETE https://api.target.com/users/5"}}, _env(tmp_path, "ask"))
    assert r.returncode == 0
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and "DESTRUCTIVE DELETE" in out["permissionDecisionReason"]


def test_hook_read_is_silent(tmp_path):
    r = _hook({"tool_name": "Bash", "tool_input": {"command": "curl -s https://api.target.com/"}},
              _env(tmp_path, "ask"))
    assert r.returncode == 0 and r.stdout.strip() == ""


def test_hook_deny_policy_blocks(tmp_path):
    r = _hook({"tool_name": "Bash", "tool_input": {
        "command": "curl -d x=1 https://api.target.com/api/x"}}, _env(tmp_path, "deny"))
    assert r.returncode == 2 and "WRITE BLOCKED" in r.stderr


def test_hook_allow_policy_still_guards_policy_files(tmp_path):
    env = _env(tmp_path, "allow")
    r = _hook({"tool_name": "Bash", "tool_input": {
        "command": "curl -d x=1 https://api.target.com/api/x"}}, env)
    assert r.returncode == 0 and r.stdout.strip() == ""
    r = _hook({"tool_name": "Edit", "tool_input": {
        "file_path": "/x/WAPT/a/1/engagement.json", "old_string": "a", "new_string": "b"}}, env)
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    r = _hook({"tool_name": "Write", "tool_input": {"file_path": "/x/notes.md", "content": "x"}}, env)
    assert r.returncode == 0 and r.stdout.strip() == ""


def test_write_gate_cli(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "engagement.json").write_text(json.dumps({"in_scope": ["t.com"]}))
    run = lambda *a: subprocess.run([sys.executable, str(TOOLS / "write_gate.py"),
                                     "--output-dir", str(eng), *a],
                                    capture_output=True, text=True, timeout=30)
    assert run("allow", "POST https://t.com/api/x*", "--reason", "test").returncode == 0
    assert "POST https://t.com/api/x*" in run("status").stdout
    assert run("policy", "deny").returncode == 0
    meta = json.loads((eng / "engagement.json").read_text())
    assert meta["write_policy"] == "deny" and len(meta["write_allow"]) == 1
    assert run("revoke", "1").returncode == 0
    assert run("allow", "POST /relative", "--reason", "x").returncode != 0
