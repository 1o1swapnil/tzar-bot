"""
Tests for validate-finding.py's replay + ledger checks and the three verdicts.

A throwaway HTTP server on 127.0.0.1 plays the target, so the replay really sends
requests and really compares responses. No external network.

Target behaviour:
  GET  /api/users/2   Bearer good → 200 {"email":"victim@acme.test"} · no/other auth → 401
  GET  /public        → 200 "hello"
  POST /api/plans     → 200 {"ok":true}
"""
import importlib.util
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent
PY = sys.executable

_spec = importlib.util.spec_from_file_location("tool_ledger_t", TOOLS / "tool-ledger.py")
ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger)


class Target(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/users/2":
            if self.headers.get("Authorization") == "Bearer good":
                return self._send(200, '{"id":2,"email":"victim@acme.test"}')
            return self._send(401, '{"error":"unauthorized"}')
        if self.path == "/public":
            return self._send(200, "hello", "text/plain")
        return self._send(404, "{}")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/api/plans":
            return self._send(200, '{"ok":true}')
        return self._send(404, "{}")


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


DESC = """# Finding: {title}

| Field | Value |
|-------|-------|
| Severity | Medium |
| CVSS Score | 6.5 |
| CVSS Vector | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| Affected Component | {base}/api/users/2 |

## Description
{body}
"""


def make_engagement(tmp_path, base, *, title="Sensitive data in user profile response",
                    body="The endpoint returns the email address.", replay=None,
                    policy="ask", ledger_entries=True, fid="finding-001"):
    out = tmp_path / "eng"
    (out / "logs").mkdir(parents=True, exist_ok=True)
    (out / "engagement.json").write_text(json.dumps(
        {"in_scope": ["127.0.0.1"], "out_of_scope": [], "write_policy": policy, "write_allow": []}))
    fd = out / "findings" / fid
    (fd / "evidence").mkdir(parents=True, exist_ok=True)
    (fd / "description.md").write_text(DESC.format(title=title, base=base, body=body))
    (fd / "poc.sh").write_text(f"#!/bin/sh\n# SAFE: non-destructive\ncurl -s {base}/api/users/2\n")
    (fd / "evidence" / "request.txt").write_text(f"GET {base}/api/users/2 HTTP/1.1\n")
    (fd / "evidence" / "response.txt").write_text(f"HTTP/1.1 200 OK\n\n{base}/api/users/2 victim@\n")
    if replay is not None:
        (fd / "replay.json").write_text(json.dumps(replay))
    if ledger_entries and not ledger.ledger_path(out).exists():
        ledger.append(out, "Bash", {"command": f"curl -s -H 'Authorization: Bearer good' "
                                               f"{base}/api/users/2"}, {"stdout": "victim@acme.test"})
    return out, fd


def validate(path, *extra):
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    r = subprocess.run([PY, str(TOOLS / "validate-finding.py"), str(path), *extra],
                       capture_output=True, text=True, env=env, timeout=60)
    return r


def verdict_of(out, fid="finding-001"):
    a = out / "artifacts"
    found = [v for v, p in (("validated", a / "validated" / f"{fid}.json"),
                            ("unverified", a / "unverified" / f"{fid}.json"),
                            ("rejected", a / "false-positives" / f"{fid}-rejected.json"))
             if p.exists()]
    assert len(found) == 1, f"expected exactly one verdict file, found {found}"
    return found[0]


def req(base, path="/api/users/2", auth=True, **expect):
    r = {"name": "exploit", "method": "GET", "url": base + path, "expect": expect}
    if auth:
        r["headers"] = {"Authorization": "Bearer good"}
    return r


# ── verdicts ─────────────────────────────────────────────────────────────────

def test_reproduced_finding_is_validated(tmp_path, server):
    out, fd = make_engagement(tmp_path, server, replay={"requests": [
        req(server, status=[200], body_contains=['"email":"victim@'])]})
    r = validate(fd)
    assert r.returncode == 0, r.stdout
    assert verdict_of(out) == "validated"
    rec = json.loads((out / "artifacts" / "validated" / "finding-001.json").read_text())
    assert rec["replay"]["requests"][0]["passed"] is True
    ev = fd / rec["replay"]["evidence"]
    text = ev.read_text()
    assert "victim@acme.test" in text and "Bearer good" not in text   # secret redacted


def test_not_reproduced_is_rejected(tmp_path, server):
    out, fd = make_engagement(tmp_path, server, replay={"requests": [
        req(server, status=[200], body_contains=['"role":"admin"'])]})
    r = validate(fd)
    assert r.returncode == 1 and verdict_of(out) == "rejected"
    rec = json.loads((out / "artifacts" / "false-positives" / "finding-001-rejected.json").read_text())
    assert rec["failed_check"] == "replay" and "did not reproduce" in rec["reason"]


def test_no_replay_json_is_unverified(tmp_path, server):
    out, fd = make_engagement(tmp_path, server)
    assert validate(fd).returncode == 1 and verdict_of(out) == "unverified"


def test_status_only_oracle_is_unverified(tmp_path, server):
    out, fd = make_engagement(tmp_path, server, replay={"requests": [req(server, status=[200])]})
    validate(fd)
    assert verdict_of(out) == "unverified"


def test_authz_finding_needs_control(tmp_path, server):
    title = "IDOR: any user can read another user's profile (BOLA)"
    oracle = dict(status=[200], body_contains=["victim@"])
    out, fd = make_engagement(tmp_path, server, title=title,
                              replay={"requests": [req(server, **oracle)]})
    validate(fd)
    assert verdict_of(out) == "unverified"
    control = req(server, auth=False, status=[401, 403], body_not_contains=["victim@"])
    control.update(name="control", role="control")
    (fd / "replay.json").write_text(json.dumps({"requests": [req(server, **oracle), control]}))
    assert validate(fd).returncode == 0
    assert verdict_of(out) == "validated"            # stale unverified file removed


def test_control_that_also_succeeds_rejects(tmp_path, server):
    title = "Broken access control on /public"
    oracle = dict(status=[200], body_contains=["hello"])
    control = {"name": "control", "role": "control", "method": "GET", "url": server + "/public",
               "expect": {"status": [401, 403]}}
    out, fd = make_engagement(tmp_path, server, title=title, replay={"requests": [
        {"name": "exploit", "method": "GET", "url": server + "/public", "expect": oracle}, control]})
    validate(fd)
    assert verdict_of(out) == "rejected"             # it's just public, not a bypass


def test_out_of_scope_replay_is_rejected(tmp_path, server):
    out, fd = make_engagement(tmp_path, server, replay={"requests": [
        {"name": "x", "method": "GET", "url": "http://10.255.255.1/api",
         "expect": {"body_contains": ["x"]}}]})
    r = validate(fd)
    assert verdict_of(out) == "rejected" and "out of scope" in r.stdout


def test_write_replay_needs_approval(tmp_path, server):
    write = {"name": "exploit", "method": "POST", "url": server + "/api/plans",
             "body": {"plan": "full"}, "expect": {"status": [200], "body_contains": ['"ok":true']}}
    out, fd = make_engagement(tmp_path, server, replay={"requests": [write]})
    r = validate(fd)
    assert verdict_of(out) == "unverified" and "--replay-writes" in r.stdout
    assert validate(fd, "--replay-writes").returncode == 0
    assert verdict_of(out) == "validated"
    out2, fd2 = make_engagement(tmp_path / "b", server, replay={"requests": [write]}, policy="allow")
    assert validate(fd2).returncode == 0


def test_missing_credentials_is_unverified(tmp_path, server):
    r0 = req(server, status=[200], body_contains=["victim@"])
    r0["headers"] = {"Authorization": "Bearer {{env:TZAR_TEST_TOKEN_THAT_IS_NOT_SET_9F2C}}"}
    out, fd = make_engagement(tmp_path, server, replay={"requests": [r0]})
    r = validate(fd)
    assert verdict_of(out) == "unverified" and "credentials not set" in r.stdout


# ── ledger (check 5) ─────────────────────────────────────────────────────────

def test_ledger_chain_and_tamper(tmp_path, server):
    out, fd = make_engagement(tmp_path, server, replay={"requests": [
        req(server, status=[200], body_contains=["victim@"])]})
    ledger.append(out, "Bash", {"command": "nmap 127.0.0.1"}, {"stdout": "80/tcp open"})
    ok, msg, _ = ledger.verify(out)
    assert ok, msg
    lp = ledger.ledger_path(out)
    lines = lp.read_text().splitlines()
    first = json.loads(lines[0])
    first["ts"] = "2026-01-01T08:08:00+00:00"                     # backdate an entry
    lp.write_text("\n".join([json.dumps(first)] + lines[1:]) + "\n")
    assert not ledger.verify(out)[0]
    validate(fd)
    assert verdict_of(out) == "rejected"
    rec = json.loads((out / "artifacts" / "false-positives" / "finding-001-rejected.json").read_text())
    assert rec["failed_check"] == "log_corroboration" and "ledger" in rec["reason"]


def test_ledger_must_show_the_target(tmp_path, server):
    out, fd = make_engagement(tmp_path, server, ledger_entries=False, replay={"requests": [
        req(server, status=[200], body_contains=["victim@"])]})
    ledger.append(out, "Bash", {"command": f"curl -s {server}/public"}, {"stdout": "hello"})
    validate(fd)
    assert verdict_of(out) == "rejected"                          # nothing touched /api/...


def test_legacy_agent_logs_only_warn(tmp_path, server):
    out, fd = make_engagement(tmp_path, server, ledger_entries=False, replay={"requests": [
        req(server, status=[200], body_contains=["victim@"])]})
    (out / "logs" / "executor-notes.log").write_text(f"tested {server}/api/users/2\n")
    assert validate(fd).returncode == 0                           # warn, not fail
    assert validate(fd, "--strict").returncode == 1


def test_ledger_hook_records_network_calls_only(tmp_path):
    out = tmp_path / "eng"
    (out / "logs").mkdir(parents=True)
    (out / "engagement.json").write_text(json.dumps({"in_scope": ["t.com"]}))
    env = {**os.environ, "OUTPUT_DIR": str(out), "TZAR_ACTIVE_POINTER": str(tmp_path / "p")}
    for cmd in ("ls -la", "curl -s https://t.com/x"):
        subprocess.run([PY, str(TOOLS / "tool-ledger.py")], env=env, text=True, timeout=30,
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd},
                                         "tool_response": {"stdout": "ok"}}))
    entries = ledger.read_entries(out)
    assert [e["input"] for e in entries] == ["curl -s https://t.com/x"]
    assert ledger.verify(out)[0]


# ── report gate ──────────────────────────────────────────────────────────────

def test_read_verdicts_treats_legacy_validated_as_unverified(tmp_path):
    spec = importlib.util.spec_from_file_location("vf", TOOLS / "validate-finding.py")
    vf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vf)
    (tmp_path / "artifacts" / "validated").mkdir(parents=True)
    (tmp_path / "artifacts" / "validated" / "finding-001.json").write_text(json.dumps(
        {"finding_id": "finding-001", "validated": True, "checks": {}}))
    assert vf.read_verdicts(tmp_path) == {"finding-001": "unverified"}
