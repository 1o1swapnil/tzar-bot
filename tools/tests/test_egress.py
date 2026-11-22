"""
Tests for the egress layer (tools/egress.py, tools/egress_addon.py, write_gate approvals).

No firewall is touched: rule rendering uses a fake resolver, and the proxy test runs a
real mitmdump with the addon on a random localhost port against a local HTTP target.
"""
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))


@pytest.fixture
def iso(tmp_path, monkeypatch):
    """Isolated engagement pointer + egress state dir."""
    eng = tmp_path / "eng"
    eng.mkdir()
    pointer = tmp_path / "active"
    monkeypatch.setenv("TZAR_ACTIVE_POINTER", str(pointer))
    monkeypatch.setenv("TZAR_EGRESS_DIR", str(tmp_path / "egress"))

    def set_meta(**meta):
        (eng / "engagement.json").write_text(json.dumps(meta))
        pointer.write_text(str(eng))
    return eng, set_meta


def _egress():
    spec = importlib.util.spec_from_file_location("egress_t", TOOLS / "egress.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── firewall rendering ───────────────────────────────────────────────────────

FAKE_DNS = {"target.com": {"203.0.113.10"}, "api.target.com": {"203.0.113.11"},
            "admin.target.com": {"203.0.113.10"}, "old.target.com": {"203.0.113.99"},
            "api.anthropic.com": {"160.79.104.10", "2607:6bc0::10"}}


def test_build_sets_and_render():
    eg = _egress()
    meta = {"in_scope": ["target.com", "10.10.0.0/16", "*.dev.target.com", "2001:db8::/32"],
            "out_of_scope": ["admin.target.com", "old.target.com", "10.10.5.0/24"]}
    sets, notes = eg.build_sets(meta, resolve=lambda h: FAKE_DNS.get(h, set()))
    assert {"203.0.113.10", "10.10.0.0/16"} <= sets["scope4"]
    assert "2001:db8::/32" in sets["scope6"]
    assert {"10.10.5.0/24", "203.0.113.99"} <= sets["deny4"]
    assert "203.0.113.10" not in sets["deny4"]                 # shared IP: can't split at L3
    assert any("shares IP 203.0.113.10" in n for n in notes)
    assert any("*.dev.target.com" in n for n in notes)
    assert sets["direct4"] == {"160.79.104.10"} and sets["direct6"] == {"2607:6bc0::10"}
    text = eg.render(sets, 1000)
    assert 'socket cgroupv2 level 2 "user.slice/user-1000.slice" jump restricted' in text
    assert text.index("@deny4") < text.index("@direct4") < text.index("@scope4")  # deny wins
    assert "reject with tcp reset" in text


def test_render_without_engagement_allows_only_infra():
    eg = _egress()
    sets, _ = eg.build_sets({}, resolve=lambda h: FAKE_DNS.get(h, set()))
    assert not sets["scope4"] and not sets["scope6"] and sets["direct4"]


def test_render_is_valid_nft_if_checkable(tmp_path):
    """`nft -c` validates without applying; skipped where sudo/nft isn't available."""
    if not shutil.which("nft") or subprocess.run(["sudo", "-n", "true"],
                                                 capture_output=True).returncode != 0:
        pytest.skip("needs nft + passwordless sudo")
    eg = _egress()
    sets, _ = eg.build_sets({"in_scope": ["10.10.0.0/16"], "out_of_scope": ["10.10.5.0/24"]},
                            resolve=lambda h: FAKE_DNS.get(h, set()))
    f = tmp_path / "r.nft"
    f.write_text(f"table inet {eg.TABLE}\ndelete table inet {eg.TABLE}\n" + eg.render(sets, os.getuid()))
    r = subprocess.run(["sudo", "-n", "nft", "-c", "-f", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# ── policy ───────────────────────────────────────────────────────────────────

def test_policy_host_and_write_decisions(iso):
    eng, set_meta = iso
    set_meta(in_scope=["target.com"], out_of_scope=["admin.target.com"], write_policy="ask",
             write_allow=[{"rule": "POST https://api.target.com/v1/comments*"}])
    eg = _egress()
    p = eg.Policy(reload_every=0)
    assert p.host_decision("api.target.com").kind == "scope"
    assert p.host_decision("pypi.org").kind == "infra"
    assert p.host_decision("admin.target.com").kind == "deny"
    assert not p.host_decision("evil.com").allow
    assert not p.header_host_ok("admin.target.com").allow
    assert p.header_host_ok("evil.com").allow                   # Host-header injection tests
    assert p.write_decision("GET", "https://api.target.com/x", "").allow
    assert p.write_decision("POST", "https://api.target.com/login", "u=a").allow
    assert p.write_decision("POST", "https://api.target.com/v1/comments", "x").allow
    d = p.write_decision("DELETE", "https://api.target.com/v1/users/3", "")
    assert not d.allow and "pending approval" in d.reason
    set_meta(in_scope=["target.com"], write_policy="deny")
    assert "deny" in p.write_decision("PUT", "https://api.target.com/x", "{}").reason


def test_policy_no_engagement_blocks_targets(iso):
    eg = _egress()
    p = eg.Policy(reload_every=0)
    assert not p.host_decision("target.com").allow
    assert p.host_decision("github.com").allow


def test_intent_and_approval_are_one_shot(iso):
    import write_gate
    eng, set_meta = iso
    set_meta(in_scope=["target.com"], write_policy="ask")
    eg = _egress()
    p = eg.Policy(reload_every=0)
    url = "https://api.target.com:443/v1/plans"
    write_gate.record_intent("POST", url)                       # hook asked the operator
    assert p.write_decision("POST", "https://api.target.com/v1/plans", "{}").allow
    assert not p.write_decision("POST", "https://api.target.com/v1/plans", "{}").allow
    rid = next(iter(write_gate.list_pending()))
    write_gate.approve_pending(rid, uses=1)
    assert p.write_decision("POST", "https://api.target.com/v1/plans", "{}").allow
    assert not p.write_decision("POST", "https://api.target.com/v1/plans", "{}").allow


def test_norm_url():
    import write_gate
    assert write_gate.norm_url("HTTPS://API.T.com:443/a?x=1#f") == "https://api.t.com/a?x=1"
    assert write_gate.norm_url("http://t.com:8080") == "http://t.com:8080/"


# ── hook guards for egress escapes ───────────────────────────────────────────

def _guards(cmd):
    spec = importlib.util.spec_from_file_location("sc_eg", TOOLS / "scope-check.py")
    sc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sc)
    from scope import Scope
    c = sc.Checker(Scope(in_scope=["t.com"]), cwd=".", env={}, safe_prefixes=(),
                   allowed_hosts=sc.INFRA_HOSTS)
    c.check_command(cmd)
    return c.guards


@pytest.mark.parametrize("cmd", [
    "sudo python3 tools/egress.py down", "sudo python3 tools/egress.py up",
    "python3 tools/egress.py approve ab12cd34ef", "sudo nft flush ruleset",
    "sudo nft delete table inet tzar_egress", "sudo iptables -F",
    "sudo systemctl stop tzar-egress-proxy", "pkill mitmdump",
    "sudo systemd-run --uid=kali curl https://t.com", "sudo ip netns add x",
    "sudo unshare -n bash", "docker run --rm alpine wget evil.com",
    "echo x > tools/egress_addon.py",
])
def test_egress_escapes_need_human(cmd):
    assert _guards(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "python3 tools/egress.py status", "python3 tools/egress.py render",
    "python3 tools/egress.py pending", "eval \"$(python3 tools/egress.py env)\"",
    "ip addr", "docker ps", "systemctl status ssh",
])
def test_egress_reads_pass(cmd):
    assert _guards(cmd) == [], cmd


# ── real proxy: mitmdump + addon against a local target ──────────────────────

class _Target(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _ok(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self._ok()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._ok()


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def proxy(iso, tmp_path):
    if not shutil.which("mitmdump"):
        pytest.skip("mitmdump not installed")
    eng, set_meta = iso
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{srv.server_address[1]}"
    set_meta(in_scope=["127.0.0.1"], out_of_scope=[], write_policy="ask", write_allow=[])
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    p = subprocess.Popen(["mitmdump", "--listen-host", "127.0.0.1", "--listen-port", str(port),
                          "-q", "--set", f"confdir={tmp_path / 'mitm'}",
                          "--set", "connection_strategy=lazy", "-s", str(TOOLS / "egress_addon.py")],
                         env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.25)
    else:
        p.kill()
        pytest.fail("mitmdump did not start: " + (p.stdout.read() or b"").decode()[-500:])
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
    yield target, opener, port
    p.terminate()
    p.wait(timeout=10)
    srv.shutdown()


def _call(opener, method, url, data=None):
    try:
        r = opener.open(urllib.request.Request(url, data=data, method=method), timeout=10)
        return r.status, r.headers.get("X-Tzar-Egress"), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("X-Tzar-Egress"), e.read().decode()


def test_proxy_enforces_scope_and_writes(proxy):
    import write_gate
    target, opener, port = proxy
    assert _call(opener, "GET", target + "/api/users")[0] == 200
    status, tag, body = _call(opener, "POST", target + "/api/plans", b'{"plan":"full"}')
    assert status == 403 and tag == "blocked" and "pending approval" in body
    rid = body.split("pending approval ")[1].split(".")[0]
    write_gate.approve_pending(rid)
    assert _call(opener, "POST", target + "/api/plans", b'{"plan":"full"}')[0] == 200
    assert _call(opener, "POST", target + "/api/plans", b'{"plan":"full"}')[0] == 403
    status, tag, body = _call(opener, "GET", "http://10.255.255.1/")
    assert status == 403 and "not in scope" in body
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"CONNECT evil.example.invalid:443 HTTP/1.1\r\nHost: evil.example.invalid:443\r\n\r\n")
        assert s.recv(128).startswith(b"HTTP/1.1 403")
    log = (write_gate.state_dir() / "egress.log").read_text()
    assert '"allow": false' in log and "evil.example.invalid" in log
