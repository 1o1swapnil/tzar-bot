"""
Regression corpus for tools/scope-check.py (the scope PreToolUse hook).

BLOCK cases are real bypasses found in the 2026-11-22 review (12/19 got through the
old hook) plus further evasion shapes. ALLOW cases are everyday pentest/dev commands
that must keep working, so the hook doesn't train people to switch it off.

Scope under test: in = target.com, 10.10.0.0/16 · out = admin.target.com, 10.10.5.0/24
No network traffic: everything is static analysis.
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

_spec = importlib.util.spec_from_file_location("scope_check", TOOLS / "scope-check.py")
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)

SCOPE = Scope(in_scope=["target.com", "10.10.0.0/16"],
              out_of_scope=["admin.target.com", "10.10.5.0/24"])


@pytest.fixture
def work(tmp_path):
    (tmp_path / "in-scope.txt").write_text("api.target.com\nhttps://www.target.com/x\n10.10.1.5\n")
    (tmp_path / "mixed.txt").write_text("api.target.com\nevil.com\n")
    (tmp_path / "poc.py").write_text("import requests\nrequests.get('https://evil.com/x')\n")
    (tmp_path / "ok_poc.py").write_text(
        "import requests\nr = requests.get('https://api.target.com/v1',\n"
        "    headers={'Origin': 'https://evil.com'})\n")
    (tmp_path / "run.sh").write_text("#!/bin/sh\ncurl -s https://evil.com\n")
    return tmp_path


def check(cmd, cwd, scope=SCOPE):
    c = sc.Checker(scope, cwd=cwd, env={}, safe_prefixes=(), allowed_hosts=sc.INFRA_HOSTS)
    c.check_command(cmd)
    return c.problems


BLOCK = [
    # ── the 12 bypasses from the review ──
    "curl evil.com",
    "echo x; curl https://evil.com",
    "cd /tmp && nmap 8.8.4.5",
    "rm -f x; sqlmap -u https://evil.com/?id=1",
    "sudo nmap -sV evil.com",
    "python3 -c \"import requests;requests.get('http://'+'evil.com')\"",
    "wget evil.com",
    "nc evil.com 80",
    "nmap -iL hosts-that-do-not-exist.txt",
    "curl -H 'Host: admin.target.com' https://target.com",
    "proxychains nmap evil.com",
    "TARGET=evil.com; nmap $TARGET",
    # ── deny-wins, URL tricks, encodings ──
    "curl https://admin.target.com/",
    "curl https://target.com@evil.com/",
    "curl 'https://evil.com/?next=https://target.com'",
    "nmap 10.10.5.7",
    "nmap 10.10.0.0/16",                     # overlaps the excluded /24
    "nmap 10.11.0.0/24",
    "nmap 0x08080405",                       # hex 8.8.4.5
    "nmap 134743045",                        # decimal 8.8.4.5
    "curl http://127.1.evil.com",
    "curl 'http://[2001:db8::1]/'",
    "ffuf -u https://evil.com/FUZZ -w words.txt",
    "nuclei -target evil.com",
    "subfinder -d evil.com -silent",
    "httpx -u evil.com",
    # ── shell structure ──
    "true && curl https://evil.com",
    "false || curl https://evil.com",
    "curl https://target.com & curl https://evil.com",
    "ls\ncurl https://evil.com",
    "echo $(curl -s https://evil.com)",
    "echo `wget -qO- evil.com`",
    "diff <(curl -s https://evil.com) <(curl -s https://target.com)",
    "bash -c 'curl https://evil.com'",
    "sh -c \"nmap evil.com\"",
    "eval 'curl https://evil.com'",
    "bash <<'EOF'\ncurl https://evil.com\nEOF",
    "for h in evil.com target.com; do curl $h; done",
    "curl $UNKNOWN_HOST",
    "curl \"$(cat /etc/hostname)\"",
    "timeout 5 nohup nice -n 5 curl https://evil.com",
    "env FOO=1 curl https://evil.com",
    "export T=evil.com && curl https://$T/",
    "find . -name x -exec curl https://evil.com \\;",
    "ssh user@evil.com",
    "ssh user@10.10.1.5 'curl https://evil.com'",
    "scp file.txt root@evil.com:/tmp/",
    "git clone https://evil.com/repo.git",
    # ── stdin feeds and target files ──
    "echo evil.com | httpx -silent",
    "printf 'target.com\\nevil.com' | nuclei",
    "cat mixed.txt | httpx",
    "httpx -l mixed.txt",
    "nmap -iL mixed.txt",
    "echo evil.com | xargs curl",
    "httpx <<< evil.com",
    # ── interpreters / scripts ──
    "python3 -c \"import requests; requests.get('https://evil.com')\"",
    "python3 -c \"import requests; requests.get(url='https://evil.com')\"",
    "python3 -c \"import socket; socket.create_connection(('evil.com', 80))\"",
    "python3 -c \"h='x'; import requests; requests.get(f'https://{h}/')\"",
    "python3 - <<'EOF'\nimport urllib.request\nurllib.request.urlopen('https://evil.com')\nEOF",
    "node -e \"fetch('https://evil.com')\"",
    "python3 poc.py",
    "python3 exploit.py https://evil.com",
    "sh run.sh",
    "docker run --rm projectdiscovery/nuclei -u https://evil.com",
    # ── network clients ──
    "curl --resolve target.com:443:8.8.4.5 https://target.com",
    "openssl s_client -connect evil.com:443",
    "impacket-secretsdump corp/admin:Passw0rd@8.8.4.5",
    "nxc smb 10.20.0.0/24 -u a -p b",
    "hydra -l admin -P p.txt ssh://evil.com",
]

ALLOW = [
    "git status",
    "ls -la && cat in-scope.txt | grep api",
    "python3 tools/nvd-lookup.py CVE-2024-3400",
    f"python3 {TOOLS}/scope.py --in-scope target.com https://evil.com",
    "curl -s https://target.com/",
    "curl -sk -X POST https://api.target.com/login -d 'user=a&next=https://evil.com'",
    "curl -s 'https://target.com/fetch?url=http://evil.com/x'",
    "curl -H 'Origin: https://evil.com' -I https://target.com",
    "curl -H 'Host: evil.com' https://target.com",            # Host-header injection test
    "curl -e https://evil.com https://target.com",
    "curl -x http://127.0.0.1:8080 https://target.com",
    "nmap -sV -p 80,443 -T4 -oN out.nmap 10.10.1.5",
    "nmap 10.10.1.0/24 --top-ports 100",
    "nmap -iL in-scope.txt -oA scan",
    "httpx -l in-scope.txt -silent -mc 200",
    "cat in-scope.txt | httpx -silent",
    "echo target.com | nuclei -t cves/ -severity critical,high",
    "subfinder -d target.com -o subs.txt && httpx -l subs.txt -o live.txt",
    "ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301 -fs 0",
    "ffuf -u https://target.com/ -H 'Host: FUZZ.target.com' -w words.txt",
    "sqlmap -u 'https://target.com/item?id=1' --batch --level 2 --risk 1",
    "TARGET=api.target.com; curl -s https://$TARGET/v1/users",
    "for h in api.target.com www.target.com; do curl -sI https://$h; done",
    "sudo nmap -sS 10.10.1.5",
    "dig +short @8.8.8.8 target.com",
    "whois target.com",
    "hydra -L users.txt -P pass.txt 10.10.1.5 ssh",
    "impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.10.1.1",
    "nxc smb 10.10.1.0/24 -u user -p pass",
    "ssh -i key.pem admin@10.10.1.5 'id; uname -a'",
    "python3 -c \"import requests; print(requests.get('https://api.target.com/v1').status_code)\"",
    "python3 ok_poc.py",
    "python3 -m http.server 8000",
    "python3 -m pytest tools/tests -q",
    "pip install requests",
    "curl -s https://raw.githubusercontent.com/org/repo/main/x.txt",
    "curl -s http://169.254.169.254/latest/meta-data/",
    "interactsh-client -v",
    "curl -s 'https://target.com/?x=$(id)'",
    "jq '.items[] | .url' resp.json | sort -u",
    "echo 'scan done' >> notes.log 2>&1",
    "grep -E 'https?://[^ ]+' resp.txt | sort -u",
    "openssl x509 -in cert.pem -noout -text",
    "base64 -d <<< aGVsbG8=",
]


@pytest.mark.parametrize("cmd", BLOCK)
def test_blocks(cmd, work):
    assert check(cmd, work), f"should be BLOCKED: {cmd!r}"


@pytest.mark.parametrize("cmd", ALLOW)
def test_allows(cmd, work):
    assert check(cmd, work) == [], f"should be ALLOWED: {cmd!r}"


# ── no scope loaded: fail closed ─────────────────────────────────────────────

def test_no_scope_blocks_target_traffic(work):
    assert check("curl https://target.com", work, scope=Scope())
    assert check("nmap 10.10.1.5", work, scope=Scope())


def test_no_scope_still_allows_local_and_infra(work):
    assert check("git status && ls", work, scope=Scope()) == []
    assert check("curl -s https://raw.githubusercontent.com/a/b/c", work, scope=Scope()) == []


# ── MCP tools ────────────────────────────────────────────────────────────────

def mcp(name, tool_input, scope=SCOPE):
    c = sc.Checker(scope, cwd=Path("."), env={}, safe_prefixes=(), allowed_hosts=sc.INFRA_HOSTS)
    c.check_mcp(name, tool_input)
    return c.problems


def burp(host, hdr_host=None):
    req = f"GET / HTTP/1.1\r\nHost: {hdr_host or host}\r\n\r\n"
    return {"content": req, "targetHostname": host, "targetPort": 443, "usesHttps": True}


def test_mcp_burp():
    assert mcp("mcp__burp__send_http1_request", burp("evil.com"))
    assert mcp("mcp__burp__send_http1_request", burp("target.com", "admin.target.com"))
    assert mcp("mcp__burp__send_http1_request", burp("target.com", "evil.com")) == []
    assert mcp("mcp__burp__send_http1_request", burp("api.target.com")) == []
    assert mcp("mcp__burp__send_http2_request",
               {"targetHostname": "target.com", "pseudoHeaders": {":authority": "admin.target.com"},
                "headers": {}, "requestBody": "", "targetPort": 443, "usesHttps": True})
    assert mcp("mcp__burp__get_proxy_http_history", {"count": 10, "offset": 0}) == []


def test_mcp_playwright():
    assert mcp("mcp__playwright__browser_navigate", {"url": "https://evil.com"})
    assert mcp("mcp__playwright__browser_navigate", {"url": "https://www.target.com/login"}) == []
    assert mcp("mcp__playwright__browser_evaluate", {"script": "fetch('https://evil.com/x')"})


def test_mcp_webfetch_is_denylist_only():
    assert mcp("WebFetch", {"url": "https://owasp.org/www-project-top-ten/"}) == []
    assert mcp("WebFetch", {"url": "https://admin.target.com/"})


# ── end-to-end through the hook entry point ──────────────────────────────────

def _hook(payload, env):
    return subprocess.run([sys.executable, str(TOOLS / "scope-check.py")],
                          input=json.dumps(payload), capture_output=True, text=True,
                          env=env, timeout=30)


def test_hook_reads_active_pointer(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "engagement.json").write_text(json.dumps(
        {"in_scope": ["target.com"], "out_of_scope": ["admin.target.com"]}))
    pointer = tmp_path / "active-engagement"
    pointer.write_text(str(eng))
    env = {k: v for k, v in os.environ.items() if k != "OUTPUT_DIR"}
    env.update(TZAR_ACTIVE_POINTER=str(pointer), TZAR_MEMORY_DB=str(tmp_path / "none.db"))
    ok = _hook({"tool_name": "Bash", "tool_input": {"command": "curl https://api.target.com"}}, env)
    assert ok.returncode == 0, ok.stderr
    bad = _hook({"tool_name": "Bash", "tool_input": {"command": "echo hi; curl https://admin.target.com"}}, env)
    assert bad.returncode == 2 and "out-of-scope" in bad.stderr
    burp_bad = _hook({"tool_name": "mcp__burp__send_http1_request", "tool_input": burp("evil.com")}, env)
    assert burp_bad.returncode == 2


def test_hook_no_scope_fails_closed(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "OUTPUT_DIR"}
    env.update(TZAR_ACTIVE_POINTER=str(tmp_path / "missing"), TZAR_MEMORY_DB=str(tmp_path / "none.db"))
    r = _hook({"tool_name": "Bash", "tool_input": {"command": "curl https://anything.com"}}, env)
    assert r.returncode == 2 and "no active engagement" in r.stderr
    r = _hook({"tool_name": "Bash", "tool_input": {"command": "git status"}}, env)
    assert r.returncode == 0
