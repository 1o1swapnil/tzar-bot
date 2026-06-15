#!/usr/bin/env python3
"""
scope-check.py — PreToolUse hook that enforces engagement scope at the tool layer.

Reads engagement scope from $OUTPUT_DIR/engagement.json and blocks Bash commands
that clearly target out-of-scope hosts. Permissive on ambiguity — only blocks when
a target is unambiguously outside declared scope.

Claude Code hook input (stdin): JSON with tool_name and tool_input.command
Exit codes:
    0 = allow
    2 = block (stderr message fed back to Claude as a system reminder)
"""

import sys
import os
import re
import json
import ipaddress
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))
from scope import Scope, host_of  # noqa: E402  — code-enforced scope authority

REPO_DIR = Path(__file__).parent.parent.resolve()

# Tools whose arguments are treated as network targets
SCANNING_TOOLS = {
    "nmap", "masscan", "ffuf", "gobuster", "feroxbuster", "dirsearch", "wfuzz",
    "sqlmap", "ghauri", "nuclei", "nikto", "whatweb", "wafw00f", "wapiti",
    "httpx", "subfinder", "amass", "dnsx", "katana", "gau", "waybackurls",
    "hydra", "medusa", "crackmapexec", "enum4linux", "enum4linux-ng",
    "smbclient", "smbmap", "ldapsearch", "kerbrute", "impacket-GetNPUsers",
    "impacket-GetUserSPNs", "impacket-secretsdump", "impacket-psexec",
    "aireplay-ng", "airodump-ng", "hcxdumptool", "mdk4",
    "drozer", "frida", "objection",
    "pacu", "prowler", "ScoutSuite",
    "ssrfmap", "tplmap", "commix", "dalfox",
}

# Domains that are always legitimate regardless of scope
ALWAYS_ALLOWED = {
    "github.com", "raw.githubusercontent.com", "api.github.com",
    "cli.github.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "nvd.nist.gov", "services.nvd.nist.gov",
    "api.first.org", "www.first.org",
    "cisa.gov", "www.cisa.gov",
    "exploit-db.com", "www.exploit-db.com",
    "shodan.io", "api.shodan.io",
    "crt.sh", "otx.alienvault.com",
    "pypi.org", "files.pythonhosted.org",
    "kali.org", "archive.kali.org", "http.kali.org",
    "debian.org", "security.debian.org", "packages.debian.org",
    "ubuntu.com", "archive.ubuntu.com",
    "anthropic.com", "api.anthropic.com",
    "hackerone.com", "api.hackerone.com",
    "hackthebox.com", "www.hackthebox.com", "app.hackthebox.com",
    "localhost", "127.0.0.1", "::1",
}

# Always-safe command prefixes — skip scope check entirely
SAFE_PREFIXES = (
    "git ", "git\t",
    "python3 tools/", "python3 /home/kali/Documents/tzar-bot/tools/",
    "cat ", "ls ", "mkdir ", "cp ", "mv ", "rm ", "echo ", "printf ",
    "grep ", "awk ", "sed ", "jq ", "curl -s https://api.github.com",
    "curl -s https://nvd.nist.gov", "curl -s https://api.first.org",
    "curl -s https://www.cisa.gov", "curl -s https://exploit-db.com",
    "searchsploit ", "apt-get ", "apt ", "pip ", "pip3 ",
    "hashcat ", "john ", "aircrack-ng ",  # local file operations, not network targets
    "sudo airmon-ng", "sudo ip link",
    "openvpn ", "cd ", "export ", "source ",
    "openssl ", "ssh-keygen", "chmod ", "chown ",
    "volatility", "strings ", "binwalk ", "foremost ",
    "slither ", "mythril ", "echidna ", "forge ",
    "adb ", "jadx ", "apktool ",
    "docker ps", "docker images", "docker inspect",
    "kubectl get", "kubectl describe",
    "aws sts get-caller-identity", "aws iam list",
)


def _load_extra_prefixes() -> tuple:
    """
    Merge operator-maintained safe prefixes from config/safe-prefixes.txt onto the
    built-in defaults, so the allow-list can change without editing this hook.
    One prefix per line; '#' comments and blank lines ignored. Missing file is fine
    (built-ins remain the fallback).
    """
    cfg = Path(os.environ.get("TZAR_SAFE_PREFIXES_FILE")
               or (REPO_DIR / "config" / "safe-prefixes.txt"))
    if not cfg.exists():
        return SAFE_PREFIXES
    extra = []
    try:
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.rstrip("\n")
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            extra.append(line.rstrip())          # preserve a deliberate trailing space
    except OSError:
        return SAFE_PREFIXES
    # de-dupe while preserving order, built-ins first
    seen, merged = set(), []
    for p in (*SAFE_PREFIXES, *extra):
        if p not in seen:
            seen.add(p)
            merged.append(p)
    return tuple(merged)


SAFE_PREFIXES = _load_extra_prefixes()


def load_scope(output_dir: str) -> list[str]:
    """Load scope list from engagement.json."""
    meta_path = Path(output_dir) / "engagement.json"
    if not meta_path.exists():
        return []
    try:
        meta = json.loads(meta_path.read_text())
        scope = meta.get("scope", [])
        if isinstance(scope, str):
            scope = [s.strip() for s in scope.split(",")]
        return [str(s).strip().lower() for s in scope if s]
    except Exception:
        return []


def extract_urls(command: str) -> list[str]:
    """Extract http(s):// URLs from a command string."""
    return re.findall(r'https?://([a-zA-Z0-9._-]+)', command)


def extract_ips(command: str) -> list[str]:
    """Extract IPv4 addresses from a command string."""
    candidates = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', command)
    valid = []
    for c in candidates:
        try:
            ipaddress.ip_address(c)
            valid.append(c)
        except ValueError:
            pass
    return valid


def extract_scanning_targets(command: str) -> list[str]:
    """
    For known scanning tools, extract bare hostnames / IPs that appear
    as positional arguments (not flag values like -o or --output).
    """
    targets = []
    tokens = command.split()
    if not tokens:
        return []
    tool = Path(tokens[0]).name.lower()
    if tool not in SCANNING_TOOLS:
        return []

    skip_next = False
    value_flags = {
        "-p", "--port", "-o", "--output", "-oN", "-oX", "-oG", "-oA",
        "-w", "--wordlist", "-H", "--header", "-b", "--cookie",
        "-e", "--extensions", "-t", "--threads", "-r", "--rate",
        "--tamper", "--dbms", "--level", "--risk", "--tech",
        "--timeout", "--delay", "--retries", "--proxy",
        "-d", "--data", "--body", "--filter-status", "--filter-size",
        "--mc", "--fc", "--fw", "--fl", "--mr", "--fr",
        "-u", "--url",           # handled separately — these ARE targets for some tools
        "--host", "--target",    # handled separately
        "-iL", "--input-file",
        "--bssid", "--essid", "--channel", "--interface",
    }
    target_flags = {"-u", "--url", "--host", "--target"}
    # Note: -t intentionally excluded — it means --threads in ffuf/gobuster/nuclei

    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if skip_next:
            skip_next = False
            i += 1
            continue
        if tok in target_flags and i + 1 < len(tokens):
            targets.append(tokens[i + 1])
            skip_next = True
        elif tok in value_flags:
            skip_next = True
        elif tok.startswith("-"):
            pass  # other flags
        else:
            targets.append(tok)
        i += 1

    return targets


def _always_ok(host: str) -> bool:
    """Infra/tooling hosts and localhost are allowed regardless of scope."""
    if not host:
        return True
    if host in ALWAYS_ALLOWED:
        return True
    try:
        ip = ipaddress.ip_address(host)
        if str(ip) in ("127.0.0.1", "::1") or str(ip).startswith("169.254."):
            return True
    except ValueError:
        pass
    return False


def check_command(command: str, scope: "Scope") -> tuple[bool, str]:
    """
    Returns (allowed, reason). Host/IP/CIDR decisions are delegated to the
    code-enforced Scope class (deny-wins, default-deny); this function only adds
    tzar-bot's safe-prefix and always-allowed-infra layers on top.
    """
    # Skip safe prefixes
    stripped = command.strip()
    for prefix in SAFE_PREFIXES:
        if stripped.startswith(prefix):
            return True, "safe prefix"

    # No active scope — engagement not initialised, allow everything
    if not scope.active:
        return True, "no active scope"

    # Collect candidate targets, normalise each to a host, dedupe
    candidates = []
    candidates += extract_urls(command)
    candidates += extract_ips(command)
    candidates += extract_scanning_targets(command)

    violations = []
    seen = set()
    for raw in candidates:
        raw = (raw or "").strip()
        if not raw or raw.startswith("-"):
            continue
        host = host_of(raw)
        if not host or host in seen:
            continue
        seen.add(host)
        if _always_ok(host):
            continue
        if not scope.in_scope_host(host):
            violations.append(repr(host))

    if violations:
        unique = list(dict.fromkeys(violations))
        return False, (f"OUT-OF-SCOPE target(s): {', '.join(unique[:5])}. "
                       f"In scope: {scope.in_scope}  Out of scope: {scope.out_of_scope}")

    return True, "in scope"


def main():
    # Read hook input from stdin
    try:
        hook_input = json.loads(sys.stdin.read())
    except Exception:
        sys.exit(0)  # can't parse — allow

    tool_name = hook_input.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    # Build the Scope object from OUTPUT_DIR/engagement.json
    output_dir = os.environ.get("OUTPUT_DIR", "")
    scope = Scope()
    meta_path = Path(output_dir) / "engagement.json" if output_dir else None
    if meta_path and meta_path.exists():
        try:
            scope = Scope.load(meta_path)
        except Exception:
            scope = Scope()

    # Fallback: most recent active engagement from memory.db if no OUTPUT_DIR
    if not scope.active and not output_dir:
        try:
            import sqlite3
            db = REPO_DIR / "memory.db"
            if db.exists():
                conn = sqlite3.connect(db)
                row = conn.execute(
                    "SELECT output_dir, scope FROM engagements WHERE status='active' ORDER BY last_updated DESC LIMIT 1"
                ).fetchone()
                conn.close()
                if row:
                    scope = Scope(in_scope=row[1] or "")
        except Exception:
            pass

    allowed, reason = check_command(command, scope)

    if not allowed:
        print(
            f"\n[SCOPE VIOLATION] Command blocked by scope-check.py\n"
            f"Reason: {reason}\n"
            f"Command: {command[:200]}\n"
            f"If this target IS in scope, update engagement.json scope field and re-run init.\n",
            file=sys.stderr
        )
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
