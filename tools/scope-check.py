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
import shlex
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


# ── Shell-aware command parsing ──────────────────────────────────────────────
# The hook tokenizes each command with shlex, splits it on shell operators into
# individual command stages, strips env-var assignments and command wrappers
# (sudo, env, timeout, xargs, bash -c …), resolves simple $VAR references, then
# checks EACH stage independently. This closes the trivial bypasses that a naive
# "does the whole line start with a scanning tool" check leaves wide open:
#   cd /tmp && nmap OOS   ·   git status; nmap OOS   ·   X=1 nmap OOS
#   bash -c "nmap OOS"    ·   H=OOS; nmap $H          ·   echo OOS | xargs nmap

STMT_SEPS = {";", "&", "&&", "||"}

# Network/scanning binaries: their presence in a stage (or anywhere in the same
# pipeline) means bare host-like tokens should be treated as targets.
NET_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "sshpass",
    "ftp", "tftp", "wpscan", "sslscan", "sslyze", "testssl.sh",
}
SCAN_OR_NET = SCANNING_TOOLS | NET_TOOLS

# Command wrappers: the real command follows them.
SIMPLE_WRAPPERS = {"sudo", "doas", "nohup", "setsid", "stdbuf", "time",
                   "command", "builtin", "exec", "nice", "ionice"}
ARG_WRAPPERS = {"timeout", "watch", "xargs", "env"}     # consume some leading args
SHELL_WRAPPERS = {"bash", "sh", "zsh", "dash", "ksh", "ash"}   # -c "<script>"

# Token last-labels that are local files, not network hosts.
FILE_EXTS = {
    "txt", "md", "py", "json", "log", "html", "htm", "js", "css", "sh", "csv",
    "xml", "yaml", "yml", "conf", "cfg", "ini", "png", "jpg", "jpeg", "gif",
    "svg", "pdf", "zip", "gz", "tar", "tgz", "bak", "db", "sqlite", "pem",
    "key", "crt", "cer", "pcap", "pcapng", "har", "out", "tmp", "lst",
    "nmap", "gnmap",
}

ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?[smhdSMHD]?$")

VALUE_FLAGS = {
    "-p", "--port", "-o", "--output", "-oN", "-oX", "-oG", "-oA",
    "-w", "--wordlist", "-H", "--header", "-b", "--cookie",
    "-e", "--extensions", "-t", "--threads", "-r", "--rate",
    "--tamper", "--dbms", "--level", "--risk", "--tech",
    "--timeout", "--delay", "--retries", "--proxy",
    "-d", "--data", "--body", "--filter-status", "--filter-size",
    "--mc", "--fc", "--fw", "--fl", "--mr", "--fr",
    "-u", "--url", "--host", "--target",        # also target flags (handled below)
    "-iL", "--input-file",
    "--bssid", "--essid", "--channel", "--interface",
}
TARGET_FLAGS = {"-u", "--url", "--host", "--target"}
XARGS_VALUE_FLAGS = {"-I", "-i", "-n", "-P", "-d", "-E", "-s", "-L", "-a", "-l"}


def _basename(tok: str) -> str:
    return Path(tok).name.lower()


def _lex(line: str):
    """shlex-tokenize a single line, keeping shell operators as their own tokens.
    Returns None if the line cannot be parsed (caller falls back to raw scan)."""
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=";&|<>()")
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return None


def _subst(tok: str, env: dict) -> str:
    return _VAR_RE.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), tok)


def _strip_assignments(tokens, env):
    """Pop leading NAME=VALUE tokens into env; return the remaining tokens."""
    i = 0
    while i < len(tokens) and ASSIGN_RE.match(tokens[i]):
        name, _, val = tokens[i].partition("=")
        env[name] = val
        i += 1
    return tokens[i:]


def _unwrap(tokens):
    """Strip command wrappers (sudo/env/timeout/xargs/bash -c …).
    Returns (effective_tokens, inner_shell_script_or_None)."""
    tokens = list(tokens)
    for _ in range(12):                            # depth guard
        if not tokens:
            return tokens, None
        head = _basename(tokens[0])
        if head in SHELL_WRAPPERS:
            if "-c" in tokens:
                ci = tokens.index("-c")
                if ci + 1 < len(tokens):
                    return [], tokens[ci + 1]      # re-parse the inner script
            tokens = tokens[1:]
            continue
        if head in SIMPLE_WRAPPERS:
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                f = tokens[0]
                tokens = tokens[1:]
                if f in ("-n", "-p", "-c") and tokens:
                    tokens = tokens[1:]
            continue
        if head in ARG_WRAPPERS:
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                f = tokens[0]
                tokens = tokens[1:]
                if f in XARGS_VALUE_FLAGS and tokens and not tokens[0].startswith("-"):
                    tokens = tokens[1:]
            if head == "env":
                while tokens and ASSIGN_RE.match(tokens[0]):
                    tokens = tokens[1:]
            elif head in ("timeout", "watch") and tokens and _DURATION_RE.match(tokens[0]):
                tokens = tokens[1:]
            continue
        break
    return tokens, None


def _looks_like_host(tok: str) -> bool:
    """Strict host test for pipeline harvesting: a domain (dot + alpha TLD that
    isn't a file extension) or a valid IP — never a bare word or filename."""
    tok = tok.strip().strip(",;'\"")
    if not tok or tok.startswith("-") or tok.isdigit():
        return False
    host = host_of(tok)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if "." not in host:
        return False
    last = host.rsplit(".", 1)[-1]
    return last.isalpha() and len(last) >= 2 and last not in FILE_EXTS


def _is_local_path_or_file(tok: str) -> bool:
    if tok.startswith(("/", "./", "../", "~/")):
        return True
    base = tok.split("/")[-1]
    if "." in base and base.rsplit(".", 1)[-1].lower() in FILE_EXTS:
        return True
    return False


def _positional_targets(tokens):
    """Positional (non-flag) args of a scanning/net tool that look like targets."""
    targets, i, skip = [], 1, False
    while i < len(tokens):
        tok = tokens[i]
        if skip:
            skip = False
        elif tok in TARGET_FLAGS and i + 1 < len(tokens):
            targets.append(tokens[i + 1]); skip = True
        elif tok in VALUE_FLAGS:
            skip = True
        elif tok.startswith("-"):
            pass
        elif _looks_like_host(tok):
            # bare positional: only a target if it is a dotted host or IP, so
            # tool subcommands (gobuster dir, amass enum) aren't mistaken for hosts
            targets.append(tok)
        i += 1
    return targets


def _segment(tokens):
    """Split a flat token list into pipelines (list of stages, each a token list).
    Parens are dropped (subshell grouping); redirect tokens fall through as noise
    that the host filters below discard."""
    pipelines, pipeline, stage = [], [], []
    for tok in tokens:
        if tok in ("(", ")"):
            continue
        if tok in STMT_SEPS:
            if stage:
                pipeline.append(stage); stage = []
            if pipeline:
                pipelines.append(pipeline); pipeline = []
        elif tok == "|":
            if stage:
                pipeline.append(stage); stage = []
        else:
            stage.append(tok)
    if stage:
        pipeline.append(stage)
    if pipeline:
        pipelines.append(pipeline)
    return pipelines


def _collect_candidates(command: str, env: dict, depth: int = 0) -> list[str]:
    """Walk the command shell-aware and return raw candidate target strings."""
    candidates = []
    if depth > 4:                                  # recursion guard for bash -c chains
        return candidates
    for line in command.replace("\r", "\n").split("\n"):
        if not line.strip():
            continue
        tokens = _lex(line)
        if tokens is None:                         # unparseable — conservative fallback
            candidates += extract_urls(line) + extract_ips(line)
            rough = re.findall(r"[A-Za-z0-9._:/-]+", line)
            if any(_basename(t) in SCAN_OR_NET for t in rough):
                candidates += [t for t in rough if _looks_like_host(t)]
            continue
        for pipeline in _segment(tokens):
            stages = []
            for raw_stage in pipeline:
                sub = [_subst(t, env) for t in raw_stage]
                cmd_tokens = _strip_assignments(sub, env)
                if not cmd_tokens:
                    continue
                safe_str = " ".join(cmd_tokens)
                safe = any(safe_str.startswith(p) for p in SAFE_PREFIXES)
                eff_tokens, inner = _unwrap(cmd_tokens)
                if inner is not None:              # bash -c "<script>": recurse
                    candidates += _collect_candidates(inner, env, depth + 1)
                eff_cmd = _basename(eff_tokens[0]) if eff_tokens else ""
                stages.append({"tokens": cmd_tokens, "eff": eff_tokens,
                               "cmd": eff_cmd, "safe": safe})
            has_scanner = any(s["cmd"] in SCAN_OR_NET for s in stages)
            for s in stages:
                # Harvest host-like tokens from EVERY stage of a pipeline that
                # contains a scanner — even safe-prefixed ones — so a target fed
                # through a pipe (echo OOS | xargs nmap) is still caught.
                if has_scanner:
                    candidates += [t for t in s["tokens"] if _looks_like_host(t)]
                if s["safe"]:
                    continue
                stage_str = " ".join(s["tokens"])
                candidates += extract_urls(stage_str)
                candidates += extract_ips(stage_str)
                if s["cmd"] in SCAN_OR_NET:
                    candidates += _positional_targets(s["eff"])
    return candidates


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
    Returns (allowed, reason). The command is parsed shell-aware (see
    _collect_candidates): split on operators, wrappers/assignments stripped,
    $VARs resolved, each stage checked independently. Host/IP/CIDR decisions are
    delegated to the code-enforced Scope class (deny-wins, default-deny); this
    function adds tzar-bot's per-stage safe-prefix and always-allowed-infra
    layers on top.
    """
    # No active scope — engagement not initialised, allow everything
    if not scope.active:
        return True, "no active scope"

    # Collect candidate targets shell-aware, normalise each to a host, dedupe
    candidates = _collect_candidates(command, {})

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
