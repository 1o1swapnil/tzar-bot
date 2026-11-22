#!/usr/bin/env python3
"""
scope-check.py — PreToolUse hook: block tool calls that target out-of-scope hosts.

What is checked
  Bash               every segment of the command line: ; && || | & newline, $(...),
                     `...`, <(...), bash -c / sh -c / eval bodies, heredoc bodies,
                     wrappers (sudo, env, timeout, proxychains, xargs, ...), ssh remote
                     commands, -iL/-l target files, hosts piped into stdin-reading tools,
                     inline interpreter code (python -c, perl -e, node -e, heredocs) and
                     scripts the executors wrote.
  mcp__burp__*       targetHostname (default-deny) + Host / :authority (deny-list).
  mcp__playwright__* URL arguments (default-deny) + URLs in evaluated JS.
  WebFetch           deny-list only: research fetches to unrelated sites are allowed,
                     hosts matching an out-of-scope rule are blocked.

Write gate (tools/write_gate.py)
  The same pass records state-changing requests (PUT/PATCH/DELETE, non-auth POSTs, GraphQL
  mutations, destructive paths, risky sqlmap, PoC .post()/fetch, Burp send_*, Playwright
  clicks on Delete/Submit-style controls) and changes to trust anchors (engagement.json,
  .tzar/, config/*, this hook, write_gate.py, .claude/settings*.json). Per engagement
  write_policy: ask → permissionDecision "ask" (the human approves at the prompt),
  deny → exit 2, allow → pass. Trust-anchor changes always ask.

Scope source (first that exists wins)
  1. $OUTPUT_DIR/engagement.json     (hook-process env; mostly tests / MCP scope_check)
  2. .tzar/active-engagement         (pointer written by init-engagement.py /
                                      `scope.py --activate`)
  3. memory.db most recent 'active' engagement → its engagement.json

Policy — fail closed
  * Out-of-scope rules win over everything, including the infrastructure allow-list.
  * With no scope loaded, traffic to any non-infrastructure host is blocked.
  * A network tool whose target is dynamic ($VAR, $(...)) is blocked: the hook can't
    see what it resolves to. Use a literal host or a -iL/-l file (files are checked).
  * Host header values are checked against the out-of-scope list only, so Host-header
    injection tests (Host: evil.com → in-scope IP) still work, but vhost-routing to an
    explicitly excluded host does not.

Operator config (merged onto built-ins, never removes one)
  config/safe-prefixes.txt   segments starting with these prefixes skip the check
  config/allowed-hosts.txt   extra infra hosts (scope pattern syntax), e.g. a private
                             OAST server or package mirror

Known limits — string analysis cannot close these; an egress proxy/firewall can:
  * hosts built at runtime inside third-party binaries or scripts outside the engagement
  * output of one network tool piped into another (subfinder | httpx): the derived host
    list isn't known until it runs. Write it to a file and pass -l FILE to get it checked.
  * in-scope hostnames that DNS-resolve to out-of-scope IPs
  * single-label hostnames (dc01) given as bare words

Exit: 0 = allow, 2 = block (stderr is fed back to the model).
"""

import ipaddress
import json
import os
import re
import shlex
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent.resolve()))
from scope import Scope, _match, read_active  # noqa: E402  — code-enforced scope authority
import write_gate  # noqa: E402  — write-request policy (allow / ask / deny)

REPO_DIR = Path(__file__).parent.parent.resolve()
TOOLS_DIR = REPO_DIR / "tools"
MAX_FILE_BYTES = 5_000_000
MAX_SCRIPT_BYTES = 512_000
MAX_DEPTH = 6

# ── Infrastructure that is never a target (scope pattern syntax: apex + subdomains) ──
INFRA_HOSTS = [
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "ghcr.io",
    "nvd.nist.gov", "first.org", "cisa.gov", "exploit-db.com", "cve.org", "mitre.org",
    "shodan.io", "crt.sh", "otx.alienvault.com",
    "pypi.org", "pythonhosted.org", "npmjs.org", "npmjs.com", "golang.org", "go.dev",
    "crates.io", "rubygems.org", "docker.io", "docker.com", "quay.io",
    "kali.org", "debian.org", "ubuntu.com", "projectdiscovery.io",
    "anthropic.com", "claude.ai", "claude.com",
    "hackerone.com", "hackthebox.com", "bugcrowd.com",
    # OAST / collaborator callback domains (payload destinations, not targets)
    "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me",
    "interact.sh", "oastify.com", "burpcollaborator.net",
    # RFC 2606 documentation domains
    "example.com", "example.org", "example.net",
    "localhost",
    # public DNS resolvers (dig @8.8.8.8 ...)
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
]
LOCAL_NETS = [ipaddress.ip_network(n) for n in
              ("127.0.0.0/8", "::1/128", "169.254.0.0/16", "0.0.0.0/32", "fe80::/10")]

# ── Tool knowledge ───────────────────────────────────────────────────────────
NETWORK_TOOLS = {
    # scanners / fuzzers / web
    "nmap", "masscan", "naabu", "rustscan", "zmap", "ffuf", "gobuster", "feroxbuster",
    "dirsearch", "dirb", "wfuzz", "sqlmap", "ghauri", "nuclei", "nikto", "whatweb",
    "wafw00f", "wapiti", "httpx", "katana", "hakrawler", "gospider", "gau",
    "waybackurls", "arjun", "paramspider", "dalfox", "xsstrike", "commix", "tplmap",
    "sstimap", "ssrfmap", "wpscan", "joomscan", "droopescan", "cmseek", "kiterunner",
    "kr", "testssl", "testssl.sh", "sslscan", "sslyze", "tlsx", "jwt_tool",
    # recon / dns
    "subfinder", "amass", "assetfinder", "dnsx", "dnsrecon", "dnsenum", "fierce",
    "puredns", "shuffledns", "massdns", "theharvester", "dig", "host", "nslookup",
    "whois", "cdncheck",
    # generic network clients
    "curl", "wget", "http", "https", "xh", "aria2c", "lynx", "w3m", "links",
    "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp", "ping", "ping6",
    "traceroute", "tracepath", "hping3", "arping", "websocat", "wscat", "grpcurl",
    "openssl",
    # auth / AD / services
    "hydra", "medusa", "ncrack", "patator", "crackmapexec", "cme", "nxc", "netexec",
    "enum4linux", "enum4linux-ng", "smbclient", "smbmap", "rpcclient", "ldapsearch",
    "ldapdomaindump", "kerbrute", "bloodhound-python", "certipy", "certipy-ad",
    "evil-winrm", "xfreerdp", "rdesktop", "mysql", "psql", "redis-cli", "mongo",
    "mongosh", "snmpwalk", "snmpget", "onesixtyone", "showmount", "rpcinfo",
    # wireless / mobile / cloud
    "aireplay-ng", "airodump-ng", "hcxdumptool", "mdk4", "drozer", "frida",
    "objection", "pacu", "prowler", "scoutsuite",
}
IMPACKET_SCRIPTS = {
    "getnpusers", "getuserspns", "secretsdump", "psexec", "wmiexec", "smbexec",
    "dcomexec", "atexec", "ntlmrelayx", "smbclient", "lookupsid", "samrdump",
    "rpcdump", "gettgt", "getst", "mssqlclient", "reg", "services", "addcomputer",
    "dacledit", "owneredit", "finddelegation", "getadusers", "raisechild",
}
SSH_LIKE = {"ssh", "scp", "sftp", "rsync", "sshpass", "autossh"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
INTERPRETERS = re.compile(r"^(python[0-9.]*|pypy[0-9.]*|perl|ruby|node|nodejs|php|deno|bun)$")
CODE_FLAGS = {"-c", "-e", "-E", "-r", "--eval", "-p", "--print"}

# Tools that read their target list from stdin when piped into.
STDIN_TARGET_TOOLS = {
    "httpx", "nuclei", "katana", "dnsx", "naabu", "hakrawler", "gau", "waybackurls",
    "subfinder", "feroxbuster", "gospider", "dalfox", "tlsx", "cdncheck", "puredns",
    "shuffledns", "massdns", "assetfinder", "nmap", "masscan", "kr", "nc", "ncat",
}

# Flags whose value is a FILE of targets (read and checked line by line).
LIST_FLAGS = {"-iL", "--input-file", "--targets-file", "-tL", "--includefile"}
LIST_FLAGS_BY_TOOL = {
    "httpx": {"-l", "-list"}, "nuclei": {"-l", "-list"}, "katana": {"-l", "-list"},
    "dnsx": {"-l", "-list"}, "naabu": {"-l", "-list"}, "tlsx": {"-l", "-list"},
    "subfinder": {"-dL", "-list"}, "sqlmap": {"-m"}, "wget": {"-i", "--input-file"},
    "hydra": {"-M"}, "medusa": {"-H"}, "dirsearch": {"-l", "--urls-file"},
    "feroxbuster": {"--resume-from"}, "ffuf": set(), "kerbrute": set(),
}
# Flags whose value IS a target.
TARGET_FLAGS = {"-u", "--url", "-url", "-target", "--target", "-host", "--host",
                "-connect", "--hostname", "-J", "-dc-ip", "-target-ip", "--dc-ip"}
TARGET_FLAGS_BY_TOOL = {
    "subfinder": {"-d", "-domain"}, "amass": {"-d"}, "dnsrecon": {"-d"},
    "theharvester": {"-d"}, "gobuster": {"-d", "--domain"}, "nikto": {"-h"},
    "fierce": {"--domain"}, "assetfinder": set(), "certipy": {"-target", "-dc-ip"},
}
# Flags whose value is a payload / file / setting — never a destination.
SKIP_VALUE_FLAGS = {
    "-o", "-oN", "-oX", "-oG", "-oA", "-oJ", "--output", "-output", "-w", "--wordlist",
    "-A", "--user-agent", "-b", "--cookie", "--data", "--data-raw", "--data-binary",
    "--data-urlencode", "--json", "-F", "--form", "--form-string", "--referer",
    "-x", "--proxy", "-proxy", "--preproxy", "--socks5", "--socks5-hostname",
    "-replay-proxy", "--replay-proxy", "--proxy-url", "--exclude", "--excludefile",
    "-D", "-S", "--script-args", "-T", "--cacert", "--cert", "--key", "-E",
    "--tamper", "--dbms", "--technique", "--os", "-X", "--request",
}
SKIP_VALUE_BY_TOOL = {
    "curl": {"-d", "-e", "-u", "--user", "-c", "-K", "-w", "--write-out", "-r", "-m",
             "-y", "-Y", "-C", "--retry", "-D", "--dump-header"},
    "wget": {"-O", "-U", "--header", "--post-data", "-e", "-P", "--user", "--password"},
    "hydra": {"-l", "-L", "-p", "-P", "-C", "-s", "-t", "-m", "-o", "-W"},
    "medusa": {"-u", "-U", "-p", "-P", "-M", "-m", "-n"},
    "nxc": {"-u", "-p", "-H", "-d", "--local-auth"}, "netexec": {"-u", "-p", "-H", "-d"},
    "crackmapexec": {"-u", "-p", "-H", "-d"}, "cme": {"-u", "-p", "-H", "-d"},
    "kerbrute": {"-d", "--domain", "--dc"}, "smbclient": {"-U", "-W"},
    "ldapsearch": {"-D", "-w", "-b"}, "evil-winrm": {"-u", "-p", "-H"},
    "sqlmap": {"-d", "--data", "-p", "--cookie", "-r"}, "ffuf": {"-d", "-e", "-c"},
    "ssh": {"-p", "-i", "-l", "-o", "-L", "-R", "-D", "-F", "-E", "-c", "-m", "-b",
            "-e", "-O", "-Q", "-S", "-W", "-w", "-I"},
    "nc": {"-p", "-s", "-w", "-e", "-c"}, "ncat": {"-p", "-s", "-w", "-e", "-c"},
}
HEADER_FLAGS = {"-H", "--header", "-header"}

WRAPPERS = {"sudo", "doas", "env", "timeout", "nohup", "nice", "ionice", "time",
            "stdbuf", "proxychains", "proxychains4", "torsocks", "tsocks", "unbuffer",
            "exec", "command", "builtin", "setsid", "watch", "strace", "ltrace", "xargs",
            "parallel", "faketime", "chronic"}
WRAPPER_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-C", "-p", "-h", "-U", "-r", "-t"}, "env": {"-u", "-C", "-S"},
    "nice": {"-n"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k", "--signal",
    "--kill-after"}, "stdbuf": {"-i", "-o", "-e"}, "proxychains": {"-f"},
    "proxychains4": {"-f"}, "watch": {"-n", "-d"}, "strace": {"-o", "-e", "-p", "-s"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-a", "-s", "-E"}, "parallel": {"-j", "-I"},
}
SHELL_KEYWORDS = {"then", "do", "else", "elif", "if", "while", "until", "!", "{", "(",
                  "time", "coproc"}
SHELL_TERMINATORS = {"fi", "done", "esac", "}", ")", ";;"}

# Commands that never generate target traffic (their args may feed a pipeline).
LOCAL_COMMANDS = {
    "echo", "printf", "cat", "tac", "ls", "cd", "pwd", "mkdir", "rmdir", "cp", "mv",
    "rm", "touch", "ln", "chmod", "chown", "grep", "egrep", "fgrep", "rg", "awk",
    "gawk", "sed", "jq", "yq", "head", "tail", "sort", "uniq", "wc", "cut", "tr", "tee",
    "less", "more", "file", "stat", "diff", "cmp", "base64", "base32", "xxd", "hexdump",
    "od", "strings", "md5sum", "sha1sum", "sha256sum", "sha512sum", "date", "sleep",
    "true", "false", "test", "[", "[[", "basename", "dirname", "realpath", "readlink",
    "du", "df", "ps", "kill", "pkill", "which", "type", "whoami", "id", "uname",
    "unset", "alias", "history", "column", "paste", "split", "tar", "zip", "unzip",
    "gzip", "gunzip", "zcat", "7z", "xz", "bzip2", "hashcat", "john", "aircrack-ng",
    "binwalk", "foremost", "exiftool", "jadx", "apktool", "ssh-keygen", "iconv", "nl",
    "fold", "rev", "shuf", "seq", "yes", "wait", "jobs", "disown", "trap", "set",
    "shopt", "read", "return", "exit", "break", "continue", "local", "declare",
    "readonly", "typeset", "export", "printenv", "tree", "find", "locate", "xclip",
    "openvpn", "pip", "pip3", "pipx", "apt", "apt-get", "dpkg", "npm", "yarn",
    "go", "cargo", "gem", "make", "cmake", "gcc", "g++", "clang", "rustc", "javac",
    "searchsploit", "volatility", "volatility3", "vol", "vol.py", "slither", "mythril",
    "myth", "echidna", "forge", "adb", "pytest", "ruff", "black",
    "mypy", "semgrep", "gitleaks", "sqlite3", "code", "vim",
    "nano", "systemctl", "service", "journalctl", "ip", "ifconfig", "iwconfig",
    "airmon-ng", "umask", "mktemp", "envsubst", "gpg",
}
FEEDERS = {"echo", "printf", "cat", "tac", "head", "tail", "sort", "uniq"}
# Repo tools that do send target traffic (everything else under tools/ is local).
TRAFFIC_REPO_TOOLS = {"burp-playwright-capture.py", "continuous-scan.py"}

# ── Write-request detection ──────────────────────────────────────────────────
HTTP_CLIENTS = {"curl", "wget", "http", "https", "xh", "ffuf", "wfuzz", "sqlmap", "ghauri",
                "feroxbuster", "dirsearch", "commix", "dalfox", "arjun", "kr", "kiterunner"}
METHOD_FLAGS = {"-X", "--request", "--method", "-method"}
BODY_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json",
              "-F", "--form", "--form-string", "--post-data", "--post-file", "--body-data",
              "--body-file", "--body", "-body"}
HTTP_VALUE_FLAGS = {"-e", "--referer", "-x", "--proxy", "-o", "--output", "-O", "-H",
                    "--header", "-A", "--user-agent", "-b", "--cookie", "-c", "--cookie-jar",
                    "-w", "--write-out", "-u", "--user", "-r", "--range", "-m", "--max-time",
                    "--resolve", "--connect-to", "-K", "--config", "-E", "--cert", "--key",
                    "--cacert", "-U", "--level", "--risk", "--technique", "-p", "--dbms",
                    "--tamper", "--threads", "-t", "-mc", "-fc", "-fs", "-fw", "-fl", "-ms",
                    "-mr", "-fr", "-rate", "--rate", "-wordlist"}
WRITE_CALL = re.compile(
    r"""\.(?P<m>post|put|patch|delete)\s*\(\s*(?:url\s*=\s*)?(?:f?(?P<q>['"`])(?P<u>[^'"`]*)(?P=q))?""",
    re.I)
REQ_CALL = re.compile(
    r"""\.request\s*\(\s*(?P<q>['"])(?P<m>[A-Za-z]+)(?P=q)\s*,\s*(?:f?(?P<q2>['"])(?P<u>[^'"]*)(?P=q2))?""")
METHOD_KW = re.compile(r"""(?i)\bmethod\s*[:=]\s*(?P<q>['"])(?P<m>POST|PUT|PATCH|DELETE)(?P=q)""")
UI_WRITE_WORDS = re.compile(
    r"(?i)\b(delete|remove|destroy|deactivate|disable|cancel|terminate|revoke|reset|"
    r"unsubscribe|archive|submit|save|update|confirm|pay|purchase|buy|checkout|transfer|"
    r"send|publish|approve|reject|create|invite|upgrade|downgrade|subscribe)\b")

# ── Trust anchors: changing these changes what the gate enforces → human approval ──
PROTECTED = re.compile(
    r"(?:^|[\s/'\"=])(?:[\w./-]*/)?(?:engagement\.json|\.tzar/[\w.-]*|config/allowed-hosts\.txt|"
    r"config/safe-prefixes\.txt|tools/scope-check\.py|tools/scope\.py|tools/write_gate\.py|"
    r"\.claude/settings(?:\.local)?\.json)")
CODE_FILE_WRITE = re.compile(
    r"write_text|write_bytes|open\([^)]*['\"][wax]\+?['\"]|\.write\(|json\.dump\(|shutil\.|"
    r"os\.(?:replace|rename|remove|unlink)|\.unlink\(|\.rename\(|writeFileSync|writeFile\(")
PROTECTED_REDIRECT = re.compile(
    r">{1,2}\s*['\"]?[^\s'\"]*(?:engagement\.json|\.tzar/|allowed-hosts\.txt|safe-prefixes\.txt|"
    r"scope-check\.py|scope\.py|write_gate\.py|settings(?:\.local)?\.json)")
READONLY_TOOLS = {"cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "jq",
                  "wc", "ls", "stat", "diff", "cmp", "file", "sed", "awk", "gawk", "sha256sum",
                  "md5sum", "realpath", "readlink", "test", "[", "echo", "printf", "perl"}
READONLY_REPO_TOOLS = {"scope.py", "validate-finding.py", "generate-report.py",
                       "engagement-state.py", "report-export.py", "session-memory.py",
                       "continuous-scan.py", "token-meter.py", "memory-search.py",
                       "write_gate.py", "scope-check.py"}


def _summarise_init(args):
    want = {"--target": "target", "--scope": "in", "--out-of-scope": "out",
            "--write-policy": "write-policy", "--type": "type", "--project": "project"}
    out, i = [], 0
    while i < len(args):
        flag, _, att = args[i].partition("=")
        if flag in want:
            val = att or (args[i + 1] if i + 1 < len(args) else "")
            out.append(f"{want[flag]}={val}")
            i += 1 if att else 2
            continue
        i += 1
    if not any(o.startswith("write-policy=") for o in out):
        out.append("write-policy=ask")
    return ", ".join(out)


ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")
# Dotted tokens with these endings are files, never hosts.
FILE_EXTS = {
    "txt", "json", "xml", "csv", "tsv", "html", "htm", "lst", "list", "yaml", "yml",
    "log", "out", "gnmap", "nmap", "req", "pcap", "pcapng", "cap", "conf", "cfg", "ini",
    "pem", "crt", "der", "pfx", "p12", "jar", "war", "zip", "gz", "tgz", "bz2", "xz",
    "tar", "bak", "sqlite", "db", "ovpn", "exe", "dll", "ps1", "bat", "apk", "ipa",
    "png", "jpg", "jpeg", "gif", "pdf", "docx", "xlsx", "js", "php", "jsp", "aspx",
    "asp", "har", "kirbi", "ccache", "hash", "hashes", "key", "toml", "lock", "env",
}
# Real TLDs that are also common file extensions: a file only if it exists.
AMBIGUOUS_EXTS = {"sh", "py", "md", "pl", "rs", "so", "cc", "go", "ts", "rb", "cs", "ps"}
# For commands we know nothing about, only these TLDs make a bare word a host.
COMMON_TLDS = {
    "com", "net", "org", "io", "co", "ai", "app", "dev", "gov", "edu", "mil", "int",
    "info", "biz", "us", "uk", "in", "de", "fr", "nl", "eu", "ru", "cn", "jp", "au",
    "ca", "br", "es", "it", "ch", "se", "no", "pl", "me", "xyz", "cloud", "tech",
    "site", "online", "store", "shop", "live", "pro", "sg", "ae", "nz", "za", "kr",
    "id", "ie", "be", "at", "dk", "fi", "pt", "mx", "ar", "tw", "hk", "il", "tr",
}


# ── Config ───────────────────────────────────────────────────────────────────
def _read_lines(path: Path) -> list:
    try:
        return [l.rstrip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines()
                if l.strip() and not l.strip().startswith("#")]
    except OSError:
        return []


def load_safe_prefixes() -> tuple:
    cfg = Path(os.environ.get("TZAR_SAFE_PREFIXES_FILE")
               or (REPO_DIR / "config" / "safe-prefixes.txt"))
    return tuple(dict.fromkeys(_read_lines(cfg)))


def load_allowed_hosts() -> list:
    cfg = Path(os.environ.get("TZAR_ALLOWED_HOSTS_FILE")
               or (REPO_DIR / "config" / "allowed-hosts.txt"))
    return INFRA_HOSTS + [l.strip() for l in _read_lines(cfg)]


# ── Scope resolution ─────────────────────────────────────────────────────────
def resolve_scope(env=None):
    """Return (output_dir | None, Scope, source description)."""
    env = os.environ if env is None else env
    od = env.get("OUTPUT_DIR", "")
    if od and (Path(od) / "engagement.json").exists():
        try:
            return Path(od), Scope.load(Path(od) / "engagement.json"), "$OUTPUT_DIR"
        except Exception:
            pass
    active = read_active()
    if active:
        try:
            return active, Scope.load(active / "engagement.json"), ".tzar/active-engagement"
        except Exception:
            pass
    db = Path(env.get("TZAR_MEMORY_DB") or (REPO_DIR / "memory.db"))
    if db.exists():
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            row = conn.execute(
                "SELECT output_dir, scope FROM engagements WHERE status='active' "
                "ORDER BY last_updated DESC LIMIT 1").fetchone()
            conn.close()
            if row:
                meta = Path(row[0] or "") / "engagement.json"
                if row[0] and meta.exists():
                    return Path(row[0]), Scope.load(meta), "memory.db"
                return None, Scope(in_scope=row[1] or ""), "memory.db (scope only)"
        except Exception:
            pass
    return None, Scope(), "none"


# ── Target classification ────────────────────────────────────────────────────
class Target:
    __slots__ = ("kind", "value", "raw")

    def __init__(self, kind, value, raw):
        self.kind, self.value, self.raw = kind, value, raw  # host | ip | net | dynamic | bad


def _is_dynamic(t: str) -> bool:
    return "$(" in t or "`" in t or bool(re.search(r"\$\{?[A-Za-z_]", t))


def _parse_ip(h: str):
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-f]{1,8}", h):
        return ipaddress.ip_address(int(h, 16))
    if re.fullmatch(r"\d{6,10}", h) and 65535 < int(h) < 2 ** 32:
        return ipaddress.ip_address(int(h))
    return None


def classify_host(h: str, raw: str, loose: bool, cwd: Path):
    h = (h or "").strip().lower().rstrip(".")
    if not h or h in ("-", "*"):
        return None
    ip = _parse_ip(h)
    if ip is not None:
        return Target("ip", ip, raw)
    if re.fullmatch(r"(?:\d{1,3}|\*)(?:\.(?:\d{1,3}|\*)){3}", h) and "*" in h:
        parts = h.split(".")
        first_star = parts.index("*")
        if all(p == "*" for p in parts[first_star:]):
            base = ".".join(parts[:first_star] + ["0"] * (4 - first_star))
            try:
                return Target("net", ipaddress.ip_network(f"{base}/{8 * first_star}"), raw)
            except ValueError:
                pass
        return None if loose else Target("bad", h, raw)
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})", h)
    if m:
        try:
            lo = ipaddress.ip_address(m.group(1))
            hi_s = m.group(2)
            hi = ipaddress.ip_address(hi_s if "." in hi_s
                                      else ".".join(m.group(1).split(".")[:3] + [hi_s]))
            nets = list(ipaddress.summarize_address_range(lo, hi))
            return Target("net", nets, raw)
        except (ValueError, TypeError):
            return None if loose else Target("bad", h, raw)
    if not loose and re.fullmatch(r"0x[0-9a-f.x]+|[0-9.]*0x[0-9a-fx.]*|(?:\d+\.){1,3}\d+", h) \
            and h.count(".") in (1, 2, 3) and not re.fullmatch(r"\d+\.\d+", h):
        return Target("bad", h, raw)          # 127.1, 0x7f.0.0.1, 010.0.0.1, ...
    if HOSTNAME.match(h):
        tld = h.rsplit(".", 1)[1]
        if tld in FILE_EXTS:
            return None
        if tld in AMBIGUOUS_EXTS and (cwd / raw).exists():
            return None
        if loose and tld not in COMMON_TLDS:
            return None
        return Target("host", h, raw)
    return None


def target_of(tok: str, cwd: Path, loose=False, allow_dynamic=True):
    """Interpret one argv token as a network destination, or None if it isn't one."""
    t = (tok or "").strip().strip("'\"")
    if not t or t.startswith("-"):
        return None
    low = t.lower()
    m = re.match(r"^([a-z][a-z0-9+.-]*)://", low)
    # Only the authority (host) part decides dynamism: a substitution in the path or
    # query string is a payload, the destination is still the literal host.
    authority = re.split(r"[/?#]", t[m.end():] if m else t, maxsplit=1)[0]
    if _is_dynamic(authority):
        return Target("dynamic", t, t) if allow_dynamic else None
    if m:
        if m.group(1) in ("file", "data", "jar"):
            return None
        try:
            host = urlsplit(t).hostname or ""
        except ValueError:
            return Target("bad", t, t)
        if not host:
            return None
        return classify_host(host, t, loose=False, cwd=cwd) or Target("bad", host, t)
    if t.startswith(("/", "./", "../", "~")):
        return None
    if re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", t):          # CIDR
        try:
            return Target("net", ipaddress.ip_network(t, strict=False), t)
        except ValueError:
            return None if loose else Target("bad", t, t)
    if "@" in t:
        t = t.rsplit("@", 1)[1]                            # user:pass@host, dom/u@host
    if t.startswith("["):
        host = t[1:t.find("]")] if "]" in t else t[1:]
    else:
        try:
            ipaddress.ip_address(t)
            host = t
        except ValueError:
            host = re.split(r"[/:?#,]", t, maxsplit=1)[0]
    return classify_host(host, tok, loose=loose, cwd=cwd)


# ── Shell parsing ────────────────────────────────────────────────────────────
HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(['\"]?)([A-Za-z_][\w.-]*)\2")


def extract_heredocs(cmd: str):
    """Pull heredoc bodies out of the command; leave __HEREDOC_k__ placeholders."""
    lines, out, bodies, i = cmd.split("\n"), [], [], 0
    while i < len(lines):
        pending = []

        def rep(m):
            pending.append((m.group(3), m.group(1) == "-"))
            return f" __HEREDOC_{len(bodies) + len(pending) - 1}__ "
        out.append(HEREDOC.sub(rep, lines[i]))
        i += 1
        for term, strip in pending:
            body = []
            while i < len(lines) and (lines[i].strip() if strip else lines[i]) != term:
                body.append(lines[i])
                i += 1
            i += 1
            bodies.append("\n".join(body))
    return "\n".join(out), bodies


def _balanced(s: str, i: int):
    """Return (body, index after the closing paren) for s[i:] after an opening '('."""
    depth, sq, dq, start = 1, False, False, i
    while i < len(s):
        c = s[i]
        if sq:
            sq = c != "'"
        elif c == "\\":
            i += 1
        elif c == "'" and not dq:
            sq = True
        elif c == '"':
            dq = not dq
        elif not dq and c == "(":
            depth += 1
        elif not dq and c == ")":
            depth -= 1
            if depth == 0:
                return s[start:i], i + 1
        i += 1
    return s[start:], len(s)


def split_shell(cmd: str):
    """
    Quote-aware split into pipelines (list of segment strings). Command / process
    substitutions are lifted into `subs` and replaced by $(__SUB_k__) placeholders.
    """
    pipelines, cur, subs = [[]], [], []
    sq = dq = False
    i, n = 0, len(cmd)

    def flush():
        s = "".join(cur).strip()
        cur.clear()
        if s:
            pipelines[-1].append(s)

    while i < n:
        c = cmd[i]
        if sq:
            cur.append(c)
            sq = c != "'"
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            cur.append(cmd[i:i + 2])
            i += 2
            continue
        if c == "'" and not dq:
            sq = True
            cur.append(c)
            i += 1
            continue
        if c == '"':
            dq = not dq
            cur.append(c)
            i += 1
            continue
        if cmd.startswith("$((", i):                       # arithmetic, not a command
            body, j = _balanced(cmd, i + 3)
            cur.append("0")
            i = j + 1 if j < n and cmd[j] == ")" else j
            continue
        if cmd.startswith("$(", i):
            body, j = _balanced(cmd, i + 2)
            subs.append(body)
            cur.append(f"$(__SUB_{len(subs) - 1}__)")
            i = j
            continue
        if c == "`":
            j = cmd.find("`", i + 1)
            j = n if j < 0 else j
            subs.append(cmd[i + 1:j])
            cur.append(f"$(__SUB_{len(subs) - 1}__)")
            i = j + 1
            continue
        if not dq and c in "<>" and cmd.startswith("(", i + 1):
            body, j = _balanced(cmd, i + 2)
            subs.append(body)
            cur.append("/dev/fd/63")
            i = j
            continue
        if dq:
            cur.append(c)
            i += 1
            continue
        if c == "#" and (i == 0 or cmd[i - 1] in " \t\n;&|("):
            j = cmd.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in ";\n":
            flush()
            pipelines.append([])
            i += 1
            continue
        if c == "&":
            if cmd.startswith("&&", i):
                flush()
                pipelines.append([])
                i += 2
                continue
            if (i > 0 and cmd[i - 1] in "<>") or cmd.startswith("&>", i):
                cur.append(c)
                i += 1
                continue
            flush()
            pipelines.append([])
            i += 1
            continue
        if c == "|":
            if cmd.startswith("||", i):
                flush()
                pipelines.append([])
                i += 2
                continue
            flush()
            i += 2 if cmd.startswith("|&", i) else 1
            continue
        if c == "(" and not "".join(cur).strip():           # subshell group
            i += 1
            continue
        if c == ")" and not "".join(cur).strip():
            i += 1
            continue
        cur.append(c)
        i += 1
    flush()
    return [p for p in pipelines if p], subs


def tokenize(seg: str) -> list:
    try:
        return shlex.split(seg, comments=False, posix=True)
    except ValueError:
        return seg.split()


REDIR = re.compile(r"^(\d*|&)(>>?|<|<<<)(&?\d*)$")
REDIR_ATTACHED = re.compile(r"^(\d*|&)(>>?|<)(?!&)(.+)$")


def strip_redirections(tokens):
    """Return (argv without redirections, stdin file or None, here-string or None)."""
    out, stdin_file, herestr, i = [], None, None, 0
    while i < len(tokens):
        t = tokens[i]
        m = REDIR.match(t)
        if m:
            if m.group(3):                    # 2>&1
                i += 1
                continue
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if m.group(2) == "<":
                stdin_file = nxt
            elif m.group(2) == "<<<":
                herestr = nxt
            i += 2
            continue
        m = REDIR_ATTACHED.match(t)
        if m:                                   # >out.txt  2>>err  <in.txt
            if m.group(2) == "<":
                stdin_file = m.group(3)
            i += 1
            continue
        out.append(t)
        i += 1
    return out, stdin_file, herestr


# ── The checker ──────────────────────────────────────────────────────────────
class Checker:
    def __init__(self, scope: Scope, output_dir=None, cwd=None, env=None,
                 safe_prefixes=None, allowed_hosts=None):
        self.scope = scope
        self.output_dir = Path(output_dir).resolve() if output_dir else None
        self.cwd = Path(cwd or os.getcwd())
        self.safe_prefixes = load_safe_prefixes() if safe_prefixes is None else safe_prefixes
        self.allowed = load_allowed_hosts() if allowed_hosts is None else allowed_hosts
        self.vars = {}
        for k, v in (env if env is not None else os.environ).items():
            if k in ("OUTPUT_DIR", "HOME", "PWD", "USER", "TARGET", "DOMAIN", "URL", "HOST",
                     "RHOST", "LHOST", "IP"):
                self.vars[k] = [v]
        if self.output_dir:
            self.vars["OUTPUT_DIR"] = [str(self.output_dir)]
        self.problems = []
        self.subs = []
        self.heredocs = []
        self._missing_files = []
        self._xargs = False
        self.writes = []      # write_gate.WriteOp — state-changing requests seen
        self.guards = []      # changes to scope / write policy that need a human

    # -- verdicts --
    def _denied(self, host: str) -> bool:
        return any(_match(p, host) for p in self.scope.out_of_scope)

    def _infra(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            if any(ip in n for n in LOCAL_NETS):
                return True
        except ValueError:
            if host == "localhost" or host.endswith(".localhost"):
                return True
        return any(_match(p, host) for p in self.allowed)

    def block(self, msg: str):
        if msg not in self.problems:
            self.problems.append(msg)

    def judge(self, tgt, where: str, mode="default"):
        """mode: 'default' = default-deny scope check; 'deny' = out-of-scope list only."""
        if tgt is None:
            return
        if tgt.kind == "dynamic":
            if mode == "default":
                self.block(f"{where}: target `{tgt.raw}` is dynamic (variable or command "
                           f"substitution) so it can't be verified. Use a literal host, or put "
                           f"the targets in a file and pass it with -iL/-l (files are checked).")
            return
        if tgt.kind == "bad":
            if mode == "default":
                self.block(f"{where}: `{tgt.raw}` is an unusual address encoding; write it as "
                           f"a normal dotted IP or CIDR.")
            return
        if tgt.kind == "net":
            nets = tgt.value if isinstance(tgt.value, list) else [tgt.value]
            for net in nets:
                self._judge_net(net, tgt.raw, where, mode)
            return
        host = str(tgt.value)
        if self._denied(host):
            self.block(f"{where}: `{host}` matches an out-of-scope rule.")
            return
        if mode == "deny" or self._infra(host):
            return
        if not self.scope.active:
            self.block(f"{where}: `{host}` — no active engagement scope. Start one with "
                       f"tools/init-engagement.py, or `python3 tools/scope.py --activate "
                       f"<OUTPUT_DIR>`.")
            return
        if not self.scope.in_scope_host(host):
            self.block(f"{where}: `{host}` is not in scope.")

    def _judge_net(self, net, raw, where, mode):
        for p in self.scope.out_of_scope:
            try:
                deny = ipaddress.ip_network(p.strip(), strict=False)
            except ValueError:
                continue
            if deny.version == net.version and net.overlaps(deny):
                self.block(f"{where}: range `{raw}` overlaps out-of-scope `{p}`.")
                return
        if mode == "deny":
            return
        if net.num_addresses == 1:
            self.judge(Target("ip", net.network_address, raw), where, mode)
            return
        for p in self.scope.in_scope:
            try:
                allow = ipaddress.ip_network(p.strip(), strict=False)
            except ValueError:
                continue
            if allow.version == net.version and net.subnet_of(allow):
                return
        if not self.scope.active:
            self.block(f"{where}: range `{raw}` — no active engagement scope.")
        else:
            self.block(f"{where}: range `{raw}` is not fully inside an in-scope CIDR.")

    # -- helpers --
    def expand(self, tok: str) -> list:
        """Substitute known variables; unknown ones stay (and read as dynamic)."""
        if "$" not in tok:
            return [tok]
        results = [tok]
        for name in set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", tok)):
            if name not in self.vars:
                continue
            nxt = []
            for r in results:
                for v in self.vars[name]:
                    nxt.append(re.sub(r"\$\{" + name + r"\}|\$" + name + r"(?![A-Za-z0-9_])",
                                      lambda _m, v=v: v, r))
            results = nxt
        return results

    def read_target_file(self, path: str, where: str, mode="default"):
        if _is_dynamic(path):
            path = self.expand(path)[0]
        if path in ("-", "/dev/stdin"):
            return
        p = Path(path).expanduser()
        p = p if p.is_absolute() else self.cwd / p
        if not p.exists():
            self._missing_files.append(path)
            return
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                self.block(f"{where}: target file `{path}` is too large to verify.")
                return
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self.judge(target_of(line.split()[0], self.cwd), f"{where} ({path})", mode)
        except OSError:
            self.block(f"{where}: target file `{path}` is unreadable.")

    def _sub_body(self, tok: str):
        m = re.fullmatch(r"\$\(__SUB_(\d+)__\)", tok)
        return self.subs[int(m.group(1))] if m else None

    # -- entry points --
    def check_command(self, command: str, depth=0):
        if depth > MAX_DEPTH:
            self.block("command nesting too deep to verify.")
            return
        text, bodies = extract_heredocs(command)
        hd_base = len(self.heredocs)
        self.heredocs.extend(bodies)
        if hd_base:
            text = re.sub(r"__HEREDOC_(\d+)__",
                          lambda m: f"__HEREDOC_{int(m.group(1)) + hd_base}__", text)
        pipelines, subs = split_shell(text)
        sub_base = len(self.subs)
        self.subs.extend(subs)
        if sub_base:
            pipelines = [[re.sub(r"__SUB_(\d+)__",
                                 lambda m: f"__SUB_{int(m.group(1)) + sub_base}__", s)
                          for s in p] for p in pipelines]
        for body in subs:
            self.check_command(body, depth + 1)
        for pipe in pipelines:
            self.check_pipeline(pipe, depth)
        if depth == 0:
            for path in dict.fromkeys(self._missing_files):
                # A list file this same command generates (subfinder -o subs.txt && httpx -l
                # subs.txt) can't exist yet; anything else is unverifiable → block.
                if command.count(path) < 2:
                    self.block(f"target file `{path}` not found, so its hosts can't be "
                               f"verified.")
            self._missing_files = []

    def check_pipeline(self, segments, depth):
        feed = None                      # tokens produced by a local feeder (echo/cat)
        for seg in segments:
            feed = self.check_segment(seg, feed, depth)

    def check_segment(self, seg: str, feed, depth):
        """Analyse one simple command. Returns the tokens it feeds to the next stage."""
        self._xargs = False
        stripped = seg.strip()
        for prefix in self.safe_prefixes:
            if stripped.startswith(prefix):
                return None
        tokens = tokenize(seg)
        hd_ids = [int(x) for t in tokens for x in re.findall(r"__HEREDOC_(\d+)__", t)]
        tokens = [t for t in tokens if not re.fullmatch(r"__HEREDOC_\d+__", t)]
        tokens, stdin_file, herestr = strip_redirections(tokens)
        heredoc = "\n".join(self.heredocs[i] for i in hd_ids) if hd_ids else None

        while tokens and tokens[0] in SHELL_KEYWORDS:
            tokens = tokens[1:]
        while tokens and tokens[-1] in SHELL_TERMINATORS:
            tokens = tokens[:-1]
        if not tokens or tokens[0] in SHELL_TERMINATORS or tokens[0] in ("case", "esac"):
            return None

        # for VAR in words...
        if tokens[0] == "for" and len(tokens) >= 3 and tokens[2] == "in":
            values = []
            for w in tokens[3:]:
                body = self._sub_body(w)
                if body is not None:
                    m = re.fullmatch(r"\s*cat\s+(\S+)\s*", body)
                    if m:
                        values += self._file_words(m.group(1))
                    else:
                        values.append(w)
                else:
                    values += self.expand(w)
            self.vars[tokens[1]] = values or ["$" + tokens[1]]
            return None

        # leading assignments: FOO=bar cmd ...
        while tokens and ASSIGN.match(tokens[0]):
            name, val = ASSIGN.match(tokens[0]).groups()
            self.vars[name] = self.expand(val)
            tokens = tokens[1:]
        if not tokens:
            return None
        if tokens[0] in ("export", "declare", "local", "readonly", "typeset"):
            for t in tokens[1:]:
                m = ASSIGN.match(t)
                if m:
                    self.vars[m.group(1)] = self.expand(m.group(2))
            return None

        tokens = self.unwrap(tokens)
        if not tokens:
            return None
        tool_path = tokens[0]
        tool = Path(tool_path).name.lower()
        args = [x for t in tokens[1:] for x in self.expand(t)]
        where = f"`{tool}`"
        self._guard_segment(tool, args, seg)

        # here-string / stdin redirection count as stdin feed
        if herestr is not None:
            feed = (feed or []) + herestr.split()
        if stdin_file:
            feed = (feed or []) + self._file_words(stdin_file)

        if tool == "eval":
            self.check_command(" ".join(args), depth + 1)
            return None
        if tool in ("source", "."):
            if args:
                self._check_script(args[0], shell=True, depth=depth)
            return None
        if tool in SHELLS:
            return self._check_shell(args, heredoc, depth)
        if tool == "find":
            for flag in ("-exec", "-execdir", "-ok", "-okdir"):
                if flag in args:
                    i = args.index(flag) + 1
                    j = next((k for k in range(i, len(args)) if args[k] in (";", "\\;", "+")),
                             len(args))
                    self.check_command(shlex.join(args[i:j]), depth + 1)
            return None
        if tool in LOCAL_COMMANDS:
            if tool in FEEDERS:
                return self._feed_from(tool, args, heredoc)
            return None
        if tool == "git":
            for a in args:
                if "://" in a or re.match(r"^[\w.-]+@[\w.-]+:", a):
                    self.judge(target_of(a, self.cwd), where)
            return None
        if INTERPRETERS.match(tool):
            self._check_interpreter(tool, args, heredoc, feed, depth)
            return None
        if tool in SSH_LIKE:
            self._check_ssh(tool, args, depth)
            return None
        if tool in NETWORK_TOOLS or tool.startswith("impacket-") or \
                (tool.endswith(".py") and tool[:-3].lower() in IMPACKET_SCRIPTS):
            self._check_network_tool(tool, args, feed)
            return None
        # Unknown command: only unmistakable destinations (URLs, IPs, common-TLD hosts).
        for a in args:
            t = target_of(a, self.cwd, loose=True, allow_dynamic=False)
            self.judge(t, where)
        return None

    def unwrap(self, tokens):
        for _ in range(8):
            if not tokens:
                return tokens
            w = Path(tokens[0]).name
            if w not in WRAPPERS:
                return tokens
            vflags = WRAPPER_VALUE_FLAGS.get(w, set())
            i = 1
            while i < len(tokens):
                t = tokens[i]
                if w == "env" and ASSIGN.match(t):
                    name, val = ASSIGN.match(t).groups()
                    self.vars[name] = self.expand(val)
                    i += 1
                elif t in vflags:
                    i += 2
                elif t.startswith("-"):
                    i += 1
                elif w == "timeout" and re.fullmatch(r"[\d.]+[smhd]?", t):
                    i += 1
                    break
                else:
                    break
            if w in ("xargs", "parallel"):
                rest = tokens[i:]
                if w == "parallel" and ":::" in rest:
                    k = rest.index(":::")
                    rest = rest[:k] + rest[k + 1:]
                tokens = rest
                self._xargs = True
            else:
                tokens = tokens[i:]
        return tokens

    def _file_words(self, path):
        p = Path(self.expand(path)[0]).expanduser()
        p = p if p.is_absolute() else self.cwd / p
        try:
            if p.stat().st_size <= MAX_FILE_BYTES:
                return [l.split()[0] for l in p.read_text(errors="replace").splitlines()
                        if l.strip() and not l.strip().startswith("#")]
        except OSError:
            pass
        return []

    def _feed_from(self, tool, args, heredoc):
        if tool in ("echo", "printf"):
            words = []
            for a in args:
                if a.startswith("-") and tool == "echo":
                    continue
                words += re.split(r"\s+|\\n", a)
            return [w for w in words if w]
        if tool in ("cat", "tac", "head", "tail", "sort", "uniq"):
            if heredoc is not None:
                return heredoc.split()
            words = []
            for a in args:
                if not a.startswith("-"):
                    words += self._file_words(a)
            return words
        return None

    def _check_shell(self, args, heredoc, depth):
        if "-c" in args:
            i = args.index("-c")
            if i + 1 < len(args):
                self.check_command(args[i + 1], depth + 1)
            return None
        if heredoc is not None:
            self.check_command(heredoc, depth + 1)
            return None
        script = next((a for a in args if not a.startswith("-")), None)
        if script:
            self._check_script(script, shell=True, depth=depth)
        return None

    def _script_path(self, path):
        p = Path(path).expanduser()
        p = p if p.is_absolute() else self.cwd / p
        try:
            p = p.resolve()
        except OSError:
            return None
        if not p.is_file():
            return None
        trusted_roots = [Path("/usr"), Path("/opt"), Path("/snap"), TOOLS_DIR,
                         Path.home() / "go", Path.home() / ".local"]
        if any(str(p).startswith(str(r) + os.sep) for r in trusted_roots):
            return None                       # third-party tools / our own tooling
        try:
            if p.stat().st_size > MAX_SCRIPT_BYTES:
                return None
        except OSError:
            return None
        return p

    def _check_script(self, path, shell, depth):
        p = self._script_path(path)
        if not p:
            return
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if shell:
            self.check_command(text, depth + 1)
        else:
            self.check_code(text, f"`{p.name}`")

    def _check_interpreter(self, tool, args, heredoc, feed, depth):
        where = f"`{tool}`"
        i, script = 0, None
        while i < len(args):
            a = args[i]
            if a in CODE_FLAGS and i + 1 < len(args):
                self.check_code(args[i + 1], f"{where} {a}")
                i += 2
                continue
            if a == "-m" and i + 1 < len(args):
                if args[i + 1] in ("http.server", "SimpleHTTPServer", "pip", "venv", "pytest"):
                    return
                i += 2
                continue
            if a == "-":
                if heredoc is not None:
                    self.check_code(heredoc, f"{where} heredoc")
                i += 1
                continue
            if a.startswith("-"):
                i += 1
                continue
            script = a
            break
        if script is None:
            if heredoc is not None:
                self.check_code(heredoc, f"{where} heredoc")
            return
        sp = Path(script)
        resolved = (sp if sp.is_absolute() else self.cwd / sp)
        try:
            resolved = resolved.resolve()
        except OSError:
            pass
        if str(resolved).startswith(str(TOOLS_DIR) + os.sep) and \
                resolved.name not in TRAFFIC_REPO_TOOLS:
            return                            # tzar-bot's own local tooling
        self._check_script(script, shell=False, depth=depth)
        for a in args[i + 1:]:
            self.judge(target_of(a, self.cwd, loose=True, allow_dynamic=False), where)

    def _check_ssh(self, tool, args, depth):
        where = f"`{tool}`"
        if tool == "sshpass":
            i = 0
            while i < len(args) and args[i].startswith("-"):
                i += 2 if args[i] in ("-p", "-f", "-d") else 1
            self.check_command(shlex.join(args[i:]), depth + 1)
            return
        if tool == "ssh":
            skip = SKIP_VALUE_BY_TOOL["ssh"]
            i = 0
            while i < len(args):
                a = args[i]
                if a == "-J" and i + 1 < len(args):
                    for hop in args[i + 1].split(","):
                        self.judge(target_of(hop, self.cwd), f"{where} -J")
                    i += 2
                elif a in skip:
                    i += 2
                elif a.startswith("-"):
                    i += 1
                else:
                    break
            if i < len(args):
                self.judge(target_of(args[i], self.cwd), where)
                remote = args[i + 1:]
                if remote:                     # runs on the remote host: check it too
                    self.check_command(" ".join(remote), depth + 1)
            return
        for a in args:                          # scp / rsync / sftp: host:path operands
            if a.startswith("-"):
                continue
            if re.match(r"^(?:[\w.-]+@)?(?:\[[0-9a-f:]+\]|[\w.-]+):", a) or "://" in a:
                self.judge(target_of(a, self.cwd), where)
            elif tool == "sftp":
                self.judge(target_of(a, self.cwd), where)

    def _check_network_tool(self, tool, args, feed):
        where = f"`{tool}`"
        if tool == "openssl":
            if not args or args[0] not in ("s_client", "s_time"):
                return
        list_flags = LIST_FLAGS | LIST_FLAGS_BY_TOOL.get(tool, set())
        target_flags = TARGET_FLAGS | TARGET_FLAGS_BY_TOOL.get(tool, set())
        skip_flags = (SKIP_VALUE_FLAGS | SKIP_VALUE_BY_TOOL.get(tool, set())) - target_flags
        reads_stdin = tool in STDIN_TARGET_TOOLS or self._xargs
        impacket = tool.startswith("impacket-") or tool.endswith(".py") or \
            tool in ("certipy", "certipy-ad", "nxc", "netexec", "crackmapexec", "cme")
        i = 0
        while i < len(args):
            a = args[i]
            nxt = args[i + 1] if i + 1 < len(args) else None
            flag, _, attached = a.partition("=") if a.startswith("--") else (a, "", "")
            val = attached or nxt
            consumed = 1 if attached else 2
            if flag in HEADER_FLAGS and val is not None:
                m = re.match(r"\s*host\s*:\s*(\S+)", val, re.I)
                if m:
                    self.judge(target_of(m.group(1), self.cwd), f"{where} Host header", "deny")
                i += consumed
                continue
            if flag in ("--resolve", "--connect-to") and val is not None:
                parts = val.split(":")
                if parts:
                    self.judge(target_of(parts[0], self.cwd), f"{where} {flag}", "deny")
                dest = parts[-1] if flag == "--resolve" else (parts[2] if len(parts) > 2 else "")
                if dest:
                    self.judge(target_of(dest.strip("[]"), self.cwd), f"{where} {flag}")
                i += consumed
                continue
            if flag in list_flags and val is not None:
                if val == "-":
                    reads_stdin = True
                else:
                    self.read_target_file(val, f"{where} {flag}")
                i += consumed
                continue
            if flag in target_flags and val is not None:
                self.judge(target_of(val, self.cwd), f"{where} {flag}")
                i += consumed
                continue
            if flag in skip_flags:
                if val is not None and (attached or not val.startswith("-")):
                    i += consumed
                else:
                    i += 1
                continue
            if a.startswith("-"):
                # -uhttps://x attached short-flag form
                if len(a) > 2 and a[:2] in ("-u", "-h") and "://" in a:
                    self.judge(target_of(a[2:], self.cwd), f"{where} {a[:2]}")
                i += 1
                continue
            if impacket and "@" not in a and re.fullmatch(r"[\w.-]+/[^/\s]+", a) \
                    and not re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", a):
                i += 1                         # domain/user[:pass] credential operand
                continue
            if tool == "dig" and a.startswith("@"):
                self.judge(target_of(a[1:], self.cwd), where)
                i += 1
                continue
            self.judge(target_of(a, self.cwd), where)
            i += 1
        if reads_stdin and feed:
            for w in feed:
                self.judge(target_of(w, self.cwd), f"{where} (stdin)")
        self._xargs = False
        if tool in HTTP_CLIENTS:
            self._record_http_writes(tool, args)

    # -- write-request detection (feeds tools/write_gate.py) --
    def _record_http_writes(self, tool, args):
        where = f"`{tool}`"
        method, bodies, urls, force_get = None, [], [], False
        i = 0
        while i < len(args):
            a = args[i]
            nxt = args[i + 1] if i + 1 < len(args) else None
            flag, _, att = a.partition("=") if a.startswith("--") else (a, "", "")
            val = att or nxt
            step = 1 if att else 2
            if flag in METHOD_FLAGS and val:
                method = val.upper()
                i += step
                continue
            if re.fullmatch(r"-X[A-Za-z]+", a):
                method = a[2:].upper()
                i += 1
                continue
            if flag in BODY_FLAGS and val is not None:
                bodies.append(val)
                i += step
                continue
            if tool == "curl" and flag in ("-T", "--upload-file"):
                method = method or "PUT"
                i += step
                continue
            if tool == "curl" and flag in ("-I", "--head"):
                method = method or "HEAD"
                i += 1
                continue
            if tool == "curl" and flag in ("-G", "--get"):
                force_get = True
                i += 1
                continue
            if flag in ("-u", "--url", "-url", "-target") and tool != "curl" and val:
                urls.append(val)
                i += step
                continue
            if flag == "--url" and val:
                urls.append(val)
                i += step
                continue
            if flag in HTTP_VALUE_FLAGS:
                i += step
                continue
            if a.startswith("-"):
                i += 1
                continue
            if tool in ("http", "https", "xh") and method is None and re.fullmatch(r"[A-Z]+", a):
                method = a
            elif tool in ("http", "https", "xh") and "://" not in a and \
                    re.match(r"^[^=:/\s]+(?::=|=|@)", a) and not re.match(r"^[^=]+==", a):
                bodies.append(a)                  # httpie data item → POST
            else:
                t = target_of(a, self.cwd)
                if t is not None and t.kind in ("host", "ip"):
                    urls.append(a)
            i += 1
        if force_get:
            method = method or "GET"
        method = method or ("POST" if bodies else "GET")
        body = " ".join(bodies)
        for u in urls:
            u = u if "://" in u else f"http://{u}"
            op = write_gate.classify(method, u, body, where)
            if op:
                self.writes.append(op)
        if tool in ("sqlmap", "ghauri"):
            self._record_sqlmap(args, urls, where)

    def _record_sqlmap(self, args, urls, where):
        joined = " ".join(args)
        risky = []
        m = re.search(r"--risk[ =](\d)", joined)
        if m and int(m.group(1)) >= 3:
            risky.append("--risk 3 (OR-based payloads can UPDATE/DELETE every row)")
        m = re.search(r"--technique[ =](\S+)", joined)
        if m and "S" in m.group(1).upper():
            risky.append("stacked queries")
        for f in ("--sql-shell", "--os-shell", "--os-cmd", "--os-pwn", "--file-write",
                  "--file-dest", "--eval", "--reg-add", "--reg-del", "--udf-inject"):
            if f in args or any(a.startswith(f + "=") for a in args):
                risky.append(f)
        m = re.search(r"--sql-query[ =]['\"]?\s*(\w+)", joined)
        if m and m.group(1).lower() not in ("select", "show", "describe", "explain"):
            risky.append(f"--sql-query {m.group(1).upper()}")
        if risky:
            url = urls[0] if urls else ""
            self.writes.append(write_gate.WriteOp(
                "SQLI", url, where, "sqlmap " + ", ".join(risky), destructive=True))

    def _record_code_writes(self, code, where):
        for m in WRITE_CALL.finditer(code):
            self._code_write(m.group("m"), m.group("u"), code, where)
        for m in REQ_CALL.finditer(code):
            self._code_write(m.group("m"), m.group("u"), code, where)
        for m in METHOD_KW.finditer(code):
            self._code_write(m.group("m"), None, code, where)
        if re.search(r"\.submit\(\s*\)|requestSubmit\(", code):
            self._code_write("POST", None, code, where, "form submit")

    def _code_write(self, method, url, code, where, reason=None):
        op = write_gate.classify(method, url or "", code, where)
        if op:
            if reason:
                op.reason = reason
            if not any(o.method == op.method and o.url == op.url and o.where == where
                       for o in self.writes):
                self.writes.append(op)

    # -- trust anchors: scope / write-policy changes need a human --
    def _guard_segment(self, tool, args, seg):
        script = None
        if INTERPRETERS.match(tool):
            if any(a in CODE_FLAGS for a in args) or "-" in args or not args:
                return                 # inline code / heredoc: check_code() checks real writes
            script = next((a for a in args if not a.startswith("-")), None)
        name = Path(script).name if script else tool
        sub = [a for a in args if a != script]
        if name == "init-engagement.py":
            self.guards.append("starts a new engagement and sets the enforced scope: "
                               + _summarise_init(sub))
            return
        if name == "scope.py" and "--activate" in sub:
            i = sub.index("--activate")
            self.guards.append("switches the enforced scope to engagement "
                               + (sub[i + 1] if i + 1 < len(sub) else "?"))
            return
        if name == "write_gate.py" and any(c in sub for c in ("allow", "revoke", "policy")):
            self.guards.append("changes the write policy: " + " ".join(sub))
            return
        if not PROTECTED.search(seg):
            return
        if tool in READONLY_TOOLS and not PROTECTED_REDIRECT.search(seg) and \
                not (tool in ("sed", "perl") and any(a.startswith("-i") for a in args)):
            return
        if tool == "git" and args and args[0] in ("diff", "log", "show", "status", "add",
                                                  "commit", "blame", "grep", "push", "fetch"):
            return
        if script and Path(script).name in READONLY_REPO_TOOLS:
            return
        self.guards.append(f"modifies a scope / write-policy file: `{seg.strip()[:160]}`")

    # -- inline / script code --
    URL_LIT = re.compile(r"""(?P<q>['"`])(?P<s>[A-Za-z][A-Za-z0-9+.-]*://[^'"`\s]*)(?P=q)""")
    HOST_CALL = re.compile(
        r"""(?:connect|create_connection|gethostbyname|getaddrinfo|HTTPS?Connection|"""
        r"""TCPSocket|fsockopen|Net::HTTP\.start|socket\.create_connection)\s*\(\s*\(?\s*"""
        r"""(?P<q>['"])(?P<h>[^'"]+)(?P=q)""")
    # Header / parameter values that carry an attacker URL as a payload, not a destination.
    PAYLOAD_CTX = re.compile(r"""['"]?(?:origin|referer|referrer|redirect_uri|redirect|"""
                             r"""callback|next|return_to|returnurl|payload)['"]?\s*[:=,]\s*$""",
                             re.I)

    def check_code(self, code: str, where: str):
        for m in self.URL_LIT.finditer(code):
            url = m.group("s")
            scheme = url.split("://", 1)[0].lower()
            if scheme in ("file", "data", "jar", "chrome", "about"):
                continue
            before = code[max(0, m.start() - 40):m.start()]
            if self.PAYLOAD_CTX.search(before):
                continue                       # Origin/Referer/redirect payload, not a destination
            rest = url.split("://", 1)[1]
            hostpart = re.split(r"[/?#]", rest, maxsplit=1)[0]
            after = code[m.end():m.end() + 3]
            if not hostpart:
                if after.lstrip().startswith("+") or code[m.start() - 1:m.start()] in ("f", "r"):
                    self.block(f"{where}: URL built at runtime (`{url}` + ...) can't be "
                               f"verified. Use a literal in-scope URL.")
                continue
            if re.search(r"[{}%$]|\$\{", hostpart):
                self.block(f"{where}: URL host `{hostpart}` is built at runtime and can't be "
                           f"verified. Use a literal in-scope URL.")
                continue
            self.judge(target_of(url, self.cwd), where)
        for m in self.HOST_CALL.finditer(code):
            self.judge(target_of(m.group("h"), self.cwd), where)
        self._record_code_writes(code, where)
        if PROTECTED.search(code) and CODE_FILE_WRITE.search(code):
            self.guards.append(f"{where} code writes to a scope / write-policy file")

    # -- MCP tools --
    def check_mcp(self, tool_name: str, tool_input: dict):
        name = tool_name.lower()
        if name == "webfetch":
            self.judge(target_of(str(tool_input.get("url", "")), self.cwd), "WebFetch", "deny")
            return
        if name.startswith("mcp__burp__"):
            where = tool_name
            host = tool_input.get("targetHostname")
            if host:
                self.judge(target_of(str(host), self.cwd) or Target("bad", host, host), where)
            content = tool_input.get("content")
            if isinstance(content, str):
                head = re.split(r"\r?\n\r?\n", content, maxsplit=1)[0]
                for hm in re.finditer(r"^host\s*:\s*(\S+)", head, re.I | re.M):
                    self.judge(target_of(hm.group(1), self.cwd), f"{where} Host header", "deny")
            for key in ("headers", "pseudoHeaders"):
                hdrs = tool_input.get(key)
                if isinstance(hdrs, dict):
                    for k, v in hdrs.items():
                        if k.lower() in ("host", ":authority"):
                            self.judge(target_of(str(v), self.cwd), f"{where} {k}", "deny")
            self._record_burp_write(name, tool_input)
            return
        if name.startswith("mcp__playwright__"):
            for k, v in tool_input.items():
                if not isinstance(v, str):
                    continue
                if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
                    self.judge(target_of(v, self.cwd), f"{tool_name} {k}")
                elif name.endswith(("evaluate", "evaluate_js")) or k in ("script", "expression"):
                    self.check_code(v, f"{tool_name} {k}")
            if name.endswith(("_click", "_press", "_type", "_fill")):
                text = " ".join(str(v) for v in tool_input.values() if isinstance(v, str))
                m = UI_WRITE_WORDS.search(text)
                if m and (name.endswith("_click") or "enter" in text.lower()
                          or name.endswith("_press")):
                    self.writes.append(write_gate.WriteOp(
                        "UI", "", tool_name, f"browser action on a '{m.group(0)}' control",
                        destructive=bool(write_gate.DESTRUCTIVE_PATH.search("/" + m.group(0)))))
            return

    def _record_burp_write(self, name, ti):
        if name == "mcp__burp__set_task_execution_engine_state":
            if ti.get("running") in (True, "true", "True"):
                self.writes.append(write_gate.WriteOp(
                    "SCAN", "", name, "resumes Burp scanner tasks (active scans send writes)"))
            return
        if name not in ("mcp__burp__send_http1_request", "mcp__burp__send_http2_request"):
            return
        host = str(ti.get("targetHostname") or "")
        port = ti.get("targetPort")
        scheme = "https" if ti.get("usesHttps") in (True, "true", "True") else "http"
        default = 443 if scheme == "https" else 80
        hostport = host if port in (None, "", default, str(default)) else f"{host}:{port}"
        if name == "mcp__burp__send_http1_request":
            content = str(ti.get("content") or "")
            m = re.match(r"\s*([A-Za-z]+)\s+(\S+)", content)
            method, target = (m.group(1), m.group(2)) if m else ("GET", "/")
            parts = re.split(r"\r?\n\r?\n", content, maxsplit=1)
            body = parts[1] if len(parts) > 1 else ""
        else:
            ph = ti.get("pseudoHeaders") or {}
            method = str(ph.get(":method", "GET"))
            target = str(ph.get(":path", "/"))
            body = str(ti.get("requestBody") or "")
        url = target if "://" in target else f"{scheme}://{hostport}{target}"
        op = write_gate.classify(method, url, body, name)
        if op:
            self.writes.append(op)


# ── Back-compat API (MCP scope_check + tests) ────────────────────────────────
def check_command(command: str, scope: Scope, output_dir=None, cwd=None):
    """Returns (allowed, reason)."""
    c = Checker(scope, output_dir=output_dir, cwd=cwd)
    c.check_command(command)
    if c.problems:
        return False, " | ".join(c.problems)
    return True, "in scope" if scope.active else "no network targets"


NETWORKY = re.compile(r"://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:" + "|".join(
    sorted(map(re.escape, NETWORK_TOOLS), key=len, reverse=True)) + r")\b")


def main():
    try:
        hook_input = json.loads(sys.stdin.read() or "{}")
    except Exception:
        sys.exit(0)
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        sys.exit(0)
    is_bash = tool_name == "Bash"
    is_mcp = tool_name == "WebFetch" or tool_name.startswith(("mcp__burp__", "mcp__playwright__"))
    if tool_name in EDIT_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if PROTECTED.search(" " + path):
            emit_ask([f"POLICY: {tool_name} of `{path}` changes what the scope / write gate "
                      f"enforces."], None)
        sys.exit(0)
    if not (is_bash or is_mcp):
        sys.exit(0)
    command = tool_input.get("command", "") if is_bash else ""
    if is_bash and not command.strip():
        sys.exit(0)

    try:
        output_dir, scope, source = resolve_scope()
        checker = Checker(scope, output_dir=output_dir, cwd=hook_input.get("cwd") or os.getcwd())
        if is_bash:
            checker.check_command(command)
        else:
            checker.check_mcp(tool_name, tool_input)
    except Exception as e:  # fail closed on anything that might be network traffic
        if is_mcp or NETWORKY.search(command):
            print(f"\n[SCOPE CHECK ERROR] {type(e).__name__}: {e}\n"
                  f"Blocked fail-closed because the call may reach the network.", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)

    if checker.problems:
        shown = command[:300] if is_bash else json.dumps(tool_input)[:300]
        print("\n[SCOPE VIOLATION] blocked by tools/scope-check.py\n"
              + "\n".join(f"  - {p}" for p in checker.problems[:8])
              + f"\nScope ({source}): in={scope.in_scope} out={scope.out_of_scope}"
              + f"\nCall: {shown}\n"
              + "If the target really is in scope, fix engagement.json (or activate the right "
                "engagement with `python3 tools/scope.py --activate <OUTPUT_DIR>`).\n",
              file=sys.stderr)
        sys.exit(2)

    # ── write gate ──
    meta = write_gate.load_meta(output_dir)
    decision, pending = write_gate.decide(checker.writes, meta)
    if decision == "deny":
        print("\n[WRITE BLOCKED] engagement write_policy is 'deny' (read-only engagement)\n"
              + "\n".join(f"  - {op.label()}" for op in pending[:8])
              + "\nDocument the request in the finding instead of sending it, or ask the "
                "operator to pre-approve it: python3 tools/write_gate.py allow "
                "\"METHOD URL-GLOB\" --reason \"...\"\n", file=sys.stderr)
        sys.exit(2)
    reasons = [f"WRITE: {op.label()}" for op in pending] + \
              [f"POLICY: {g}" for g in checker.guards]
    if reasons:
        emit_ask(reasons, output_dir, meta)
    sys.exit(0)


EDIT_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}


def emit_ask(reasons, output_dir, meta=None):
    """Hand the call to the human permission prompt. The model cannot answer it."""
    head = "tzar-bot write gate — human approval required"
    if output_dir:
        head += f" (engagement {Path(output_dir).name}, write_policy="
        head += f"{(meta or {}).get('write_policy', 'ask')})"
    body = "\n".join(f"• {r}" for r in reasons[:8])
    tail = ("\nApprove only if the client agreed to this change and you know how to undo it. "
            "To pre-approve a repeatable write: python3 tools/write_gate.py allow "
            "\"METHOD URL-GLOB\" --reason \"...\"")
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": f"{head}\n{body}{tail if any(r.startswith('WRITE') for r in reasons) else ''}",
    }}))
    sys.exit(0)


if __name__ == "__main__":
    main()
