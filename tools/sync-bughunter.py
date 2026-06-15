#!/usr/bin/env python3
"""
sync-bughunter.py — detect drift between the upstream claude-bughunter repo and
the skills we imported into tzar-bot, WITHOUT being fooled by our local edits.

Why a manifest:
  At import time we adapted every file (path/MCP rewrites, OOB notes, slash-command
  remaps, removed install boilerplate). So `diff upstream vs our-copy` is pure noise.
  Instead we record a BASELINE hash of each *upstream* skill at the moment we synced,
  then compare upstream-now against upstream-then. Local edits never enter the picture.

Workflow:
  python3 tools/sync-bughunter.py --init        # record baseline from current upstream
  python3 tools/sync-bughunter.py               # report drift since baseline
  python3 tools/sync-bughunter.py --pull        # `git pull` upstream first, then report
  python3 tools/sync-bughunter.py --diff NAME    # show what changed upstream for one skill
  python3 tools/sync-bughunter.py --accept NAME  # mark NAME reviewed (bump its baseline)
  python3 tools/sync-bughunter.py --accept all   # bump baseline for everything (re-sync)

Exit code: 0 = in sync, 1 = drift detected (changed / new / missing), 2 = error.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# ----------------------------------------------------------------- locations
TZAR_ROOT = Path(__file__).resolve().parent.parent          # .../tzar-bot
SKILLS = TZAR_ROOT / "skills"
MANIFEST = TZAR_ROOT / "tools" / "bughunter-sync.manifest.json"
DEFAULT_UPSTREAM = os.environ.get(
    "BUGHUNTER_DIR", "/home/kali/Documents/AI-tools/Claude-BugHunter"
)

# ----------------------------------------------------------------- import map
# The authoritative record of what we pulled from BugHunter and where it lives now.
# kind=standalone -> whole skill dir copied to skills/<name>/
# kind=merged     -> SKILL.md copied to skills/<broad>/reference/<name>.md
TIER1 = [
    "m365-entra-attack", "okta-attack", "vmware-vcenter-attack", "enterprise-vpn-attack",
    "hunt-sharepoint", "hunt-ntlm-info", "supply-chain-attack-recon", "cloud-iam-deep",
    "hunt-cache-poison", "hunt-deserialization", "hunt-http-smuggling", "hunt-host-header",
    "hunt-open-redirect", "hunt-websocket", "hunt-grpc", "hunt-saml", "hunt-nosqli",
    "hunt-ldap", "hunt-cicd", "hunt-tls-network", "hunt-aspnet", "hunt-laravel",
    "hunt-nextjs", "hunt-nodejs", "hunt-springboot", "bugcrowd-reporting", "evidence-hygiene",
    "redteam-report-template", "mid-engagement-ir-detection", "bb-methodology",
    "bb-local-toolkit", "meme-coin-audit",
]
# source-skill -> broad skill it was merged into
TIER2 = {
    "hunt-sqli": "injection", "hunt-ssrf": "injection", "hunt-ssti": "injection",
    "hunt-xss": "injection", "hunt-xxe": "injection", "hunt-lfi": "injection", "hunt-rce": "injection",
    "hunt-ato": "authentication", "hunt-auth-bypass": "authentication", "hunt-brute-force": "authentication",
    "hunt-mfa-bypass": "authentication", "hunt-oauth": "authentication", "hunt-session": "authentication",
    "hunt-idor": "api-security", "hunt-api-misconfig": "api-security", "hunt-graphql": "api-security",
    "hunt-csrf": "client-side", "hunt-dom": "client-side",
    "hunt-cors": "server-side", "hunt-file-upload": "server-side", "hunt-misc": "server-side",
    "hunt-business-logic": "web-app-logic", "hunt-race-condition": "web-app-logic",
    "hunt-cloud-misconfig": "cloud-containers", "hunt-k8s": "cloud-containers",
    "hunt-subdomain": "reconnaissance", "web2-recon": "reconnaissance", "hunt-source-leak": "reconnaissance",
    "offensive-osint": "osint", "osint-methodology": "osint",
    "apk-redteam-pipeline": "mapt", "redteam-mindset": "red-team",
    "security-arsenal": "essential-tools", "web3-audit": "blockchain-security",
    "bug-bounty": "hackerone", "triage-validation": "coordination", "report-writing": "coordination",
}
# Upstream skills deliberately NOT imported (already covered natively / engine-internal),
# so they should not be reported as actionable "new upstream".
SKIPPED = {
    "hunt-llm-ai",    # covered by tzar-bot's ai-threat-testing (Tier 3 peer)
    "hunt-dispatch",  # internal to BugHunter's /hunt engine, not portable
}

C = {"red": "\033[1;31m", "grn": "\033[1;32m", "yel": "\033[1;33m",
     "cyn": "\033[1;36m", "dim": "\033[2m", "rst": "\033[0m"}
def c(col, s): return f"{C[col]}{s}{C['rst']}" if sys.stdout.isatty() else s


def entries():
    """Yield (name, kind, upstream_dir, local_path)."""
    for n in TIER1:
        yield n, "standalone", f"skills/{n}", SKILLS / n
    for n, broad in TIER2.items():
        yield n, "merged", f"skills/{n}", SKILLS / broad / "reference" / f"{n}.md"


def dir_hash(d: Path) -> str | None:
    """Stable hash over all files in an upstream skill dir (catches reference/ changes too)."""
    if not d.is_dir():
        return None
    h = hashlib.sha256()
    for f in sorted(d.rglob("*")):
        if f.is_file():
            h.update(f.relative_to(d).as_posix().encode())
            h.update(b"\0")
            h.update(f.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def git(upstream: Path, *args) -> str | None:
    try:
        return subprocess.run(["git", "-C", str(upstream), *args],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return None


def load_manifest():
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text())
    return None


def save_manifest(m):
    MANIFEST.write_text(json.dumps(m, indent=2) + "\n")


def build_baseline(upstream: Path):
    m = {"upstream": str(upstream),
         "upstream_commit": git(upstream, "rev-parse", "HEAD") or "unknown",
         "skills": {}}
    for name, kind, up_rel, _local in entries():
        m["skills"][name] = {"kind": kind, "upstream_rel": up_rel,
                             "hash": dir_hash(upstream / "skills" / name)}
    return m


# ----------------------------------------------------------------- commands
def cmd_init(upstream: Path):
    m = build_baseline(upstream)
    save_manifest(m)
    n = sum(1 for v in m["skills"].values() if v["hash"])
    print(c("grn", f"[+] baseline recorded: {n}/{len(m['skills'])} skills "
                   f"@ upstream {m['upstream_commit'][:10]}"))
    print(f"    manifest: {MANIFEST}")
    miss = [k for k, v in m["skills"].items() if not v["hash"]]
    if miss:
        print(c("yel", f"[!] not found in upstream ({len(miss)}): {', '.join(miss)}"))


def cmd_report(upstream: Path) -> int:
    m = load_manifest()
    if not m:
        print(c("red", "[-] no baseline. Run:  python3 tools/sync-bughunter.py --init"))
        return 2

    base_commit = m.get("upstream_commit", "unknown")
    now_commit = git(upstream, "rev-parse", "HEAD") or "unknown"
    print(c("cyn", "=== Tzar-Bot ↔ BugHunter sync report ==="))
    print(f"upstream : {upstream}")
    print(f"baseline : {base_commit[:10]}   now: {now_commit[:10]}")
    print()

    up_to_date, changed, local_missing = [], [], []
    for name, kind, up_rel, local in entries():
        rec = m["skills"].get(name)
        cur = dir_hash(upstream / "skills" / name)
        if not local.exists():
            local_missing.append((name, local))
        if rec is None:
            changed.append((name, "not in baseline", up_rel))
        elif cur is None:
            changed.append((name, "REMOVED upstream", up_rel))
        elif cur != rec["hash"]:
            changed.append((name, "upstream changed", up_rel))
        else:
            up_to_date.append(name)

    # upstream skills we never imported (candidate new imports)
    known = set(TIER1) | set(TIER2) | SKIPPED
    up_skills = {p.name for p in (upstream / "skills").iterdir() if p.is_dir()} \
        if (upstream / "skills").is_dir() else set()
    new_upstream = sorted(s for s in up_skills - known)

    print(c("grn", f"UP TO DATE        : {len(up_to_date)}"))
    print((c("yel", f"UPSTREAM CHANGED  : {len(changed)}")) + ("   <- review & --diff/--accept" if changed else ""))
    for name, why, rel in changed:
        print(f"   {name:<22} {c('dim', why)}  {rel}")
    print((c("cyn", f"NEW UPSTREAM      : {len(new_upstream)}")) + ("   <- consider importing" if new_upstream else ""))
    for s in new_upstream:
        print(f"   {s}")
    print((c("red", f"LOCAL MISSING     : {len(local_missing)}")) + ("   <- imported file gone" if local_missing else ""))
    for name, local in local_missing:
        print(f"   {name:<22} {local.relative_to(TZAR_ROOT)}")

    drift = bool(changed or new_upstream or local_missing)
    print()
    print(c("yel", "[!] drift detected.") if drift else c("grn", "[+] fully in sync."))
    if changed:
        print(c("dim", "    inspect:  python3 tools/sync-bughunter.py --diff <name>"))
        print(c("dim", "    re-sync:  re-import the file, re-apply adaptations, then --accept <name>"))
    return 1 if drift else 0


def cmd_diff(upstream: Path, name: str) -> int:
    m = load_manifest()
    if not m or name not in m["skills"]:
        print(c("red", f"[-] {name} not in baseline")); return 2
    base = m.get("upstream_commit")
    rel = m["skills"][name]["upstream_rel"]
    out = git(upstream, "diff", base, "--", rel) if base and base != "unknown" else None
    if out is None:
        print(c("yel", f"[!] git diff unavailable; hashes differ for {name}. "
                       f"Compare manually under {upstream}/{rel}"))
        return 1
    if not out.strip():
        print(c("grn", f"[+] no upstream changes for {name} since baseline")); return 0
    print(out)
    return 1


def cmd_accept(upstream: Path, name: str) -> int:
    m = load_manifest()
    if not m:
        print(c("red", "[-] no baseline; run --init first")); return 2
    if name == "all":
        m = build_baseline(upstream)
        save_manifest(m)
        print(c("grn", f"[+] baseline bumped for ALL @ {m['upstream_commit'][:10]}"))
        return 0
    if name not in m["skills"]:
        print(c("red", f"[-] {name} not tracked")); return 2
    m["skills"][name]["hash"] = dir_hash(upstream / "skills" / name)
    m["upstream_commit"] = git(upstream, "rev-parse", "HEAD") or m.get("upstream_commit", "unknown")
    save_manifest(m)
    print(c("grn", f"[+] {name} accepted (baseline updated)"))
    return 0


def main():
    ap = argparse.ArgumentParser(description="Detect drift vs upstream claude-bughunter.")
    ap.add_argument("--upstream", default=DEFAULT_UPSTREAM, help="path to Claude-BugHunter repo")
    ap.add_argument("--init", action="store_true", help="record baseline from current upstream")
    ap.add_argument("--pull", action="store_true", help="git pull upstream before reporting")
    ap.add_argument("--diff", metavar="NAME", help="show upstream changes for one skill since baseline")
    ap.add_argument("--accept", metavar="NAME", help="mark NAME (or 'all') reviewed; bump baseline")
    a = ap.parse_args()

    upstream = Path(a.upstream).expanduser()
    if not upstream.is_dir():
        print(c("red", f"[-] upstream not found: {upstream}  (set --upstream or $BUGHUNTER_DIR)"))
        sys.exit(2)

    if a.pull:
        print(c("cyn", f"[*] git pull {upstream} ..."))
        print(git(upstream, "pull", "--ff-only") or c("yel", "    (pull failed / not a git repo)"))

    if a.init:
        cmd_init(upstream); sys.exit(0)
    if a.diff:
        sys.exit(cmd_diff(upstream, a.diff))
    if a.accept:
        sys.exit(cmd_accept(upstream, a.accept))
    sys.exit(cmd_report(upstream))


if __name__ == "__main__":
    main()
