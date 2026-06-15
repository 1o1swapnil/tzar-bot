#!/usr/bin/env python3
"""
lint-skills.py — quality + convention gate for tzar-bot skills.

Enforces standard skill hygiene AND the tzar-bot integration invariants established
when claude-bughunter skills were imported, so a later edit can't silently
reintroduce upstream-only assumptions (recon/$TARGET paths, Burp MCP, ~/.claude
paths) or break a reference/ link.

Scope:
  skills/<name>/SKILL.md          full checks (structure + conventions + safety)
  skills/<name>/reference/*.md     lighter checks (safety + integration invariants)

Severities:
  ERROR   -> fails the build (exit 1)
  WARN    -> reported, never fails (exit 0)  unless --strict (then WARN == ERROR)

Usage:
  python3 tools/lint-skills.py                 # lint everything
  python3 tools/lint-skills.py skills/injection # lint specific skill dir(s) or file(s)
  python3 tools/lint-skills.py --strict        # warnings fail too
  python3 tools/lint-skills.py --quiet         # only show problems + summary

Stdlib only.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
CLAUDE_MD = ROOT / "CLAUDE.md"
SYNC_MANIFEST = ROOT / "tools" / "bughunter-sync.manifest.json"

NAME_RE = re.compile(r"^[a-z0-9-]+$")
MAX_DESC = 400          # always-on routing-token budget: every description loads every session
WARN_BODY_LINES = 1600

# --- integration invariants (regressions of our import adaptations) ----------
RX_RECON_TARGET = re.compile(r"recon/\$\{?TARGET\}?")        # must be $OUTPUT_DIR/recon
RX_BURP_MCP     = re.compile(r"mcp__burp__")                 # tzar-bot has no Burp MCP
RX_DOTCLAUDE    = re.compile(r"~/\.claude/")                 # hardcoded plugin path
RX_INSTALL_HDR  = re.compile(r"^#+\s*INSTALLATION", re.M)    # standalone-distribution boilerplate
RX_THIRDPARTY   = re.compile(r"git clone\s+\S+\s+~/\.claude")
# BugHunter slash commands that don't exist in tzar-bot (not the $OUTPUT_DIR/recon path).
# Only flag when used as a COMMAND (context word on the line), so API endpoints / paths
# like `/report?x=` or `/api/*/validate` or the gitignore glob `*/recon/*` don't trip it.
RX_BH_CMD = re.compile(
    r"(?<![\w/])/(recon|validate|triage|hunt|chain|autopilot|remember|report|intel|surface|token-scan|pickup|memory-gc)\b(?![\w/])"
)
RX_CMD_CTX = re.compile(r"invoke|invokes|\bcalls?\b|\brun\b|command|slash", re.I)

# --- secret patterns (errors are tight; token-like docs are warnings) ---------
SECRET_ERR = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]
SECRET_WARN = [
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("GitHub PAT", re.compile(r"\bghp_[0-9A-Za-z]{36}")),
]
SECRET_ALLOW = re.compile(r"EXAMPLE|AKIAIOSFODNN7|wJalrXUtnFEMI|<[^>]+>|\.\.\.|\[[A-Za-z0-9]|\\b|xxx|XXX|placeholder", re.I)

C = {"red": "\033[1;31m", "yel": "\033[1;33m", "grn": "\033[1;32m", "cyn": "\033[1;36m", "dim": "\033[2m", "rst": "\033[0m"}
def col(k, s): return f"{C[k]}{s}{C['rst']}" if sys.stdout.isatty() else s


class Report:
    def __init__(self):
        self.errors = []   # (file, msg)
        self.warns = []    # (file, msg)
    def err(self, f, m):  self.errors.append((f, m))
    def warn(self, f, m): self.warns.append((f, m))


def split_frontmatter(raw):
    if not raw.startswith("---"):
        return None, raw, "no frontmatter (file must start with '---')"
    lines = raw.split("\n")
    close = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if close is None:
        return None, raw, "frontmatter opened but never closed"
    fm = {}
    for ln in lines[1:close]:
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", ln)
        if m:
            fm[m.group(1)] = m.group(2).strip()
    return fm, "\n".join(lines[close + 1:]), None


def scan_secrets(rel, raw, rep):
    for ln_no, line in enumerate(raw.split("\n"), 1):
        if SECRET_ALLOW.search(line):
            continue
        for label, rx in SECRET_ERR:
            if rx.search(line):
                rep.err(rel, f"possible real secret ({label}) at line {ln_no}")
        for label, rx in SECRET_WARN:
            if rx.search(line):
                rep.warn(rel, f"token-like value ({label}) at line {ln_no} — confirm it's a doc example")


def integration_checks(rel, raw, rep, oob_context=""):
    if RX_RECON_TARGET.search(raw):
        rep.err(rel, "uses 'recon/$TARGET/' — must be '$OUTPUT_DIR/recon/' (tzar-bot routing)")
    if RX_BURP_MCP.search(raw):
        rep.err(rel, "references 'mcp__burp__' — tzar-bot has no Burp MCP; use interactsh/raw socket")
    if RX_DOTCLAUDE.search(raw):
        rep.err(rel, "hardcoded '~/.claude/' path — use a tzar-bot absolute/relative path")
    if RX_INSTALL_HDR.search(raw) or RX_THIRDPARTY.search(raw):
        rep.err(rel, "contains standalone '# INSTALLATION' / third-party clone boilerplate — remove")
    seen = set()
    for line in raw.split("\n"):
        if RX_CMD_CTX.search(line):
            for m in RX_BH_CMD.findall(line):
                if m not in seen:
                    seen.add(m)
                    rep.warn(rel, f"references BugHunter slash command '/{m}' in command context — remap to tzar-bot tool/skill")
    # OOB note may live in this file OR its parent broad SKILL.md (for merged references)
    if re.search(r"collaborator", raw, re.I) and "OOB callbacks (Tzar-Bot)" not in (raw + oob_context):
        rep.warn(rel, "mentions Burp Collaborator but no interactsh OOB note (here or in parent skill)")


def load_imports():
    """Names of standalone-imported skills (deliberately left without allowed-tools)."""
    if not SYNC_MANIFEST.exists():
        return set()
    import json
    try:
        m = json.loads(SYNC_MANIFEST.read_text())
        return {n for n, v in m.get("skills", {}).items() if v.get("kind") == "standalone"}
    except Exception:
        return set()


def lint_skill_md(path: Path, registered: set, imports: set, rep: Report):
    rel = path.relative_to(ROOT).as_posix()
    raw = path.read_text(encoding="utf-8", errors="replace")
    fm, body, fmerr = split_frontmatter(raw)
    if fmerr:
        rep.err(rel, fmerr)
        return
    name = fm.get("name")
    if not name:
        rep.err(rel, "missing 'name' in frontmatter")
    else:
        if not NAME_RE.match(name):
            rep.err(rel, f"name '{name}' must match ^[a-z0-9-]+$")
        if name != path.parent.name:
            rep.err(rel, f"name '{name}' != directory '{path.parent.name}'")
    desc = fm.get("description")
    if not desc:
        rep.err(rel, "missing 'description' in frontmatter")
    elif len(desc) > MAX_DESC:
        rep.warn(rel, f"description {len(desc)} chars > {MAX_DESC} routing-token budget — trim prose, keep trigger keywords")
    if "allowed-tools" not in fm and name not in imports:
        rep.warn(rel, "no 'allowed-tools' (tzar-bot native skills declare it)")
    nbody = len(body.split("\n"))
    if nbody > WARN_BODY_LINES:
        rep.warn(rel, f"body {nbody} lines > {WARN_BODY_LINES} (consider splitting into reference/)")

    scan_secrets(rel, raw, rep)
    integration_checks(rel, raw, rep)

    # reference/ links resolve — only bare 'reference/x.md' (the skill's own dir),
    # NOT fully-qualified 'skills/<other>/reference/x.md' cross-references.
    for m in re.finditer(r"(?<![\w/])reference/([A-Za-z0-9_.-]+\.md)", raw):
        tgt = path.parent / "reference" / m.group(1)
        if not tgt.exists():
            rep.err(rel, f"broken reference link: reference/{m.group(1)} not found")

    # registration in CLAUDE.md (top-level skills only)
    if name and name not in registered:
        rep.warn(rel, "not referenced in CLAUDE.md Skills Overview")


def lint_reference_md(path: Path, rep: Report):
    rel = path.relative_to(ROOT).as_posix()
    raw = path.read_text(encoding="utf-8", errors="replace")
    fm, _body, _ = split_frontmatter(raw)
    if fm and fm.get("name") and not NAME_RE.match(fm["name"]):
        rep.warn(rel, f"name '{fm['name']}' not kebab-case")
    parent_skill = path.parent.parent / "SKILL.md"
    parent_text = parent_skill.read_text(encoding="utf-8", errors="replace") if parent_skill.exists() else ""
    scan_secrets(rel, raw, rep)
    integration_checks(rel, raw, rep, oob_context=parent_text)


def load_registered():
    if not CLAUDE_MD.exists():
        return set()
    text = CLAUDE_MD.read_text(encoding="utf-8", errors="replace")
    return set(re.findall(r"`([a-z0-9-]+)`", text))


def collect_targets(args_paths):
    """Return (skill_mds, reference_mds)."""
    skill_mds, ref_mds = [], []
    if args_paths:
        for p in args_paths:
            p = Path(p).resolve()
            if p.is_dir():
                if (p / "SKILL.md").exists():
                    skill_mds.append(p / "SKILL.md")
                ref_mds += sorted((p / "reference").glob("*.md")) if (p / "reference").is_dir() else []
            elif p.name == "SKILL.md":
                skill_mds.append(p)
            elif p.suffix == ".md":
                ref_mds.append(p)
    else:
        for d in sorted(SKILLS.iterdir()):
            if not d.is_dir():
                continue
            if (d / "SKILL.md").exists():
                skill_mds.append(d / "SKILL.md")
            if (d / "reference").is_dir():
                ref_mds += sorted((d / "reference").glob("*.md"))
    return skill_mds, ref_mds


def main():
    ap = argparse.ArgumentParser(description="Lint tzar-bot skills.")
    ap.add_argument("paths", nargs="*", help="skill dirs or .md files (default: all)")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--quiet", action="store_true", help="only show problems + summary")
    a = ap.parse_args()

    registered = load_registered()
    imports = load_imports()
    skill_mds, ref_mds = collect_targets(a.paths)
    rep = Report()

    for m in skill_mds:
        lint_skill_md(m, registered, imports, rep)
    for m in ref_mds:
        lint_reference_md(m, rep)

    # group output by file
    by_file = {}
    for f, msg in rep.errors:
        by_file.setdefault(f, []).append(("E", msg))
    for f, msg in rep.warns:
        by_file.setdefault(f, []).append(("W", msg))

    for f in sorted(by_file):
        print(col("cyn", f))
        for sev, msg in by_file[f]:
            tag = col("red", "ERROR") if sev == "E" else col("yel", "WARN ")
            print(f"  {tag} {msg}")

    files_scanned = len(skill_mds) + len(ref_mds)
    print()
    print(f"scanned {files_scanned} files "
          f"({len(skill_mds)} SKILL.md, {len(ref_mds)} reference)")
    ne, nw = len(rep.errors), len(rep.warns)
    summary = f"{col('red', str(ne) + ' errors')}, {col('yel', str(nw) + ' warnings')}"
    print(summary)

    fail = ne > 0 or (a.strict and nw > 0)
    if not fail and not a.quiet:
        print(col("grn", "[+] lint passed"))
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
