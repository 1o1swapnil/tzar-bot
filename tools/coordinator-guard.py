#!/usr/bin/env python3
"""
coordinator-guard.py — PreToolUse hook enforcing the coordinator HARD BOUNDARY.

The coordinator must never run scanning/exploitation tools inline; it delegates to
executor agents. CLAUDE.md states this as a rule, but for the inline Claude Code
coordinator it was previously only self-policed. This hook makes it code-enforced.

Behaviour (only while an engagement is ACTIVE — like scope-check, it is a no-op when
there is no active engagement, so casual use is unaffected):
  - A command whose binary is a gated scanner/exploit tool (nmap, sqlmap, ffuf, ...)
    is BLOCKED with a "spawn an executor" message — UNLESS it carries an executor
    opt-out marker.
  - Executor opt-out: env `TZAR_ROLE` in {executor,validator}, OR the command is
    prefixed with `TZAR_ROLE=executor` / `TZAR_EXEC=1` (executors set this; see
    skills/coordination/reference/executor-role.md).

Modes via env `TZAR_COORDINATOR_GUARD`: enforce (default) | warn | off.
Exit: 2 = blocked (enforce); 0 = allowed / warned / no active engagement.
"""
import os
import re
import sys
import json
import shlex
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent

# Scanning / exploitation tools the coordinator must not run inline (CLAUDE.md boundary).
GATED = {
    "nmap", "masscan", "zmap", "rustscan",
    "ffuf", "gobuster", "feroxbuster", "dirb", "dirsearch", "wfuzz",
    "sqlmap", "nikto", "nuclei", "wpscan",
    "katana", "subfinder", "amass", "naabu", "gospider", "hakrawler",
    "hydra", "medusa", "patator", "crackmapexec", "nxc", "msfconsole",
}
# Shell wrappers to strip when finding the real binary of a stage.
WRAPPERS = {"sudo", "env", "time", "timeout", "nohup", "stdbuf", "nice", "ionice",
            "xargs", "doas", "setsid", "proxychains", "proxychains4"}
_OPERATOR_SPLIT = re.compile(r"\s*(?:\|\||&&|\||;|&|\n)\s*")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_MARKER = re.compile(r"\b(?:TZAR_ROLE=(?:executor|validator)|TZAR_EXEC=1)\b")


def _active_engagement() -> bool:
    out = os.environ.get("OUTPUT_DIR", "")
    if out and (Path(out) / "engagement.json").exists():
        return True
    try:
        import sqlite3
        db = REPO_DIR / "memory.db"
        if db.exists():
            conn = sqlite3.connect(db)
            row = conn.execute(
                "SELECT 1 FROM engagements WHERE status='active' LIMIT 1").fetchone()
            conn.close()
            return bool(row)
    except Exception:
        pass
    return False


def _has_executor_marker(command: str) -> bool:
    if os.environ.get("TZAR_ROLE", "").lower() in {"executor", "validator"}:
        return True
    return bool(_MARKER.search(command))


def _stage_binaries(command: str):
    """Yield the real binary (basename) of each pipeline/operator stage."""
    for stage in _OPERATOR_SPLIT.split(command):
        stage = stage.strip()
        if not stage:
            continue
        try:
            toks = shlex.split(stage)
        except ValueError:
            toks = stage.split()
        i = 0
        while i < len(toks):
            t = toks[i]
            if _ASSIGN.match(t):           # leading VAR=val
                i += 1; continue
            base = os.path.basename(t)
            if base in WRAPPERS:           # strip wrapper, look at its command
                i += 1
                # bash -c "..." — peek into the quoted command
                if base in {"bash", "sh", "zsh"}:
                    break
                continue
            yield base
            break


def main():
    try:
        hook = json.loads(sys.stdin.read())
    except Exception:
        sys.exit(0)
    if hook.get("tool_name") != "Bash":
        sys.exit(0)
    command = hook.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    mode = os.environ.get("TZAR_COORDINATOR_GUARD", "enforce").lower()
    if mode == "off":
        sys.exit(0)
    if not _active_engagement():
        sys.exit(0)                         # no engagement context — don't gate
    if _has_executor_marker(command):
        sys.exit(0)                         # executor / validator — allowed to scan

    hits = sorted({b for b in _stage_binaries(command) if b in GATED})
    if not hits:
        sys.exit(0)

    msg = (
        f"\n[COORDINATOR BOUNDARY] '{', '.join(hits)}' is a scanning/exploitation tool — "
        f"the coordinator must not run it inline.\n"
        f"→ Spawn an executor agent: Agent(prompt=..., run_in_background=True).\n"
        f"  Long scans: have the executor use tools/long-run.py.\n"
        f"  If you ARE an executor/validator, prefix the command with TZAR_ROLE=executor "
        f"(or export TZAR_ROLE=executor).\n"
        f"  To disable this guard: TZAR_COORDINATOR_GUARD=off.\n"
        f"Command: {command[:160]}\n"
    )
    if mode == "warn":
        sys.stderr.write("[coordinator-guard:warn]" + msg)
        sys.exit(0)
    sys.stderr.write(msg)
    sys.exit(2)


if __name__ == "__main__":
    main()
