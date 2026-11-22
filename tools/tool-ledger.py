#!/usr/bin/env python3
"""
tool-ledger.py — PostToolUse hook: append-only, hash-chained record of target traffic.

Why: the validator's "log corroboration" check used to read logs the executor wrote
itself. In one past engagement a 4-line note stamped 08:08 was written at 08:12:45,
30 ms before the finding was re-validated, and the gate passed. This hook records what
the tools actually ran and returned. The agent never writes it, every entry chains to
the previous one by SHA-256, and editing the file is approval-gated by scope-check.py.

Recorded (when an engagement is active): Bash commands that look like network traffic,
Burp send_* requests, Playwright actions. Each entry: seq, UTC time, tool, input
(truncated), response SHA-256 + size + excerpt, prev hash, entry hash.
Written to $OUTPUT_DIR/logs/tool-ledger.ndjson.

CLI:
  python3 tools/tool-ledger.py verify <OUTPUT_DIR>     # exit 1 if the chain is broken
  python3 tools/tool-ledger.py search <OUTPUT_DIR> <text> [<text> ...]
"""
import fcntl
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from scope import read_active  # noqa: E402

LEDGER_NAME = "tool-ledger.ndjson"
MAX_INPUT = 4000
MAX_EXCERPT = 2000
GENESIS = "0" * 64


def _networky():
    spec = importlib.util.spec_from_file_location("scope_check_ledger", TOOLS / "scope-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.NETWORKY


def ledger_path(output_dir) -> Path:
    return Path(output_dir) / "logs" / LEDGER_NAME


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


def read_entries(output_dir):
    p = ledger_path(output_dir)
    if not p.exists():
        return None
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"_corrupt": line[:80]})
    return out


def verify(output_dir):
    """Return (ok, message, entries)."""
    entries = read_entries(output_dir)
    if entries is None:
        return False, "no ledger", []
    prev = GENESIS
    for i, e in enumerate(entries, 1):
        if "_corrupt" in e:
            return False, f"line {i} is not valid JSON", entries
        if e.get("prev") != prev:
            return False, f"chain broken at entry {i} (prev hash mismatch)", entries
        if e.get("hash") != entry_hash(e):
            return False, f"entry {i} was modified (hash mismatch)", entries
        if e.get("seq") != i:
            return False, f"entry {i} has seq {e.get('seq')} (entries removed or reordered)", entries
        prev = e["hash"]
    return True, f"{len(entries)} entries, chain intact", entries


def append(output_dir, tool, tool_input, response, now=None):
    p = ledger_path(output_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    resp_text = response if isinstance(response, str) else json.dumps(response, ensure_ascii=False)
    inp = tool_input.get("command") if tool == "Bash" else json.dumps(tool_input, ensure_ascii=False)
    with open(p, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        lines = [l for l in fh.read().splitlines() if l.strip()]
        prev, seq = GENESIS, 1
        if lines:
            try:
                last = json.loads(lines[-1])
                prev, seq = last.get("hash", GENESIS), int(last.get("seq", len(lines))) + 1
            except ValueError:
                prev, seq = hashlib.sha256(lines[-1].encode()).hexdigest(), len(lines) + 1
        entry = {
            "seq": seq,
            "ts": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
            "tool": tool,
            "input": (inp or "")[:MAX_INPUT],
            "response_sha256": hashlib.sha256(resp_text.encode("utf-8", "replace")).hexdigest(),
            "response_bytes": len(resp_text),
            "response_excerpt": resp_text[:MAX_EXCERPT],
            "prev": prev,
        }
        entry["hash"] = entry_hash(entry)
        fh.seek(0, os.SEEK_END)
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        fh.flush()
        fcntl.flock(fh, fcntl.LOCK_UN)
    return entry


def search(output_dir, needles):
    entries = read_entries(output_dir) or []
    needles = [n.lower() for n in needles if n]
    return [e for e in entries
            if all(n in (e.get("input", "") + " " + e.get("response_excerpt", "")).lower()
                   for n in needles)]


def _active_output_dir():
    od = os.environ.get("OUTPUT_DIR", "")
    if od and (Path(od) / "engagement.json").exists():
        return Path(od)
    return read_active()


def hook_main():
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return
    tool = data.get("tool_name", "")
    ti = data.get("tool_input") or {}
    if not isinstance(ti, dict):
        return
    if tool == "Bash":
        if not _networky().search(ti.get("command", "")):
            return
    elif tool.startswith("mcp__burp__"):
        if tool not in ("mcp__burp__send_http1_request", "mcp__burp__send_http2_request"):
            return
    elif not tool.startswith("mcp__playwright__"):
        return
    od = _active_output_dir()
    if not od:
        return
    append(od, tool, ti, data.get("tool_response", ""))


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("verify", "search"):
        if len(sys.argv) < 3:
            sys.exit(__doc__)
        od = Path(sys.argv[2])
        if sys.argv[1] == "verify":
            ok, msg, _ = verify(od)
            print(("OK  " if ok else "FAIL ") + msg)
            sys.exit(0 if ok else 1)
        for e in search(od, sys.argv[3:]):
            print(f"#{e['seq']} {e['ts']} {e['tool']}: {e['input'][:160]}")
        return
    try:
        hook_main()
    except Exception as exc:          # a ledger failure must never break the tool call
        print(f"[tool-ledger] {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
