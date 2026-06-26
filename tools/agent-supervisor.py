#!/usr/bin/env python3
"""
agent-supervisor.py — registry + lifecycle control for spawned executor processes.

Problem it solves: during an engagement, background executor/scan processes kept
running (and even re-spawning) after a "stand down", and orphans had to be hunted
with pgrep + kill -9 by hand. This gives the coordinator a deterministic registry so
"stand down" = a real terminate, and a reaper to clean orphaned processes touching
the engagement.

Registry lives at <output-dir>/.agents/registry.json.

Usage:
  agent-supervisor.py register --output-dir DIR --name scan-A --pid 1234 [--owns recon/batch-A] [--cmd "nmap ..."]
  agent-supervisor.py list     --output-dir DIR [--json]
  agent-supervisor.py stop     --output-dir DIR (--name scan-A | --all) [--grace 3]
  agent-supervisor.py reap     --output-dir DIR [--pattern STR] [--dry-run]
  agent-supervisor.py claim    --output-dir DIR --name scan-A --owns recon/batch-A
  agent-supervisor.py --selftest

Exit: 0 ok; 2 not-found; 3 ownership collision; 1 bad args.
"""
import os
import sys
import json
import time
import signal
import argparse
from pathlib import Path
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _reg_path(output_dir):
    return Path(output_dir) / ".agents" / "registry.json"

def _load(output_dir):
    p = _reg_path(output_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"agents": {}}

def _save(output_dir, reg):
    p = _reg_path(output_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(reg, indent=1), encoding="utf-8")

def _alive(pid):
    if not pid:
        return False
    # Treat zombie/defunct (state 'Z' or 'X') as dead — a killed child not yet reaped
    # by its parent still answers kill(pid,0) but is not running.
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        state = stat.rsplit(")", 1)[1].split()[0]
        if state in ("Z", "X", "x"):
            return False
    except (OSError, IndexError):
        pass
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return Path(f"/proc/{pid}").exists()

def _cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        return ""

def _term(pid, sig):
    """Signal the process group if possible (covers detached children), else the pid."""
    try:
        os.killpg(os.getpgid(pid), sig)
        return True
    except (ProcessLookupError, OSError):
        try:
            os.kill(pid, sig)
            return True
        except (ProcessLookupError, OSError):
            return False


# ── commands ────────────────────────────────────────────────────────────────
def cmd_register(args):
    reg = _load(args.output_dir)
    a = reg["agents"].setdefault(args.name, {})
    pids = set(a.get("pids", []))
    pids.update(args.pid or [])
    a.update(pids=sorted(pids), owns=args.owns or a.get("owns", ""),
             cmd=args.cmd or a.get("cmd", ""), state="running",
             registered=a.get("registered", _now()), updated=_now())
    # ownership collision check
    if args.owns:
        for other, oa in reg["agents"].items():
            if other != args.name and oa.get("owns") == args.owns and oa.get("state") == "running":
                print(f"[!] ownership collision: {args.owns!r} already owned by running agent {other!r}",
                      file=sys.stderr)
                _save(args.output_dir, reg)
                return 3
    _save(args.output_dir, reg)
    print(f"[+] registered {args.name} pids={sorted(pids)} owns={args.owns or '-'}")
    return 0

def cmd_claim(args):
    a = argparse.Namespace(output_dir=args.output_dir, name=args.name,
                           pid=[], owns=args.owns, cmd="")
    return cmd_register(a)

def cmd_list(args):
    reg = _load(args.output_dir)
    rows = []
    for name, a in sorted(reg["agents"].items()):
        live = [p for p in a.get("pids", []) if _alive(p)]
        rows.append({"name": name, "state": a.get("state"), "pids": a.get("pids", []),
                     "alive_pids": live, "owns": a.get("owns", ""), "cmd": a.get("cmd", "")})
    if args.json:
        print(json.dumps(rows, indent=2)); return 0
    if not rows:
        print("  (no agents registered)"); return 0
    print(f"  {len(rows)} registered agent(s):")
    for r in rows:
        alive = f"{len(r['alive_pids'])}/{len(r['pids'])} alive" if r["pids"] else "no pids"
        print(f"   {r['name']:16s} {r['state'] or '?':8s} [{alive}] owns={r['owns'] or '-'}")
    return 0

def cmd_stop(args):
    reg = _load(args.output_dir)
    targets = list(reg["agents"]) if args.all else ([args.name] if args.name else [])
    if not targets:
        print("[!] specify --name or --all", file=sys.stderr); return 1
    missing = [t for t in targets if t not in reg["agents"]]
    if missing and not args.all:
        print(f"[!] no such agent: {', '.join(missing)}", file=sys.stderr); return 2
    stopped = []
    for name in targets:
        a = reg["agents"].get(name)
        if not a:
            continue
        pids = [p for p in a.get("pids", []) if _alive(p)]
        for p in pids:
            _term(p, signal.SIGTERM)
        if pids:
            time.sleep(max(0.2, args.grace))
            for p in pids:
                if _alive(p):
                    _term(p, signal.SIGKILL)
        a["state"] = "stopped"; a["stopped"] = _now()
        stopped.append((name, pids))
    _save(args.output_dir, reg)
    for name, pids in stopped:
        survivors = [p for p in pids if _alive(p)]
        print(f"  stopped {name}: signalled {pids or '[]'}" +
              (f"  STILL ALIVE: {survivors}" if survivors else "  (clean)"))
    return 0

def cmd_reap(args):
    """Kill processes that touch this engagement but are NOT a live registered agent.
    Default match: the engagement OUTPUT_DIR path in the cmdline; override with --pattern."""
    reg = _load(args.output_dir)
    registered = set()
    for a in reg["agents"].values():
        if a.get("state") == "running":
            registered.update(a.get("pids", []))
    pattern = args.pattern or str(Path(args.output_dir).resolve())
    self_pid = os.getpid()
    victims = []
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(proc.name)
        except ValueError:
            continue
        if pid == self_pid or pid in registered:
            continue
        cl = _cmdline(pid)
        if pattern in cl and "agent-supervisor.py" not in cl:
            victims.append((pid, cl[:100]))
    if args.dry_run:
        print(f"  [dry-run] {len(victims)} orphan(s) matching {pattern!r}:")
        for pid, cl in victims:
            print(f"     {pid}  {cl}")
        return 0
    for pid, _ in victims:
        _term(pid, signal.SIGTERM)
    if victims:
        time.sleep(0.3)
        for pid, _ in victims:
            if _alive(pid):
                _term(pid, signal.SIGKILL)
    # prune dead pids from registry
    for a in reg["agents"].values():
        a["pids"] = [p for p in a.get("pids", []) if _alive(p)]
        if not a["pids"] and a.get("state") == "running":
            a["state"] = "exited"
    _save(args.output_dir, reg)
    print(f"  reaped {len(victims)} orphan process(es) matching {pattern!r}")
    return 0


def _selftest():
    import tempfile, subprocess
    d = tempfile.mkdtemp(prefix="agentsup-")
    # spawn a detached long-lived dummy
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                            start_new_session=True)
    ns = argparse.Namespace
    assert cmd_register(ns(output_dir=d, name="dummy", pid=[proc.pid],
                           owns="x", cmd="sleep")) == 0
    reg = _load(d)
    assert reg["agents"]["dummy"]["pids"] == [proc.pid]
    assert _alive(proc.pid), "dummy should be alive"
    # collision check
    assert cmd_register(ns(output_dir=d, name="other", pid=[], owns="x", cmd="")) == 3, \
        "ownership collision not detected"
    # stop it
    assert cmd_stop(ns(output_dir=d, name="dummy", all=False, grace=0.3)) == 0
    time.sleep(0.2)
    assert not _alive(proc.pid), "dummy should be dead after stop"
    assert _load(d)["agents"]["dummy"]["state"] == "stopped"
    print("[+] agent-supervisor selftest OK")
    return 0


def main():
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("register"); pr.add_argument("--output-dir", required=True)
    pr.add_argument("--name", required=True); pr.add_argument("--pid", type=int, action="append")
    pr.add_argument("--owns", default=""); pr.add_argument("--cmd", default="")
    pr.set_defaults(func=cmd_register)

    pc = sub.add_parser("claim"); pc.add_argument("--output-dir", required=True)
    pc.add_argument("--name", required=True); pc.add_argument("--owns", required=True)
    pc.set_defaults(func=cmd_claim)

    pl = sub.add_parser("list"); pl.add_argument("--output-dir", required=True)
    pl.add_argument("--json", action="store_true"); pl.set_defaults(func=cmd_list)

    psp = sub.add_parser("stop"); psp.add_argument("--output-dir", required=True)
    psp.add_argument("--name"); psp.add_argument("--all", action="store_true")
    psp.add_argument("--grace", type=float, default=3.0); psp.set_defaults(func=cmd_stop)

    pre = sub.add_parser("reap"); pre.add_argument("--output-dir", required=True)
    pre.add_argument("--pattern", default=""); pre.add_argument("--dry-run", action="store_true")
    pre.set_defaults(func=cmd_reap)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
