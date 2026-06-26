#!/usr/bin/env python3
"""
long-run.py — run a long tool detached, with incremental output + a status sidecar,
immune to the caller's command timeout (e.g. the sub-agent Bash ~2-minute default).

Problem it solves: an executor that runs a multi-minute scan inline gets its Bash call
killed at the default timeout, and tools that only persist on completion lose ALL output.
This wrapper detaches the work, streams output to a log as it happens, and records the
final exit code — so the caller returns immediately and polls.

Usage:
  python3 tools/long-run.py start --log OUT/recon/scan.log -- nmap -p- -sS 10.0.0.5
      → spawns the command detached, streams stdout+stderr to the log, writes
        <log>.status, prints the supervisor PID, and RETURNS IMMEDIATELY.

  python3 tools/long-run.py status --log OUT/recon/scan.log [--tail 20]
      → prints state (running|done|failed), exit code when finished, and the last lines.

  python3 tools/long-run.py --selftest

Pattern for executors: `start` the tool, then `status` on later turns until state != running.
Exit: 0 on success, 1 on error. (`status` exits 0 while running/done, 2 if the run failed.)
"""
import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _status_path(log):
    return str(log) + ".status"

def _write_status(log, **fields):
    Path(_status_path(log)).write_text(json.dumps(fields, indent=1), encoding="utf-8")

def _read_status(log):
    p = Path(_status_path(log))
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return pid and _proc_exists(pid)
    except OSError:
        return False

def _proc_exists(pid):
    return Path(f"/proc/{pid}").exists()


# Exit codes that indicate a signal / resource kill (worth retrying at lower concurrency).
# Popen.wait() returns a negative value when killed by a signal on POSIX; shells/wrappers
# surface the same as 128+signum (137 SIGKILL/OOM, 143 SIGTERM, 144, 134 SIGABRT, 139 SIGSEGV).
_KILL_CODES = {137, 143, 144, 134, 139}

def _is_kill(rc):
    return rc is not None and (rc < 0 or rc in _KILL_CODES)


# ── supervisor (internal) ──────────────────────────────────────────────────
def _supervise(log, cmd, cwd, workers=None, retry_on_kill=0):
    """Run cmd, stream output to log, record final status. Runs detached.
    On a signal/resource kill, retry up to `retry_on_kill` times, each time halving
    the TZAR_WORKERS passed to the child (so a resource-killed scan re-runs lower)."""
    Path(log).parent.mkdir(parents=True, exist_ok=True)
    started = _now()
    w = workers
    attempt = 0
    rc = None
    try:
        with open(log, "ab", buffering=0) as lf:
            while True:
                attempt += 1
                env = os.environ.copy()
                if w is not None:
                    env["TZAR_WORKERS"] = str(w)
                _write_status(log, state="running", supervisor_pid=os.getpid(),
                              attempt=attempt, workers=w, cmd=cmd, cwd=cwd, started=started)
                lf.write(f"[long-run] {_now()} attempt {attempt} "
                         f"(workers={w}) starting: {' '.join(cmd)}\n".encode())
                proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT,
                                        cwd=cwd or None, env=env)
                _write_status(log, state="running", supervisor_pid=os.getpid(),
                              child_pid=proc.pid, attempt=attempt, workers=w,
                              cmd=cmd, cwd=cwd, started=started)
                rc = proc.wait()
                lf.write(f"[long-run] {_now()} attempt {attempt} finished rc={rc}\n".encode())
                if _is_kill(rc) and attempt <= retry_on_kill:
                    w = max(50, (w if w else 400) // 2)
                    lf.write(f"[long-run] signal/resource kill — retrying at "
                             f"lower concurrency (workers={w})\n".encode())
                    continue
                break
    except (OSError, ValueError) as e:
        _write_status(log, state="failed", error=str(e), cmd=cmd, cwd=cwd,
                      started=started, finished=_now(), attempts=attempt)
        return 1
    _write_status(log, state=("done" if rc == 0 else "failed"),
                  exit_code=rc, cmd=cmd, cwd=cwd, started=started, finished=_now(),
                  attempts=attempt, workers=w)
    return 0


# ── commands ────────────────────────────────────────────────────────────────
def cmd_start(args):
    if not args.command:
        print("[!] no command after '--'", file=sys.stderr); return 1
    log = os.path.abspath(args.log)
    Path(log).parent.mkdir(parents=True, exist_ok=True)
    # Detach a supervisor process that owns the child and updates status.
    extra = []
    if getattr(args, "workers", None):
        extra += ["--workers", str(args.workers)]
    if getattr(args, "retry_on_kill", 0):
        extra += ["--retry-on-kill", str(args.retry_on_kill)]
    sup = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "_run", "--log", log,
         *(["--cwd", args.cwd] if args.cwd else []), *extra, "--", *args.command],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # brief settle so the status file exists before we return
    for _ in range(50):
        if _read_status(log):
            break
        time.sleep(0.02)
    print(f"[+] started detached (supervisor pid {sup.pid})")
    print(f"    log:    {log}")
    print(f"    status: {_status_path(log)}")
    print(f"    poll:   python3 tools/long-run.py status --log {args.log}")
    return 0

def cmd_status(args):
    log = os.path.abspath(args.log)
    st = _read_status(log)
    if st is None:
        print(f"[!] no status for {args.log} (not started?)", file=sys.stderr); return 1
    state = st.get("state")
    # reconcile: supervisor died without finishing
    if state == "running":
        sup = st.get("supervisor_pid")
        if sup and not _alive(sup):
            state = "failed"
            st["state"] = "failed"; st["error"] = "supervisor exited without recording completion"
    print(f"  state    : {state}")
    if "exit_code" in st:
        print(f"  exit_code: {st['exit_code']}")
    if st.get("error"):
        print(f"  error    : {st['error']}")
    print(f"  started  : {st.get('started','?')}   finished: {st.get('finished','-')}")
    tail = args.tail
    if tail and Path(log).exists():
        lines = Path(log).read_text(encoding="utf-8", errors="replace").splitlines()
        print(f"  --- last {min(tail, len(lines))} log line(s) ---")
        for l in lines[-tail:]:
            print("  " + l)
    if args.json:
        print(json.dumps(st, indent=2))
    return 2 if state == "failed" else 0


def _selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="longrun-")
    log = os.path.join(d, "t.log")
    # a short multi-line command (NOT instant) to exercise streaming + completion
    cmd = [sys.executable, "-c",
           "import time;\nfor i in range(3):\n print('line',i,flush=True)\n"]
    class A: pass
    a = A(); a.log = log; a.cwd = None; a.command = cmd
    assert cmd_start(a) == 0, "start failed"
    # poll until done
    ok = False
    for _ in range(100):
        st = _read_status(log)
        if st and st.get("state") in ("done", "failed"):
            ok = (st["state"] == "done" and st.get("exit_code") == 0)
            break
        time.sleep(0.05)
    body = Path(log).read_text() if Path(log).exists() else ""
    assert ok, f"run did not complete cleanly: {_read_status(log)}"
    assert "line 0" in body and "line 2" in body, f"log missing streamed output:\n{body}"
    print("[+] long-run selftest OK")
    return 0


def main():
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("start", "_run"):
        p = sub.add_parser(name, help=argparse.SUPPRESS if name == "_run" else "start a detached long-running command")
        p.add_argument("--log", required=True)
        p.add_argument("--cwd", default="")
        p.add_argument("--workers", type=int, default=None,
                       help="set $TZAR_WORKERS for the child (concurrency knob)")
        p.add_argument("--retry-on-kill", type=int, default=0,
                       help="retries on signal/resource kill, halving workers each time")
        p.add_argument("command", nargs=argparse.REMAINDER,
                       help="-- then the command and its args")

    ps = sub.add_parser("status", help="check a detached run")
    ps.add_argument("--log", required=True)
    ps.add_argument("--tail", type=int, default=10)
    ps.add_argument("--json", action="store_true")

    ap.add_argument("--selftest", action="store_true", help="run internal self-test")
    args = ap.parse_args()

    # strip a leading '--' left in REMAINDER
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]

    if args.cmd == "_run":
        sys.exit(_supervise(args.log, args.command, args.cwd,
                            workers=args.workers, retry_on_kill=args.retry_on_kill))
    elif args.cmd == "start":
        sys.exit(cmd_start(args))
    elif args.cmd == "status":
        sys.exit(cmd_status(args))


if __name__ == "__main__":
    main()
