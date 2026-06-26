#!/usr/bin/env python3
"""
concurrency.py — one source of truth for safe parallelism (avoid resource-kills).

Running 5 batches x 1200 worker threads (~6000 sockets) once triggered an external
`exit 144` kill. This module gives scan helpers and the coordinator a bounded, CPU-aware
default for (a) worker threads per process and (b) parallel-executor fan-out, plus the
`TZAR_WORKERS` env convention that long-run.py lowers on a signal-kill retry.

As a library:
    from concurrency import safe_workers, safe_fanout
    workers = safe_workers()              # honours $TZAR_WORKERS, capped
    workers = safe_workers(requested=800) # capped to HARD_CAP
    n_par   = safe_fanout(len(hosts))     # parallel executors

As a CLI:
    python3 tools/concurrency.py recommend [--workers N] [--items N] [--json]
    python3 tools/concurrency.py --selftest
"""
import os
import sys
import json
import argparse

# Per-process worker ceiling for I/O-bound work (sockets). Above this, fd/thread
# pressure risks an external kill. Override with $TZAR_HARD_CAP.
DEFAULT_WORKERS = 400


def _cpu():
    return os.cpu_count() or 2

def hard_cap():
    try:
        return max(50, int(os.environ.get("TZAR_HARD_CAP", "512")))
    except ValueError:
        return 512

def safe_workers(requested=None, hard=None):
    """Bounded worker count for a single process.
    Priority: explicit `requested` → $TZAR_WORKERS → DEFAULT_WORKERS, then capped."""
    cap = hard if hard is not None else hard_cap()
    if requested is None:
        env = os.environ.get("TZAR_WORKERS")
        if env:
            try:
                requested = int(env)
            except ValueError:
                requested = None
    if requested is None:
        requested = DEFAULT_WORKERS
    return max(1, min(int(requested), cap))

def safe_fanout(items, cap=None):
    """How many executors/processes to run in parallel over `items`.
    Bounded by CPU (cpu-2, min 1) so total concurrency stays sane."""
    by_cpu = max(1, _cpu() - 2)
    limit = by_cpu if cap is None else min(by_cpu, cap)
    return max(1, min(int(items), limit))

def recommend(requested=None, items=1):
    w = safe_workers(requested)
    f = safe_fanout(items)
    return {
        "cpu": _cpu(),
        "hard_cap": hard_cap(),
        "workers_per_process": w,
        "parallel_fanout": f,
        "total_concurrency": w * f,
        "note": ("requested workers capped" if requested and requested > w else "within limits"),
    }


def _selftest():
    assert safe_workers(1200) <= hard_cap(), "workers not capped"
    assert safe_workers(10) == 10, "small request should pass through"
    assert safe_fanout(100) <= max(1, _cpu() - 2), "fanout not bounded by cpu"
    assert safe_fanout(1) == 1
    os.environ["TZAR_WORKERS"] = "50"
    assert safe_workers() == 50, "env TZAR_WORKERS not honoured"
    os.environ["TZAR_WORKERS"] = "99999"
    assert safe_workers() == hard_cap(), "env over-cap not clamped"
    del os.environ["TZAR_WORKERS"]
    print("[+] concurrency selftest OK")
    return 0


def main():
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("recommend", help="print recommended worker/fanout counts")
    pr.add_argument("--workers", type=int, default=None)
    pr.add_argument("--items", type=int, default=1)
    pr.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rec = recommend(args.workers, args.items)
    if args.json:
        print(json.dumps(rec, indent=2))
    else:
        print(f"  cpu={rec['cpu']}  hard_cap={rec['hard_cap']}")
        print(f"  workers/process : {rec['workers_per_process']}")
        print(f"  parallel fanout : {rec['parallel_fanout']}")
        print(f"  total concurrency: {rec['total_concurrency']}  ({rec['note']})")
    sys.exit(0)


if __name__ == "__main__":
    main()
