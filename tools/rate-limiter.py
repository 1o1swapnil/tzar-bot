#!/usr/bin/env python3
"""
rate-limiter.py — per-host request pacing for executors (token-bucket).

Parallel executors can hammer a target and trip a WAF or get the source IP
banned. This is a tiny, persistent token-bucket keyed by host: an executor calls
`acquire` before each request and the bucket blocks (or reports throttle) until a
slot frees up. State is a small JSON per host, so pacing holds ACROSS processes —
two executors sharing a key share the budget.

State location (first that applies):
    --state-dir DIR
    $OUTPUT_DIR/.ratelimit/        (per-engagement; the normal case)
    <tmp>/tzar-ratelimit/          (fallback when no engagement is set)

CLI:
    # block until a slot is free, then consume it (default: wait)
    python3 tools/rate-limiter.py acquire --key target.com --rps 5 --burst 10
    # don't wait — exit 1 if throttled (for callers that prefer to back off themselves)
    python3 tools/rate-limiter.py acquire --key target.com --rps 5 --no-wait
    # inspect current bucket
    python3 tools/rate-limiter.py status --key target.com

Exit codes: acquire → 0 acquired, 1 throttled (only with --no-wait). status → 0.

Importable: `TokenBucket` takes an explicit clock so it is unit-testable without
sleeping — TokenBucket(rps, burst).acquire(now) returns seconds-to-wait (0 = took one).
"""

import os
import re
import sys
import json
import time
import tempfile
import argparse
from pathlib import Path


class TokenBucket:
    """Classic token bucket. `acquire(now)` consumes a token if one is available
    (returns 0.0) or returns the seconds to wait until one will be, without
    consuming. The clock is passed in so behaviour is deterministic in tests."""

    def __init__(self, rps, burst=None, tokens=None, ts=None):
        self.rps = float(rps)
        self.burst = float(burst if burst is not None else max(1.0, self.rps))
        self.tokens = float(tokens if tokens is not None else self.burst)
        self.ts = ts  # epoch seconds of last refill, or None

    def _refill(self, now):
        if self.ts is None:
            self.ts = now
            return
        elapsed = max(0.0, now - self.ts)
        self.tokens = min(self.burst, self.tokens + elapsed * self.rps)
        self.ts = now

    def acquire(self, now):
        self._refill(now)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return 0.0
        return (1.0 - self.tokens) / self.rps if self.rps > 0 else float("inf")

    def to_dict(self):
        return {"rps": self.rps, "burst": self.burst, "tokens": self.tokens, "ts": self.ts}

    @classmethod
    def from_dict(cls, d):
        return cls(d.get("rps", 1), d.get("burst"), d.get("tokens"), d.get("ts"))


def _state_path(key, state_dir):
    if state_dir:
        base = Path(state_dir)
    elif os.environ.get("OUTPUT_DIR"):
        base = Path(os.environ["OUTPUT_DIR"]) / ".ratelimit"
    else:
        base = Path(tempfile.gettempdir()) / "tzar-ratelimit"
    base.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", key) or "default"
    return base / f"{safe}.json"


def _load(path, rps, burst):
    if path.exists():
        try:
            b = TokenBucket.from_dict(json.loads(path.read_text()))
            b.rps = float(rps)                       # CLI flags win on each call
            if burst is not None:
                b.burst = float(burst)
            return b
        except (ValueError, OSError):
            pass
    return TokenBucket(rps, burst)


def _save(path, bucket):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(bucket.to_dict()))
    tmp.replace(path)


def cmd_acquire(a):
    path = _state_path(a.key, a.state_dir)
    bucket = _load(path, a.rps, a.burst)
    waited = 0.0
    while True:
        wait = bucket.acquire(time.time())
        if wait == 0.0:
            break
        if a.no_wait:
            _save(path, bucket)
            print(f"THROTTLED {a.key}: retry in {wait:.2f}s "
                  f"(tokens {bucket.tokens:.2f}/{bucket.burst:g}, {bucket.rps:g} rps)")
            sys.exit(1)
        time.sleep(min(wait, 5.0))
        waited += min(wait, 5.0)
    _save(path, bucket)
    print(f"OK {a.key}: acquired (waited {waited:.2f}s, "
          f"tokens {bucket.tokens:.2f}/{bucket.burst:g}, {bucket.rps:g} rps)")
    sys.exit(0)


def cmd_status(a):
    path = _state_path(a.key, a.state_dir)
    if not path.exists():
        print(f"{a.key}: no bucket yet (state: {path})")
        return
    bucket = TokenBucket.from_dict(json.loads(path.read_text()))
    bucket._refill(time.time())
    print(json.dumps({"key": a.key, "tokens": round(bucket.tokens, 3),
                      "burst": bucket.burst, "rps": bucket.rps,
                      "state_file": str(path)}, indent=2))


def main():
    ap = argparse.ArgumentParser(description="Per-host request pacing (token bucket).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    acq = sub.add_parser("acquire", help="Consume a slot, blocking until one is free")
    acq.add_argument("--key", required=True, help="Bucket key, usually the target host")
    acq.add_argument("--rps", type=float, default=5.0, help="Requests per second (refill rate)")
    acq.add_argument("--burst", type=float, default=None, help="Bucket capacity (default: max(1, rps))")
    acq.add_argument("--no-wait", action="store_true", help="Exit 1 instead of blocking when throttled")
    acq.add_argument("--state-dir", default=None, help="Override bucket state directory")
    acq.set_defaults(func=cmd_acquire)

    st = sub.add_parser("status", help="Show current bucket state")
    st.add_argument("--key", required=True)
    st.add_argument("--state-dir", default=None)
    st.set_defaults(func=cmd_status)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
