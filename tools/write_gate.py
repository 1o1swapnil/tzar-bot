#!/usr/bin/env python3
"""
write_gate.py — stop state-changing requests to targets unless a human approved them.

"Non-destructive" used to be a sentence in the prompt. In a past engagement an
executor's POST deactivated the client's live subscription and there was no endpoint to
undo it. This module is the code behind the rule: tools/scope-check.py (the PreToolUse
hook) records every request it can see that changes server state, and this module
decides allow / ask / deny from the engagement's write policy.

What counts as a write
  * PUT, PATCH, DELETE and WebDAV write methods, always
  * POST, except authentication/session/search endpoints and GraphQL *queries*
  * GraphQL mutations, whatever the method
  * any method (GET included) whose path names a destructive action:
    /delete, /remove, /destroy, /purge, /deactivate, /cancel, /reset, /revoke, ...
  * sqlmap at --risk 3, with stacked queries, --sql-query/--sql-shell, --os-*,
    --file-write, --eval; ffuf/wfuzz fuzzing with a write method or body
  * .post()/.put()/.patch()/.delete() / fetch({method}) in inline code and PoC scripts

Policy (engagement.json `write_policy`, default "ask")
  ask    every write not pre-approved needs a human yes/no in the Claude Code prompt
  deny   writes are blocked outright (read-only engagements)
  allow  writes are allowed (lab / CTF / your own staging only)

Pre-approval (engagement.json `write_allow`): "METHOD URL-GLOB" rules a human approved,
e.g. "POST https://staging.acme.com/api/v1/comments*". Adding one goes through the
same human prompt, because the hook gates every change to the write policy.

Human CLI (the model can run these too, but the hook turns each one into a prompt):
  python3 tools/write_gate.py status   [--output-dir DIR]
  python3 tools/write_gate.py allow "POST https://t.com/api/x*" --reason "test account only"
  python3 tools/write_gate.py revoke 2
  python3 tools/write_gate.py policy ask|deny|allow
"""

import argparse
import fnmatch
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

POLICIES = ("ask", "deny", "allow")
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "MKCOL", "MOVE", "COPY", "PROPPATCH",
                 "LOCK", "UNLOCK"}

DESTRUCTIVE_WORDS = (r"delete|remove|destroy|purge|drop|truncate|wipe|erase|deactivate|"
                     r"disable|cancel|terminate|revoke|reset|unsubscribe|archive|suspend|"
                     r"ban|block")
DESTRUCTIVE_PATH = re.compile(rf"(?i)(?:^|[/_.\-?&=])(?:{DESTRUCTIVE_WORDS})(?:$|[/_.\-?&=])")
# POST endpoints that create a session or run a read: testing auth needs these.
SAFE_POST_PATH = re.compile(
    r"(?i)/(?:login|log-in|signin|sign-in|sign_in|logon|auth|authenticate|authorize|"
    r"oauth2?/(?:token|authorize)|token|refresh|session|sessions|sso|saml/acs|saml2?/sso|"
    r"mfa/verify|otp/verify|2fa/verify|verify-otp|search|query|lookup|graphql|introspect|"
    r"api/graphql|v\d+/graphql)(?:[/.?#]|$)")
GRAPHQL_MUTATION = re.compile(r"(?i)(?:^|[\"'{\s])mutation\b")


class WriteOp:
    __slots__ = ("method", "url", "where", "reason", "destructive")

    def __init__(self, method, url, where, reason, destructive=False):
        self.method, self.url, self.where = method, url, where
        self.reason, self.destructive = reason, destructive

    def label(self):
        tag = "DESTRUCTIVE " if self.destructive else ""
        return f"{tag}{self.method} {self.url or '<url built at runtime>'} — {self.reason} ({self.where})"


def classify(method, url, body=None, where="request"):
    """Return a WriteOp if this request changes server state, else None."""
    m = (method or "GET").upper()
    u = url or ""
    try:
        parts = urlsplit(u) if "://" in u else urlsplit("//" + u)
        path = parts.path + ("?" + parts.query if parts.query else "")
    except ValueError:
        path = u
    destructive = m == "DELETE" or bool(DESTRUCTIVE_PATH.search(path))
    if body and GRAPHQL_MUTATION.search(body):
        return WriteOp(m, u, where, "GraphQL mutation", destructive)
    if m in READ_METHODS:
        if destructive:
            return WriteOp(m, u, where, "destructive action in the URL", True)
        return None
    if m == "POST" and not destructive and SAFE_POST_PATH.search(path):
        return None                                   # login / token / search / GraphQL query
    if m in WRITE_METHODS or m not in READ_METHODS:
        return WriteOp(m, u, where, f"{m} request", destructive)
    return None


# ── Policy ───────────────────────────────────────────────────────────────────
def load_meta(output_dir):
    if not output_dir:
        return {}
    try:
        return json.loads((Path(output_dir) / "engagement.json").read_text())
    except (OSError, ValueError):
        return {}


def _rule_parts(rule):
    r = rule["rule"] if isinstance(rule, dict) else str(rule)
    method, _, glob = r.strip().partition(" ")
    if not glob:
        method, glob = "*", method
    return method.upper(), glob.strip()


def preapproved(op, rules):
    if not op.url:
        return False
    url_noq = op.url.split("?", 1)[0]
    for rule in rules or []:
        method, glob = _rule_parts(rule)
        if method not in ("*", op.method):
            continue
        if fnmatch.fnmatchcase(op.url, glob) or fnmatch.fnmatchcase(url_noq, glob):
            return True
    return False


def decide(ops, meta):
    """Return (decision, pending ops). decision: allow | ask | deny."""
    if not ops:
        return "allow", []
    policy = meta.get("write_policy", "ask")
    if policy not in POLICIES:
        policy = "ask"
    if policy == "allow":
        return "allow", []
    pending = [o for o in ops if not preapproved(o, meta.get("write_allow"))]
    if not pending:
        return "allow", []
    return ("deny" if policy == "deny" else "ask"), pending


# ── Approval state shared with the egress proxy (tools/egress.py) ────────────
# The proxy sees every HTTP(S) request, including ones the PreToolUse hook can't parse.
# Writes it sees are allowed when (a) the policy/pre-approvals allow them, (b) the hook
# just put the same METHOD+URL to the operator ("intent", one use, short TTL — the
# operator's yes at the prompt is what lets the call run), or (c) the operator approved
# a pending id with `python3 tools/egress.py approve <id>`.
import fcntl as _fcntl
import hashlib as _hashlib
import os as _os
import time as _time

INTENT_TTL = 180


def state_dir() -> Path:
    d = Path(_os.environ.get("TZAR_EGRESS_DIR")
             or (Path(__file__).resolve().parent.parent / ".tzar" / "egress"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def norm_url(url: str) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    host = (p.hostname or "").lower()
    port = p.port
    default = {"http": 80, "https": 443}.get(p.scheme.lower())
    netloc = host if port in (None, default) else f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]" + ("" if port in (None, default) else f":{port}")
    return f"{p.scheme.lower()}://{netloc}{p.path or '/'}" + (f"?{p.query}" if p.query else "")


def request_id(method: str, url: str) -> str:
    return _hashlib.sha256(f"{method.upper()} {norm_url(url)}".encode()).hexdigest()[:10]


class _State:
    """Tiny locked JSON store under state_dir()."""

    def __init__(self, name):
        self.path = state_dir() / name
        self.lock = state_dir() / ".lock"

    def __enter__(self):
        self._lf = open(self.lock, "a+")
        _fcntl.flock(self._lf, _fcntl.LOCK_EX)
        try:
            self.data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            self.data = {}
        return self

    def __exit__(self, *exc):
        if exc[0] is None:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1))
            _os.replace(tmp, self.path)
        _fcntl.flock(self._lf, _fcntl.LOCK_UN)
        self._lf.close()


def record_intent(method, url):
    if not url:
        return
    rid = request_id(method, url)
    with _State("intents.json") as st:
        now = _time.time()
        st.data = {k: v for k, v in st.data.items() if v.get("expires", 0) > now}
        st.data[rid] = {"method": method.upper(), "url": norm_url(url),
                        "expires": now + INTENT_TTL}


def consume_approval(method, url):
    """One-use: hook intent or operator approval for exactly this METHOD+URL."""
    rid = request_id(method, url)
    now = _time.time()
    with _State("intents.json") as st:
        st.data = {k: v for k, v in st.data.items() if v.get("expires", 0) > now}
        if st.data.pop(rid, None):
            return "operator approved at the prompt"
    with _State("approvals.json") as st:
        a = st.data.get(rid)
        if a and a.get("uses", 1) > 0:
            a["uses"] = a.get("uses", 1) - 1
            if a["uses"] <= 0:
                st.data.pop(rid)
            return "operator approved via egress.py approve"
    return None


def add_pending(method, url, reason):
    rid = request_id(method, url)
    with _State("pending.json") as st:
        e = st.data.setdefault(rid, {"method": method.upper(), "url": norm_url(url),
                                     "reason": reason, "first_seen": _time.time(), "count": 0})
        e["count"] += 1
        e["last_seen"] = _time.time()
    return rid


def approve_pending(rid, uses=1):
    with _State("pending.json") as st:
        e = st.data.pop(rid, None)
    if not e:
        return None
    with _State("approvals.json") as st:
        st.data[rid] = {"method": e["method"], "url": e["url"], "uses": uses,
                        "approved": _time.time()}
    return e


def list_pending():
    with _State("pending.json") as st:
        return dict(st.data)


# ── Human CLI ────────────────────────────────────────────────────────────────
def _resolve_dir(arg):
    if arg:
        return Path(arg)
    sys.path.insert(0, str(Path(__file__).parent))
    from scope import read_active
    od = read_active()
    if not od:
        sys.exit("no active engagement — pass --output-dir")
    return od


def _save(od, meta):
    (od / "engagement.json").write_text(json.dumps(meta, indent=2) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Engagement write policy (human-approved).")
    ap.add_argument("--output-dir")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    a = sub.add_parser("allow")
    a.add_argument("rule", help='"METHOD URL-GLOB", e.g. "POST https://t.com/api/x*"')
    a.add_argument("--reason", required=True)
    r = sub.add_parser("revoke")
    r.add_argument("index", type=int)
    p = sub.add_parser("policy")
    p.add_argument("value", choices=POLICIES)
    args = ap.parse_args()

    od = _resolve_dir(args.output_dir)
    meta = load_meta(od)
    if not meta:
        sys.exit(f"{od}/engagement.json not found or unreadable")
    rules = meta.setdefault("write_allow", [])

    if args.cmd == "status":
        print(f"engagement:   {od}")
        print(f"write_policy: {meta.get('write_policy', 'ask')}")
        for i, rule in enumerate(rules, 1):
            m, g = _rule_parts(rule)
            why = rule.get("reason", "") if isinstance(rule, dict) else ""
            print(f"  {i}. {m} {g}" + (f"   ({why})" if why else ""))
        if not rules:
            print("  (no pre-approved writes)")
        return
    if args.cmd == "allow":
        method, glob = _rule_parts(args.rule)
        if "://" not in glob:
            sys.exit("rule needs a full URL glob, e.g. \"POST https://t.com/api/x*\"")
        rules.append({"rule": f"{method} {glob}", "reason": args.reason,
                      "approved": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")})
        _save(od, meta)
        print(f"pre-approved: {method} {glob}")
        return
    if args.cmd == "revoke":
        if not 1 <= args.index <= len(rules):
            sys.exit("no such rule")
        gone = rules.pop(args.index - 1)
        _save(od, meta)
        print(f"revoked: {_rule_parts(gone)}")
        return
    if args.cmd == "policy":
        meta["write_policy"] = args.value
        _save(od, meta)
        print(f"write_policy = {args.value}")


if __name__ == "__main__":
    main()
