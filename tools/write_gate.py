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
