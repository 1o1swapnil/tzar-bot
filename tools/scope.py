#!/usr/bin/env python3
"""
scope.py — deterministic, code-enforced engagement scope for tzar-bot.

Scope is enforced in CODE, not by trusting an LLM. Every host/URL/IP is checked
here before any agent or tool is allowed to touch it. This is the single source
of truth used by the scope-check.py PreToolUse hook and any other gate.

Rules:
  - Deny wins:    an out-of-scope match excludes even if an in-scope pattern matches.
  - Default deny: anything not matching an in-scope pattern is out of scope.

Pattern forms (matched against the URL's host / a bare host / an IP):
  example.com      -> the apex AND any subdomain (example.com, api.example.com)
  *.example.com    -> any subdomain (NOT the bare apex)
  api.example.com  -> that exact host
  10.0.0.0/8       -> any IP in the CIDR (IPv4/IPv6)
  re:^staging[0-9]+\\.example\\.com$   -> explicit regex (prefix re:)

Reads tzar-bot engagement.json, accepting either `in_scope` or legacy `scope`,
plus optional `out_of_scope` (each a list OR a comma-separated string).

CLI:
  python3 tools/scope.py --engagement WAPT/acme/TS/engagement.json https://api.acme.com
  python3 tools/scope.py --in-scope acme.com --out-of-scope admin.acme.com host.acme.com
  python3 tools/scope.py --selftest
"""
import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlparse


def host_of(target: str) -> str:
    """Extract the lowercase host from a URL or bare host/IP."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "//" + t
    return (urlparse(t).hostname or "").lower().rstrip(".")


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [p.strip() for p in v.strip().strip("[]").replace("'", "").replace('"', "").split(",")]
    return [str(p).strip() for p in v]


def _match(pattern: str, host: str) -> bool:
    p = (pattern or "").strip().lower()
    if not p or not host:
        return False
    if p.startswith("re:"):
        try:
            return re.search(p[3:], host) is not None
        except re.error:
            return False
    # CIDR (digits, dots, optional colons for v6, exactly one slash)
    if "/" in p and re.fullmatch(r"[0-9a-f:.]+/\d{1,3}", p):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    if p.startswith("*."):
        return host.endswith("." + p[2:])           # subdomains only, not the apex
    return host == p or host.endswith("." + p)        # exact host, apex, or any subdomain


class Scope:
    def __init__(self, in_scope=None, out_of_scope=None, name="engagement"):
        self.in_scope = [p for p in _as_list(in_scope) if p]
        self.out_of_scope = [p for p in _as_list(out_of_scope) if p]
        self.name = name

    @property
    def active(self) -> bool:
        """No in-scope rules == no active scope (callers may choose to allow-all)."""
        return bool(self.in_scope)

    @classmethod
    def from_engagement(cls, meta: dict):
        return cls(
            in_scope=meta.get("in_scope", meta.get("scope", [])),
            out_of_scope=meta.get("out_of_scope", []),
            name=meta.get("project", meta.get("name", "engagement")),
        )

    @classmethod
    def load(cls, path):
        with open(path) as fh:
            return cls.from_engagement(json.load(fh))

    def in_scope_host(self, target: str) -> bool:
        host = host_of(target)
        if not host:
            return False
        if any(_match(p, host) for p in self.out_of_scope):
            return False                              # deny wins
        return any(_match(p, host) for p in self.in_scope)

    def reject_reason(self, target: str):
        """None if in scope, else a human-readable reason (for logging/blocking)."""
        host = host_of(target)
        if not host:
            return "could not parse host"
        if any(_match(p, host) for p in self.out_of_scope):
            return f"{host} matches an out-of-scope rule"
        if not any(_match(p, host) for p in self.in_scope):
            return f"{host} matches no in-scope rule (default deny)"
        return None


def _selftest():
    s = Scope(in_scope=["example.com", "*.test.example.com", "10.0.0.0/8",
                        "re:^lab[0-9]+\\.acme\\.io$"],
              out_of_scope=["admin.example.com", "internal.example.com"])
    ok = s.in_scope_host
    assert ok("https://example.com/login")            # apex
    assert ok("http://api.example.com/x")             # subdomain of bare domain
    assert ok("https://a.test.example.com")           # wildcard
    assert ok("https://10.1.2.3:8080/")               # CIDR
    assert ok("10.255.0.9")                           # bare IP in CIDR
    assert ok("https://lab42.acme.io")                # regex
    assert not ok("https://admin.example.com")        # out-of-scope (deny wins)
    assert not ok("https://internal.example.com/x")   # out-of-scope
    assert ok("https://test.example.com")             # in scope via bare rule
    assert not ok("https://evil.com")                 # default deny
    assert not ok("https://notexample.com")           # suffix-confusion guard
    assert not ok("https://example.com.evil.com")     # suffix-confusion guard
    assert not ok("https://11.0.0.1")                 # outside CIDR
    assert s.reject_reason("https://evil.com")
    assert s.reject_reason("https://example.com") is None
    # *.x needs a label deeper than x
    s2 = Scope(in_scope=["*.test.example.com"])
    assert s2.in_scope_host("a.test.example.com")
    assert not s2.in_scope_host("test.example.com")
    # legacy `scope` key + comma-string parsing
    s3 = Scope.from_engagement({"scope": "acme.com, api.acme.com", "out_of_scope": "blog.acme.com"})
    assert s3.in_scope_host("https://api.acme.com") and not s3.in_scope_host("https://blog.acme.com")
    # inactive scope
    assert not Scope().active and Scope(in_scope=["x.com"]).active
    print("scope.py self-test: PASS")


def main():
    ap = argparse.ArgumentParser(description="Check a target against engagement scope (code-enforced).")
    ap.add_argument("targets", nargs="*", help="URLs / hosts / IPs to check")
    ap.add_argument("--engagement", help="path to engagement.json")
    ap.add_argument("--in-scope", default=None, help="comma-separated in-scope rules")
    ap.add_argument("--out-of-scope", default=None, help="comma-separated out-of-scope rules")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        _selftest(); return

    if a.engagement:
        sc = Scope.load(a.engagement)
    else:
        sc = Scope(in_scope=a.in_scope, out_of_scope=a.out_of_scope)

    if not a.targets:
        print(f"scope '{sc.name}': in={sc.in_scope} out={sc.out_of_scope} active={sc.active}")
        return

    any_out = False
    for t in a.targets:
        reason = sc.reject_reason(t)
        if reason:
            any_out = True
            print(f"OUT  {t}  ({reason})")
        else:
            print(f"IN   {t}")
    sys.exit(1 if any_out else 0)


if __name__ == "__main__":
    main()
