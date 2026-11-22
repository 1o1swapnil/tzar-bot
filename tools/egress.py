#!/usr/bin/env python3
"""
egress.py — network-level egress control for an engagement (nftables + mitmproxy).

The PreToolUse hook reads command text, so it can't see hosts computed at runtime,
one tool's output piped into another, or DNS names that resolve to out-of-scope IPs.
This layer checks the packets and the HTTP requests themselves.

  ┌ user.slice/user-<uid>.slice (Claude Code, every tool it runs, and their sudo) ┐
  │  nftables `tzar_egress`: only these destinations are reachable directly:      │
  │    in-scope IPs/CIDRs (hostnames resolved) · DNS resolvers on :53 ·           │
  │    Anthropic API (keeps the session alive) · loopback (→ the proxy)           │
  │  everything else → TCP reset / ICMP admin-prohibited (+ rate-limited log)     │
  └───────────────────────────────────────────────────────────────────────────────┘
          │ HTTP(S)_PROXY=127.0.0.1:8899
          ▼
  mitmproxy + tools/egress_addon.py  (systemd unit in system.slice, runs as <user>)
    infra hosts (GitHub, PyPI, Anthropic, OAST, …) → TLS passed through untouched
    in-scope hosts → intercepted: Host/vhost re-checked (deny wins), write gate applied
                     (pending writes → 403 + id; operator: egress.py approve <id>)
    anything else  → 403

Safety: `up` self-checks (Anthropic API still reachable, out-of-scope blocked, proxy
answering) and arms an automatic rollback (default 120 s) unless `confirm` is run.
Nothing persists across a reboot. `down` removes everything.

Commands
  python3 tools/egress.py render [--uid N] [--hosts FILE]   # dry run: print the nft ruleset
  sudo python3 tools/egress.py up [--confirm-within 120] [--allow IP[:PORT]] [--hosts FILE]
  sudo python3 tools/egress.py confirm                       # keep it (cancel rollback)
  sudo python3 tools/egress.py refresh [--hosts FILE]        # after switching engagement
  sudo python3 tools/egress.py down
  python3 tools/egress.py status
  eval "$(python3 tools/egress.py env)"                      # before starting `claude`
  python3 tools/egress.py pending | approve <id> [--uses N] | log [-n 20]

Limits (documented, not hidden): passwordless sudo can still remove the rules — the hook
puts nft/iptables/systemd-run/egress changes to the operator, but only removing NOPASSWD
for the operator account makes this absolute. HTTP hostname rules can't be split at the
IP layer: a raw (non-HTTP) tool can reach any vhost on an in-scope IP. Wildcard/regex
scope rules can't be pre-resolved; `refresh --hosts` adds discovered hosts.
"""

import argparse
import importlib.util
import ipaddress
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from scope import Scope, _match, read_active  # noqa: E402
import write_gate  # noqa: E402

TABLE = "tzar_egress"
PROXY_UNIT = "tzar-egress-proxy"
ROLLBACK_UNIT = "tzar-egress-rollback"
PROXY_HOST, PROXY_PORT = "127.0.0.1", int(os.environ.get("TZAR_EGRESS_PORT", "8899"))
ANTHROPIC_DIRECT = ["api.anthropic.com"]          # resolved; keeps the session alive
PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"]


def _scope_check_module():
    spec = importlib.util.spec_from_file_location("scope_check_egress", TOOLS / "scope-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Policy used by the proxy addon ───────────────────────────────────────────
class Decision:
    __slots__ = ("allow", "kind", "reason")

    def __init__(self, allow, kind, reason=""):
        self.allow, self.kind, self.reason = allow, kind, reason


class Policy:
    """Engagement-aware decisions; reloads when the active engagement changes."""

    def __init__(self, reload_every=2.0):
        self._sc = _scope_check_module()
        self._loaded_at = 0.0
        self._sig = None
        self.reload_every = reload_every
        self.output_dir, self.meta, self.scope = None, {}, Scope()
        self.allowed = self._sc.load_allowed_hosts()

    def _refresh(self):
        now = time.time()
        if now - self._loaded_at < self.reload_every:
            return
        self._loaded_at = now
        od = read_active()
        meta_path = od / "engagement.json" if od else None
        sig = (str(od), meta_path.stat().st_mtime if meta_path and meta_path.exists() else 0)
        if sig == self._sig:
            return
        self._sig = sig
        self.output_dir = od
        try:
            self.meta = json.loads(meta_path.read_text()) if meta_path else {}
        except (OSError, ValueError):
            self.meta = {}
        self.scope = Scope.from_engagement(self.meta) if self.meta else Scope()
        self.allowed = self._sc.load_allowed_hosts()

    def _infra(self, host):
        # Loopback IPs are NOT infra here: clients skip the proxy for localhost via NO_PROXY,
        # so anything that does arrive for 127.x gets the normal scope + write checks.
        return any(_match(p, host) for p in self.allowed)

    def host_decision(self, host) -> Decision:
        self._refresh()
        h = (host or "").strip().lower().rstrip(".").strip("[]")
        if not h:
            return Decision(False, "block", "no host")
        if any(_match(p, h) for p in self.scope.out_of_scope):
            return Decision(False, "deny", f"{h} matches an out-of-scope rule")
        if self._infra(h):
            return Decision(True, "infra")
        if not self.scope.active:
            return Decision(False, "block", f"{h}: no active engagement")
        if self.scope.in_scope_host(h):
            return Decision(True, "scope")
        return Decision(False, "block", f"{h} is not in scope")

    def header_host_ok(self, host_header) -> Decision:
        """Host header: deny-list only, so Host-header injection tests still work."""
        self._refresh()
        h = (host_header or "").split(":")[0].strip().lower().strip("[]")
        if h and any(_match(p, h) for p in self.scope.out_of_scope):
            return Decision(False, "deny", f"Host header {h} matches an out-of-scope rule")
        return Decision(True, "ok")

    def write_decision(self, method, url, body) -> Decision:
        self._refresh()
        op = write_gate.classify(method, url, body, "egress proxy")
        if not op:
            return Decision(True, "read")
        policy = self.meta.get("write_policy", "ask")
        if policy == "allow":
            return Decision(True, "write", "write_policy allow")
        if write_gate.preapproved(op, self.meta.get("write_allow")):
            return Decision(True, "write", "pre-approved rule")
        why = write_gate.consume_approval(op.method, url)
        if why:
            return Decision(True, "write", why)
        if policy == "deny":
            return Decision(False, "write", f"{op.label()} — write_policy is deny")
        rid = write_gate.add_pending(op.method, url, op.reason)
        return Decision(False, "write",
                        f"{op.label()} — pending approval {rid}. Operator: "
                        f"python3 tools/egress.py approve {rid}")

    def log(self, event: dict):
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **event}
        try:
            with open(write_gate.state_dir() / "egress.log", "a") as fh:
                fh.write(json.dumps(event) + "\n")
        except OSError:
            pass


# ── nftables rendering ───────────────────────────────────────────────────────
def _resolve(host):
    out = set()
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None):
            out.add(sa[0])
    except (socket.gaierror, UnicodeError, OSError):
        pass
    return out


def _known_hosts(output_dir, hosts_file):
    hosts = set()
    if output_dir:
        st = Path(output_dir) / "state.json"
        try:
            text = st.read_text()
            hosts.update(h.lower() for h in re.findall(r"[a-z][a-z0-9+.-]*://([A-Za-z0-9.-]+)", text))
        except OSError:
            pass
    if hosts_file:
        for line in Path(hosts_file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                h = urlsplit(line if "://" in line else "//" + line).hostname
                if h:
                    hosts.add(h.lower())
    return hosts


def _resolvers():
    ips = set(PUBLIC_RESOLVERS)
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            m = re.match(r"\s*nameserver\s+(\S+)", line)
            if m:
                ips.add(m.group(1).split("%")[0])
    except OSError:
        pass
    return {ip for ip in ips if not ipaddress.ip_address(ip).is_loopback}


def build_sets(meta, output_dir=None, hosts_file=None, extra_allow=(), resolve=_resolve):
    """Return (sets: {name: set[str]}, notes: list[str])."""
    sc = Scope.from_engagement(meta) if meta else Scope()
    sets = {k: set() for k in ("scope4", "scope6", "deny4", "deny6", "direct4", "direct6",
                               "dns4", "dns6")}
    notes = []

    def add(prefix, value):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        sets[f"{prefix}{net.version}"].add(str(net) if net.num_addresses > 1
                                           else str(net.network_address))
        return True

    scope_ips = set()
    for rule in sc.in_scope:
        r = rule.strip()
        if add("scope", r):
            continue
        if r.startswith(("re:", "*.")):
            notes.append(f"in-scope rule `{r}` can't be resolved to IPs (raw tools need "
                         f"`refresh --hosts`; HTTP is enforced by the proxy)")
            continue
        ips = resolve(r)
        if not ips:
            notes.append(f"in-scope host `{r}` did not resolve")
        for ip in ips:
            add("scope", ip)
            scope_ips.add(ip)
    for h in sorted(_known_hosts(output_dir, hosts_file)):
        if sc.in_scope_host(h):
            for ip in resolve(h):
                add("scope", ip)
                scope_ips.add(ip)

    for rule in sc.out_of_scope:
        r = rule.strip()
        if add("deny", r):
            continue
        if r.startswith(("re:", "*.")):
            continue
        for ip in resolve(r):
            if ip in scope_ips:
                notes.append(f"out-of-scope `{r}` shares IP {ip} with an in-scope host — can't "
                             f"be split at the IP layer (HTTP vhosts are split by the proxy)")
            else:
                add("deny", ip)

    for h in ANTHROPIC_DIRECT:
        for ip in resolve(h):
            add("direct", ip)
    for a in extra_allow:
        add("direct", a.rsplit(":", 1)[0] if a.count(":") == 1 else a)
    for ip in _resolvers():
        add("dns", ip)
    return sets, notes


def render(sets, uid):
    def elements(name):
        items = sorted(sets.get(name, ()), key=lambda s: (ipaddress.ip_network(s, strict=False).version, s))
        return f" elements = {{ {', '.join(items)} }};" if items else ""

    decl = []
    for name in ("scope4", "deny4", "direct4", "dns4"):
        decl.append(f"  set {name} {{ type ipv4_addr; flags interval; auto-merge;{elements(name)} }}")
    for name in ("scope6", "deny6", "direct6", "dns6"):
        decl.append(f"  set {name} {{ type ipv6_addr; flags interval; auto-merge;{elements(name)} }}")
    cgroup = f"user.slice/user-{uid}.slice"
    return "\n".join([
        f"table inet {TABLE} {{",
        *decl,
        "  chain restricted {",
        '    oifname "lo" accept',
        "    ct state established,related accept",
        '    ip daddr @deny4 counter log prefix "tzar-egress-deny " reject with icmpx admin-prohibited',
        '    ip6 daddr @deny6 counter log prefix "tzar-egress-deny " reject with icmpx admin-prohibited',
        "    meta l4proto { tcp, udp } th dport 53 ip daddr @dns4 accept",
        "    meta l4proto { tcp, udp } th dport 53 ip6 daddr @dns6 accept",
        "    ip daddr @direct4 accept",
        "    ip6 daddr @direct6 accept",
        "    ip daddr @scope4 accept",
        "    ip6 daddr @scope6 accept",
        '    limit rate 5/second log prefix "tzar-egress-drop "',
        "    meta l4proto tcp counter reject with tcp reset",
        "    counter reject with icmpx admin-prohibited",
        "  }",
        "  chain output {",
        "    type filter hook output priority filter; policy accept;",
        f'    socket cgroupv2 level 2 "{cgroup}" jump restricted',
        "  }",
        "}",
        "",
    ])


# ── system helpers (root) ────────────────────────────────────────────────────
def _run(cmd, check=True, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip() or r.stdout.strip()}")
    return r


def _need_root():
    if os.geteuid() != 0:
        sys.exit("this command changes the firewall: run it with sudo")


def _operator_uid(arg=None):
    if arg is not None:
        return int(arg)
    return int(os.environ.get("SUDO_UID") or os.getuid())


def _load_active_meta():
    od = read_active()
    if not od:
        return None, {}
    try:
        return od, json.loads((od / "engagement.json").read_text())
    except (OSError, ValueError):
        return od, {}


def apply_rules(text):
    tmp = write_gate.state_dir() / "rules.nft"
    tmp.write_text(f"table inet {TABLE}\ndelete table inet {TABLE}\n" + text)
    _run(["nft", "-f", str(tmp)])


def start_proxy(uid):
    pw = pwd.getpwuid(uid)
    mitm = shutil.which("mitmdump")
    if not mitm:
        raise RuntimeError("mitmdump not found (apt install mitmproxy)")
    _run(["systemctl", "stop", PROXY_UNIT], check=False)
    _run(["systemctl", "reset-failed", PROXY_UNIT], check=False)
    _run(["systemd-run", f"--unit={PROXY_UNIT}", f"--uid={pw.pw_name}", f"--gid={pw.pw_gid}",
          f"--working-directory={REPO}", f"--setenv=HOME={pw.pw_dir}",
          f"--setenv=TZAR_EGRESS_DIR={write_gate.state_dir()}",
          "--property=Restart=on-failure",
          mitm, "--listen-host", PROXY_HOST, "--listen-port", str(PROXY_PORT), "-q",
          "--set", f"confdir={pw.pw_dir}/.mitmproxy", "--set", "connection_strategy=lazy",
          "-s", str(TOOLS / "egress_addon.py")])


def arm_rollback(seconds):
    _run(["systemctl", "stop", f"{ROLLBACK_UNIT}.timer"], check=False)
    _run(["systemctl", "reset-failed", ROLLBACK_UNIT], check=False)
    _run(["systemd-run", f"--unit={ROLLBACK_UNIT}", f"--on-active={seconds}",
          shutil.which("nft") or "/usr/sbin/nft", "delete", "table", "inet", TABLE])


def _tcp(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _connect_via_proxy(host, port=443, timeout=8):
    """Return the proxy's status code for CONNECT host:port, or None."""
    try:
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout) as s:
            s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            line = s.recv(256).split(b"\r\n", 1)[0].decode("latin1")
            m = re.match(r"HTTP/1\.[01] (\d{3})", line)
            return int(m.group(1)) if m else None
    except OSError:
        return None


def self_check(sets):
    """(ok, lines). Runs from the operator's cgroup when invoked via sudo from their shell."""
    lines, ok = [], True
    api = _tcp("api.anthropic.com", 443)
    lines.append(("PASS" if api else "FAIL") + "  Anthropic API reachable directly (session safety)")
    ok &= api
    probe = next((ip for ip in PUBLIC_RESOLVERS if ip not in sets.get("scope4", ())), None)
    if probe:
        blocked = not _tcp(probe, 443, timeout=3)
        lines.append(("PASS" if blocked else "FAIL") + f"  direct TCP to out-of-scope {probe}:443 blocked")
        ok &= blocked
    for _ in range(20):
        if _tcp(PROXY_HOST, PROXY_PORT, timeout=1):
            break
        time.sleep(0.5)
    up = _tcp(PROXY_HOST, PROXY_PORT, timeout=2)
    lines.append(("PASS" if up else "FAIL") + f"  proxy listening on {PROXY_HOST}:{PROXY_PORT}")
    ok &= up
    if up:
        infra = _connect_via_proxy("pypi.org")
        lines.append(("PASS" if infra == 200 else "FAIL") + f"  proxy passes infra (pypi.org → {infra})")
        bad = _connect_via_proxy("tzar-egress-selftest.invalid")
        lines.append(("PASS" if bad == 403 else "FAIL") + f"  proxy blocks out-of-scope (→ {bad})")
        ok &= infra == 200 and bad == 403
    return ok, lines


# ── CLI ──────────────────────────────────────────────────────────────────────
def cmd_render(a):
    od, meta = _load_active_meta()
    sets, notes = build_sets(meta, od, a.hosts, a.allow or ())
    print(render(sets, _operator_uid(a.uid)))
    for n in notes:
        print(f"# note: {n}", file=sys.stderr)
    if not meta:
        print("# note: no active engagement — only DNS, Anthropic API and loopback are reachable",
              file=sys.stderr)


def cmd_up(a):
    _need_root()
    uid = _operator_uid(a.uid)
    if not Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice").exists():
        sys.exit(f"cgroup user.slice/user-{uid}.slice not found — is uid {uid} logged in?")
    od, meta = _load_active_meta()
    sets, notes = build_sets(meta, od, a.hosts, a.allow or ())
    if not sets["direct4"] and not sets["direct6"]:
        sys.exit("could not resolve api.anthropic.com — refusing to cut off the session")
    start_proxy(uid)
    apply_rules(render(sets, uid))
    arm_rollback(a.confirm_within)
    ok, lines = self_check(sets)
    print("\n".join(lines))
    for n in notes:
        print(f"note: {n}")
    if not ok:
        _run(["nft", "delete", "table", "inet", TABLE], check=False)
        _run(["systemctl", "stop", f"{ROLLBACK_UNIT}.timer"], check=False)
        sys.exit("self-check failed → rules removed (proxy left running; `down` stops it)")
    print(f"\negress control is UP for engagement {od.name if od else '(none)'}.\n"
          f"It rolls back automatically in {a.confirm_within}s unless you run:\n"
          f"  sudo python3 tools/egress.py confirm\n"
          f"Start Claude Code / tools with:  eval \"$(python3 tools/egress.py env)\"")


def cmd_confirm(a):
    _need_root()
    _run(["systemctl", "stop", f"{ROLLBACK_UNIT}.timer"], check=False)
    print("confirmed — automatic rollback cancelled")


def cmd_refresh(a):
    _need_root()
    od, meta = _load_active_meta()
    sets, notes = build_sets(meta, od, a.hosts, a.allow or ())
    apply_rules(render(sets, _operator_uid(a.uid)))
    for n in notes:
        print(f"note: {n}")
    print(f"refreshed for {od.name if od else '(no engagement)'}: "
          f"{len(sets['scope4']) + len(sets['scope6'])} in-scope IP entries")


def cmd_down(a):
    _need_root()
    _run(["nft", "delete", "table", "inet", TABLE], check=False)
    _run(["systemctl", "stop", f"{ROLLBACK_UNIT}.timer"], check=False)
    _run(["systemctl", "stop", PROXY_UNIT], check=False)
    print("egress control is DOWN (firewall table removed, proxy stopped)")


def cmd_status(a):
    table = _run(["nft", "list", "table", "inet", TABLE], check=False) if os.geteuid() == 0 else None
    proxy = _run(["systemctl", "is-active", PROXY_UNIT], check=False).stdout.strip()
    timer = _run(["systemctl", "is-active", f"{ROLLBACK_UNIT}.timer"], check=False).stdout.strip()
    od, _ = _load_active_meta()
    print(f"engagement : {od or '(none)'}")
    if table is None:
        print("firewall   : (run with sudo to inspect)")
    else:
        print(f"firewall   : {'UP' if table.returncode == 0 else 'down'}")
    print(f"proxy      : {proxy} ({PROXY_HOST}:{PROXY_PORT})")
    print(f"rollback   : {'ARMED — run confirm' if timer == 'active' else 'not armed'}")
    print(f"pending    : {len(write_gate.list_pending())} write(s) awaiting approval")


def cmd_env(a):
    pw = pwd.getpwuid(_operator_uid(a.uid))
    ca = Path(pw.pw_dir) / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    bundle = write_gate.state_dir() / "ca-bundle.pem"
    system = Path("/etc/ssl/certs/ca-certificates.crt")
    if ca.exists() and system.exists():
        bundle.write_text(system.read_text() + "\n" + ca.read_text())
    proxy = f"http://{PROXY_HOST}:{PROXY_PORT}"
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        print(f"export {k}={proxy}")
    print("export NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1")
    if bundle.exists():
        for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
            print(f"export {k}={bundle}")
    else:
        print("# mitmproxy CA not generated yet — run `egress.py up` once, then re-run env",
              file=sys.stderr)


def cmd_pending(a):
    p = write_gate.list_pending()
    if not p:
        print("no pending writes")
    for rid, e in sorted(p.items(), key=lambda kv: kv[1].get("last_seen", 0)):
        print(f"{rid}  {e['method']} {e['url']}  ({e['reason']}, seen {e['count']}x)")


def cmd_approve(a):
    e = write_gate.approve_pending(a.id, uses=a.uses)
    if not e:
        sys.exit(f"no pending write with id {a.id}")
    print(f"approved {a.uses}x: {e['method']} {e['url']} — the next identical request passes")


def cmd_log(a):
    p = write_gate.state_dir() / "egress.log"
    lines = p.read_text().splitlines()[-a.n:] if p.exists() else []
    print("\n".join(lines) or "(empty)")


def main():
    ap = argparse.ArgumentParser(description="Network-level egress control (nftables + mitmproxy).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, hosts=True):
        p.add_argument("--uid", help="operator uid (default: $SUDO_UID or current)")
        if hosts:
            p.add_argument("--hosts", help="file of discovered in-scope hosts/URLs to resolve")
            p.add_argument("--allow", action="append",
                           help="extra direct destination IP[:PORT] (e.g. a VPN server); repeatable")
        return p

    common(sub.add_parser("render"))
    up = common(sub.add_parser("up"))
    up.add_argument("--confirm-within", type=int, default=120)
    common(sub.add_parser("refresh"))
    common(sub.add_parser("confirm"), hosts=False)
    common(sub.add_parser("down"), hosts=False)
    sub.add_parser("status")
    common(sub.add_parser("env"), hosts=False)
    sub.add_parser("pending")
    ap_ = sub.add_parser("approve")
    ap_.add_argument("id")
    ap_.add_argument("--uses", type=int, default=1)
    lg = sub.add_parser("log")
    lg.add_argument("-n", type=int, default=20)
    a = ap.parse_args()
    {"render": cmd_render, "up": cmd_up, "confirm": cmd_confirm, "refresh": cmd_refresh,
     "down": cmd_down, "status": cmd_status, "env": cmd_env, "pending": cmd_pending,
     "approve": cmd_approve, "log": cmd_log}[a.cmd](a)


if __name__ == "__main__":
    main()
