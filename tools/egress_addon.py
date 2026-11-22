"""
egress_addon.py — mitmproxy addon for tools/egress.py (scope + write gate on real traffic).

Loaded by:  mitmdump -s tools/egress_addon.py   (started by `sudo python3 tools/egress.py up`)

  CONNECT / plain-HTTP host  → Policy.host_decision: infra = TLS passthrough (not decrypted),
                               in scope = intercepted, out of scope / no engagement = 403
  every intercepted request  → host re-checked, Host header vs out-of-scope rules,
                               write gate (write_gate.classify + engagement write_policy,
                               pre-approvals, the hook's one-shot intents, operator approvals)
Every decision is appended to .tzar/egress/egress.log.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import egress  # noqa: E402
from mitmproxy import http  # noqa: E402

MAX_BODY = 200_000


def _block(flow, status, message):
    flow.response = http.Response.make(
        status, f"tzar-egress: {message}\n".encode(),
        {"Content-Type": "text/plain", "X-Tzar-Egress": "blocked"})


class TzarEgress:
    def __init__(self, policy=None):
        self.policy = policy or egress.Policy()

    # CONNECT host:port (HTTPS / any tunnelled protocol)
    def http_connect(self, flow: http.HTTPFlow):
        host, port = flow.request.host, flow.request.port
        d = self.policy.host_decision(host)
        self.policy.log({"event": "connect", "host": host, "port": port,
                         "allow": d.allow, "kind": d.kind, "reason": d.reason})
        if not d.allow:
            _block(flow, 403, f"CONNECT {host}:{port} blocked — {d.reason}")

    # Don't decrypt infrastructure (Anthropic, GitHub, PyPI, ...): pass TLS through untouched.
    def tls_clienthello(self, data):
        sni = data.client_hello.sni
        if not sni and data.context.server.address:
            sni = data.context.server.address[0]
        if sni and self.policy.host_decision(sni).kind == "infra":
            data.ignore_connection = True

    def request(self, flow: http.HTTPFlow):
        if flow.response is not None:
            return
        req = flow.request
        d = self.policy.host_decision(req.host)
        if not d.allow:
            self.policy.log({"event": "request", "method": req.method, "url": req.pretty_url,
                             "allow": False, "reason": d.reason})
            return _block(flow, 403, f"{req.method} {req.pretty_url} blocked — {d.reason}")
        hh = self.policy.header_host_ok(req.headers.get("host", ""))
        if not hh.allow:
            self.policy.log({"event": "request", "method": req.method, "url": req.pretty_url,
                             "allow": False, "reason": hh.reason})
            return _block(flow, 403, f"blocked — {hh.reason}")
        if d.kind == "infra":
            return
        body = req.get_text(strict=False) or ""
        w = self.policy.write_decision(req.method, req.pretty_url, body[:MAX_BODY])
        self.policy.log({"event": "request", "method": req.method, "url": req.pretty_url,
                         "allow": w.allow, "kind": w.kind, "reason": w.reason})
        if not w.allow:
            _block(flow, 403, w.reason)


addons = [TzarEgress()]
