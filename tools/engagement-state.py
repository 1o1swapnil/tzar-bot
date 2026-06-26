#!/usr/bin/env python3
"""
engagement-state.py — persistent, resumable, scope-guarded engagement ledger.

The coordinator's attack-chain.md holds prose reasoning; this holds the STRUCTURED
state — surface, worklist, tested set, candidate + confirmed findings, phase — as a
machine-checkable JSON ledger that survives context compaction and makes a long run
auditable and resumable. Scope is enforced in code here too: surface items whose host
is out of scope are dropped before they can enter the worklist.

Layout (under $OUTPUT_DIR):
  state.json        the ledger (atomic writes)
  logs/engine.log   append-only run log

CLI (reads $OUTPUT_DIR from env, or --output-dir):
  python3 tools/engagement-state.py summary
  python3 tools/engagement-state.py set-phase hunt
  python3 tools/engagement-state.py add-surface --json '[{"url":"https://api.acme.com/x?id=1","param":"id","vuln_class":"idor"}]'
  python3 tools/engagement-state.py add-surface --file surface.json
  python3 tools/engagement-state.py worklist --top 10
  python3 tools/engagement-state.py mark-tested --url https://api.acme.com/x?id=1 --param id --vuln-class idor
  python3 tools/engagement-state.py add-candidate --url ... --vuln-class idor --severity high --evidence "id=N leaks PII"
  python3 tools/engagement-state.py confirm --url ... --vuln-class idor --real true --reason "verified"
  python3 tools/engagement-state.py selftest
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))
from scope import Scope, host_of  # noqa: E402

# impact-ish ranking used to order the worklist (mirrors engagement priorities)
CLASS_WEIGHT = {
    "rce": 100, "sqli": 90, "deserialization": 88, "ssti": 88, "ssrf": 85,
    "auth-bypass": 85, "idor": 80, "lfi": 78, "xxe": 75, "csrf": 50,
    "open-redirect": 40, "xss": 55, "cors": 45, "info-leak": 30,
}

# Weight given to a vuln class we don't recognise — keeps it on the worklist
# (so nothing is silently dropped) but below every known class.
DEFAULT_WEIGHT = 20

# Full-string aliases → canonical class, so verbose/standard names rank correctly
# instead of falling through to DEFAULT_WEIGHT.
CLASS_ALIASES = {
    "sql-injection": "sqli", "sql_injection": "sqli", "sqlinjection": "sqli",
    "remote-code-execution": "rce", "command-injection": "rce", "cmd-injection": "rce",
    "os-command-injection": "rce", "code-injection": "rce",
    "insecure-deserialization": "deserialization", "deser": "deserialization",
    "server-side-template-injection": "ssti", "template-injection": "ssti",
    "server-side-request-forgery": "ssrf",
    "authentication-bypass": "auth-bypass", "authn-bypass": "auth-bypass",
    "auth_bypass": "auth-bypass", "authentication-bypass-jwt": "auth-bypass",
    "insecure-direct-object-reference": "idor", "bola": "idor",
    "local-file-inclusion": "lfi", "path-traversal": "lfi", "directory-traversal": "lfi",
    "xml-external-entity": "xxe",
    "cross-site-request-forgery": "csrf",
    "cross-site-scripting": "xss", "dom-xss": "xss", "stored-xss": "xss", "reflected-xss": "xss",
    "information-disclosure": "info-leak", "info-disclosure": "info-leak",
    "information-leak": "info-leak", "sensitive-data-exposure": "info-leak",
    "cors-misconfiguration": "cors", "cors-misconfig": "cors",
}


def class_weight(cls):
    """
    Resolve a vuln class to a worklist weight. Order: exact match → full-string
    alias → token match (split on non-alnum, e.g. 'sqli-blind' → sqli) → default.
    Token match avoids the false positives of naive substring matching
    ('rce' in 'source').
    """
    c = (cls or "").strip().lower()
    if c in CLASS_WEIGHT:
        return CLASS_WEIGHT[c]
    if c in CLASS_ALIASES:
        return CLASS_WEIGHT[CLASS_ALIASES[c]]
    tokens = [t for t in re.split(r"[^a-z0-9]+", c) if t]
    for known in CLASS_WEIGHT:
        if known in tokens:
            return CLASS_WEIGHT[known]
    for tok in tokens:
        if tok in CLASS_ALIASES:
            return CLASS_WEIGHT[CLASS_ALIASES[tok]]
    return DEFAULT_WEIGHT


def _now():
    return datetime.now(timezone.utc).isoformat()


class Engagement:
    def __init__(self, output_dir):
        self.dir = Path(output_dir).expanduser().resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "logs").mkdir(exist_ok=True)
        self.state_path = self.dir / "state.json"
        self.log_path = self.dir / "logs" / "engine.log"
        self.scope = self._load_scope()
        self.state = self._load()

    def _load_scope(self):
        meta = self.dir / "engagement.json"
        if meta.exists():
            try:
                return Scope.load(meta)
            except Exception:
                pass
        return Scope()

    def _load(self):
        if self.state_path.is_file():
            return json.loads(self.state_path.read_text())
        return {"project": self.scope.name, "created": _now(), "phase": "init",
                "surface": [], "tested": [], "candidates": [], "confirmed": [],
                "claims": {}}

    def save(self):
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.state, indent=2) + "\n")
        tmp.replace(self.state_path)

    def log(self, msg):
        with open(self.log_path, "a") as f:
            f.write(f"{_now()}  {msg}\n")

    # ---- phase ----
    def set_phase(self, phase):
        self.state["phase"] = phase
        self.save()
        self.log(f"phase -> {phase}")

    # ---- surface (scope-guarded) ----
    @staticmethod
    def _key(s):
        return f"{s.get('url','')}|{s.get('param','')}|{s.get('vuln_class','')}"

    def add_surface(self, items):
        """Add discovered surface items; drop out-of-scope ones in code. Returns (added, dropped)."""
        existing = {self._key(s) for s in self.state["surface"]}
        added = dropped = 0
        for it in items:
            url = it.get("url", "")
            if self.scope.active and not self.scope.in_scope_host(url):
                dropped += 1
                self.log(f"surface DROPPED out-of-scope: {url} ({self.scope.reject_reason(url)})")
                continue
            it.setdefault("vuln_class", "info-leak")
            k = self._key(it)
            if k not in existing:
                self.state["surface"].append(it)
                existing.add(k)
                added += 1
        self.save()
        self.log(f"surface +{added} new, {dropped} out-of-scope dropped")
        return added, dropped

    def worklist(self, top=None, for_agent=None, ttl_minutes=120):
        """
        Untested surface, ranked by impact. If for_agent is given, also drop items
        actively claimed by a DIFFERENT executor (fresh + unreleased) so two agents
        don't re-test the same surface. Default behaviour (for_agent=None) is unchanged.
        """
        tested = set(self.state["tested"])
        claims = self.state.get("claims", {})
        now = datetime.now(timezone.utc)

        def claimed_by_other(k):
            c = claims.get(k)
            if not c or c.get("released"):
                return False
            if c.get("agent") == for_agent:
                return False
            try:
                age = (now - datetime.fromisoformat(c["ts"])).total_seconds() / 60
            except Exception:
                return True
            return age < ttl_minutes

        items = []
        for s in self.state["surface"]:
            k = self._key(s)
            if k in tested:
                continue
            if for_agent is not None and claimed_by_other(k):
                continue
            items.append(s)
        for s in items:
            s["_priority"] = class_weight(s.get("vuln_class", "")) + (5 if s.get("param") else 0)
        ranked = sorted(items, key=lambda s: -s["_priority"])
        return ranked[:top] if top else ranked

    # ---- work-claim dedup (so parallel executors don't re-test the same surface) ----
    def claim(self, url, param, vuln_class, agent, ttl_minutes=120):
        """Atomically claim a surface item for an executor. Returns (acquired, holder)."""
        self.state = self._load()                     # re-read to shrink the race window
        claims = self.state.setdefault("claims", {})
        k = self._key({"url": url, "param": param, "vuln_class": vuln_class})
        held = claims.get(k)
        now = datetime.now(timezone.utc)
        if held and not held.get("released") and held.get("agent") != agent:
            try:
                age = (now - datetime.fromisoformat(held["ts"])).total_seconds() / 60
            except Exception:
                age = 0
            if age < ttl_minutes:
                self.log(f"claim DENIED {k} (held by {held.get('agent')})")
                return False, held
        claims[k] = {"agent": agent, "ts": now.isoformat(), "released": False}
        self.save()
        self.log(f"claim {k} -> {agent}")
        return True, claims[k]

    def release(self, url, param, vuln_class, agent):
        self.state = self._load()
        claims = self.state.setdefault("claims", {})
        k = self._key({"url": url, "param": param, "vuln_class": vuln_class})
        if k in claims:
            claims[k]["released"] = True
            claims[k]["released_ts"] = _now()
            self.save()
            self.log(f"release {k} by {agent}")
            return True
        return False

    def list_claims(self):
        return self.state.get("claims", {})

    def mark_tested(self, url, param="", vuln_class=""):
        k = self._key({"url": url, "param": param, "vuln_class": vuln_class})
        if k not in self.state["tested"]:
            self.state["tested"].append(k)
            self.save()
            self.log(f"tested: {k}")

    def add_candidate(self, finding):
        finding["ts"] = _now()
        self.state["candidates"].append(finding)
        self.save()
        self.log(f"candidate: {finding.get('vuln_class')} @ {finding.get('url')}")

    def confirm(self, url, vuln_class, verdict):
        rec = {"url": url, "vuln_class": vuln_class, "verdict": verdict, "confirmed_ts": _now()}
        self.state["confirmed"].append(rec)
        self.save()
        self.log(f"{'CONFIRMED' if verdict.get('real') else 'rejected'}: {vuln_class} @ {url}")

    def summary(self):
        claims = self.state.get("claims", {})
        active_claims = sum(1 for c in claims.values() if not c.get("released"))
        return {"project": self.state.get("project"), "phase": self.state["phase"],
                "surface": len(self.state["surface"]), "tested": len(self.state["tested"]),
                "candidates": len(self.state["candidates"]), "confirmed": len(self.state["confirmed"]),
                "active_claims": active_claims, "scope_active": self.scope.active}


# ----------------------------------------------------------------- CLI
def _resolve_dir(a):
    d = a.output_dir or os.environ.get("OUTPUT_DIR", "")
    if not d:
        print("error: no OUTPUT_DIR (set env or --output-dir)", file=sys.stderr)
        sys.exit(2)
    return d


def _load_items(a):
    if a.json:
        return json.loads(a.json)
    if a.file:
        return json.loads(Path(a.file).read_text())
    data = sys.stdin.read().strip()
    return json.loads(data) if data else []


def main():
    # Convention: every tzar-bot tool accepts `--selftest` (the `selftest` subcommand
    # is kept as a back-compat alias).
    if "--selftest" in sys.argv:
        _selftest(); return
    ap = argparse.ArgumentParser(description="Resumable, scope-guarded engagement ledger.")
    ap.add_argument("--output-dir", help="engagement OUTPUT_DIR (default: $OUTPUT_DIR)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("summary")
    p = sub.add_parser("set-phase"); p.add_argument("phase")
    p = sub.add_parser("add-surface"); p.add_argument("--json"); p.add_argument("--file")
    p = sub.add_parser("worklist"); p.add_argument("--top", type=int)
    p.add_argument("--agent", default=None, help="exclude items actively claimed by other agents")
    p = sub.add_parser("mark-tested"); p.add_argument("--url", required=True); p.add_argument("--param", default=""); p.add_argument("--vuln-class", default="")
    p = sub.add_parser("claim"); p.add_argument("--url", required=True); p.add_argument("--param", default=""); p.add_argument("--vuln-class", default=""); p.add_argument("--agent", required=True); p.add_argument("--ttl-minutes", type=int, default=120)
    p = sub.add_parser("release"); p.add_argument("--url", required=True); p.add_argument("--param", default=""); p.add_argument("--vuln-class", default=""); p.add_argument("--agent", required=True)
    sub.add_parser("claims")
    p = sub.add_parser("add-candidate")
    p.add_argument("--url", required=True); p.add_argument("--param", default=""); p.add_argument("--vuln-class", required=True)
    p.add_argument("--severity", default="unknown"); p.add_argument("--evidence", default=""); p.add_argument("--request", default="")
    p = sub.add_parser("confirm")
    p.add_argument("--url", required=True); p.add_argument("--vuln-class", required=True)
    p.add_argument("--real", choices=["true", "false"], required=True); p.add_argument("--severity", default=""); p.add_argument("--reason", default="")
    sub.add_parser("selftest")
    a = ap.parse_args()

    if a.cmd == "selftest":
        _selftest(); return

    e = Engagement(_resolve_dir(a))

    if a.cmd == "summary":
        print(json.dumps(e.summary(), indent=2))
    elif a.cmd == "set-phase":
        e.set_phase(a.phase); print(f"phase -> {a.phase}")
    elif a.cmd == "add-surface":
        added, dropped = e.add_surface(_load_items(a))
        print(f"added {added}, dropped {dropped} out-of-scope")
    elif a.cmd == "worklist":
        for s in e.worklist(a.top, for_agent=a.agent):
            print(f"[{s['_priority']:>3}] {s.get('vuln_class'):<16} {s.get('url')}"
                  + (f"  (param {s['param']})" if s.get("param") else ""))
    elif a.cmd == "mark-tested":
        e.mark_tested(a.url, a.param, a.vuln_class); print("ok")
    elif a.cmd == "claim":
        ok, holder = e.claim(a.url, a.param, a.vuln_class, a.agent, a.ttl_minutes)
        print(f"claimed by {a.agent}" if ok else f"DENIED — held by {holder.get('agent')}")
        sys.exit(0 if ok else 1)
    elif a.cmd == "release":
        ok = e.release(a.url, a.param, a.vuln_class, a.agent)
        print("released" if ok else "no such claim")
    elif a.cmd == "claims":
        print(json.dumps(e.list_claims(), indent=2))
    elif a.cmd == "add-candidate":
        e.add_candidate({"url": a.url, "param": a.param, "vuln_class": a.vuln_class,
                         "severity": a.severity, "evidence": a.evidence, "request": a.request})
        print("candidate added")
    elif a.cmd == "confirm":
        e.confirm(a.url, a.vuln_class, {"real": a.real == "true", "severity": a.severity, "reason": a.reason})
        print("recorded")


def _selftest():
    import tempfile, shutil
    d = tempfile.mkdtemp()
    try:
        (Path(d) / "engagement.json").write_text(json.dumps(
            {"project": "demo", "scope": ["acme.com"], "out_of_scope": ["admin.acme.com"]}))
        e = Engagement(d)
        added, dropped = e.add_surface([
            {"url": "https://api.acme.com/a?id=1", "param": "id", "vuln_class": "idor"},
            {"url": "https://api.acme.com/a?id=1", "param": "id", "vuln_class": "idor"},   # dup
            {"url": "https://acme.com/s?q=x", "param": "q", "vuln_class": "xss"},
            {"url": "https://admin.acme.com/x", "param": "", "vuln_class": "sqli"},          # deny-wins drop
            {"url": "https://evil.com/x", "param": "", "vuln_class": "rce"},                 # out of scope drop
        ])
        assert (added, dropped) == (2, 2), (added, dropped)
        wl = e.worklist()
        assert wl[0]["vuln_class"] == "idor"           # idor(80)+param(5) > xss(55)+param(5)
        e.mark_tested(wl[0]["url"], wl[0]["param"], wl[0]["vuln_class"])
        assert all(s["vuln_class"] != "idor" for s in e.worklist())
        e.add_candidate({"url": "https://api.acme.com/a?id=1", "vuln_class": "idor", "evidence": "x"})
        e.confirm("https://api.acme.com/a?id=1", "idor", {"real": True, "severity": "high"})
        # resume: fresh handle sees persisted state
        e2 = Engagement(d)
        s = e2.summary()
        assert s["surface"] == 2 and s["tested"] == 1 and s["confirmed"] == 1, s

        # class_weight: aliases and tokenised names resolve, unknown → default
        assert class_weight("sql-injection") == CLASS_WEIGHT["sqli"]
        assert class_weight("remote-code-execution") == CLASS_WEIGHT["rce"]
        assert class_weight("sqli-blind") == CLASS_WEIGHT["sqli"]   # token match
        assert class_weight("quantum-flux") == DEFAULT_WEIGHT       # unknown → default
        assert class_weight("source-map-leak") == DEFAULT_WEIGHT    # 'rce' NOT substring-matched

        # work-claim dedup: second agent denied while fresh; released → reclaimable
        ok, _ = e2.claim("https://acme.com/s?q=x", "q", "xss", "exec-A")
        assert ok
        ok2, holder = e2.claim("https://acme.com/s?q=x", "q", "xss", "exec-B")
        assert not ok2 and holder["agent"] == "exec-A", holder
        # exec-B's claim-aware worklist hides the item exec-A holds
        assert all(w["vuln_class"] != "xss" for w in e2.worklist(for_agent="exec-B"))
        # exec-A still sees its own claim
        assert any(w["vuln_class"] == "xss" for w in e2.worklist(for_agent="exec-A"))
        e2.release("https://acme.com/s?q=x", "q", "xss", "exec-A")
        ok3, _ = e2.claim("https://acme.com/s?q=x", "q", "xss", "exec-B")
        assert ok3                                                 # reclaimable after release
        print("engagement-state.py self-test: PASS")
    finally:
        shutil.rmtree(d)


if __name__ == "__main__":
    main()
