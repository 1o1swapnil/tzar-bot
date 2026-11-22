#!/usr/bin/env python3
"""
benchmark.py — measure tzar-bot against deliberately vulnerable targets with known answers.

Targets run locally in Docker, bound to 127.0.0.1 only, and each has a curated
ground-truth list (benchmarks/targets/<name>/ground-truth.json): the vulnerabilities a
competent tester should report, with vulnerability classes, endpoint patterns and
severity. Any tool's output can be scored against it, so tzar-bot, Burp, ZAP, nuclei
and a human tester are compared on the same answer key.

  python3 tools/benchmark.py list
  python3 tools/benchmark.py up juice-shop            # sudo docker; hook asks the operator
  python3 tools/benchmark.py status | down juice-shop
  python3 tools/benchmark.py init juice-shop          # prints the init-engagement command
  python3 tools/benchmark.py verify-gt juice-shop     # GET-probe ground-truth endpoints
  python3 tools/benchmark.py solved juice-shop        # Juice Shop scoreboard (objective)
  python3 tools/benchmark.py score juice-shop tzar:WAPT/bench-juice-shop/<TS> --label tzar-v1
  python3 tools/benchmark.py score juice-shop burp:issues.xml   --label burp-pro-2026
  python3 tools/benchmark.py score juice-shop zap:zap.json | nuclei:out.jsonl | csv:human.csv
  python3 tools/benchmark.py compare juice-shop

Scoring
  A finding matches a ground-truth entry when their vulnerability classes overlap (with
  families: xss ⊃ xss-dom, access-control ⊃ idor/bfla, ...) AND one of the entry's
  endpoint patterns matches a URL in the finding (entries without patterns match on class).
  recall            = ground-truth entries found / total
  weighted recall   = same, weighted critical 4 · high 3 · medium 2 · low 1
  precision (raw)   = matched findings / (matched + unmatched)   — unmatched may be real
                      bugs missing from the answer key; adjudicate them with
                      --adjudicate FILE ({"finding-id": "valid"|"invalid"}) for the
                      adjudicated precision
  hygiene           = header/cookie/TLS/banner findings, counted separately, excluded
                      from precision and recall
  tzar runs are scored twice: VALIDATED-only (what the report contains) and all findings.
Results: benchmarks/results/<target>/<UTC>-<label>.json + .md
"""

import argparse
import csv
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
BENCH = Path(__import__("os").environ.get("TZAR_BENCH_DIR") or (REPO / "benchmarks"))
SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}

# ── vulnerability taxonomy ───────────────────────────────────────────────────
FAMILY = {
    "xss-dom": "xss", "xss-reflected": "xss", "xss-stored": "xss",
    "idor": "access-control", "bola": "access-control", "bfla": "access-control",
    "auth-bypass": "broken-auth", "weak-credentials": "broken-auth",
    "password-reset": "broken-auth", "weak-session": "broken-auth",
    "brute-force": "rate-limit", "captcha": "rate-limit",
    "lfi": "path-traversal", "rfi": "path-traversal",
    "ssti": "code-injection", "deserialization": "code-injection",
    "command-injection": "code-injection",
}
HYGIENE = {"security-headers", "cookie-flags", "tls-config", "clickjacking", "server-banner",
           "autocomplete", "cache-control"}

CWE_CLASS = {
    89: "sqli", 564: "sqli", 943: "nosqli", 79: "xss", 80: "xss", 83: "xss", 87: "xss",
    639: "idor", 284: "access-control", 285: "access-control", 862: "access-control",
    863: "access-control", 425: "access-control", 287: "broken-auth", 306: "broken-auth",
    288: "auth-bypass", 1390: "weak-credentials", 521: "weak-credentials",
    798: "weak-credentials", 307: "brute-force", 640: "password-reset", 384: "weak-session",
    330: "weak-session", 352: "csrf", 918: "ssrf", 611: "xxe", 776: "xxe",
    601: "open-redirect", 22: "path-traversal", 23: "path-traversal", 35: "path-traversal",
    158: "path-traversal", 98: "lfi", 434: "file-upload", 77: "command-injection",
    78: "command-injection", 94: "code-injection", 95: "code-injection", 1336: "ssti",
    502: "deserialization", 200: "info-disclosure", 209: "info-disclosure",
    497: "info-disclosure", 538: "info-disclosure", 548: "info-disclosure",
    215: "info-disclosure", 532: "info-disclosure", 615: "info-disclosure",
    915: "mass-assignment", 1104: "vulnerable-component", 937: "vulnerable-component",
    1035: "vulnerable-component", 327: "crypto", 328: "crypto", 326: "crypto", 916: "crypto",
    347: "jwt", 840: "business-logic", 841: "business-logic", 770: "rate-limit",
    799: "rate-limit", 804: "captcha", 942: "cors", 1021: "clickjacking",
    693: "security-headers", 16: "security-headers", 614: "cookie-flags",
    1004: "cookie-flags", 319: "tls-config", 523: "tls-config",
}
KEYWORDS = [  # (class, regex on title + text)
    ("nosqli", r"nosql|\$ne\b|\$where|mongo.*inject"),
    ("sqli", r"sql[\s-]*inject|sqli\b|union[\s-]+select|blind sql"),
    ("xss-dom", r"dom[\s-]*(based\s*)?xss|dom[\s-]based cross"),
    ("xss-stored", r"(stored|persistent)[\s-]*(xss|cross)"),
    ("xss-reflected", r"reflected[\s-]*(xss|cross)"),
    ("xss", r"\bxss\b|cross[\s-]site scripting"),
    ("ssti", r"template injection|\bssti\b"),
    ("command-injection", r"command injection|os command|\bexec\b.*inject|\brce\b"),
    ("deserialization", r"deserial"),
    ("code-injection", r"code injection|remote code execution"),
    ("xxe", r"\bxxe\b|xml external entit"),
    ("ssrf", r"\bssrf\b|server[\s-]side request forgery"),
    ("open-redirect", r"open redirect|unvalidated redirect"),
    ("csrf", r"\bcsrf\b|cross[\s-]site request forgery"),
    ("lfi", r"local file inclusion|\blfi\b"),
    ("rfi", r"remote file inclusion|\brfi\b"),
    ("path-traversal", r"path traversal|directory traversal|null byte|poison null"),
    ("file-upload", r"file upload|unrestricted upload|upload.*(bypass|type|size)"),
    ("idor", r"\bidor\b|insecure direct object|\bbola\b|broken object level"),
    ("bfla", r"\bbfla\b|function[\s-]level auth|admin (function|endpoint|section)"),
    ("access-control", r"access control|authori[sz]ation|privilege escalation|forged"),
    ("mass-assignment", r"mass assignment|over[\s-]?posting|role.*(param|field).*(admin)"),
    ("auth-bypass", r"authentication bypass|login bypass|auth bypass"),
    ("weak-credentials", r"default (credential|password)|weak password|admin123|guessable password"),
    ("password-reset", r"password reset|security question|forgot password"),
    ("weak-session", r"weak session|predictable session|session id"),
    ("brute-force", r"brute[\s-]?force|credential stuffing|no (account )?lockout"),
    ("captcha", r"captcha"),
    ("rate-limit", r"rate[\s-]?limit|resource consumption|denial of service|\bdos\b"),
    ("jwt", r"\bjwt\b|json web token|alg[\s\"':]*none"),
    ("business-logic", r"business logic|negative (quantity|price)|price (manipulat|tamper)|payment bypass|free (item|membership)|deluxe"),
    ("info-disclosure", r"information disclosure|exposed? (metrics|directory|file|backup|ftp|api doc|swagger)|stack trace|verbose error|sensitive data exposure|directory listing|excessive data"),
    ("vulnerable-component", r"vulnerable (library|component|dependency)|outdated|known vulnerab|cve-\d{4}"),
    ("crypto", r"weak (hash|crypto|cipher)|md5|unsalted|cryptographic"),
    ("cors", r"\bcors\b|cross[\s-]origin resource"),
    ("security-headers", r"missing (security )?header|content[\s-]security[\s-]policy (header )?(missing|not set)|x-content-type|strict[\s-]transport|hsts|x-frame-options|referrer-policy|permissions-policy"),
    ("cookie-flags", r"cookie.*(httponly|secure|samesite)|(httponly|samesite).*cookie"),
    ("tls-config", r"\btls\b|\bssl\b|cipher suite|certificate|plain(text)? http|cleartext"),
    ("clickjacking", r"clickjack"),
    ("server-banner", r"server (banner|version)|version disclosure|x-powered-by"),
]
KEYWORDS = [(c, re.compile(rx, re.I)) for c, rx in KEYWORDS]


def classify(title, text="", cwes=(), declared=()):
    classes = set(declared)
    for c in cwes:
        try:
            n = int(re.sub(r"\D", "", str(c)) or 0)
        except ValueError:
            continue
        if n in CWE_CLASS:
            classes.add(CWE_CLASS[n])
    blob = f"{title}\n{text[:4000]}"
    title_hits = {c for c, rx in KEYWORDS if rx.search(title)}
    classes |= title_hits or {c for c, rx in KEYWORDS if rx.search(blob)}
    if any(c.startswith("xss-") for c in classes):
        classes.discard("xss")
    return classes


def expand(classes):
    return set(classes) | {FAMILY[c] for c in classes if c in FAMILY}


def is_hygiene(classes):
    return bool(classes) and classes <= HYGIENE


# ── finding records ──────────────────────────────────────────────────────────
URL_RX = re.compile(r"(?:https?://[^\s`'\"<>|)\]]+|/#/[^\s`'\"<>|)\]]+|(?<![\w.])/(?:rest|api|ftp|b2b|vulnerabilities|identity|workshop|community|redirect|profile|file-upload|metrics|api-docs|socket\.io)[^\s`'\"<>|)\]]*)")


def finding(fid, title, severity, text="", urls=(), cwes=(), declared=(), verdict=None):
    found = list(urls) + URL_RX.findall(f"{title}\n{text}")
    return {"id": fid, "title": title.strip(), "severity": (severity or "info").strip().lower(),
            "classes": sorted(classify(title, text, cwes, declared)),
            "urls": sorted(set(u.rstrip(".,;:") for u in found))[:50], "verdict": verdict}


def _vf():
    spec = importlib.util.spec_from_file_location("validate_finding_b", TOOLS / "validate-finding.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_tzar(output_dir):
    od = Path(output_dir)
    vf = _vf()
    verdicts = vf.read_verdicts(od)
    out = []
    for desc in sorted((od / "findings").glob("*/description.md")):
        info = vf.parse_description(desc)
        replay = vf.load_replay(desc.parent)
        urls = [r.get("url", "") for r in (replay or {}).get("requests", [])] \
            if isinstance(replay, dict) else []
        cwes = re.findall(r"CWE[-\s:]*(\d+)", info["full_text"])[:5]
        out.append(finding(desc.parent.name, info["title"], info["severity"],
                           info["affected"] + "\n" + info["full_text"], urls, cwes,
                           verdict=verdicts.get(desc.parent.name, "not validated")))
    meta = {}
    try:
        meta = json.loads((od / "engagement.json").read_text())
    except (OSError, ValueError):
        pass
    times = [p.stat().st_mtime for p in (od / "findings").rglob("*") if p.is_file()]
    started = meta.get("started")
    duration = None
    if started and times:
        try:
            t0 = datetime.strptime(started, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
            duration = round((max(times) - t0.timestamp()) / 60, 1)
        except ValueError:
            pass
    return out, {"tool": "tzar-bot", "output_dir": str(od), "duration_min": duration}


def load_burp(path):
    root = ET.parse(path).getroot()
    out = []
    for i, it in enumerate(root.iter("issue"), 1):
        g = lambda tag: (it.findtext(tag) or "").strip()
        host, p = g("host"), g("path")
        text = " ".join(g(t) for t in ("issueBackground", "issueDetail",
                                       "vulnerabilityClassifications", "location"))
        out.append(finding(f"burp-{i}", g("name"), g("severity"), text, [host.rstrip("/") + p],
                           re.findall(r"CWE-(\d+)", text)))
    return out, {"tool": "burp"}


def load_zap(path):
    data = json.loads(Path(path).read_text())
    out, n = [], 0
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            n += 1
            sev = (a.get("riskdesc") or a.get("risk") or "info").split(" ")[0]
            urls = [inst.get("uri", "") for inst in a.get("instances", [])][:20]
            out.append(finding(f"zap-{n}", a.get("alert") or a.get("name", ""), sev,
                               re.sub("<[^>]+>", " ", a.get("desc", "")), urls, [a.get("cweid", "")]))
    return out, {"tool": "zap"}


def load_nuclei(path):
    out = []
    for i, line in enumerate(Path(path).read_text().splitlines(), 1):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        info = r.get("info", {})
        cl = info.get("classification") or {}
        out.append(finding(f"nuclei-{i}", info.get("name", r.get("template-id", "")),
                           info.get("severity", "info"),
                           " ".join(info.get("tags", []) if isinstance(info.get("tags"), list)
                                    else [str(info.get("tags", ""))]) + " " + info.get("description", ""),
                           [r.get("matched-at", "")], cl.get("cwe-id") or []))
    return out, {"tool": "nuclei"}


def load_csv(path):
    out = []
    with open(path, newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh), 1):
            out.append(finding(row.get("id") or f"row-{i}", row.get("title", ""),
                               row.get("severity", ""), row.get("description", ""),
                               [u for u in re.split(r"[\s;]+", row.get("url", "")) if u],
                               [row.get("cwe", "")],
                               [c.strip() for c in row.get("class", "").split(";") if c.strip()]))
    return out, {"tool": "csv"}


def load_json(path):
    data = json.loads(Path(path).read_text())
    items = data.get("findings", data) if isinstance(data, dict) else data
    out = []
    for i, f in enumerate(items, 1):
        urls = f.get("urls") or [f.get("url") or ((f.get("host") or "") + (f.get("path") or ""))]
        out.append(finding(str(f.get("id", f"json-{i}")), f.get("title") or f.get("name", ""),
                           f.get("severity", ""), f.get("description", ""), urls,
                           [f.get("cwe", "")], f.get("classes", [])))
    return out, {"tool": "json"}


LOADERS = {"tzar": load_tzar, "burp": load_burp, "zap": load_zap, "nuclei": load_nuclei,
           "csv": load_csv, "json": load_json}


# ── scoring ──────────────────────────────────────────────────────────────────
def _paths(urls):
    out = set()
    for u in urls:
        if "://" in u:
            p = urlsplit(u)
            out.add(p.path + (("?" + p.query) if p.query else "") + (("#" + p.fragment) if p.fragment else ""))
        out.add(u)
    return out


def matches(f, gt):
    if not (expand(f["classes"]) & expand(gt["classes"])):
        return False
    pats = gt.get("endpoints") or []
    if not pats:
        return True
    paths = _paths(f["urls"])
    return any(re.search(p, s, re.I) for p in pats for s in paths)


def score(findings, ground_truth, adjudication=None):
    adjudication = adjudication or {}
    entries = [g for g in ground_truth["entries"] if not g.get("hygiene")]
    hygiene = [f for f in findings if is_hygiene(set(f["classes"]))]
    scored = [f for f in findings if f not in hygiene]
    found, matched_f, unmatched = {}, [], []
    for f in scored:
        hits = [g["id"] for g in entries if matches(f, g)]
        f["matched"] = hits
        if hits:
            matched_f.append(f)
            for h in hits:
                found.setdefault(h, []).append(f["id"])
        else:
            unmatched.append(f)
    total_w = sum(SEV_WEIGHT.get(g["severity"], 1) for g in entries) or 1
    found_w = sum(SEV_WEIGHT.get(g["severity"], 1) for g in entries if g["id"] in found)
    valid = [f for f in unmatched if adjudication.get(f["id"]) == "valid"]
    invalid = [f for f in unmatched if adjudication.get(f["id"]) == "invalid"]
    pending = [f for f in unmatched if f["id"] not in adjudication]
    n_scored = len(matched_f) + len(unmatched)
    adj_den = len(matched_f) + len(valid) + len(invalid)
    per_class = {}
    for g in entries:
        for c in g["classes"]:
            pc = per_class.setdefault(c, [0, 0])
            pc[1] += 1
            pc[0] += g["id"] in found
    return {
        "ground_truth_total": len(entries),
        "ground_truth_found": len(found),
        "recall": round(len(found) / len(entries), 3) if entries else None,
        "weighted_recall": round(found_w / total_w, 3),
        "findings_total": len(findings),
        "findings_matched": len(matched_f),
        "findings_unmatched": len(unmatched),
        "hygiene": len(hygiene),
        "precision_raw": round(len(matched_f) / n_scored, 3) if n_scored else None,
        "precision_adjudicated": round((len(matched_f) + len(valid)) / adj_den, 3) if adj_den else None,
        "unadjudicated": [f["id"] for f in pending],
        "duplicates": {g: ids for g, ids in found.items() if len(ids) > 1},
        "found": sorted(found),
        "missed": [g["id"] for g in entries if g["id"] not in found],
        "per_class": {c: f"{a}/{b}" for c, (a, b) in sorted(per_class.items())},
        "unmatched_findings": [{"id": f["id"], "title": f["title"], "classes": f["classes"]}
                               for f in unmatched],
    }


def load_target(name):
    d = BENCH / "targets" / name
    if not (d / "target.json").exists():
        sys.exit(f"unknown target {name!r} — see `benchmark.py list`")
    return json.loads((d / "target.json").read_text()), json.loads((d / "ground-truth.json").read_text())


def cmd_score(a):
    target, gt = load_target(a.target)
    kind, _, src = a.run.partition(":")
    if kind not in LOADERS or not src:
        sys.exit(f"run must be one of {', '.join(k + ':PATH' for k in LOADERS)}")
    findings, meta = LOADERS[kind](src)
    adj = json.loads(Path(a.adjudicate).read_text()) if a.adjudicate else {}
    result = {"target": a.target, "ground_truth_version": gt.get("version"),
              "label": a.label or f"{meta['tool']}", "scored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              **meta, "score": score([dict(f) for f in findings], gt, adj)}
    if kind == "tzar":
        report = [f for f in findings if f["verdict"] == "validated"]
        result["score_report_only"] = score([dict(f) for f in report], gt, adj)
        result["verdicts"] = {v: sum(1 for f in findings if f["verdict"] == v)
                              for v in sorted({f["verdict"] for f in findings})}
    out_dir = BENCH / "results" / a.target
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{re.sub(r'[^\w.-]', '_', result['label'])}"
    (out_dir / f"{stem}.json").write_text(json.dumps(result, indent=2) + "\n")
    md = render_md(result, gt)
    (out_dir / f"{stem}.md").write_text(md)
    print(md)
    print(f"→ {out_dir / stem}.json")


def _line(label, s):
    pct = lambda v: "—" if v is None else f"{v * 100:.0f}%"
    return (f"| {label} | {s['ground_truth_found']}/{s['ground_truth_total']} ({pct(s['recall'])}) "
            f"| {pct(s['weighted_recall'])} | {pct(s['precision_raw'])} | {pct(s['precision_adjudicated'])} "
            f"| {s['findings_total']} | {s['hygiene']} |")


HEADER = ("| run | recall | weighted recall | precision (raw) | precision (adjudicated) "
          "| findings | hygiene |\n|---|---|---|---|---|---|---|")


def render_md(r, gt):
    s = r["score"]
    lines = [f"# {r['target']} — {r['label']}", "",
             f"Ground truth {gt.get('version')} · {s['ground_truth_total']} entries · scored {r['scored_at']}",
             "", HEADER, _line("all findings", s)]
    if "score_report_only" in r:
        lines.append(_line("report (VALIDATED only)", r["score_report_only"]))
        lines += ["", f"Verdicts: {r['verdicts']}"]
    if r.get("duration_min") is not None:
        lines.append(f"Duration: {r['duration_min']} min")
    names = {g["id"]: g["title"] for g in gt["entries"]}
    lines += ["", "## Missed", *([f"- `{m}` {names.get(m, '')}" for m in s["missed"]] or ["- none"]),
              "", "## Unmatched findings (real bug missing from the answer key, or a false positive)",
              *([f"- `{u['id']}` {u['title']} {u['classes']}" for u in s["unmatched_findings"]] or ["- none"]),
              "", "## Recall by class", *[f"- {c}: {v}" for c, v in s["per_class"].items()], ""]
    return "\n".join(lines)


def cmd_compare(a):
    rows = []
    for p in sorted((BENCH / "results" / a.target).glob("*.json")):
        r = json.loads(p.read_text())
        rows.append(_line(r["label"], r["score"]))
        if "score_report_only" in r:
            rows.append(_line(r["label"] + " (report)", r["score_report_only"]))
    print(f"# {a.target}\n\n{HEADER}\n" + "\n".join(rows) if rows else "no results yet")


# ── target lifecycle (Docker, 127.0.0.1 only) ────────────────────────────────
def _sudo_docker(*args, check=True):
    cmd = ["sudo", "-n", "docker", *args]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"{' '.join(cmd)}\n{r.stderr.strip()}")
    return r


def _http(url, timeout=5):
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=timeout) as r:
            return r.status, r.read(2_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except OSError:
        return None, ""


def _compose(target, *args):
    d = BENCH / ".cache" / target["name"]
    d.mkdir(parents=True, exist_ok=True)
    f = d / "docker-compose.yml"
    if not f.exists():
        urllib.request.urlretrieve(target["compose_url"], f)
    text = f.read_text()
    if re.search(r'^\s*-\s*"?0\.0\.0\.0:', text, re.M):
        sys.exit(f"{f} binds 0.0.0.0 — refusing (this box is internet-facing)")
    env = {**__import__("os").environ, **target.get("compose_env", {})}
    exe = shutil.which("docker-compose")
    cmd = ["sudo", "-n", "--preserve-env=" + ",".join(target.get("compose_env", {})),
           *( [exe] if exe else ["docker", "compose"]), "-f", str(f), "-p", f"tzar-bench-{target['name']}", *args]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        sys.exit(r.stderr.strip()[-2000:])
    return r


def cmd_up(a):
    target, _ = load_target(a.target)
    if target["kind"] == "compose":
        _compose(target, "up", "-d")
    else:
        name = f"tzar-bench-{target['name']}"
        _sudo_docker("rm", "-f", name, check=False)
        args = ["run", "-d", "--name", name, "--memory", target.get("memory", "1g"),
                "--restart", "unless-stopped"]
        for host_ip, hp, cp in target["ports"]:
            if host_ip != "127.0.0.1":
                sys.exit("targets must bind 127.0.0.1")
            args += ["-p", f"{host_ip}:{hp}:{cp}"]
        for k, v in target.get("env", {}).items():
            args += ["-e", f"{k}={v}"]
        _sudo_docker(*args, target["image"])
    url = target["url"] + target.get("health", "/")
    for _ in range(int(target.get("startup_seconds", 120) / 2)):
        st, _ = _http(url, 3)
        if st and st < 500:
            print(f"{target['name']} is up at {target['url']} (health {st})")
            for n in target.get("after_up", []):
                print(f"note: {n}")
            return
        time.sleep(2)
    sys.exit(f"{target['name']} did not become healthy at {url}")


def cmd_down(a):
    target, _ = load_target(a.target)
    if target["kind"] == "compose":
        _compose(target, "down")
    else:
        _sudo_docker("rm", "-f", f"tzar-bench-{target['name']}", check=False)
    print(f"{target['name']} stopped")


def cmd_status(a):
    for d in sorted((BENCH / "targets").iterdir()):
        if not (d / "target.json").exists():
            continue
        t = json.loads((d / "target.json").read_text())
        if t["kind"] == "external":
            print(f"{t['name']:<12} external — {t.get('notes', '')[:70]}")
            continue
        st, _ = _http(t["url"] + t.get("health", "/"), 2)
        print(f"{t['name']:<12} {'UP' if st else 'down'} {t['url']}")


def cmd_list(a):
    for d in sorted((BENCH / "targets").iterdir()):
        if (d / "target.json").exists():
            t = json.loads((d / "target.json").read_text())
            gt = json.loads((d / "ground-truth.json").read_text())
            print(f"{t['name']:<12} {t['kind']:<9} {len(gt['entries']):>3} ground-truth entries  "
                  f"{t.get('engagement_type', '')}  {t.get('summary', '')}")


def cmd_init(a):
    target, _ = load_target(a.target)
    if target["kind"] == "external":
        sys.exit(target.get("notes"))
    scope = ",".join(target.get("scope", ["127.0.0.1"]))
    print("# Benchmark engagement (lab target, writes allowed):")
    print(f'eval $(python3 tools/init-engagement.py --type {target["engagement_type"]} '
          f'--project bench-{target["name"]} --target {target["url"]} --mode {target.get("mode", "blackbox")} '
          f'--scope {scope} --write-policy allow)')
    for n in target.get("tester_notes", []):
        print(f"# {n}")
    print(f"# then score: python3 tools/benchmark.py score {target['name']} tzar:\"$OUTPUT_DIR\" --label tzar-<version>")


def cmd_verify_gt(a):
    target, gt = load_target(a.target)
    bad = 0
    for g in gt["entries"]:
        probe = g.get("probe")
        if not probe:
            print(f"  ·   {g['id']:<28} (no safe GET probe)")
            continue
        st, _ = _http(target["url"] + probe, 5)
        ok = st is not None and st != 404
        bad += not ok
        print(f"  {'ok ' if ok else 'BAD'} {g['id']:<28} GET {probe} → {st}")
    print(f"{bad} ground-truth endpoint(s) missing on this build" if bad else "all probed endpoints exist")
    if target["name"] == "juice-shop":
        print("note: these probes solve a few scoreboard challenges — restart the target "
              "(down + up) before a benchmark run so `solved` starts from zero")
    sys.exit(1 if bad else 0)


def cmd_solved(a):
    target, _ = load_target(a.target)
    if target["name"] != "juice-shop":
        sys.exit("scoreboard is Juice Shop only")
    st, body = _http(target["url"] + "/api/Challenges/")
    if st != 200:
        sys.exit(f"could not read the scoreboard ({st})")
    ch = json.loads(body).get("data", [])
    solved = [c for c in ch if c.get("solved")]
    by_cat = {}
    for c in ch:
        s = by_cat.setdefault(c.get("category", "?"), [0, 0])
        s[1] += 1
        s[0] += bool(c.get("solved"))
    _, ver = _http(target["url"] + "/rest/admin/application-version")
    print(f"Juice Shop {ver.strip()[:40]} — solved {len(solved)}/{len(ch)} challenges")
    for cat, (s, t) in sorted(by_cat.items()):
        print(f"  {cat:<32} {s}/{t}")
    out = BENCH / "results" / "juice-shop"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"scoreboard-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json").write_text(
        json.dumps({"solved": [c["key"] if "key" in c else c.get("name") for c in solved],
                    "total": len(ch)}, indent=2))


def main():
    ap = argparse.ArgumentParser(description="Benchmark tzar-bot against vulnerable targets.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("status")
    for name in ("up", "down", "init", "verify-gt", "solved", "compare"):
        sub.add_parser(name).add_argument("target")
    sp = sub.add_parser("score")
    sp.add_argument("target")
    sp.add_argument("run", help="tzar:DIR | burp:FILE.xml | zap:FILE.json | nuclei:FILE.jsonl | csv:FILE | json:FILE")
    sp.add_argument("--label")
    sp.add_argument("--adjudicate", help='JSON {"finding-id": "valid"|"invalid"} for unmatched findings')
    a = ap.parse_args()
    {"list": cmd_list, "status": cmd_status, "up": cmd_up, "down": cmd_down, "init": cmd_init,
     "verify-gt": cmd_verify_gt, "solved": cmd_solved, "score": cmd_score,
     "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    main()
