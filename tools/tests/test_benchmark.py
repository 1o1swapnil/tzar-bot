"""
Tests for tools/benchmark.py — classification, matching, metrics and every input adapter.
Synthetic data only; no containers are started.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent
REPO = TOOLS.parent
PY = sys.executable

_spec = importlib.util.spec_from_file_location("benchmark_t", TOOLS / "benchmark.py")
bm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bm)

GT = {"version": "test", "entries": [
    {"id": "sqli-login", "title": "SQLi login", "classes": ["sqli", "auth-bypass"],
     "endpoints": ["/rest/user/login"], "severity": "critical"},
    {"id": "xss-dom", "title": "DOM XSS", "classes": ["xss-dom"], "endpoints": ["/#/search"],
     "severity": "medium"},
    {"id": "idor-basket", "title": "IDOR basket", "classes": ["idor"],
     "endpoints": ["/rest/basket/\\d+"], "severity": "high"},
    {"id": "jwt", "title": "JWT", "classes": ["jwt"], "endpoints": [], "severity": "high"},
]}


def test_classify():
    assert "sqli" in bm.classify("SQL Injection in login form")
    assert bm.classify("DOM-based XSS in search") == {"xss-dom"}
    assert "idor" in bm.classify("Insecure Direct Object Reference on basket")
    assert bm.classify("Thing", cwes=["CWE-918"]) == {"ssrf"}
    assert bm.is_hygiene(bm.classify("Missing HSTS header (Strict-Transport-Security)"))
    assert not bm.is_hygiene(bm.classify("Reflected XSS"))


def test_family_and_endpoint_matching():
    generic_xss = bm.finding("f1", "Cross-site scripting", "medium", urls=["http://h/#/search?q=x"])
    assert bm.matches(generic_xss, GT["entries"][1])              # xss ⊃ xss-dom
    wrong_place = bm.finding("f2", "SQL injection", "high", urls=["http://h/api/Products"])
    assert not bm.matches(wrong_place, GT["entries"][0])          # class ok, endpoint not
    any_place = bm.finding("f3", "JWT alg none accepted", "high")
    assert bm.matches(any_place, GT["entries"][3])                # no endpoint constraint
    bola = bm.finding("f4", "Broken object level authorization", "high",
                      urls=["http://h/rest/basket/2"])
    assert bm.matches(bola, GT["entries"][2])


def test_score_metrics():
    fs = [
        bm.finding("a", "SQL injection authentication bypass", "critical", urls=["http://h/rest/user/login"]),
        bm.finding("b", "SQLi in login (again)", "critical", urls=["http://h/rest/user/login"]),
        bm.finding("c", "IDOR on basket", "high", urls=["http://h/rest/basket/3"]),
        bm.finding("d", "Missing X-Frame-Options header", "low", urls=["http://h/"]),
        bm.finding("e", "Open redirect", "medium", urls=["http://h/redirect?to=x"]),
    ]
    s = bm.score(fs, GT, {"e": "valid"})
    assert s["ground_truth_found"] == 2 and s["recall"] == 0.5
    assert s["weighted_recall"] == round((4 + 3) / (4 + 2 + 3 + 3), 3)
    assert s["hygiene"] == 1 and s["findings_unmatched"] == 1
    assert s["precision_raw"] == 0.75 and s["precision_adjudicated"] == 1.0
    assert s["duplicates"] == {"sqli-login": ["a", "b"]}
    assert s["missed"] == ["xss-dom", "jwt"]


def _tzar_engagement(tmp_path):
    od = tmp_path / "eng"
    (od / "artifacts" / "validated").mkdir(parents=True)
    (od / "engagement.json").write_text(json.dumps({"started": "2026-11-22 08:00 UTC", "in_scope": ["h"]}))
    for fid, title, url, verdict in [
        ("finding-001", "SQL injection in login bypasses authentication", "http://h/rest/user/login", "validated"),
        ("finding-002", "DOM XSS in search", "http://h/#/search?q=<img>", None),
    ]:
        d = od / "findings" / fid
        d.mkdir(parents=True)
        (d / "description.md").write_text(
            f"# Finding: {title}\n\n| Severity | High |\n| CVSS Score | 7.5 |\n"
            f"| Affected Component | {url} |\n\nCWE-89\n")
        if verdict:
            (od / "artifacts" / "validated" / f"{fid}.json").write_text(json.dumps(
                {"finding_id": fid, "verdict": "validated", "replay": {"requests": [{"passed": True}]}}))
    return od


def test_tzar_adapter_scores_report_separately(tmp_path, monkeypatch):
    od = _tzar_engagement(tmp_path)
    findings, meta = bm.load_tzar(od)
    assert {f["id"]: f["verdict"] for f in findings} == {"finding-001": "validated",
                                                         "finding-002": "not validated"}
    assert meta["duration_min"] is not None
    bench = tmp_path / "bench"
    (bench / "targets" / "t").mkdir(parents=True)
    (bench / "targets" / "t" / "target.json").write_text(json.dumps({"name": "t", "kind": "docker", "url": "http://h"}))
    (bench / "targets" / "t" / "ground-truth.json").write_text(json.dumps(GT))
    env = {**__import__("os").environ, "TZAR_BENCH_DIR": str(bench)}
    r = subprocess.run([PY, str(TOOLS / "benchmark.py"), "score", "t", f"tzar:{od}", "--label", "tzar-test"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    res = json.loads(next((bench / "results" / "t").glob("*.json")).read_text())
    assert res["score"]["ground_truth_found"] == 2
    assert res["score_report_only"]["ground_truth_found"] == 1       # only VALIDATED in report
    r = subprocess.run([PY, str(TOOLS / "benchmark.py"), "compare", "t"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert "tzar-test (report)" in r.stdout


def test_burp_zap_nuclei_csv_adapters(tmp_path):
    (tmp_path / "b.xml").write_text("""<?xml version="1.0"?><issues>
      <issue><name>SQL injection</name><host>http://h</host><path>/rest/user/login</path>
        <severity>High</severity><issueDetail>CWE-89</issueDetail></issue>
      <issue><name>Strict transport security not enforced</name><host>http://h</host><path>/</path>
        <severity>Low</severity></issue></issues>""")
    fs, _ = bm.load_burp(tmp_path / "b.xml")
    s = bm.score(fs, GT)
    assert s["found"] == ["sqli-login"] and s["hygiene"] == 1

    (tmp_path / "z.json").write_text(json.dumps({"site": [{"alerts": [
        {"alert": "Cross Site Scripting (DOM Based)", "riskdesc": "High (Medium)", "cweid": "79",
         "instances": [{"uri": "http://h/#/search?q=x"}]}]}]}))
    assert bm.score(bm.load_zap(tmp_path / "z.json")[0], GT)["found"] == ["xss-dom"]

    (tmp_path / "n.jsonl").write_text(json.dumps({"template-id": "jwt-none", "matched-at": "http://h/rest/user/whoami",
                                                  "info": {"name": "JWT none algorithm", "severity": "high",
                                                           "tags": ["jwt"]}}) + "\n")
    assert bm.score(bm.load_nuclei(tmp_path / "n.jsonl")[0], GT)["found"] == ["jwt"]

    (tmp_path / "h.csv").write_text("id,title,url,severity,cwe,class\n"
                                    "H1,Basket of other user readable,http://h/rest/basket/4,high,639,idor\n")
    assert bm.score(bm.load_csv(tmp_path / "h.csv")[0], GT)["found"] == ["idor-basket"]


@pytest.mark.parametrize("target", ["juice-shop", "dvwa", "crapi", "goad"])
def test_shipped_targets_are_well_formed(target):
    t, gt = bm.load_target(target)
    assert t["name"] == target
    ids = [g["id"] for g in gt["entries"]]
    assert len(ids) == len(set(ids))
    known = set(bm.CWE_CLASS.values()) | set(bm.FAMILY) | set(bm.FAMILY.values()) | {c for c, _ in bm.KEYWORDS}
    for g in gt["entries"]:
        assert g["severity"] in bm.SEV_WEIGHT, g
        assert set(g["classes"]) <= known, g
        for p in g.get("endpoints", []):
            __import__("re").compile(p)
    for host_ip, *_ in t.get("ports", []):
        assert host_ip == "127.0.0.1"                       # never expose a vulnerable app


def test_benchmark_up_needs_human():
    spec = importlib.util.spec_from_file_location("sc_bm", TOOLS / "scope-check.py")
    sc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sc)
    from scope import Scope
    c = sc.Checker(Scope(in_scope=["127.0.0.1"]), cwd=".", env={}, safe_prefixes=(),
                   allowed_hosts=sc.INFRA_HOSTS)
    c.check_command("python3 tools/benchmark.py up juice-shop")
    assert c.guards
    c2 = sc.Checker(Scope(in_scope=["127.0.0.1"]), cwd=".", env={}, safe_prefixes=(),
                    allowed_hosts=sc.INFRA_HOSTS)
    c2.check_command("python3 tools/benchmark.py score juice-shop tzar:WAPT/x/1")
    assert c2.guards == []
