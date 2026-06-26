#!/usr/bin/env python3
"""
atomic-red.py — Local Atomic Red Team (Red Canary) lookup, keyed by MITRE ATT&CK technique.

Surfaces atomic detection-validation tests from the redcanaryco/atomic-red-team library,
distilled into a compact offline index under data/atomic-red/index.json. Read commands are
stdlib-only and work offline; `update` (re-fetch/distill) needs PyYAML.

READ-ONLY: this tool lists and displays atomic tests and their commands. It does NOT execute
them. Atomic tests run real adversary TTPs — execute only in an authorized lab via Red Canary's
`Invoke-AtomicRedTeam` framework, never from this tool.

Usage:
  python3 tools/atomic-red.py update                       # fetch + distill (needs PyYAML)
  python3 tools/atomic-red.py lookup T1133                 # tests for a technique
  python3 tools/atomic-red.py search "vpn"                 # search by name/description
  python3 tools/atomic-red.py show T1133 --test 1          # full detail incl command + cleanup
  python3 tools/atomic-red.py map "ssl vpn exposed" [--limit 5]   # finding -> technique -> atomic tests
  python3 tools/atomic-red.py stats
  (--platform windows|linux|macos to filter; --json for machine-readable output)

Exit: 0 on success, 1 on error.
"""
import os
import re
import sys
import json
import argparse
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).resolve().parent
DATA_DIR = REPO_DIR / "data" / "atomic-red"
INDEX = DATA_DIR / "index.json"
INDEX_URL = ("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
             "master/atomics/Indexes/index.yaml")
TIMEOUT = 180
PLAT_ALIASES = {"macos": "macos", "mac": "macos", "osx": "macos",
                "windows": "windows", "win": "windows",
                "linux": "linux", "nix": "linux"}


# ── update (fetch + distill) ───────────────────────────────────────────────
def cmd_update(args):
    try:
        import yaml  # noqa
    except ImportError:
        print("[!] update needs PyYAML. Install it (e.g. in a venv): pip install pyyaml\n"
              "    Read commands (lookup/search/show/stats) work offline without it.",
              file=sys.stderr)
        return 1
    print(f"[*] Fetching Atomic Red Team index … ({INDEX_URL})", flush=True)
    try:
        raw = urllib.request.urlopen(
            urllib.request.Request(INDEX_URL, headers={"User-Agent": "tzar-bot-atomic-red"}),
            timeout=TIMEOUT).read()
        data = yaml.safe_load(raw)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[!] download failed: {e}", file=sys.stderr); return 1

    techniques = {}
    for tactic, techs in (data or {}).items():
        for tid, body in (techs or {}).items():
            entry = techniques.setdefault(tid, {
                "id": tid,
                "display_name": (body.get("technique") or {}).get("name", ""),
                "tactics": [],
                "tests": [],
                "_guids": set(),
            })
            if tactic not in entry["tactics"]:
                entry["tactics"].append(tactic)
            for t in body.get("atomic_tests", []) or []:
                guid = t.get("auto_generated_guid", "")
                if guid and guid in entry["_guids"]:
                    continue
                entry["_guids"].add(guid)
                ex = t.get("executor", {}) or {}
                entry["tests"].append({
                    "name": t.get("name", ""),
                    "guid": guid,
                    "description": re.sub(r"\s+", " ", (t.get("description") or "")).strip()[:500],
                    "platforms": t.get("supported_platforms", []) or [],
                    "executor": ex.get("name", ""),
                    "elevation_required": bool(ex.get("elevation_required")),
                    "command": (ex.get("command") or "").strip(),
                    "cleanup": (ex.get("cleanup_command") or "").strip(),
                })
    # finalise (drop helper sets)
    out = {}
    for tid, e in techniques.items():
        e.pop("_guids", None)
        out[tid] = e
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(json.dumps(out, indent=1, sort_keys=True), encoding="utf-8")
    ntests = sum(len(e["tests"]) for e in out.values())
    print(f"[+] {len(out)} techniques, {ntests} atomic tests -> data/atomic-red/index.json")
    return 0


# ── load ───────────────────────────────────────────────────────────────────
def load():
    if not INDEX.exists():
        print("[!] No local index. Run: python3 tools/atomic-red.py update  (needs PyYAML)",
              file=sys.stderr)
        return {}
    return json.loads(INDEX.read_text(encoding="utf-8"))

def _plat_ok(test, plat):
    if not plat:
        return True
    return PLAT_ALIASES.get(plat, plat) in [p.lower() for p in test.get("platforms", [])]

def _filter_tests(entry, plat):
    return [t for t in entry.get("tests", []) if _plat_ok(t, plat)]


# ── presentation ───────────────────────────────────────────────────────────
def _emit(args, payload, human):
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
    else:
        human()

def _print_test_line(i, t):
    elev = " [elevation]" if t["elevation_required"] else ""
    plats = ",".join(t["platforms"])
    print(f"   {i}. {t['name']}  ({plats}; {t['executor']}{elev})")


# ── commands ───────────────────────────────────────────────────────────────
def cmd_lookup(args):
    idx = load()
    tid = args.technique.upper()
    e = idx.get(tid)
    if not e:
        print(f"[!] No atomic tests indexed for {tid}.", file=sys.stderr)
        return 1
    tests = _filter_tests(e, args.platform)
    payload = {**{k: e[k] for k in ("id", "display_name", "tactics")}, "tests": tests}
    def human():
        print(f"  {tid} — {e['display_name']}  (tactics: {', '.join(e['tactics'])})")
        print(f"  {len(tests)} atomic test(s)" + (f" on {args.platform}" if args.platform else "") + ":")
        for i, t in enumerate(tests, 1):
            _print_test_line(i, t)
        print("  (use 'show %s --test N' for the command; execute only in an authorized lab)" % tid)
    _emit(args, payload, human)
    return 0

def cmd_search(args):
    idx = load()
    q = args.terms if isinstance(args.terms, str) else " ".join(args.terms)
    ql = q.lower()
    hits = []
    for tid, e in idx.items():
        for t in _filter_tests(e, args.platform):
            if ql in t["name"].lower() or ql in t["description"].lower():
                hits.append({"technique": tid, "display_name": e["display_name"], **t})
    hits = hits[:args.limit]
    def human():
        if not hits:
            print("  (no matching atomic tests)"); return
        print(f"  {len(hits)} atomic test(s) matching '{q}':")
        for h in hits:
            elev = " [elevation]" if h["elevation_required"] else ""
            print(f"   {h['technique']:10s} {h['name']}  ({','.join(h['platforms'])}; {h['executor']}{elev})")
    _emit(args, hits, human)
    return 0

def cmd_show(args):
    idx = load()
    tid = args.technique.upper()
    e = idx.get(tid)
    if not e:
        print(f"[!] No atomic tests indexed for {tid}.", file=sys.stderr); return 1
    tests = e["tests"]
    sel = None
    if args.guid:
        sel = next((t for t in tests if t["guid"] == args.guid), None)
    elif args.test:
        if 1 <= args.test <= len(tests):
            sel = tests[args.test - 1]
    if not sel:
        print(f"[!] pick a test: 1..{len(tests)} via --test, or --guid <id>", file=sys.stderr)
        for i, t in enumerate(tests, 1):
            _print_test_line(i, t)
        return 1
    def human():
        print(f"  {tid} — {e['display_name']}")
        print(f"  Test : {sel['name']}")
        print(f"  GUID : {sel['guid']}")
        print(f"  Plat : {', '.join(sel['platforms'])}   Executor: {sel['executor']}"
              + ("   [requires elevation]" if sel["elevation_required"] else ""))
        if sel["description"]:
            print(f"  Desc : {sel['description']}")
        print("\n  ── Command (REVIEW; run only in an authorized lab via Invoke-AtomicRedTeam) ──")
        print("  " + sel["command"].replace("\n", "\n  "))
        if sel["cleanup"]:
            print("\n  ── Cleanup ──")
            print("  " + sel["cleanup"].replace("\n", "\n  "))
    _emit(args, sel, human)
    return 0

def cmd_map(args):
    """Cross-link: map a finding -> ATT&CK technique IDs (via mitre-lookup) -> atomic tests."""
    idx = load()
    mitre = TOOLS_DIR / "mitre-lookup.py"
    tids = []
    if mitre.exists():
        try:
            r = subprocess.run([sys.executable, str(mitre), "map", "--limit", str(args.limit),
                                "--json", "--", args.text],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                tids = [x["id"] for x in json.loads(r.stdout)]
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
            pass
    if not tids:
        print("[!] could not map finding to techniques (is the MITRE index built? "
              "run: python3 tools/mitre-lookup.py update --matrix all)", file=sys.stderr)
        return 1
    result = []
    for tid in tids:
        # atomics index has no sub-technique granularity for some; try exact then parent
        e = idx.get(tid) or idx.get(tid.split(".")[0])
        tests = _filter_tests(e, args.platform) if e else []
        result.append({"technique": tid, "display_name": e["display_name"] if e else "",
                       "atomic_tests": [{"name": t["name"], "guid": t["guid"],
                                         "platforms": t["platforms"], "executor": t["executor"]}
                                        for t in tests]})
    def human():
        print(f"  Finding -> ATT&CK techniques -> Atomic Red Team tests:")
        for r in result:
            n = len(r["atomic_tests"])
            print(f"\n  {r['technique']:10s} {r['display_name']}  — {n} atomic test(s)")
            for t in r["atomic_tests"]:
                print(f"      • {t['name']}  ({','.join(t['platforms'])}; {t['executor']})")
        print("\n  Validate detections for these techniques in an authorized lab "
              "(Invoke-AtomicTest <Txxxx>).")
    _emit(args, result, human)
    return 0

def cmd_stats(args):
    if not INDEX.exists():
        payload = {"error": "not downloaded — run: python3 tools/atomic-red.py update"}
        _emit(args, payload, lambda: print("  " + payload["error"]))
        return 0
    idx = load()
    ntests = sum(len(e["tests"]) for e in idx.values())
    by_plat = {}
    for e in idx.values():
        for t in e["tests"]:
            for p in t["platforms"]:
                by_plat[p] = by_plat.get(p, 0) + 1
    payload = {"techniques": len(idx), "atomic_tests": ntests, "by_platform": by_plat}
    def human():
        print("  Atomic Red Team local index:")
        print(f"     techniques   : {payload['techniques']}")
        print(f"     atomic tests : {payload['atomic_tests']}")
        for p, c in sorted(by_plat.items(), key=lambda x: -x[1]):
            print(f"       {p:14s} {c}")
    _emit(args, payload, human)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    pu = sub.add_parser("update", help="download + distill the atomics index (needs PyYAML)")
    pu.set_defaults(func=cmd_update)

    def common(p, platform=True):
        if platform:
            p.add_argument("--platform", default="", help="windows|linux|macos filter")
        p.add_argument("--json", action="store_true", help="machine-readable output")

    pl = sub.add_parser("lookup", help="atomic tests for a technique ID")
    pl.add_argument("technique"); common(pl); pl.set_defaults(func=cmd_lookup)

    ps = sub.add_parser("search", help="search tests by name/description")
    ps.add_argument("terms", nargs="+"); ps.add_argument("--limit", type=int, default=20)
    common(ps); ps.set_defaults(func=cmd_search)

    psh = sub.add_parser("show", help="full test detail incl. command + cleanup")
    psh.add_argument("technique"); psh.add_argument("--test", type=int, help="test number (1-based)")
    psh.add_argument("--guid", help="select test by GUID")
    common(psh); psh.set_defaults(func=cmd_show)

    pf = sub.add_parser("map", help="map a finding -> techniques -> atomic tests")
    pf.add_argument("text"); pf.add_argument("--limit", type=int, default=5)
    common(pf); pf.set_defaults(func=cmd_map)

    pst = sub.add_parser("stats", help="local index stats")
    common(pst, platform=False); pst.set_defaults(func=cmd_stats)

    args = ap.parse_args()
    try:
        sys.exit(args.func(args))
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    main()
