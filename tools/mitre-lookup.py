#!/usr/bin/env python3
"""
mitre-lookup.py — Local MITRE ATT&CK lookup across Enterprise, Mobile and ICS (OT).

Backed by the official MITRE ATT&CK STIX data (github.com/mitre-attack/attack-stix-data),
distilled into a compact offline index under data/mitre/. Works offline after one `update`.

Usage:
  python3 tools/mitre-lookup.py update [--matrix all|enterprise|mobile|ics]
  python3 tools/mitre-lookup.py lookup T1133 [--matrix all]
  python3 tools/mitre-lookup.py search "ssl vpn" [--matrix enterprise] [--limit 10]
  python3 tools/mitre-lookup.py tactic credential-access [--matrix mobile]
  python3 tools/mitre-lookup.py map "override portal exposed over cleartext http" [--limit 8]
  python3 tools/mitre-lookup.py tactics [--matrix all]
  python3 tools/mitre-lookup.py stats
  (add --json to any read command for machine-readable output)

Exit: 0 on success, 1 on error.
"""
import os
import re
import sys
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_DIR / "data" / "mitre"

MATRICES = {
    "enterprise": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "kill_chain": "mitre-attack",
        "src": "mitre-attack",
    },
    "mobile": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
        "kill_chain": "mitre-mobile-attack",
        "src": "mitre-attack",
    },
    "ics": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
        "kill_chain": "mitre-ics-attack",
        "src": "mitre-attack",
    },
}
TIMEOUT = 120
STOPWORDS = set("the a an of to in on for and or is are be by with via from at as it its "
                "that this an over no not can could may attacker attack target system user "
                "vulnerability via using able without".split())


# ── distill (update) ──────────────────────────────────────────────────────
def _tech_id(obj, src):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == src and ref.get("external_id", "").startswith("T"):
            return ref.get("external_id"), ref.get("url", "")
    return None, ""

def distill(bundle, matrix):
    """Turn a STIX bundle into a list of compact technique dicts."""
    cfg = MATRICES[matrix]
    out = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid, url = _tech_id(obj, cfg["src"])
        if not tid:
            continue
        tactics = [ph["phase_name"] for ph in obj.get("kill_chain_phases", [])
                   if ph.get("kill_chain_name") == cfg["kill_chain"]]
        out.append({
            "id": tid,
            "name": obj.get("name", ""),
            "matrix": matrix,
            "tactics": tactics,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent": tid.split(".")[0] if "." in tid else None,
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": (obj.get("x_mitre_detection", "") or "").strip(),
            "description": (obj.get("description", "") or "").strip(),
            "url": url,
        })
    out.sort(key=lambda t: t["id"])
    return out

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "tzar-bot-mitre-lookup"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))

def cmd_update(args):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    targets = list(MATRICES) if args.matrix == "all" else [args.matrix]
    total = 0
    for m in targets:
        print(f"[*] Fetching {m} ATT&CK STIX …", flush=True)
        try:
            bundle = fetch(MATRICES[m]["url"])
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            print(f"[!] {m}: download/parse failed: {e}", file=sys.stderr)
            continue
        techs = distill(bundle, m)
        (DATA_DIR / f"{m}.json").write_text(json.dumps(techs, indent=1), encoding="utf-8")
        ver = bundle.get("objects", [{}])
        print(f"[+] {m}: {len(techs)} techniques -> data/mitre/{m}.json")
        total += len(techs)
    print(f"[+] Done. {total} techniques across {len(targets)} matrix(es).")
    return 0


# ── load ──────────────────────────────────────────────────────────────────
def load(matrix="all"):
    names = list(MATRICES) if matrix == "all" else [matrix]
    techs = []
    missing = []
    for m in names:
        f = DATA_DIR / f"{m}.json"
        if f.exists():
            techs.extend(json.loads(f.read_text(encoding="utf-8")))
        else:
            missing.append(m)
    if missing:
        print(f"[!] No local data for: {', '.join(missing)}. Run: "
              f"python3 tools/mitre-lookup.py update --matrix all", file=sys.stderr)
    return techs


# ── presentation ──────────────────────────────────────────────────────────
def _tok(text):
    return [w for w in re.findall(r"[a-z0-9]+", text.lower())
            if w not in STOPWORDS and len(w) > 2]

def print_tech(t, full=False):
    sub = " (sub-technique of %s)" % t["parent"] if t.get("is_subtechnique") else ""
    print(f"  {t['id']:10s} [{t['matrix']:10s}] {t['name']}{sub}")
    if t["tactics"]:
        print(f"     Tactics : {', '.join(t['tactics'])}")
    if full:
        if t["platforms"]:
            print(f"     Platforms: {', '.join(t['platforms'])}")
        if t["description"]:
            d = re.sub(r"\s+", " ", t["description"])[:600]
            print(f"     Desc    : {d}")
        if t["detection"]:
            d = re.sub(r"\s+", " ", t["detection"])[:400]
            print(f"     Detect  : {d}")
        if t["url"]:
            print(f"     URL     : {t['url']}")

def _emit(args, payload, human):
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
    else:
        human()


# ── commands ──────────────────────────────────────────────────────────────
def cmd_lookup(args):
    techs = load(args.matrix)
    tid = args.technique.upper()
    hits = [t for t in techs if t["id"] == tid]
    if not hits:
        print(f"[!] {tid} not found in {args.matrix}. (Sub-technique? try the full Txxxx.yyy id.)",
              file=sys.stderr)
        return 1
    def human():
        for t in hits:
            print_tech(t, full=True)
            subs = [s for s in techs if s.get("parent") == t["id"] and s["id"] != t["id"]]
            if subs:
                print(f"     Sub-techniques: {', '.join(s['id'] for s in subs)}")
    _emit(args, hits, human)
    return 0

def _score(query_tokens, t):
    hay = set(_tok(t["name"]) * 3 + _tok(t["description"]))
    return len(query_tokens & hay)

def cmd_search(args):
    techs = load(args.matrix)
    q = set(_tok(" ".join(args.terms)))
    scored = [(s, t) for t in techs if (s := _score(q, t)) > 0]
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    top = [t for _, t in scored[:args.limit]]
    def human():
        if not top:
            print("  (no matches)"); return
        print(f"  Top {len(top)} matches for: {' '.join(args.terms)}")
        for t in top:
            print_tech(t)
    _emit(args, top, human)
    return 0

def cmd_map(args):
    """Suggest ATT&CK techniques for a free-text finding description."""
    techs = load(args.matrix)
    q = set(_tok(args.text))
    scored = [(s, t) for t in techs if (s := _score(q, t)) > 0]
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    top = [{"id": t["id"], "name": t["name"], "matrix": t["matrix"],
            "tactics": t["tactics"], "score": s, "url": t["url"]}
           for s, t in scored[:args.limit]]
    def human():
        if not top:
            print("  (no candidate techniques — try richer wording)"); return
        print(f"  Candidate ATT&CK techniques for the finding:")
        for r in top:
            print(f"  {r['id']:10s} [{r['matrix']:10s}] {r['name']}  "
                  f"(tactics: {', '.join(r['tactics']) or '-'})")
    _emit(args, top, human)
    return 0

def cmd_tactic(args):
    techs = load(args.matrix)
    want = args.tactic.lower().replace(" ", "-")
    hits = [t for t in techs if want in [x.lower() for x in t["tactics"]]]
    hits.sort(key=lambda t: t["id"])
    def human():
        print(f"  {len(hits)} techniques in tactic '{want}' ({args.matrix}):")
        for t in hits:
            print_tech(t)
    _emit(args, hits, human)
    return 0

def cmd_tactics(args):
    techs = load(args.matrix)
    by = {}
    for t in techs:
        for ph in t["tactics"]:
            by.setdefault((t["matrix"], ph), 0)
            by[(t["matrix"], ph)] += 1
    rows = sorted(by.items())
    def human():
        cur = None
        for (mtx, ph), c in rows:
            if mtx != cur:
                print(f"\n  [{mtx}]"); cur = mtx
            print(f"     {ph:28s} {c}")
    _emit(args, [{"matrix": m, "tactic": p, "techniques": c} for (m, p), c in rows], human)
    return 0

def cmd_stats(args):
    payload = {}
    for m in MATRICES:
        f = DATA_DIR / f"{m}.json"
        if f.exists():
            d = json.loads(f.read_text(encoding="utf-8"))
            payload[m] = {"techniques": len([x for x in d if not x["is_subtechnique"]]),
                          "sub_techniques": len([x for x in d if x["is_subtechnique"]]),
                          "total": len(d)}
        else:
            payload[m] = {"error": "not downloaded — run update"}
    def human():
        print("  MITRE ATT&CK local index:")
        for m, s in payload.items():
            if "error" in s:
                print(f"     {m:11s} {s['error']}")
            else:
                print(f"     {m:11s} {s['total']:4d} total "
                      f"({s['techniques']} techniques + {s['sub_techniques']} sub)")
    _emit(args, payload, human)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    pu = sub.add_parser("update", help="download + distill STIX")
    pu.add_argument("--matrix", default="all", choices=["all", *MATRICES])
    pu.set_defaults(func=cmd_update)

    def add_common(p):
        p.add_argument("--matrix", default="all", choices=["all", *MATRICES])
        p.add_argument("--json", action="store_true", help="machine-readable output")

    pl = sub.add_parser("lookup", help="technique by ID (Txxxx[.yyy])")
    pl.add_argument("technique"); add_common(pl); pl.set_defaults(func=cmd_lookup)

    ps = sub.add_parser("search", help="keyword search")
    ps.add_argument("terms", nargs="+"); ps.add_argument("--limit", type=int, default=12)
    add_common(ps); ps.set_defaults(func=cmd_search)

    pm = sub.add_parser("map", help="suggest techniques for a finding description")
    pm.add_argument("text"); pm.add_argument("--limit", type=int, default=8)
    add_common(pm); pm.set_defaults(func=cmd_map)

    pt = sub.add_parser("tactic", help="techniques in a tactic")
    pt.add_argument("tactic"); add_common(pt); pt.set_defaults(func=cmd_tactic)

    pts = sub.add_parser("tactics", help="list tactics + counts")
    add_common(pts); pts.set_defaults(func=cmd_tactics)

    pst = sub.add_parser("stats", help="local index stats")
    add_common(pst); pst.set_defaults(func=cmd_stats)

    args = ap.parse_args()
    try:
        sys.exit(args.func(args))
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    main()
