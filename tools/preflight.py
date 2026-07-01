#!/usr/bin/env python3
"""
preflight.py — engagement tooling preflight & graceful-degradation matrix.

Probes whether the binaries an engagement type needs are present, whether root/
passwordless-sudo is available for tools that require it, and records the documented
fallback + dropped coverage for any gap. Run automatically by init-engagement.py; can
also be run standalone.

Usage:
  python3 tools/preflight.py check --type Network [--output-dir DIR] [--json]
  python3 tools/preflight.py --selftest

Writes <output-dir>/preflight.json when --output-dir is given.
Exit: 0 always for `check` (informational); 1 only on bad arguments.
"""
import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path

VALID_TYPES = ["WAPT", "MAPT", "API", "Network", "CodeReview",
               "Cloud", "RedTeam", "DFIR", "BugBounty"]

# tool -> metadata. needs_root: human description of the root-only feature (or None).
TOOL_META = {
    "nmap":      {"purpose": "port/service scanning + NSE",
                  "needs_root": "SYN scan (-sS) and UDP scan (-sU)",
                  "fallback": "TCP connect scan (-sT, no root) or tools/ python connect-scan; UDP scan NOT possible without root"},
    "masscan":   {"purpose": "fast port scanning", "needs_root": "raw sockets",
                  "fallback": "nmap -sT or python connect-scan"},
    "enum4linux-ng": {"purpose": "SMB/LDAP enumeration", "needs_root": None,
                  "fallback": "smbclient / rpcclient manual enumeration"},
    "smbclient": {"purpose": "SMB share access", "needs_root": None, "fallback": "impacket smbclient.py"},
    "snmpwalk":  {"purpose": "SNMP enumeration", "needs_root": None, "fallback": "onesixtyone + manual OIDs"},
    "ike-scan":  {"purpose": "IKE/VPN fingerprint", "needs_root": "raw sockets", "fallback": "manual UDP/500 probing (needs root)"},
    "curl":      {"purpose": "HTTP requests", "needs_root": None, "fallback": "python urllib / wget"},
    "ffuf":      {"purpose": "content/parameter fuzzing", "needs_root": None, "fallback": "gobuster / feroxbuster / dirb"},
    "gobuster":  {"purpose": "content discovery", "needs_root": None, "fallback": "ffuf / feroxbuster"},
    "nuclei":    {"purpose": "templated vuln scanning", "needs_root": None, "fallback": "manual checks + gen-nuclei-template.py"},
    "nikto":     {"purpose": "web server scanning", "needs_root": None, "fallback": "manual + nuclei"},
    "sqlmap":    {"purpose": "SQLi automation", "needs_root": None, "fallback": "manual injection testing"},
    "whatweb":   {"purpose": "tech fingerprint", "needs_root": None, "fallback": "wappalyzer / manual headers"},
    "wafw00f":   {"purpose": "WAF detection", "needs_root": None, "fallback": "manual header analysis"},
    "httpx":     {"purpose": "HTTP probing", "needs_root": None, "fallback": "curl loop"},
    "katana":    {"purpose": "crawling", "needs_root": None, "fallback": "hakrawler / gau"},
    "subfinder": {"purpose": "subdomain enum", "needs_root": None, "fallback": "amass / crt.sh"},
    "amass":     {"purpose": "asset discovery", "needs_root": None, "fallback": "subfinder / dnsx"},
    "dnsx":      {"purpose": "DNS resolution", "needs_root": None, "fallback": "dig loop"},
    "gau":       {"purpose": "URL harvesting", "needs_root": None, "fallback": "waybackurls"},
    "waybackurls": {"purpose": "URL harvesting", "needs_root": None, "fallback": "gau"},
    "adb":       {"purpose": "Android device bridge", "needs_root": None, "fallback": "(device required)"},
    "apktool":   {"purpose": "APK decode", "needs_root": None, "fallback": "jadx"},
    "jadx":      {"purpose": "APK decompile", "needs_root": None, "fallback": "apktool + dex2jar"},
    "frida":     {"purpose": "dynamic instrumentation", "needs_root": None, "fallback": "objection (needs frida-server)"},
    "objection": {"purpose": "mobile runtime testing", "needs_root": None, "fallback": "raw frida scripts"},
    "aws":       {"purpose": "AWS CLI", "needs_root": None, "fallback": "boto3 scripts"},
    "az":        {"purpose": "Azure CLI", "needs_root": None, "fallback": "REST API"},
    "gcloud":    {"purpose": "GCP CLI", "needs_root": None, "fallback": "REST API"},
    "kubectl":   {"purpose": "Kubernetes CLI", "needs_root": None, "fallback": "kube REST API"},
    "docker":    {"purpose": "container runtime", "needs_root": "daemon socket access", "fallback": "(group/sudo for docker.sock)"},
    "crackmapexec": {"purpose": "AD/network attack", "needs_root": None, "fallback": "nxc / impacket suite"},
    "responder": {"purpose": "LLMNR/NBT-NS poisoning", "needs_root": "raw sockets / privileged ports", "fallback": "(needs root)"},
    "volatility": {"purpose": "memory forensics", "needs_root": None, "fallback": "volatility3 module"},
    "binwalk":   {"purpose": "firmware/file carving", "needs_root": None, "fallback": "foremost / strings"},
    "foremost":  {"purpose": "file carving", "needs_root": None, "fallback": "binwalk / scalpel"},
    "semgrep":   {"purpose": "SAST", "needs_root": None, "fallback": "bandit / manual grep"},
    "trufflehog":{"purpose": "secret scanning", "needs_root": None, "fallback": "gitleaks / grep patterns"},
    "gitleaks":  {"purpose": "secret scanning", "needs_root": None, "fallback": "trufflehog"},
    "bandit":    {"purpose": "python SAST", "needs_root": None, "fallback": "semgrep"},
}

TYPE_TOOLS = {
    "Network":    {"critical": ["nmap"], "recommended": ["masscan", "enum4linux-ng", "smbclient", "snmpwalk", "ike-scan"]},
    "WAPT":       {"critical": ["curl"], "recommended": ["ffuf", "gobuster", "nuclei", "nikto", "sqlmap", "whatweb", "wafw00f", "httpx", "katana"]},
    "API":        {"critical": ["curl"], "recommended": ["nuclei", "ffuf", "httpx"]},
    "MAPT":       {"critical": [], "recommended": ["adb", "apktool", "jadx", "frida", "objection"]},
    "Cloud":      {"critical": [], "recommended": ["aws", "az", "gcloud", "kubectl", "docker"]},
    "RedTeam":    {"critical": [], "recommended": ["nmap", "crackmapexec", "responder", "smbclient"]},
    "DFIR":       {"critical": [], "recommended": ["volatility", "binwalk", "foremost"]},
    "CodeReview": {"critical": [], "recommended": ["semgrep", "trufflehog", "gitleaks", "bandit"]},
    "BugBounty":  {"critical": [], "recommended": ["subfinder", "amass", "dnsx", "httpx", "nuclei", "ffuf", "gau", "waybackurls", "katana"]},
}


def root_available():
    """Return (is_root, passwordless_sudo)."""
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    sudo = False
    if not is_root and shutil.which("sudo"):
        try:
            sudo = subprocess.run(["sudo", "-n", "true"], capture_output=True,
                                  timeout=5).returncode == 0
        except (subprocess.SubprocessError, OSError):
            sudo = False
    return is_root, sudo


def probe(eng_type):
    spec = TYPE_TOOLS.get(eng_type, {"critical": [], "recommended": []})
    is_root, sudo = root_available()
    root_ok = is_root or sudo
    rows, residual, missing_critical = [], [], []
    for tier in ("critical", "recommended"):
        for tool in spec[tier]:
            meta = TOOL_META.get(tool, {"purpose": "", "needs_root": None, "fallback": ""})
            present = shutil.which(tool) is not None
            status = "present"
            if not present:
                status = "MISSING"
                if tier == "critical":
                    missing_critical.append(tool)
                    residual.append({"area": tool, "reason": f"{tool} not installed (critical for {eng_type})",
                                     "fallback": meta["fallback"]})
                else:
                    residual.append({"area": tool, "reason": f"{tool} not installed",
                                     "fallback": meta["fallback"]})
            elif meta["needs_root"] and not root_ok:
                status = "DEGRADED (needs root)"
                residual.append({"area": f"{tool}: {meta['needs_root']}",
                                 "reason": "no root / passwordless-sudo",
                                 "fallback": meta["fallback"]})
            rows.append({"tool": tool, "tier": tier, "status": status,
                         "purpose": meta["purpose"], "needs_root": meta["needs_root"],
                         "fallback": meta["fallback"] if status != "present" else ""})
    return {
        "engagement_type": eng_type,
        "root": {"is_root": is_root, "passwordless_sudo": sudo, "root_capable": root_ok},
        "tools": rows,
        "missing_critical": missing_critical,
        "residual_coverage": residual,
    }


def cmd_check(args):
    if args.type not in VALID_TYPES:
        print(f"[!] unknown type {args.type!r}; valid: {', '.join(VALID_TYPES)}", file=sys.stderr)
        return 1
    result = probe(args.type)
    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "preflight.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    # human summary
    r = result["root"]
    rootmsg = ("root" if r["is_root"] else ("passwordless-sudo" if r["passwordless_sudo"]
               else "NO root / sudo"))
    print(f"  Preflight — {args.type} engagement   (privilege: {rootmsg})")
    for row in result["tools"]:
        mark = {"present": "✓", "MISSING": "✗"}.get(row["status"], "▲")
        tag = "" if row["status"] == "present" else f"  → {row['fallback']}"
        print(f"   {mark} {row['tool']:14s} [{row['tier']:11s}] {row['status']}{tag}")
    if result["missing_critical"]:
        print(f"  [!] CRITICAL tools missing: {', '.join(result['missing_critical'])}")
    if result["residual_coverage"]:
        print("  Residual coverage (record in report as follow-up):")
        for rc in result["residual_coverage"]:
            print(f"     - {rc['area']} — {rc['reason']} (fallback: {rc['fallback']})")
    return 0


def _selftest():
    res = probe("Network")
    assert res["engagement_type"] == "Network"
    assert any(t["tool"] == "nmap" for t in res["tools"]), "nmap not in Network spec"
    assert "root" in res and "root_capable" in res["root"]
    # every type probes without error
    for t in VALID_TYPES:
        probe(t)
    print("[+] preflight selftest OK")
    return 0


def main():
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true", help="run internal self-test")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("check", help="probe tooling for an engagement type")
    pc.add_argument("--type", required=True)
    pc.add_argument("--output-dir", default="")
    pc.add_argument("--json", action="store_true")
    pc.set_defaults(func=cmd_check)
    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
