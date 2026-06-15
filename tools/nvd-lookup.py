#!/usr/bin/env python3
"""
nvd-lookup.py — Fetch CVE details from the NVD 2.0 API.
Usage: python3 tools/nvd-lookup.py CVE-2024-12345 [--api-key KEY]
       NVD_API_KEY=<key> python3 tools/nvd-lookup.py CVE-2024-12345

API key raises the rate limit from 5 req/10 s to 50 req/10 s.
Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
Store it as NVD_API_KEY in your .env file and env-reader.py will supply it.

Exit: 0 on success, 1 on error.
"""

import os
import sys
import json
import re
import time
import urllib.request
import urllib.error

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 10
RATE_LIMIT_WAIT_UNAUTH = 6   # 5 req/10 s without key
RATE_LIMIT_WAIT_AUTH   = 1   # 50 req/10 s with key
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def get_api_key(cli_key=None):
    """Return API key from CLI arg, then NVD_API_KEY env var, then None."""
    if cli_key:
        return cli_key.strip()
    return os.environ.get("NVD_API_KEY", "").strip() or None


def validate_cve_id(cve_id):
    cve_id = cve_id.strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID format: '{cve_id}'. Expected CVE-YYYY-NNNNN.")
    return cve_id


def fetch_cve(cve_id, api_key=None, retry=True):
    url = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"User-Agent": "pentest-bot/nvd-lookup"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(f"[ERROR] CVE not found: {cve_id}", file=sys.stderr)
            sys.exit(1)
        if exc.code == 429:
            if retry:
                wait = RATE_LIMIT_WAIT_AUTH if api_key else RATE_LIMIT_WAIT_UNAUTH
                print(f"[WARNING] Rate-limited. Retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
                return fetch_cve(cve_id, api_key=api_key, retry=False)
            print("[ERROR] Still rate-limited after retry.", file=sys.stderr)
            sys.exit(1)
        print(f"[ERROR] HTTP {exc.code}: {exc.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"[ERROR] Network error: {exc.reason}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("[ERROR] Malformed JSON response from NVD API.", file=sys.stderr)
        sys.exit(1)


def extract_cvss(metrics):
    for key, label in [("cvssMetricV31", "v3.1"), ("cvssMetricV30", "v3.0")]:
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return str(data.get("baseScore", "N/A")), data.get("baseSeverity", "N/A"), label
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0].get("cvssData", {})
        return str(data.get("baseScore", "N/A")), entries[0].get("baseSeverity", "N/A"), "v2.0"
    return "N/A", "N/A", "N/A"


def extract_description(descriptions):
    for item in descriptions:
        if item.get("lang") == "en":
            text = item.get("value", "").strip()
            return text[:497] + "..." if len(text) > 500 else text
    return "No description available."


def main():
    # Parse args: CVE-ID [--api-key KEY]
    args = sys.argv[1:]
    cli_key = None
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--api-key" and i + 1 < len(args):
            cli_key = args[i + 1]
            i += 2
        else:
            positional.append(args[i])
            i += 1

    if len(positional) != 1:
        print("Usage: python3 nvd-lookup.py CVE-YYYY-NNNNN [--api-key KEY]", file=sys.stderr)
        sys.exit(1)

    try:
        cve_id = validate_cve_id(positional[0])
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    api_key = get_api_key(cli_key)
    if api_key:
        print(f"[*] Using NVD API key (rate limit: 50 req/10 s)", file=sys.stderr)

    data = fetch_cve(cve_id, api_key=api_key)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(f"[ERROR] No data for {cve_id}", file=sys.stderr)
        sys.exit(1)

    cve = vulns[0].get("cve", {})
    published = cve.get("published", "N/A")[:10]
    score, severity, version = extract_cvss(cve.get("metrics", {}))
    description = extract_description(cve.get("descriptions", []))

    sep = "-" * 60
    print(sep)
    print(f"  CVE ID      : {cve_id}")
    print(f"  CVSS Score  : {score}  ({version})")
    print(f"  Severity    : {severity}")
    print(f"  Published   : {published}")
    print(sep)
    print(f"  Description :\n")
    words = description.split()
    line = "    "
    for word in words:
        if len(line) + len(word) + 1 > 74:
            print(line)
            line = "    " + word
        else:
            line += ("" if line == "    " else " ") + word
    if line.strip():
        print(line)
    print(sep)
    sys.exit(0)


if __name__ == "__main__":
    main()
