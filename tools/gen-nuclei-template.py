#!/usr/bin/env python3
"""
Generate a Nuclei v3 YAML detection template from CVE metadata + PoC details.

Usage:
    python3 tools/gen-nuclei-template.py \\
        --cve CVE-2024-1234 \\
        --severity critical \\
        --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \\
        --cvss-score 9.8 \\
        --cwe CWE-78 \\
        --description "Command injection in Foo <= 1.2.3 via the bar parameter." \\
        --path "/api/v1/exec" \\
        --method POST \\
        --body '{"cmd": "{{cmd}}"}' \\
        --match-word "root:x:0" \\
        --match-status 200 \\
        --tags rce,injection,foo \\
        --output OUTPUT_DIR/tools/CVE-2024-1234/nuclei-template.yaml

    # Minimal (HTTP GET, word match only):
    python3 tools/gen-nuclei-template.py \\
        --cve CVE-2024-5678 --severity high --description "Path traversal in Bar." \\
        --path "/download?file=../../etc/passwd" --match-word "root:x:0"

Reads NVD lookup JSON from OUTPUT_DIR/tools/CVE-ID/nvd.json when available to
auto-fill description, CVSS, and CWE fields.
"""
import argparse
import json
import os
import re
import sys
import textwrap


SEVERITY_MAP = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "info": 0.0}

TEMPLATE = """\
id: {cve_id_lower}

info:
  name: {name}
  author: tzar-bot
  severity: {severity}
  description: {description}
  reference:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
  classification:
    cvss-metrics: {cvss_metrics}
    cvss-score: {cvss_score}
    cve-id: {cve_id}
    cwe-id: {cwe}
  metadata:
    max-request: 1
  tags: cve,{year_tag},{tags}

http:
  - method: {method}
    path:
      - "{base_url}{path}"
{body_block}
    headers:
      User-Agent: Mozilla/5.0 (compatible; tzar-bot/1.0)
{content_type_header}
    matchers-condition: and
    matchers:
{matchers}
"""

BODY_BLOCK = """\
    body: '{body}'
"""

CONTENT_TYPE_HEADER = """\
      Content-Type: application/json
"""

WORD_MATCHER = """\
      - type: word
        part: body
        words:
          - "{word}"
"""

STATUS_MATCHER = """\
      - type: status
        status:
          - {status}
"""

REGEX_MATCHER = """\
      - type: regex
        part: body
        regex:
          - "{regex}"
"""


def slugify(cve_id: str) -> str:
    return cve_id.lower().replace("_", "-")


def year_from_cve(cve_id: str) -> str:
    m = re.search(r"CVE-(\d{4})-", cve_id, re.I)
    return f"cve{m.group(1)}" if m else "cve"


def load_nvd_json(cve_id: str, output_dir: str) -> dict:
    path = os.path.join(output_dir, "tools", cve_id, "nvd.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def build_name(cve_id: str, description: str) -> str:
    # Derive a short name from the description — first 80 chars, strip trailing punctuation
    short = description[:80].rstrip(".!,; ")
    return short if short else cve_id


def main():
    parser = argparse.ArgumentParser(description="Generate Nuclei v3 CVE detection template")
    parser.add_argument("--cve", required=True, help="CVE ID (e.g. CVE-2024-1234)")
    parser.add_argument("--severity", default="medium",
                        choices=["critical", "high", "medium", "low", "info"])
    parser.add_argument("--cvss", default="", help="CVSS v3.1 vector string")
    parser.add_argument("--cvss-score", type=float, default=0.0)
    parser.add_argument("--cwe", default="CWE-0", help="CWE ID")
    parser.add_argument("--description", default="", help="Short vulnerability description")
    parser.add_argument("--path", default="/", help="Vulnerable URL path")
    parser.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    parser.add_argument("--body", default="", help="Request body (POST/PUT)")
    parser.add_argument("--match-word", action="append", dest="match_words", default=[],
                        help="Word to match in response body (repeatable)")
    parser.add_argument("--match-regex", action="append", dest="match_regexes", default=[],
                        help="Regex to match in response body (repeatable)")
    parser.add_argument("--match-status", type=int, default=200)
    parser.add_argument("--tags", default="detection", help="Comma-separated tags")
    parser.add_argument("--output", default="", help="Output file path (default: stdout)")
    parser.add_argument("--output-dir", default=".", help="Engagement OUTPUT_DIR for NVD JSON lookup")
    args = parser.parse_args()

    cve_id = args.cve.upper()

    # Try to fill from NVD JSON if description/cvss not provided
    nvd = load_nvd_json(cve_id, args.output_dir)
    description = args.description or nvd.get("description", f"Detection probe for {cve_id}")
    cvss_metrics = args.cvss or nvd.get("cvssV31Vector", nvd.get("cvssV30Vector", "N/A"))
    cvss_score = args.cvss_score or nvd.get("cvssV31Score", nvd.get("baseScore", 0.0))
    cwe = args.cwe if args.cwe != "CWE-0" else nvd.get("cwe", "CWE-0")

    # Matchers block
    matcher_lines = []
    for word in args.match_words:
        matcher_lines.append(WORD_MATCHER.format(word=word))
    for regex in args.match_regexes:
        matcher_lines.append(REGEX_MATCHER.format(regex=regex))
    if args.match_status:
        matcher_lines.append(STATUS_MATCHER.format(status=args.match_status))

    if not matcher_lines:
        print("[!] Warning: no matchers specified — template will match any response", file=sys.stderr)
        matcher_lines.append(STATUS_MATCHER.format(status=200))

    matchers = "".join(matcher_lines).rstrip()

    body_block = BODY_BLOCK.format(body=args.body) if args.body else ""
    content_type = CONTENT_TYPE_HEADER if args.body else ""

    # Ensure path starts with /
    path = args.path if args.path.startswith("/") else f"/{args.path}"

    result = TEMPLATE.format(
        cve_id=cve_id,
        cve_id_lower=slugify(cve_id),
        name=build_name(cve_id, description),
        severity=args.severity,
        description=textwrap.fill(description, 100).replace("\n", " "),
        cvss_metrics=cvss_metrics,
        cvss_score=cvss_score,
        cwe=cwe,
        year_tag=year_from_cve(cve_id),
        tags=args.tags,
        method=args.method.upper(),
        base_url="{{BaseURL}}",
        path=path,
        body_block=body_block,
        content_type_header=content_type,
        matchers=matchers,
    )

    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w") as f:
            f.write(result)
        print(f"[+] Template written: {args.output}", file=sys.stderr)
    else:
        print(result)


if __name__ == "__main__":
    main()
