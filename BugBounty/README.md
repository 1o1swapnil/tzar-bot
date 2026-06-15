# BugBounty — Bug Bounty Programs

Automated and manual bug bounty hunting on HackerOne, Bugcrowd, and private programs.

## When to Use This Folder

- HackerOne program submissions
- Bugcrowd program submissions
- Private bug bounty programs
- Vulnerability Disclosure Programs (VDP)
- CTF competitions (web/API challenges)

## Skills Used

`hackerone` · `web-chain` · `api-security` · `reconnaissance` · `osint`

## Credentials Required

```bash
python3 tools/env-reader.py HACKERONE_TOKEN HACKERONE_USERNAME BUGCROWD_TOKEN
```

## Quick Start

```
# HackerOne program:
"start bug bounty hunt on HackerOne program: target-program-handle"

# Specific scope:
"test https://target.com for bug bounty — it's in scope for the acme H1 program"

# CTF:
"this is a CTF challenge at https://ctf.example.com — find the flag"
```

## IMPORTANT: Scope Validation

**ALWAYS check program scope before testing.**

```bash
# Fetch scope from HackerOne API before any testing:
python3 tools/env-reader.py HACKERONE_TOKEN
curl -s "https://api.hackerone.com/v1/hackers/programs/PROGRAM" \
  --user "USERNAME:TOKEN" | jq '.relationships.structured_scopes.data[]'
```

**If the target is NOT in scope: DO NOT test it.**

## Output Structure

```
BugBounty/
└── <program-name>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/
        ├── findings/
        │   └── finding-001/
        │       ├── description.md    # H1-formatted report
        │       ├── poc.py
        │       └── evidence/
        ├── submissions/
        │   └── H1-report-001.md      # submitted report (markdown)
        ├── screenshots/
        ├── logs/
        └── reports/BugBounty-Summary.md
```

## Severity → Bounty Estimate

| CVSS | Severity | Typical H1 Bounty |
|------|----------|-------------------|
| 9.0+ | Critical | $5,000 – $50,000+ |
| 7.0–8.9 | High | $1,000 – $10,000 |
| 4.0–6.9 | Medium | $200 – $2,000 |
| 0.1–3.9 | Low | $50 – $500 |
| N/A | Info | $0 |

## H1 Report Template

See `skills/hackerone/SKILL.md` for the full submission format and API integration.
