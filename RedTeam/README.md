# RedTeam — Red Team Engagements

Full-scope adversary simulation including phishing, C2, lateral movement, and objective-based operations.

## When to Use This Folder

- Full red team engagements (assume-breach or external)
- Purple team exercises
- Phishing simulation campaigns
- Social engineering assessments
- C2 infrastructure testing
- Adversary simulation (MITRE ATT&CK-aligned)
- Physical security testing (authorized)

## Skills Used

`social-engineering` · `reconnaissance` · `osint` · `infrastructure` · `system` · `cloud-containers`

## Authorization Required

**ALWAYS verify written authorization before any red team activity:**

```bash
cat OUTPUT_DIR/artifacts/engagement-auth.txt
# Must contain: client name, scope, SE authorization (if applicable), dates, emergency contact
```

## Quick Start

```
# Phishing campaign:
"run phishing simulation for client acme-corp, targets in OUTPUT_DIR/artifacts/targets.csv"

# Full red team:
"begin red team engagement against acme-corp, scope: acme.com and 203.0.113.0/24"
```

## Output Structure

```
RedTeam/
└── <client-name>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/
        │   ├── osint-employees.txt   # from LinkedIn/theHarvester
        │   └── infrastructure.txt    # external attack surface
        ├── phishing/
        │   ├── campaign-results/     # GoPhish export
        │   ├── templates/            # email templates used
        │   └── landing-pages/        # credential harvest pages
        ├── c2/
        │   ├── implants/             # NEVER commit to git
        │   └── beacons/
        ├── findings/
        ├── screenshots/
        ├── logs/
        └── reports/Red-Team-Report.pdf
```

## MITRE ATT&CK Alignment

Document all TTPs used in `attack-chain.md` with ATT&CK technique IDs:
- `T1566.001` — Spearphishing Attachment
- `T1078` — Valid Accounts  
- `T1021.002` — Remote Services: SMB/Windows Admin Shares
- `T1003.001` — OS Credential Dumping: LSASS Memory
