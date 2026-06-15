# CodeReview — Source Code Security Review

Security analysis of source code, dependencies, and infrastructure-as-code configurations.

## When to Use This Folder

- Static application security testing (SAST)
- Software composition analysis (SCA / dependency audit)
- SBOM (Software Bill of Materials) review
- Infrastructure-as-Code security (Terraform, CloudFormation, Helm)
- Secret scanning in repositories
- Code review for specific vulnerability classes
- Pre-deployment security gates

## Skills Used

`source-code-scanning` · `cve-risk-score` · `cve-poc-generator` · `essential-tools`

## Tools Required

```bash
semgrep --version         # SAST
trufflehog --version      # Secret scanning
gitleaks --version        # Git secret scanning
trivy --version           # Dependency + container scanning
bandit --version          # Python SAST
safety --version          # Python dependency audit
npm audit --help          # Node.js dependency audit
```

## Quick Start

```
# From repo URL:
"review the source code at https://github.com/org/repo for security issues"

# From local path:
"run code review on /path/to/project"

# From SAST output files:
"triage these semgrep findings: /path/to/semgrep.json"

# Dependency audit:
"check dependencies in /path/to/package.json for known CVEs"
```

## Output Structure

```
CodeReview/
└── <project-name>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/
        │   ├── semgrep.json          # SAST findings
        │   ├── trufflehog.json       # secrets found
        │   ├── trivy.json            # dependency CVEs
        │   └── normalized.json       # deduplicated findings
        ├── findings/
        ├── artifacts/
        │   └── dashboard.xlsx        # interactive Excel dashboard
        ├── logs/
        └── reports/Code-Review-Report.pdf
```

## Input Formats Accepted

SARIF · JSON · XML · CSV · HTML · CycloneDX · SPDX · Snyk JSON · Semgrep JSON · Trivy JSON · Gitleaks JSON · TruffleHog JSON · Checkmarx XML · Fortify FPR
