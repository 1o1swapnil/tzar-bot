# WAPT — Web Application Penetration Testing

Tests targeting web applications, portals, SaaS platforms, web services, and HTTP-based systems.

## When to Use This Folder

- Web application pentests (blackbox, graybox, whitebox)
- OWASP Top 10 assessments
- Web portal security reviews
- E-commerce platform testing
- SaaS application assessments
- Login/authentication bypass testing

## Skills Used

`web-chain` (full auto) · `reconnaissance` · `osint` · `techstack-identification` · `authentication` · `injection` · `server-side` · `client-side` · `api-security` · `web-app-logic`

## Quick Start

```
# Full autonomous 6-phase web pentest:
run web chain on https://target.com

# Or scoped:
run web chain on https://target.com --mode graybox --scope target.com,api.target.com
```

## Output Structure

```
WAPT/
└── <project-name>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/
        ├── findings/finding-NNN/
        ├── screenshots/
        ├── logs/
        ├── artifacts/validated/
        └── reports/Penetration-Test-Report.pdf
```

## Project Naming Convention

Use lowercase with hyphens: `acme-corp`, `client-portal-v2`, `staging-env`
