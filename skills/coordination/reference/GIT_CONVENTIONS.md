# Git Conventions

## Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Engagement | `engagement/<client>-<date>` | `engagement/acme-20260603` |
| Feature/skill | `feat/<skill-name>` | `feat/api-security-v2` |
| Bug fix | `fix/<description>` | `fix/report-cvss-format` |
| Skill update | `skill/<skill-name>` | `skill/injection-waf-bypass` |

## Commit Message Format

```
<type>(<scope>): <short description>

<body — what changed and why, if non-obvious>
```

Types: `feat`, `fix`, `skill`, `report`, `docs`, `chore`

Examples:
```
skill(injection): add WAF bypass techniques for Cloudflare
feat(web-chain): add Phase 2 source-code-scanning conditional
fix(validator): check 3 now handles shell PoC scripts
report(acme): add executive summary and remediation roadmap
```

## Rules

- **Never commit**: `.env`, `*.key`, `*.pem`, credentials, raw evidence files containing PII
- **Always add** to `.gitignore`: `.env`, `*/evidence/*.png`, `*/evidence/*.mp4`, `output/`, `*.ndjson`
- **Tag on delivery**: `git tag -a report/acme-20260603 -m "Delivered pentest report to Acme Corp"`
- **One branch per engagement** — never mix engagement output with skill development
- **Commit findings as validated** — only commit finding-NNN/ after the validator approves it

## .gitignore Template

```
.env
*.key
*.pem
output/
*/evidence/
*.ndjson
__pycache__/
*.pyc
reports/*.pdf
```
