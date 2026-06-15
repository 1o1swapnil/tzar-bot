---
name: github-workflow
description: Git workflow for engagements — branching, committing findings, tagging reports, .gitignore
allowed-tools: [Bash, Read, Write]
---

# GitHub Workflow

See also: `skills/coordination/reference/GIT_CONVENTIONS.md`

## Engagement Setup

```bash
# Initialize repo (first engagement)
cd /home/kali/pentest-bot
git init
git remote add origin https://github.com/YOUR_ORG/pentest-bot.git

# Create engagement branch
git checkout -b engagement/client-name-$(date +%Y%m%d)
```

## .gitignore (create at project root)

```gitignore
# Never commit sensitive engagement data
.env
*.key
*.pem
*.p12
*.pfx

# Output directories (raw findings — share via secure channel)
*/evidence/
*/output/
*/recon/*.pcap

# Credential dumps
**/hashes.txt
**/credentials.txt
**/secretsdump*

# Generated files
__pycache__/
*.pyc
*.pyo
.DS_Store

# Reports (share encrypted PDFs separately)
**/reports/*.pdf
```

## Committing Validated Findings

```bash
# Only commit after validator approves
# Stage specific finding directory
git add skills/output/findings/finding-001/description.md
git add skills/output/findings/finding-001/poc.py
# Never: git add skills/output/findings/finding-001/evidence/

git commit -m "finding: add XSS in search parameter (High, finding-001)"
```

## Tagging Report Delivery

```bash
git tag -a "report/client-name-20260603" \
  -m "Delivered penetration test report to Client Name — 3 Critical, 5 High findings"
git push origin engagement/client-name-20260603 --tags
```

## Skill Updates

```bash
git checkout -b skill/injection-waf-bypass
# Edit skills/injection/SKILL.md
git add skills/injection/SKILL.md
git commit -m "skill(injection): add Cloudflare bypass patterns for chunked encoding"
git checkout main
git merge skill/injection-waf-bypass
```

## Pre-Push Checklist

```bash
# Check for accidentally staged sensitive files
git diff --cached --name-only | grep -E "\.env|credentials|hashes|secretsdump"
git status --short | grep -E "\.env|\.pem|\.key"
# If any match: git reset HEAD <file> && echo "REMOVED sensitive file"
```
