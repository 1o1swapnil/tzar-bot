---
name: skill-update
description: Update skills based on engagement learnings — capture what worked, fix what failed
allowed-tools: [Bash, Read, Write]
---

# Skill Update

Called with `/skill-update` after an engagement, or when a technique is discovered to work or fail.

## When to Call

- After completing an engagement (capture learnings)
- When a new bypass technique is discovered
- When a tool produces unexpected results that need documenting
- When a SKILL.md instruction is found to be incorrect or incomplete

## Update Workflow

### 1. Identify What Changed

```bash
# Review engagement logs for what worked
grep '"result": "vulnerable"' OUTPUT_DIR/logs/*.ndjson | jq '.action, .detail'

# Review what failed (to avoid repeating)
grep '"result": "negative"' OUTPUT_DIR/logs/*.ndjson | jq '.action, .detail'

# Check validator feedback
cat OUTPUT_DIR/artifacts/false-positives/*.json | jq '.failed_check, .reason'
```

### 2. Update the Relevant Skill

Identify which skill the learning belongs to:
- New bypass payload → `skills/injection/SKILL.md` or `config/payloads/`
- Better tool command → relevant skill's SKILL.md
- WAF behavior → `skills/injection/reference/waf-analysis.md`
- Auth pattern → `skills/authentication/SKILL.md`

### 3. Commit the Update

```bash
git checkout -b skill/<skill-name>
# Edit the relevant SKILL.md
git add skills/<skill-name>/SKILL.md
git commit -m "skill(<skill-name>): <what changed and why>"
git checkout main && git merge skill/<skill-name>
```

## Learning Capture Format

When editing a SKILL.md, add learnings as:

```markdown
## Field Notes

| Date | Engagement Type | Finding | What Worked | What Failed |
|------|----------------|---------|-------------|-------------|
| 2026-06 | Web app (Laravel) | SQLi | ghauri with --tamper=space2comment bypassed WAF | sqlmap tamper scripts blocked by Cloudflare |
```

## Common Updates

- **New WAF bypass**: add to `config/payloads/waf-bypass.txt` and note in `skills/injection/SKILL.md`
- **New default credential**: add to relevant section in `skills/authentication/SKILL.md`
- **New nuclei template category**: add to `skills/server-side/SKILL.md` nuclei commands
- **Improved recon command**: update in `skills/reconnaissance/SKILL.md`
- **False positive pattern**: add to `skills/source-code-scanning/references/false_positive_patterns.md`
