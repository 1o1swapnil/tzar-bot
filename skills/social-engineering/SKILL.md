---
name: social-engineering
description: Social engineering simulation — phishing, pretexting, vishing (authorized only)
allowed-tools: [Bash, Read, Write]
---

# Social Engineering

**Authorization Required:** Always confirm written authorization and defined scope before any SE activity.

```bash
# Verify authorization is documented
cat OUTPUT_DIR/artifacts/engagement-auth.txt | grep -i "social engineering\|phishing\|vishing"
```

## Phishing Campaigns (GoPhish)

```bash
# Start GoPhish (configure in goPhish admin panel first)
# Default: https://localhost:3333 (admin: gophish)

# Create campaign via API
curl -s -X POST https://localhost:3333/api/campaigns/ \
  -H "Authorization: YOUR_GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Client Name - Phishing Test",
    "template": {"name": "IT Security Update"},
    "page": {"name": "Credential Harvest"},
    "smtp": {"name": "SendGrid"},
    "launch_date": "2026-06-10T09:00:00+00:00",
    "groups": [{"name": "Target Group"}]
  }' | jq '.'
```

## Email Templates

Key elements for realistic phishing:
- **Sender**: spoof legitimate internal domain (`it-support@target.com`)
- **Urgency**: "Your account will be disabled in 24 hours"
- **Action**: Single clear CTA — "Click here to verify"
- **Landing page**: Mirror actual target login page

## OSINT-Driven Targeting

```bash
# Use OSINT from reconnaissance phase
cat OUTPUT_DIR/recon/osint-harvester-emails.txt | head -20

# LinkedIn employee names (manual)
# Build pretexting context: department, manager names, internal jargon
```

## Pretexting Scenarios

Common pretext scenarios (scope-dependent):
1. **IT Helpdesk**: "Resetting your account, need to verify identity"
2. **HR/Payroll**: "Updating direct deposit — confirm banking details"
3. **Vendor/Supplier**: "Invoice payment — update your portal login"
4. **Executive impersonation**: CEO requesting urgent wire transfer

## Vishing Script Template

```
Opening: "Hi [name], this is [pretext name] from [pretext department] at [company]."
Reason: "We're [urgency reason — security incident/account update/audit]."
Hook: "I need to [specific action — verify your credentials/confirm your employee ID]."
Handling objection: "I understand, this is a security protocol required by [policy/regulation]."
Closing: "Thank you, you'll receive an email confirmation shortly."
```

## Campaign Metrics Dashboard

```bash
# Pull metrics from GoPhish API and generate dashboard + CSV
# GOPHISH_API_KEY and GOPHISH_URL must be in .env
python3 tools/se-dashboard.py --all --output-dir "$OUTPUT_DIR"

# Specific campaign
python3 tools/se-dashboard.py --campaign-id 3 --output-dir "$OUTPUT_DIR"

# Outputs:
#   OUTPUT_DIR/artifacts/se-metrics.json   — full metrics with credentials
#   OUTPUT_DIR/artifacts/se-metrics.csv    — CSV for client reporting
```

**Key metrics to report:**

| Metric | Industry Benchmark | Finding Threshold |
|---|---|---|
| Open rate | 20–30% | >40% = high susceptibility |
| Click rate | 5–15% | >25% = phishing training needed |
| Submit rate | 1–5% | >10% = critical finding |
| Report rate | 5–10% | <2% = poor security awareness |
| Time-to-first-click | >10 min | <2 min = urgency tactics effective |

## Vishing Tracking

```bash
# Log each vishing call attempt
cat >> "$OUTPUT_DIR/artifacts/vishing-log.json" << EOF
{"timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "target": "NAME", "pretext": "IT helpdesk", "outcome": "success|failure|refused", "data_obtained": "credentials|badge_number|none", "duration_min": 3, "notes": "..."}
EOF

# Aggregate vishing stats
jq '{
  total:    [.] | length,
  success:  [.[] | select(.outcome == "success")] | length,
  refused:  [.[] | select(.outcome == "refused")] | length,
  avg_min:  ([.[].duration_min] | add / length)
}' "$OUTPUT_DIR/artifacts/vishing-log.json" 2>/dev/null
```

## Evidence Collection

- GoPhish campaign results → `OUTPUT_DIR/artifacts/gophish-results.json`
- Metrics dashboard → `OUTPUT_DIR/artifacts/se-metrics.json` + `se-metrics.csv`
- Screenshot of credential harvest landing page → `OUTPUT_DIR/screenshots/`
- Vishing call recordings → `OUTPUT_DIR/evidence/vishing/` (if authorized)
- Vishing log → `OUTPUT_DIR/artifacts/vishing-log.json`

```bash
# Record vishing call (sox — if authorized and legally compliant)
rec -r 44100 "$OUTPUT_DIR/evidence/vishing/call-$(date +%H%M%S).wav" &
RECORD_PID=$!
# ... make call ...
kill $RECORD_PID
```
