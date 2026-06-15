---
name: hackerone
description: HackerOne bug bounty — scope monitoring, duplicate detection, bounty estimation, report submission, status tracking, rejection avoidance
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere the per-class references under `reference/` mention Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# HackerOne Bug Bounty

End-to-end workflow: scope validation → testing → duplicate check → report submission → status tracking.

## Credentials

```bash
eval $(python3 tools/env-reader.py HACKERONE_TOKEN HACKERONE_USERNAME)
# Usage: --user "$HACKERONE_USERNAME:$HACKERONE_TOKEN" on all curl calls
```

---

## Phase 1 — Program Discovery & Scope Validation

```bash
PROGRAM="target-program"   # handle from the H1 program URL
H1_TOKEN=$(python3 tools/env-reader.py HACKERONE_TOKEN | cut -d= -f2)
H1_USER=$(python3 tools/env-reader.py HACKERONE_USERNAME | cut -d= -f2)
AUTH="$H1_USER:$H1_TOKEN"

# Fetch program metadata (policy, bounty table, response SLA)
curl -s "https://api.hackerone.com/v1/hackers/programs/$PROGRAM" \
  --user "$AUTH" | jq '{
    handle:      .handle,
    name:        .attributes.name,
    bounty:      .attributes.offers_bounties,
    state:       .attributes.state,
    response_sla: .attributes.response_efficiency_percentage
  }' | tee "$OUTPUT_DIR/artifacts/h1-program.json"

# Fetch full structured scope
curl -s "https://api.hackerone.com/v1/hackers/programs/$PROGRAM/structured_scopes" \
  --user "$AUTH" | jq '[.data[] | {
    asset:      .attributes.asset_identifier,
    type:       .attributes.asset_type,
    bounty:     .attributes.eligible_for_bounty,
    submission: .attributes.eligible_for_submission,
    max_sev:    .attributes.max_severity,
    updated:    .attributes.updated_at
  }]' | tee "$OUTPUT_DIR/artifacts/h1-scope.json"

# Show in-scope bounty-eligible targets
jq -r '.[] | select(.bounty == true) | "\(.asset)  [\(.type)]  max:\(.max_sev)"' \
  "$OUTPUT_DIR/artifacts/h1-scope.json"
```

---

## Phase 2 — Scope-Change Monitoring

Poll for scope changes since last check — new assets or newly eligible endpoints.

```bash
SCOPE_CACHE="$OUTPUT_DIR/artifacts/h1-scope-prev.json"

# On first run: save baseline
[ ! -f "$SCOPE_CACHE" ] && cp "$OUTPUT_DIR/artifacts/h1-scope.json" "$SCOPE_CACHE"

# On subsequent runs: diff for new assets
CURRENT=$(curl -s "https://api.hackerone.com/v1/hackers/programs/$PROGRAM/structured_scopes" \
  --user "$AUTH" | jq -S '[.data[] | .attributes.asset_identifier]')
PREV=$(jq -S '[.[].asset]' "$SCOPE_CACHE")

# New assets added to scope
NEW_ASSETS=$(comm -23 <(echo "$CURRENT" | jq -r '.[]' | sort) \
                      <(echo "$PREV"    | jq -r '.[]' | sort))
if [ -n "$NEW_ASSETS" ]; then
  echo "[!] NEW SCOPE ASSETS SINCE LAST CHECK:"
  echo "$NEW_ASSETS"
  echo "$NEW_ASSETS" | tee "$OUTPUT_DIR/logs/h1-scope-changes.txt"
else
  echo "[+] No scope changes detected."
fi

# Update cache
curl -s "https://api.hackerone.com/v1/hackers/programs/$PROGRAM/structured_scopes" \
  --user "$AUTH" | jq '[.data[] | {asset: .attributes.asset_identifier, bounty: .attributes.eligible_for_bounty}]' \
  > "$SCOPE_CACHE"
```

---

## Phase 3 — In-Scope Asset Verification (Before Each Test)

**Always verify live before testing** — never rely on a cached scope.

```bash
TARGET="https://api.target.com"

# Extract just the hostname/domain from target URL
TARGET_HOST=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$TARGET').netloc)")

# Check against live scope (wildcard-aware)
IN_SCOPE=$(jq --arg host "$TARGET_HOST" -r '
  .[] | select(.bounty == true) |
  .asset as $a |
  if ($a | startswith("*.")) then
    ($a | ltrimstr("*.")) as $domain |
    if ($host | endswith($domain)) then "YES: \($a)" else empty end
  elif $host == $a or ($host | endswith("." + $a)) then "YES: \($a)"
  else empty
  end
' "$OUTPUT_DIR/artifacts/h1-scope.json")

if [ -z "$IN_SCOPE" ]; then
  echo "[STOP] $TARGET_HOST is NOT in scope. Do not test."
  exit 1
else
  echo "[OK] In scope: $IN_SCOPE"
fi
```

---

## Phase 4 — Duplicate Detection

Check for existing reports before spending time on a finding.

```bash
KEYWORD="SQL injection"   # key term from your finding title

# Search your own submitted reports on this program
curl -s "https://api.hackerone.com/v1/hackers/reports?filter[program][]=$PROGRAM" \
  --user "$AUTH" | jq --arg kw "$KEYWORD" '
  [.data[] | select(
    (.attributes.title | ascii_downcase | contains($kw | ascii_downcase)) or
    (.attributes.vulnerability_information | ascii_downcase | contains($kw | ascii_downcase))
  ) | {
    id:       .id,
    title:    .attributes.title,
    state:    .attributes.state,
    created:  .attributes.created_at,
    severity: .relationships.severity.data.attributes.rating
  }]' | tee "$OUTPUT_DIR/logs/h1-dupe-check.json"

# If any results → read them carefully:
# state = "duplicate" → already reported, skip
# state = "triaged"   → being worked on, skip
# state = "resolved"  → fixed, but consider if regression is testable
# state = "new"       → your own pending report

# Also search disclosed reports (public database)
curl -s "https://api.hackerone.com/v1/hackers/programs/$PROGRAM/reports?filter[disclosed]=true" \
  --user "$AUTH" 2>/dev/null | jq --arg kw "$KEYWORD" '
  [.data[]? | select(.attributes.title | ascii_downcase | contains($kw | ascii_downcase)) |
  {id, title: .attributes.title, disclosed_at: .attributes.disclosed_at}]' 2>/dev/null || true
```

**Decision rule:**
- Exact duplicate → skip
- Similar but different endpoint/parameter → submit with clear differentiation note
- Same class, different impact → submit, note the prior report in references

---

## Phase 5 — CVSS-to-Bounty Estimation

```bash
# Fetch program-specific bounty table
curl -s "https://api.hackerone.com/v1/hackers/programs/$PROGRAM" \
  --user "$AUTH" | jq '.attributes | {
    min_bounty_table: .vulnerability_types,
    offers_bounties:  .offers_bounties
  }' 2>/dev/null

# Structured scope max_severity per asset
jq -r '.[] | select(.asset == "TARGET_ASSET") | "Max severity: \(.max_sev)"' \
  "$OUTPUT_DIR/artifacts/h1-scope.json"
```

**Standard H1 severity → bounty map (program-specific — always check program page):**

| CVSS | H1 Rating | Typical Range | Notes |
|------|-----------|---------------|-------|
| 9.0–10.0 | Critical | $5,000–$50,000+ | RCE, auth bypass, SQLi with data exfil |
| 7.0–8.9 | High | $1,000–$10,000 | Stored XSS on main domain, IDOR with sensitive data |
| 4.0–6.9 | Medium | $200–$2,500 | Reflected XSS, CSRF, limited IDOR |
| 0.1–3.9 | Low | $50–$500 | Info disclosure, missing headers |
| N/A | Informational | $0 | Best practice issues — usually not rewarded |

**Severity justification formula for H1 submission:**
```
CVSS: [score] [vector]
Impact: [what attacker achieves — data, account, system]
Scope: [authenticated/unauthenticated, user/admin]
Exploitation: [requires user interaction? chained with other vulns?]
```

**Bounty-maximising tips:**
- Demonstrate full impact, not just proof of concept
- Chain low-severity findings into a higher-severity attack path when possible
- Submit to programs with public bounty tables and high response rates
- Avoid programs in "invite only" phase unless invited

---

## Phase 6 — H1 Report Template (All Required Sections)

Replace every `[PLACEHOLDER]` before submitting. Incomplete reports are the #1 rejection reason.

```markdown
## Summary

[2–3 sentences: what the vulnerability is, where it exists, and the root cause.
Be precise — name the endpoint, parameter, or function.]

Example: A reflected XSS vulnerability exists in the `q` parameter of the search
endpoint at `https://target.com/search`. User input is rendered in the DOM without
HTML-encoding, allowing execution of arbitrary JavaScript in the victim's browser context.

## Steps to Reproduce

[Exact, numbered, reproducible steps. Assume the triager has never seen the app.]

1. Log in at `https://target.com/login` with a standard user account.
2. Navigate to `https://target.com/search?q=<script>alert(document.domain)</script>`.
3. Observe the JavaScript alert executing with the domain `target.com`.
4. [Optional] Open DevTools → Console to confirm script execution context.

[Include raw HTTP request if relevant:]
```
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: target.com
Cookie: session=abc123
```

## Supporting Material / References

- `screenshot-01-payload.png` — payload injected in search bar
- `screenshot-02-alert.png`   — alert dialog confirming XSS execution
- `request.txt`               — raw HTTP request
- `response.txt`              — raw HTTP response (200 OK with unencoded input)

[Link any relevant CVEs, CWEs, or prior disclosures:]
- CWE-79: Improper Neutralisation of Input During Web Page Generation
- OWASP A03:2021 — Injection

## Impact

[Specific, realistic impact. Answer: what can an attacker achieve?]

An unauthenticated attacker can craft a malicious link and send it to any user of
`target.com`. When the victim clicks the link, the attacker can:
- Steal the victim's session cookie (if HttpOnly is not set)
- Perform actions on behalf of the victim (CSRF-like impact)
- Redirect the victim to a phishing page
- Inject a keylogger to capture credentials

This affects all users, including administrators, and requires no special privileges.
```

---

## Phase 7 — API Submission

```bash
python3 - <<'PYEOF'
import urllib.request, json, base64, sys

H1_TOKEN  = open("/dev/stdin").readline().strip() if not sys.stdin.isatty() else ""
USERNAME  = "YOUR_H1_USERNAME"
TOKEN     = "YOUR_H1_TOKEN"
AUTH      = base64.b64encode(f"{USERNAME}:{TOKEN}".encode()).decode()

REPORT = {
    "data": {
        "type": "report",
        "attributes": {
            "team_handle":                "PROGRAM_HANDLE",
            "title":                      "Reflected XSS in /search via q parameter",
            "vulnerability_information":  open("OUTPUT_DIR/artifacts/h1-report.md").read(),
            "severity_rating":            "high",   # none|low|medium|high|critical
            "impact":                     "Session hijack / phishing via crafted URL",
            "weakness_id":                 46,       # H1 weakness ID for XSS = 46
        }
    }
}

req = urllib.request.Request(
    "https://api.hackerone.com/v1/hackers/reports",
    data    = json.dumps(REPORT).encode(),
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Basic {AUTH}",
    }
)
try:
    with urllib.request.urlopen(req) as r:
        result = json.load(r)
        rid = result["data"]["id"]
        print(f"[+] Report submitted: #{rid}")
        print(f"    URL: https://hackerone.com/reports/{rid}")
except urllib.error.HTTPError as e:
    print(f"[!] HTTP {e.code}: {e.read().decode()}")
PYEOF

# Save the report ID for status tracking
echo "REPORT_ID=XXXXXX" >> "$OUTPUT_DIR/artifacts/h1-submission.env"
```

**Common H1 weakness IDs:**

| Weakness | H1 ID |
|---|---|
| Cross-Site Scripting (XSS) | 46 |
| SQL Injection | 67 |
| CSRF | 62 |
| Open Redirect | 75 |
| SSRF | 73 |
| XXE | 129 |
| IDOR / Broken Access Control | 55 |
| Insecure Direct Object Reference | 55 |
| Path Traversal | 17 |
| Remote Code Execution | 60 |
| Information Disclosure | 116 |
| Authentication Bypass | 3 |
| Privilege Escalation | 55 |
| Business Logic | 840 |

---

## Phase 8 — Submission Status Tracking

```bash
REPORT_ID="1234567"

# Check current status
curl -s "https://api.hackerone.com/v1/hackers/reports/$REPORT_ID" \
  --user "$AUTH" | jq '{
    id:           .data.id,
    title:        .data.attributes.title,
    state:        .data.attributes.state,
    created:      .data.attributes.created_at,
    triaged:      .data.attributes.triaged_at,
    bounty_paid:  .data.attributes.bounty_awarded_at,
    closed:       .data.attributes.closed_at,
    severity:     .data.relationships.severity.data.attributes.rating,
    bounty_amount:.data.attributes.bounty_amount
  }' | tee "$OUTPUT_DIR/artifacts/h1-status-$REPORT_ID.json"

# Check all your reports on this program
curl -s "https://api.hackerone.com/v1/hackers/reports?filter[program][]=$PROGRAM" \
  --user "$AUTH" | jq '[.data[] | {
    id:     .id,
    title:  .attributes.title,
    state:  .attributes.state,
    bounty: .attributes.bounty_amount
  }]'
```

**H1 state machine:**

```
new → triaged → needs-more-info ↔ triaged
              → duplicate   (closed)
              → not-applicable (closed)
              → resolved    (may get bounty)
              → informative (closed, no bounty)
```

**Expected timelines (varies by program):**
- First response: 1–7 days (check program SLA stats)
- Triage to resolved: 1–90 days
- Bounty award: within 14 days of resolution (most programs)

---

## Phase 9 — Common Rejection Reasons and How to Avoid Them

| Rejection | Root Cause | How to Avoid |
|---|---|---|
| **Duplicate** | Same vuln already reported | Always run Phase 4 duplicate check first |
| **Out of scope** | Asset not in structured scope | Always run Phase 3 live scope check |
| **Informational** | No real impact demonstrated | Prove impact concretely — show cookie theft, account takeover, or data exfil |
| **Not reproducible** | Ambiguous steps | Test your own steps from scratch; include raw HTTP request |
| **Not a vulnerability** | Best practice issue only | Only submit if CVSS ≥ 0.1 with real attack scenario |
| **Self XSS** | XSS only in own account | Show cross-user exploitation; if impossible, don't submit |
| **Missing CSRF token required MFA** | App has secondary defence | Test actual exploitability, don't just flag missing tokens |
| **Rate limiting exists** | Brute force already mitigated | Verify the rate limit actually blocks before submitting |
| **Resolved by design** | App intentionally behaves this way | Read the policy page for accepted/excluded vuln classes |
| **Needs more info** | Evidence unclear | Always attach screenshots + raw request/response + reproduction video if complex |

---

## Output

```
OUTPUT_DIR/artifacts/
├── h1-program.json        ← program metadata
├── h1-scope.json          ← current structured scope
├── h1-scope-prev.json     ← previous scope (for change detection)
├── h1-dupe-check.json     ← duplicate search results
├── h1-report.md           ← final report markdown (edit before submission)
├── h1-submission.env      ← submitted report ID(s)
└── h1-status-XXXXXX.json  ← per-report status snapshots
OUTPUT_DIR/logs/
└── h1-scope-changes.txt   ← scope change log
```

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/bug-bounty.md` — Complete bug bounty workflow…
