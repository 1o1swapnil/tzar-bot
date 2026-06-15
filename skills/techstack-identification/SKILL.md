---
name: techstack-identification
description: Identify the full technology stack — framework, server, CMS, JS libraries, CDN, WAF
allowed-tools: [Bash, Read, Write]
---

# Tech Stack Identification

Fingerprint the target's technology stack to guide vulnerability selection.

## Tools

| Tool | Purpose |
|------|---------|
| whatweb | Comprehensive tech fingerprinting |
| wafw00f | WAF detection and identification |
| curl | Header analysis |
| nikto | Server fingerprinting + common vulns |
| wapiti | Web app vulnerability scanner with tech detection |

## Fingerprinting

```bash
# Primary fingerprinting
whatweb TARGET -v -a 3 --log-json=OUTPUT_DIR/recon/whatweb.json

# WAF detection
wafw00f TARGET -o OUTPUT_DIR/recon/waf.txt

# Header analysis
curl -sI TARGET | tee OUTPUT_DIR/recon/headers.txt
curl -sI TARGET/nonexistent | tee OUTPUT_DIR/recon/404-headers.txt

# Error page fingerprinting (reveals framework)
curl -s TARGET/nonexistent-page-xyz | head -50 > OUTPUT_DIR/recon/error-page.txt

# Cookie analysis (framework session tokens)
curl -s -c OUTPUT_DIR/tools/cookies.txt TARGET > /dev/null
cat OUTPUT_DIR/tools/cookies.txt
```

## Indicators to Check

| Indicator | Location | What It Reveals |
|-----------|---------|-----------------|
| `X-Powered-By` header | Response headers | PHP version, ASP.NET version |
| `Server` header | Response headers | Web server + version |
| `PHPSESSID` cookie | Set-Cookie | PHP backend |
| `JSESSIONID` cookie | Set-Cookie | Java/Tomcat |
| `laravel_session` cookie | Set-Cookie | Laravel framework |
| `csrf_token` in HTML | Page source | Django/Rails/Laravel |
| `wp-content/` in URLs | HTML | WordPress |
| `generator` meta tag | HTML `<head>` | CMS type and version |
| Favicon hash | Favicon MD5 | Match against known fingerprints |

## Favicon Hash Lookup

```bash
curl -s TARGET/favicon.ico | md5sum
# Cross-reference hash at: https://wiki.owasp.org/index.php/OWASP_favicon_database
```

## Output: tech-stack.json

Write a structured JSON file:

```json
{
  "target": "https://target.com",
  "web_server": "nginx/1.24.0",
  "framework": "Laravel 10.x",
  "language": "PHP 8.2",
  "database": "MySQL (inferred from error pages)",
  "cms": null,
  "waf": "Cloudflare",
  "cdn": "Cloudflare",
  "js_libraries": ["jQuery 3.6.0", "Bootstrap 5.3"],
  "interesting_headers": {
    "x-powered-by": "PHP/8.2",
    "x-frame-options": "SAMEORIGIN",
    "content-security-policy": null
  },
  "session_cookie": "laravel_session",
  "ssl_tls": "TLS 1.3",
  "notes": "Admin panel at /admin returned 302 to /admin/login"
}
```

Save to: `OUTPUT_DIR/recon/tech-stack.json`
