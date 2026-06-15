---
name: client-side
description: Client-side vulnerability testing — DOM XSS, clickjacking, CSRF, postMessage, outdated libraries
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere the per-class references under `reference/` mention Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Client-Side Testing

Test browser-executable vulnerabilities that server-side scanners miss.

## Tools

| Tool | Purpose |
|------|---------|
| dalfox | DOM + reflected XSS |
| retire.js | Vulnerable JS library detection |
| nuclei | Client-side template checks |
| curl | Header analysis |
| playwright (MCP) | Real browser — DOM inspection, screenshots |

## DOM XSS Discovery

```bash
# Source analysis — dangerous sinks in JS files
for jsfile in $(cat OUTPUT_DIR/recon/js-files.txt); do
  curl -s "$jsfile" | grep -nE "innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|location\.(href|hash)|\.src\s*=" \
    | sed "s|^|$jsfile: |" >> OUTPUT_DIR/logs/dom-sinks.txt
done

# Reflected XSS scan
dalfox url "TARGET/search?q=test" --deep-domxss --output OUTPUT_DIR/logs/dalfox-dom.txt

# Parameter mining for XSS
cat OUTPUT_DIR/recon/gau.txt | grep "?" | \
  qsreplace '"><script>alert(1)</script>' | \
  while read url; do
    curl -sk "$url" | grep -q 'alert(1)' && echo "XSS: $url"
  done
```

## Clickjacking

```bash
# Check X-Frame-Options and CSP frame-ancestors
curl -sI TARGET | grep -iE "x-frame-options|content-security-policy" | grep -i "frame"

# If neither header present → clickjacking likely possible
# Create PoC HTML:
cat > OUTPUT_DIR/findings/clickjacking-poc.html <<'EOF'
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<iframe src="TARGET" style="opacity:0.5; position:absolute; top:0; left:0; width:100%; height:100%; z-index:2"></iframe>
<button style="position:absolute; top:200px; left:200px; z-index:1">Click me</button>
</body>
</html>
EOF
```

## CSRF Testing

```bash
# Check for CSRF tokens in forms
curl -s TARGET/profile | grep -iE "csrf|token|_token|authenticity_token"

# Check SameSite cookie attribute
curl -sI TARGET | grep -i "set-cookie" | grep -iv "samesite"

# Missing SameSite + no CSRF token = testable CSRF
```

## postMessage Vulnerabilities

```bash
# Find postMessage listeners in JS
grep -rn "addEventListener.*message\|window\.addEventListener.*message" OUTPUT_DIR/recon/js-*.txt 2>/dev/null

# Check for origin validation
grep -A5 "addEventListener.*message" OUTPUT_DIR/recon/js-*.txt 2>/dev/null | grep "origin"
# No origin check = potential postMessage injection
```

## localStorage / sessionStorage Secrets

```bash
# Check JS code for sensitive data stored in browser storage
grep -rn "localStorage\.setItem\|sessionStorage\.setItem" OUTPUT_DIR/recon/js-*.txt 2>/dev/null | \
  grep -iE "token|password|secret|key|auth"
```

## Vulnerable JS Libraries

```bash
# retire.js
retire --js --path . --outputformat json --outputpath OUTPUT_DIR/logs/retire.json 2>/dev/null

# Manual version check from whatweb output
cat OUTPUT_DIR/recon/whatweb.json | jq '.[] | select(.plugins | keys[] | test("jQuery|Bootstrap|Angular|React|Vue"))' 2>/dev/null
```

## Subresource Integrity

```bash
# Check script tags missing integrity attribute
curl -s TARGET | grep -i "<script" | grep -iv "integrity="
```

## Output

DOM XSS findings → `OUTPUT_DIR/findings/finding-NNN/`
Evidence: DOM screenshots via playwright MCP, response captures

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-csrf.md` — Deep CSRF hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/hunt-dom.md` — Hunt client-side DOM vulnerabilities…
