# Module: Reconnaissance
## Phase 1 — Attack Surface Mapping

---

## 1.1 Passive Reconnaissance

**Goal:** Gather maximum information without touching the target directly.

### Subdomain Enumeration (Passive)
```bash
# Certificate Transparency Logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u

# theHarvester — email, subdomain, IP harvesting
theHarvester -d target.com -b all -f output/recon-theharvester.html

# Subfinder (passive)
subfinder -d target.com -o output/subdomains-passive.txt

# Amass (passive mode)
amass enum -passive -d target.com -o output/subdomains-amass.txt
```

### Technology Stack Identification
```bash
# Wappalyzer CLI
wappalyzer https://target.com

# WhatWeb
whatweb https://target.com -v -a 3

# Shodan (requires API key)
shodan search hostname:target.com
```

### GitHub OSINT
```bash
# Search for exposed secrets, config files, API keys
# Search operators:
# site:github.com "target.com" password
# site:github.com "target.com" api_key
# site:github.com "target.com" secret
# site:github.com "target.com" token
# site:github.com "target.com" .env
# site:github.com "target.com" config
```

### Wayback Machine
```bash
# Discover old URLs and endpoints
waybackurls target.com | sort -u | tee output/wayback-urls.txt

# Filter for interesting endpoints
cat output/wayback-urls.txt | grep -E "\.(php|asp|aspx|jsp|json|xml|env|config|bak|sql)" 
cat output/wayback-urls.txt | grep "?" | sort -u  # URLs with parameters
```

---

## 1.2 Active Reconnaissance

**Goal:** Direct interaction with the target to map endpoints, services, and behavior.

### Port & Service Scanning
```bash
# Fast port scan
nmap -sV -sC -T4 --open target.com -oN output/nmap-results.txt

# Full port scan (slower but thorough)
nmap -sV -p- -T4 target.com -oN output/nmap-full.txt

# Common web ports
nmap -sV -p 80,443,8080,8443,8000,8888 target.com
```

### Directory & File Discovery
```bash
# Gobuster
gobuster dir \
  -u https://target.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,txt,bak,zip,sql \
  -t 50 \
  -o output/directories.txt

# ffuf (faster, more flexible)
ffuf -u https://target.com/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mc 200,201,301,302,401,403 \
  -o output/ffuf-dirs.json \
  -of json

# Look for backup/sensitive files
ffuf -u https://target.com/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/sensitive-files.txt \
  -mc 200
```

### Virtual Host Discovery
```bash
ffuf -u https://target.com/ \
  -H "Host: FUZZ.target.com" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302 \
  -o output/vhosts.json
```

### DNS Brute Force
```bash
# Amass (active)
amass enum -active -d target.com -o output/subdomains-active.txt

# dnsx — resolve + filter live subdomains
cat output/subdomains-passive.txt | dnsx -silent -o output/subdomains-live.txt
```

---

## 1.3 API Discovery

### Common API Paths to Test
```
/api/
/api/v1/
/api/v2/
/api/v3/
/graphql
/graphiql
/swagger
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/api-docs/
/docs
/.well-known/
/sitemap.xml
/robots.txt
```

### JavaScript Source Mining
```bash
# Download and analyze JS files
katana -u https://target.com -jc -d 5 | grep "\.js$" | tee output/js-files.txt

# Extract endpoints from JS
cat output/js-files.txt | while read url; do
  linkfinder.py -i "$url" -o cli
done | sort -u | tee output/js-endpoints.txt
```

### GraphQL Introspection
```bash
# Check if introspection is enabled (common misconfiguration)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'
```

---

## 1.4 Reconnaissance Checklist

- [ ] Subdomain enumeration (passive)
- [ ] Subdomain enumeration (active/brute-force)
- [ ] Live subdomain verification
- [ ] Technology stack fingerprinting
- [ ] Port scan (top 1000 ports)
- [ ] Full port scan (all 65535 ports)
- [ ] Directory enumeration
- [ ] Sensitive file discovery (backup, config, .env)
- [ ] JavaScript analysis
- [ ] API endpoint discovery
- [ ] Swagger/OpenAPI documentation check
- [ ] GitHub/GitLab source code search
- [ ] Wayback Machine historical URL discovery
- [ ] Google dorking
- [ ] SSL/TLS certificate analysis

---

## Output

All reconnaissance findings should be saved to `output/findings.json` under the `"reconnaissance"` key:

```json
{
  "reconnaissance": {
    "subdomains": ["sub1.target.com", "sub2.target.com"],
    "technologies": ["nginx/1.18", "PHP/8.1", "jQuery/3.6"],
    "interesting_paths": ["/admin/", "/backup/db.sql", "/.env"],
    "api_endpoints": ["/api/v1/users", "/api/v1/login"],
    "open_ports": [80, 443, 8080],
    "notes": "Admin panel at /admin/ returned 401, no brute force protection observed."
  }
}
```
