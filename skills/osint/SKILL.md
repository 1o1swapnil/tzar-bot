---
name: osint
description: Open-source intelligence gathering — emails, credentials, GitHub secrets, historical data
allowed-tools: [Bash, Read, Write]
---

# OSINT

Gather intelligence without touching the target. Focus on leaked data, exposed credentials, GitHub secrets, and employee information.

## Tools

| Tool | Purpose |
|------|---------|
| theHarvester | Email, subdomain, employee harvesting |
| crt.sh API | Certificate transparency logs |
| waybackurls | Historical URL discovery |
| gau | GetAllURLs — Wayback + Common Crawl + OTX |
| trufflehog | Secret scanning in GitHub repos |
| gitrob | GitHub org reconnaissance |
| shodan CLI | Internet-wide scanning data |
| dnsrecon | DNS record enumeration |

## Passive Subdomain Enumeration

```bash
subfinder -d TARGET_HOST -silent -all -o OUTPUT_DIR/recon/osint-subdomains.txt
amass enum -passive -d TARGET_HOST -config /dev/null -o OUTPUT_DIR/recon/osint-amass.txt
curl -s "https://crt.sh/?q=%.TARGET_HOST&output=json" | \
  jq -r '.[].name_value' | tr ',' '\n' | sort -u > OUTPUT_DIR/recon/osint-crt.txt
```

## Email and Employee Harvesting

```bash
theHarvester -d TARGET_HOST -b google,bing,linkedin,twitter,github -f OUTPUT_DIR/recon/osint-harvester 2>/dev/null
# Manually review: emails, names, job titles from LinkedIn
```

## GitHub OSINT

```bash
# Search for leaked secrets (manual browser dorks):
# site:github.com "TARGET_HOST" password
# site:github.com "TARGET_HOST" api_key
# site:github.com "TARGET_HOST" secret
# site:github.com "TARGET_HOST" .env
# site:github.com "TARGET_HOST" DB_PASSWORD

# If GitHub org known:
trufflehog github --org=TARGET_ORG --json > OUTPUT_DIR/recon/osint-trufflehog.json 2>/dev/null
```

## Historical URL Discovery

```bash
waybackurls TARGET_HOST | sort -u | tee OUTPUT_DIR/recon/osint-wayback.txt
gau TARGET_HOST | tee OUTPUT_DIR/recon/osint-gau.txt

# Filter for interesting endpoints
cat OUTPUT_DIR/recon/osint-wayback.txt | grep -E "\.(php|asp|aspx|jsp|json|xml|env|config|bak|sql)$" \
  > OUTPUT_DIR/recon/osint-interesting-extensions.txt
cat OUTPUT_DIR/recon/osint-wayback.txt | grep "?" | sort -u \
  > OUTPUT_DIR/recon/osint-params.txt
```

## Shodan Lookup

```bash
# Requires SHODAN_API_KEY in .env
python3 tools/env-reader.py SHODAN_API_KEY
shodan search "hostname:TARGET_HOST" --fields ip_str,port,org,hostnames > OUTPUT_DIR/recon/osint-shodan.txt
shodan host TARGET_IP > OUTPUT_DIR/recon/osint-shodan-host.txt
```

## DNS Enumeration

```bash
dnsrecon -d TARGET_HOST -t std,brt,axfr -o OUTPUT_DIR/recon/osint-dnsrecon.json
```

## Output

- `recon/osint-subdomains.txt` — all passive subdomains
- `recon/osint-harvester.*` — emails and employees
- `recon/osint-trufflehog.json` — leaked secrets from GitHub
- `recon/osint-wayback.txt` — historical URLs
- `recon/osint-params.txt` — parameter-bearing URLs (injection targets)
- `recon/osint-shodan.txt` — internet exposure data

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/offensive-osint.md` — Operational arsenal for authorized external red-team and bug-bounty recon.
- `reference/osint-methodology.md` — Comprehensive OSINT methodology for external red-team operations and authorized attack-surface assessments.
