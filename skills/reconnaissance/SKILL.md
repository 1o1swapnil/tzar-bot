---
name: reconnaissance
description: Active and passive reconnaissance — map the full attack surface before testing
allowed-tools: [Bash, Read, Write]
---

# Reconnaissance

Map the target's attack surface: subdomains, ports, directories, tech stack, JS endpoints.

## Tools

| Tool | Purpose |
|------|---------|
| nmap | Port scan, service version, OS detection, NSE scripts |
| masscan | Fast port discovery (then nmap for detail) |
| subfinder | Passive subdomain enumeration |
| amass | Active + passive subdomain enumeration |
| dnsx | DNS resolution, filter live subdomains |
| httpx | HTTP probing, status codes, title, tech |
| gobuster | Directory/file brute-force |
| ffuf | Fast web fuzzer — dirs, params, vhosts |
| whatweb | Technology fingerprinting |
| wafw00f | WAF detection |
| katana | Web crawler, JS link extraction |
| waybackurls / gau | Historical URL discovery |
| nikto | Web server vulnerability scanner |
| nuclei | Template-based scanning |

## Phase 1a — Passive Recon

```bash
subfinder -d TARGET_HOST -silent -o OUTPUT_DIR/recon/subdomains-subfinder.txt
amass enum -passive -d TARGET_HOST -o OUTPUT_DIR/recon/subdomains-amass.txt
curl -s "https://crt.sh/?q=%.TARGET_HOST&output=json" | jq -r '.[].name_value' | sort -u \
  > OUTPUT_DIR/recon/subdomains-crt.txt
theHarvester -d TARGET_HOST -b all -f OUTPUT_DIR/recon/theharvester 2>/dev/null
waybackurls TARGET_HOST | sort -u > OUTPUT_DIR/recon/wayback.txt
gau TARGET_HOST > OUTPUT_DIR/recon/gau.txt
```

## Phase 1b — DNS Resolution

```bash
cat OUTPUT_DIR/recon/subdomains-*.txt | sort -u > OUTPUT_DIR/recon/subdomains-all.txt
cat OUTPUT_DIR/recon/subdomains-all.txt | dnsx -silent -o OUTPUT_DIR/recon/subdomains-live.txt
cat OUTPUT_DIR/recon/subdomains-live.txt | httpx -title -tech-detect -status-code \
  -o OUTPUT_DIR/recon/http-probing.txt
```

## Phase 1c — Port Scanning

```bash
nmap -sV -sC -T4 --open TARGET -oN OUTPUT_DIR/recon/nmap-top1000.txt
nmap -sV -p- -T3 TARGET -oN OUTPUT_DIR/recon/nmap-full.txt
nmap --script vuln TARGET -oN OUTPUT_DIR/recon/nmap-vulns.txt
```

## Phase 1d — Web Enumeration

```bash
gobuster dir -u TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,txt,bak,zip,sql,env -t 50 -o OUTPUT_DIR/recon/gobuster.txt

ffuf -u TARGET/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -mc 200,201,301,302,401,403 -o OUTPUT_DIR/recon/ffuf-files.json -of json

# Vhost discovery
ffuf -u TARGET/ -H "Host: FUZZ.TARGET_HOST" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302 -o OUTPUT_DIR/recon/vhosts.json -of json

# JS file extraction and endpoint mining
katana -u TARGET -jc -d 5 -o OUTPUT_DIR/recon/katana.txt
cat OUTPUT_DIR/recon/katana.txt | grep "\.js$" > OUTPUT_DIR/recon/js-files.txt
cat OUTPUT_DIR/recon/js-files.txt | xargs -I{} curl -s {} | grep -oE '"(/[^"]+)"' | sort -u \
  > OUTPUT_DIR/recon/js-endpoints.txt
```

## Output

- `recon/nmap-*.txt` — port scan results
- `recon/subdomains-live.txt` — confirmed live subdomains
- `recon/gobuster.txt`, `recon/ffuf-*.json` — discovered paths
- `recon/js-endpoints.txt` — API/endpoints from JavaScript
- `recon/tech-stack.json` — structured stack info

## Checklist

- [ ] Passive subdomain enum
- [ ] Active DNS resolution
- [ ] HTTP probing all subdomains
- [ ] Port scan (top 1000 + full)
- [ ] Directory enumeration
- [ ] Sensitive file discovery (.env, .git, backup)
- [ ] JS analysis and endpoint extraction
- [ ] Wayback/GAU historical URLs
- [ ] WAF detection

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-subdomain.md` — Deep SUBDOMAIN hunting — payloads, bypass tables, and disclosed-report chains.
- `reference/web2-recon.md` — Web2 recon pipeline…
- `reference/hunt-source-leak.md` — Hunt source code and build artifact leakage…
