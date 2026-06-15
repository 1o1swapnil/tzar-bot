---
name: patt-fetcher
description: Fetch payloads, attack patterns, and wordlists from SecLists, PayloadsAllTheThings, HackTricks
allowed-tools: [Bash, Read, Write]
---

# Payload and Pattern Fetcher

Locate and load attack payloads from local wordlists and pattern databases.

## Local Payload Sources

```bash
# SecLists (installed on Kali)
ls /usr/share/wordlists/SecLists/

# Project payloads
ls config/payloads/
# xss.txt, sqli.txt, lfi.txt, ssrf.txt, waf-bypass.txt

# PayloadsAllTheThings (if installed)
ls /usr/share/payloadsallthethings/ 2>/dev/null || \
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git \
  OUTPUT_DIR/tools/PATT/
```

## Fetching by Vulnerability Type

```bash
# XSS payloads
cat config/payloads/xss.txt
cat /usr/share/wordlists/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt 2>/dev/null

# SQLi payloads
cat config/payloads/sqli.txt
cat /usr/share/wordlists/SecLists/Fuzzing/SQLi/*.txt 2>/dev/null

# LFI payloads
cat config/payloads/lfi.txt
cat /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt 2>/dev/null

# SSRF payloads
cat config/payloads/ssrf.txt
cat /usr/share/wordlists/SecLists/SSRF/*.txt 2>/dev/null

# WAF bypass payloads
cat config/payloads/waf-bypass.txt

# Directory wordlists
ls /usr/share/wordlists/dirbuster/
ls /usr/share/wordlists/SecLists/Discovery/Web-Content/

# Password lists
ls /usr/share/wordlists/SecLists/Passwords/Common-Credentials/
```

## Custom Payload Generation

```bash
# Generate permutations of a base word (for password spraying)
python3 - <<'EOF'
import itertools

base = "Company"
years = ["2024", "2025", "2026"]
suffixes = ["!", "@", "#", "1", "123"]
seasons = ["Winter", "Spring", "Summer", "Fall", "Autumn"]

passwords = []
for y in years:
    for s in suffixes:
        passwords.append(f"{base}{y}{s}")
for season in seasons:
    for y in years:
        passwords.append(f"{season}{y}!")

print('\n'.join(set(passwords)))
EOF
```

## HackTricks Reference

When stuck on a specific vector, check HackTricks:
- LFI → HackTricks: "File Inclusion"
- SQLi → HackTricks: "SQL Injection"
- SSRF → HackTricks: "SSRF"
- JWT → HackTricks: "JSON Web Tokens"
- OAuth → HackTricks: "OAuth"

GTFOBins for SUID/sudo bypasses: https://gtfobins.github.io
