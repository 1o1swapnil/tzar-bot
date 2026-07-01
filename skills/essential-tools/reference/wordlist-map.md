---
name: wordlist-map
description: Canonical vuln-class → on-disk wordlist/payload path map for this Kali box. Use whenever an executor needs a wordlist or payload file for fuzzing (dir/param/subdomain discovery, password/username brute, or per-class injection payloads) so it points at the correct SecLists path instead of a guessed or broken one. Source of truth for wordlist paths across all hunt-* skills.
---

# Wordlist & Payload Map (on-disk, this Kali box)

SecLists ships with Kali at **`/usr/share/seclists/`** and is already installed — do **not** vendor copies into the repo. `rockyou` lives at `/usr/share/wordlists/rockyou.txt.gz` (gzipped — `zcat` it, or `gunzip -k` once). Every path below was verified present on this host.

> **Shortcut:** `export SL=/usr/share/seclists` in the executor shell, then reference `$SL/...`.
> **Note:** The old `~/wordlists/common.txt`-style references are **broken** (`~/wordlists/` does not exist). Use the paths here instead.

---

## Discovery / content fuzzing (ffuf, gobuster, feroxbuster)

| Need | Path |
|---|---|
| Directories (large) | `$SL/Discovery/Web-Content/raft-large-directories.txt` |
| Files (large) | `$SL/Discovery/Web-Content/raft-large-files.txt` |
| Words (large, dir+file) | `$SL/Discovery/Web-Content/raft-large-words.txt` |
| Quick common paths | `$SL/Discovery/Web-Content/common.txt` |
| API endpoints | `$SL/Discovery/Web-Content/api/api-endpoints.txt` |
| Parameter names | `$SL/Discovery/Web-Content/burp-parameter-names.txt` |

```bash
ffuf -w $SL/Discovery/Web-Content/raft-large-directories.txt -u https://TARGET/FUZZ
ffuf -w $SL/Discovery/Web-Content/burp-parameter-names.txt -u 'https://TARGET/page?FUZZ=x' -fs 0
```

## Subdomain enumeration (`hunt-subdomain`, reconnaissance)

| Need | Path |
|---|---|
| Top 110k subdomains | `$SL/Discovery/DNS/subdomains-top1million-110000.txt` |
| Deep (100k bitquark) | `$SL/Discovery/DNS/bitquark-subdomains-top100000.txt` |

## Passwords / usernames (`hunt-brute-force`, `authentication`, `hunt-ato`)

| Need | Path |
|---|---|
| Usernames (quick) | `$SL/Usernames/top-usernames-shortlist.txt` |
| Default appliance usernames | `$SL/Usernames/cirt-default-usernames.txt` |
| Real first/last names | `$SL/Usernames/Names/names.txt` |
| Passwords (probable, high-signal) | `$SL/Passwords/Common-Credentials/probable-v2_top-12000.txt` |
| Passwords (darkweb top 10k) | `$SL/Passwords/Common-Credentials/darkweb2017_top-10000.txt` |
| Passwords (1M, deep) | `$SL/Passwords/Common-Credentials/Pwdb_top-1000000.txt` |
| Full crack list | `zcat /usr/share/wordlists/rockyou.txt.gz` |
| Default creds (product→pass) | `$SL/Passwords/Default-Credentials/default-passwords.csv` |

```bash
hydra -L $SL/Usernames/top-usernames-shortlist.txt \
      -P $SL/Passwords/Common-Credentials/probable-v2_top-12000.txt TARGET http-post-form '...'
# JWT / hash crack:
hashcat -a 0 -m 16500 jwt.txt <(zcat /usr/share/wordlists/rockyou.txt.gz)
```

## Per-class injection payloads (the `hunt-*` payload libraries)

The `hunt-*.md` reference files carry **curated, high-signal payloads inline** — reach for these files only when you need **breadth/automation** (feeding a fuzzer a full list).

| Class | Path | Skill |
|---|---|---|
| SQLi (quick) | `$SL/Fuzzing/Databases/SQLi/quick-SQLi.txt` | `injection/reference/hunt-sqli.md` |
| SQLi (generic, broad) | `$SL/Fuzzing/Databases/SQLi/Generic-SQLi.txt` | " |
| SQLi (polyglots) | `$SL/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt` | " |
| SQLi (auth bypass) | `$SL/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt` | " |
| NoSQLi | `$SL/Fuzzing/Databases/SQLi/NoSQL.txt` | `hunt-nosqli` |
| MSSQL enum | `$SL/Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt` | `injection/reference/hunt-sqli.md` |
| Command injection (8k, commix) | `$SL/Fuzzing/command-injection-commix.txt` | `injection/reference/hunt-rce.md` |
| XSS (polyglots) | `$SL/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt` | `injection/reference/hunt-xss.md` |
| SSTI (template expressions) | `$SL/Fuzzing/template-engines-expression.txt` | `injection/reference/hunt-ssti.md` |
| LFI (Jhaddix, broad) | `$SL/Fuzzing/LFI/LFI-Jhaddix.txt` | `injection/reference/hunt-lfi.md` |
| LDAP | `$SL/Fuzzing/LDAP.Fuzzing.txt` | `hunt-ldap` |
| XXE | `$SL/Fuzzing/XXE-Fuzzing.txt` | `injection/reference/hunt-xxe.md` |
| Naughty strings (edge cases) | `$SL/Fuzzing/big-list-of-naughty-strings.txt` | any input-validation fuzz |
| Malicious filenames (upload) | `$SL/Payloads/File-Names/` | `hunt-file-upload` |

## Web shells (`hunt-file-upload`, `hunt-rce` — post-exploit, in scope only)

Kali ships shells too — no need to vendor: `$SL/Web-Shells/` (laudanum, FuzzDB `cmd.*`, PHP/JSP/ASPX). Also `/usr/share/webshells/` (php, asp, jsp, perl).

---

## Convention

1. Always cite the **full `/usr/share/seclists/...` path** (or `$SL/...`) — never `~/wordlists/...` (broken) or a bare filename.
2. Prefer the **inline curated payloads** in each `hunt-*.md` for manual testing; use these files only to feed a fuzzer breadth.
3. If a needed list is missing on a given host: `apt-get install seclists` (Kali) or clone `danielmiessler/SecLists`.
