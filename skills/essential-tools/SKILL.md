---
name: essential-tools
description: Core tooling reference — always-available Kali tools, piping patterns, proxy setup
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere the per-class references under `reference/` mention Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Essential Tools

Core tools available on Kali Linux throughout every engagement. Active during all phases.

## Tool Availability Check

```bash
# Verify core tools at engagement start
for tool in nmap gobuster ffuf sqlmap nuclei whatweb wafw00f httpx curl wget jq python3 \
            nikto hydra dalfox katana dnsx subfinder amass searchsploit; do
  command -v $tool &>/dev/null && echo "OK: $tool" || echo "MISSING: $tool"
done
```

## Core Tools Reference

| Tool | Basic Usage |
|------|-------------|
| curl | `curl -sI TARGET` (headers), `curl -s TARGET` (body), `curl -X POST -d "data" TARGET` |
| wget | `wget -q -O- TARGET` (stdout), `wget -r TARGET` (recursive) |
| jq | `curl -s TARGET/api | jq '.key'` — JSON parsing |
| python3 | Available with requests, urllib, json, subprocess |
| nmap | `nmap -sV -sC -T4 TARGET` |
| ffuf | `ffuf -u TARGET/FUZZ -w wordlist.txt -mc 200` |
| gobuster | `gobuster dir -u TARGET -w wordlist.txt` |
| sqlmap | `sqlmap -u "TARGET?id=1" --batch` |
| nuclei | `nuclei -u TARGET -t ~/.local/nuclei-templates/` |
| whatweb | `whatweb TARGET -a 3` |
| httpx | `cat urls.txt | httpx -status-code -title` |

## Proxy Setup (Burp / ZAP)

```bash
# Route all curl traffic through Burp at 127.0.0.1:8080
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Per-request proxy
curl -s --proxy http://127.0.0.1:8080 --insecure TARGET

# Ignore SSL errors when proxying
curl -sk --proxy http://127.0.0.1:8080 TARGET
```

## ProxyChains

```bash
# Route through SOCKS proxy (edit /etc/proxychains4.conf)
proxychains4 nmap -sT -Pn TARGET
proxychains4 curl -s TARGET
```

## Common Patterns

```bash
# Parallel requests with xargs
cat urls.txt | xargs -P 20 -I{} curl -so /dev/null -w "%{http_code} {}\n" {}

# Save and display
curl -s TARGET | tee OUTPUT_DIR/logs/response.txt | head -20

# Extract URLs from response
curl -s TARGET | grep -oE 'https?://[^"]+' | sort -u

# JSON formatting
curl -s TARGET/api | python3 -m json.tool

# Base64 encode/decode
echo -n "string" | base64
echo "c3RyaW5n" | base64 -d

# URL encode/decode
python3 -c "import urllib.parse; print(urllib.parse.quote('payload'))"
python3 -c "import urllib.parse; print(urllib.parse.unquote('%27'))"
```

## Wordlists (Kali defaults)

| Path | Contents |
|------|---------|
| `/usr/share/wordlists/rockyou.txt` | Common passwords (14M) |
| `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Web directories |
| `/usr/share/wordlists/SecLists/` | SecLists collection |
| `/usr/share/wordlists/SecLists/Usernames/` | Username lists |
| `/usr/share/wordlists/SecLists/Passwords/` | Password lists |
| `/usr/share/wordlists/SecLists/Discovery/Web-Content/` | Web content discovery |
| `config/payloads/` | Project-specific payloads |

## SearchSploit

```bash
searchsploit "nginx 1.24"
searchsploit -x EXPLOIT_ID       # view exploit
searchsploit -m EXPLOIT_ID       # copy to current directory
```

## Netcat / Socat Listeners

```bash
# Reverse shell listener
nc -lvnp 4444

# Socat (more stable)
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/security-arsenal.md` — Security payloads, bypass tables, wordlists, gf pattern names, always-rejected bug list, and conditionally-valid-with-chain table.
- `reference/wordlist-map.md` — Canonical vuln-class → on-disk SecLists/wordlist path map for this Kali box. Load whenever an executor needs a wordlist or payload file for fuzzing so it points at the correct `/usr/share/seclists/...` path instead of a guessed or broken one.
