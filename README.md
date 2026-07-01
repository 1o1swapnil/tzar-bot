# Tzar-Bot — Penetration Testing Automation Platform

AI-powered pentesting bot running on Claude Code + Kali Linux. Autonomous multi-agent system with coordinator, executor, and validator agents.

> ⚠️ **Authorized use only.** Tzar-Bot is for security testing you are *explicitly authorized* to perform — pentests, vulnerability assessments, CTFs, and bug-bounty programs within their declared scope. All activity is designed to be non-destructive. You are solely responsible for ensuring you have permission to test any target. Scope is enforced in code (`tools/scope.py` + the `scope-check.py` PreToolUse hook): the hook parses each Bash command shell-aware — splitting on operators/pipes, stripping wrappers (`sudo`, `env`, `timeout`, `xargs`, `bash -c`), resolving `$VAR`, and checking every stage — so out-of-scope targets are blocked before the command runs. Treat this as defense-in-depth, not an absolute boundary: it catches direct and shell-obfuscated invocations, but it cannot read targets hidden inside files (`-iL targets.txt`) and is not a substitute for network-level egress controls. Stay within your authorized scope regardless.

## Requirements

- [Kali Linux](https://www.kali.org/) (or a Linux box with the standard offensive-security toolchain)
- [Claude Code](https://claude.com/claude-code) CLI
- Python 3.11+
- An Anthropic API key (and optional integration tokens — see `.env.example`)

## Installation

```bash
git clone https://github.com/1o1swapnil/tzar-bot.git
cd tzar-bot
cp .env.example .env
# Add your ANTHROPIC_API_KEY and any optional tokens (HTB, HackerOne, Shodan, …) to .env
claude
```

`.env`, the `memory.db` engagement store, Python venvs, and all engagement output folders are git-ignored and never leave your machine.

Then describe your engagement in plain English:

| What you say | What happens |
|---|---|
| `"run web chain on https://target.com"` | Full 6-phase WAPT → output in `WAPT/target-com/TIMESTAMP/` |
| `"test the API at https://api.target.com"` | API Security Top 10 → output in `API/target-com/TIMESTAMP/` |
| `"pentest internal network 192.168.1.0/24"` | Network infra test → output in `Network/project/TIMESTAMP/` |
| `"review source code at https://github.com/org/repo"` | SAST + SCA → output in `CodeReview/repo/TIMESTAMP/` |
| `"scan AWS account for misconfigs"` | Cloud assessment → output in `Cloud/aws-account/TIMESTAMP/` |
| `"start H1 bug bounty on program-handle"` | Bug bounty hunt → output in `BugBounty/program-handle/TIMESTAMP/` |

## Engagement Type Folders

| Folder | Testing Type |
|--------|-------------|
| `WAPT/` | Web Application Penetration Testing |
| `MAPT/` | Mobile Application Penetration Testing |
| `API/` | API Security Testing |
| `Network/` | Network & Infrastructure Testing |
| `CodeReview/` | Source Code Security Review |
| `Cloud/` | Cloud Security Assessment |
| `RedTeam/` | Red Team Engagements |
| `DFIR/` | Digital Forensics & Incident Response |
| `BugBounty/` | Bug Bounty Programs |

Each folder has a `README.md` explaining what goes there and how to start.

## Project Output Structure

Every time you run a test, a timestamped project folder is created automatically:

```
WAPT/acme-corp/20260603_143022/
├── attack-chain.md      ← coordinator's live notes
├── recon/               ← tool output (nmap, gobuster, etc.)
├── findings/            ← one folder per vulnerability found
│   └── finding-001/
│       ├── description.md   ← title, severity, CVSS, steps to reproduce
│       ├── poc.py           ← proof-of-concept script
│       └── evidence/        ← HTTP captures, screenshots
├── screenshots/         ← browser and tool screenshots
├── logs/                ← agent activity logs (NDJSON)
├── artifacts/
│   ├── validated/       ← findings approved by validator agents
│   └── false-positives/ ← rejected findings with reason
├── tools/               ← tool-specific output archives
└── reports/
    └── Penetration-Test-Report.pdf   ← final deliverable
```

## Skill Library

```
skills/
├── coordination/        ← executor and validator role definitions
├── web-chain/           ← autonomous 6-phase web pentest orchestrator
├── reconnaissance/      ← nmap, gobuster, ffuf, whatweb, amass
├── osint/               ← theHarvester, crt.sh, waybackurls, Shodan
├── techstack-identification/
├── authentication/      ← hydra, JWT testing, OAuth, session analysis
├── injection/           ← sqlmap, dalfox, tplmap, commix, ssrfmap
├── server-side/         ← nuclei, testssl, CORS, file upload
├── client-side/         ← DOM XSS, clickjacking, CSRF, retire.js
├── api-security/        ← kiterunner, GraphQL, BOLA/IDOR
├── web-app-logic/       ← race conditions, price tampering, IDOR
├── infrastructure/      ← crackmapexec, impacket, kerbrute, BloodHound
├── system/              ← linpeas, winpeas, SUID, sudo, kernel exploits
├── cloud-containers/    ← trivy, pacu, ScoutSuite, kubectl
├── source-code-scanning/← semgrep, trufflehog, gitleaks, trivy + Python scripts
├── cve-risk-score/      ← NVD lookup, EPSS, CISA KEV check
├── cve-poc-generator/   ← searchsploit, GitHub PoC finder
├── hackthebox/          ← VPN, flag capture, HTB API submission
├── hackerone/           ← scope check, H1 API report submission
├── ai-threat-testing/   ← prompt injection, jailbreaks, RAG poisoning
├── bias-fairness-testing/ ← demographic parity, disparate impact (fair-lending)
├── model-robustness/    ← adversarial perturbation, edge-case, evasion testing
├── model-monitoring/    ← covariate/concept drift, latency SLA, fallback checks
├── incident-response/   ← IOC extraction, CERT-In disclosure packet + 6h countdown
├── social-engineering/  ← GoPhish, pretexting, vishing (authorized only)
├── dfir/                ← Volatility3, disk imaging, YARA, log analysis
├── blockchain-security/ ← Slither, Mythril, Echidna, Foundry
├── essential-tools/     ← curl, nmap, ffuf, nuclei reference
├── script-generator/    ← custom PoC scripts
├── patt-fetcher/        ← payload and wordlist lookup
├── github-workflow/     ← git conventions, branching
└── skill-update/        ← capture engagement learnings
```

## Platform Tools (`tools/`)

Python utilities the agents drive (stdlib-first; 15 are also exposed model-agnostically as **MCP tools** via `.mcp.json`):

| Tool | Purpose |
|------|---------|
| `init-engagement.py` | Create the typed engagement tree + export `$OUTPUT_DIR` |
| `engagement-state.py` | Resumable, scope-guarded ledger; **executor work-claim dedup** (`claim`/`release`/`worklist --agent`) |
| `scope.py` · `scope-check.py` | Code-enforced scope (deny-wins); shell-aware PreToolUse block hook — tokenizes commands, splits on operators/pipes, unwraps `sudo`/`env`/`timeout`/`xargs`/`bash -c`, resolves `$VAR` (allow-list extensible via `config/safe-prefixes.txt`) |
| `validate-finding.py` | 5-check mechanical finding-validation gate |
| `generate-report.py` | Canonical tzar-bot-style **PDF** report |
| `report-export.py` | **NEW** — offline **JSON + HTML** report export (no reportlab, no network) |
| `token-meter.py` | **NEW** — token/cost telemetry, budgets, `ingest` (semi-auto capture), pricing card |
| `rate-limiter.py` | **NEW** — per-host token-bucket request pacing (don't trip WAFs) |
| `nvd-lookup.py` · `gen-nuclei-template.py` | CVE detail (NVD 2.0); Nuclei v3 template generation |
| `session-memory.py` · `memory-search.py` · `continuous-scan.py` | Cross-session SQLite memory (FTS5); delta rescans |
| `env-reader.py` · `scrub-web-content.py` | Only approved secret access; prompt-injection scrubber (CWE-1336) |
| `notify.py` · `se-dashboard.py` | P0/P1 webhook alerts; GoPhish campaign metrics |
| `lint-skills.py` · `sync-bughunter.py` | Skill quality gate; upstream-drift detection |
| `mcp-server.py` · `playwright-mcp-server.py` | MCP servers (15 tools; authenticated browser automation) |

Smoke tests (84, hermetic — includes shell-obfuscation scope-bypass regression vectors): `tools/.venv-test/bin/python -m pytest tools/tests/ -q`. Full command reference: `docs/operations.md`.

## Required Tools (Kali)

Most are pre-installed. Check availability:
```bash
for t in nmap gobuster ffuf sqlmap nuclei whatweb wafw00f httpx dalfox subfinder amass dnsx; do
  command -v $t &>/dev/null && echo "OK: $t" || echo "MISSING: $t"
done
```

Install any missing:
```bash
sudo apt update && sudo apt install -y nuclei dalfox subfinder amass
pip3 install semgrep trufflehog
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```
