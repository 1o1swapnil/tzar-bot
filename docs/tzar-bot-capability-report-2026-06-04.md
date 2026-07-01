# Tzar-Bot — Capability & Market Readiness Report

> ⚠️ **SUPERSEDED (numbers stale).** Headline counts here (30 skills / 10 tools / 9 MCP) are from
> 2026-06-04. See **`tzar-bot-capability-report-2026-06-26.md`** for current figures
> (69 skills / 36 tools / 18 MCP / 119 tests). The per-domain capability tables below remain valid.

| | |
|---|---|
| **Date** | 2026-06-04 |
| **Platform** | Tzar-Bot v1.0 — Claude Code + Kali Linux |
| **Skills** | 30 |
| **Tools** | 10 |
| **Engagement Types** | 9 |
| **Prepared by** | Swapnil Khandekar — tzar-bot |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Platform Architecture](#2-platform-architecture)
3. [Capability Map](#3-capability-map)
4. [Market Comparison](#4-market-comparison)
   - 4.1 [vs. AI / LLM Pentest Frameworks](#41-vs-ai--llm-pentest-frameworks)
   - 4.2 [vs. Commercial Platforms](#42-vs-commercial-platforms)
   - 4.3 [vs. Specialized Tools by Domain](#43-vs-specialized-tools-by-domain)
5. [Advantages Over the Market](#5-advantages-over-the-market)
6. [Gaps vs. the Market](#6-gaps-vs-the-market)
7. [Engagement-Type Readiness Assessment](#7-engagement-type-readiness-assessment)
8. [Overall Scoring](#8-overall-scoring)
9. [Recommendations](#9-recommendations)
10. [Market Landscape Reference](#10-market-landscape-reference)

---

## 1. Executive Summary

Tzar-Bot is **ready for professional penetration testing** across web applications, APIs, networks, cloud infrastructure, mobile applications, wireless networks, blockchain smart contracts, source code review, DFIR, and AI/LLM threat testing.

Its coordinator/executor/validator architecture, cross-session SQLite memory, hardware-layer scope enforcement, prompt injection defense, and structured five-check evidence validation match or exceed the patterns used by the top-performing AI pentest platforms in production (PentAGI, XBOW, NodeZero). In domain breadth, tzar-bot surpasses every open-source AI pentest framework currently available.

**One critical gap** prevents full enterprise red team positioning: no C2 infrastructure integration (Cobalt Strike / Sliver / Havoc). All other gaps are moderate and do not block professional engagement delivery.

**Overall score: 7.5 / 10 — Top-tier open-source AI pentest platform.**

---

## 2. Platform Architecture

### Agent Triangle

```
┌─────────────────────────────────────────────────────────────┐
│  COORDINATOR  (main conversation session)                    │
│                                                             │
│  1. Reads attack-chain.md + session-memory.py load()        │
│  2. Scrubs web content  ──► scrub-web-content.py            │
│  3. Writes reasoning to attack-chain.md                     │
│  4. Spawns 1–2 Executor agents per batch                    │
│  5. Saves state  ──► session-memory.py save()               │
│  6. Reads executor output, updates attack-chain.md          │
│  7. Spawns Validator agents (one per finding)               │
│  8. Triggers report gate  ──► generate-report.py            │
│                                                             │
│  HARD BOUNDARY: never runs nmap, ffuf, sqlmap, curl         │
│  (enforced by scope-check.py PreToolUse hook)               │
└─────────────────────────────────────────────────────────────┘
          │ spawn (background)              │ spawn (background)
          ▼                                ▼
┌──────────────────────┐      ┌────────────────────────────┐
│  EXECUTOR AGENTS     │      │  VALIDATOR AGENTS          │
│                      │      │                            │
│  • Full mission      │      │  5-check protocol:         │
│    context in prompt │      │  1. CVSS consistency       │
│  • Source code first │      │  2. Evidence exists        │
│  • Escalate before   │      │  3. PoC validity           │
│    reporting failure │      │  4. Claims vs evidence     │
│  • Write findings/   │      │  5. Log corroboration      │
│    finding-NNN/      │      │                            │
│  • NDJSON logs       │      │  ALL 5 must pass           │
└──────────────────────┘      └────────────────────────────┘
```

### Security Hardening Stack

| Layer | Implementation | What It Stops |
|---|---|---|
| Content scrubbing | `scrub-web-content.py` (15 regex patterns) | Prompt injection embedded in HTTP responses, HTML pages, API output |
| Executor behavioral rules | `executor-role.md` mandatory section | LLM-layer: target content treated as data, never instructions; auto-documents injection as CWE-1336 finding |
| Scope enforcement | `scope-check.py` PreToolUse hook | Bash commands targeting out-of-scope hosts blocked at tool layer (exit 2) |
| Credential safety | `env-reader.py` (only approved .env reader) | No shell sourcing of credentials; no hardcoded secrets in PoCs |
| Git safety | `.gitignore` (memory.db, .env, credential dumps) | Sensitive material never committed |
| Destructive op prevention | `# SAFE: non-destructive` required on all PoCs | No DROP, DELETE, DoS, or data corruption |

### Tool Inventory

| Tool | Purpose |
|---|---|
| `init-engagement.py` | Creates OUTPUT_DIR tree, attack-chain.md, engagement.json; auto-registers in memory.db |
| `session-memory.py` | SQLite cross-session memory — save/load/list/search/note/status |
| `validate-finding.py` | Mechanical 5-check validator before agent validators are spawned |
| `scope-check.py` | PreToolUse hook blocking out-of-scope Bash commands |
| `scrub-web-content.py` | Strips prompt injection patterns from web-sourced content |
| `gen-nuclei-template.py` | Generates Nuclei v3 YAML detection templates from CVE metadata |
| `nvd-lookup.py` | Fetches CVE CVSS/severity/description from NVD 2.0 API |
| `env-reader.py` | Only approved method for reading .env credentials |
| `generate-report.py` | Produces PDF Penetration Test Report + machine-readable JSON |
| `mcp-server.py` | MCP stdio server exposing all 9 tools to Claude Code and any MCP client |

### MCP Server (9 exposed tools)

Registered in `.mcp.json` as `tzar-bot`. Auto-approved via `enabledMcpjsonServers`. Callable from Claude Code, Cursor, Windsurf, or any MCP-compatible client without shell access.

`nvd_lookup` · `validate_finding` · `validate_all_findings` · `init_engagement` · `scrub_web_content` · `gen_nuclei_template` · `read_env` · `scope_check` · `session_memory`

---

## 3. Capability Map

### 3.1 Web Application Testing

**Skills:** `injection`, `client-side`, `server-side`, `authentication`, `web-app-logic`, `api-security`

**Depth: Deep (all 6 skills)**

| Attack Class | Techniques |
|---|---|
| SQL Injection | sqlmap (tamper scripts), ghauri (WAF bypass), boolean-based, UNION, time-based |
| XSS | dalfox (reflected), DOM XSS sink analysis, ffuf parameter fuzzing, stored |
| SSRF | Cloud metadata (AWS/GCP/Azure 169.254.169.254), internal service targeting |
| SSTI | Detection probes ({{7*7}}), tplmap exploitation (Jinja2, Mako, Twig, Freemarker) |
| Command Injection | commix automated, manual payload variations, URL-encoded newlines |
| LFI / Path Traversal | ffuf + payloads, null byte bypass, PHP filter chain, Zip slip |
| XXE | External entity, blind OOB, parameter entity |
| WAF Bypass | Case variation, comment insertion, URL/double encoding, chunked transfer |
| CORS | Reflected origin, null origin, wildcard + credentials |
| Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| File Upload | Extension bypass, MIME bypass, path traversal, SVG XSS |
| Authentication | Brute force (hydra), JWT alg:none, weak secret (jwt_tool), OAuth, password reset |
| Session | Fixation, cookie flags (HttpOnly, Secure, SameSite), token predictability |
| Business Logic | Price tampering, workflow bypass, race conditions, IDOR, coupon abuse |
| GraphQL | Introspection, batching (rate-limit bypass), nested query DoS |
| API | BOLA/IDOR sequential ID walk, mass assignment, excessive data exposure, rate limiting |

**Orchestrator:** `/web-chain` — fully autonomous 6-phase web pentest (osint + recon + techstack → auth → injection + server-side → client-side + API → business logic → validate → PDF report). No user input required after initial invocation.

---

### 3.2 Reconnaissance & OSINT

**Skills:** `reconnaissance`, `osint`, `techstack-identification`

| Technique | Tools |
|---|---|
| Passive subdomain enumeration | subfinder, amass, crt.sh certificate transparency |
| DNS resolution & live filtering | dnsx, httpx |
| Port scanning | nmap (top 1000 + full, NSE scripts) |
| Web directory & file discovery | gobuster, ffuf, SecLists wordlists |
| Vhost enumeration | ffuf with Host header fuzzing |
| JS endpoint extraction | katana, manual grep |
| Historical URL discovery | waybackurls, gau (Wayback + CommonCrawl) |
| WAF detection | wafw00f, whatweb |
| Email & employee harvesting | theHarvester, LinkedIn dorks |
| GitHub secret scanning | trufflehog, gitrob, manual dorks |
| Shodan lookups | shodan CLI |
| Tech stack fingerprinting | whatweb, favicon hash lookup, cookie analysis, error page fingerprinting |

---

### 3.3 Infrastructure & Active Directory

**Skills:** `infrastructure`, `system`

| Attack Class | Tools / Techniques |
|---|---|
| Network discovery | nmap NSE scripts, targeted service fingerprinting |
| SMB enumeration | enum4linux-ng, smbclient, smbmap, null sessions |
| LDAP enumeration | ldapsearch (anonymous + authenticated) |
| Kerberos user enumeration | kerbrute (no credentials required) |
| AS-REP Roasting | impacket-GetNPUsers |
| Kerberoasting | impacket-GetUserSPNs |
| Password spraying | crackmapexec (rate-aware) |
| Pass-the-Hash | crackmapexec, impacket-psexec |
| Domain secrets extraction | impacket-secretsdump (DCSync) |
| Linux privilege escalation | linpeas, GTFOBins, pspy (cron), searchsploit (kernel CVEs) |
| Windows privilege escalation | winpeas, SeImpersonate, unquoted paths, AlwaysInstallElevated |
| Common privesc CVEs | CVE-2021-4034 (pkexec), CVE-2022-0847 (Dirty Pipe), CVE-2021-3156 (sudo) |

---

### 3.4 Cloud Security

**Skill:** `cloud-containers`

| Platform | Techniques |
|---|---|
| **AWS** | Metadata SSRF (169.254.169.254), sts/iam/s3/ec2 enumeration, Pacu exploitation, public S3 discovery |
| **GCP** | Metadata endpoint (computeMetadata/v1/), Metadata-Flavor header |
| **Azure** | Instance metadata (api-version=2021-02-01), Metadata header |
| **Containers** | Docker socket escape, privileged capability check, cgroups escape, image scanning (trivy) |
| **Kubernetes** | kubectl enumeration, unauthenticated API server, RBAC bypass (system:anonymous) |
| **Assessment** | ScoutSuite (multi-cloud), Prowler (AWS CIS), trivy (container images) |

---

### 3.5 Mobile Application (MAPT)

**Skill:** `mapt` | **Standard:** OWASP MASVS / MSTG

| MASVS Category | Techniques |
|---|---|
| **STORAGE** | SharedPrefs/NSUserDefaults/SQLite dump + grep for plaintext credentials |
| **CRYPTO** | Hardcoded keys (apkleaks), weak algorithms (DES, MD5, ECB), IV reuse |
| **AUTH** | JWT validation, biometric bypass, session fixation, cookie analysis |
| **NETWORK** | Cleartext detection (network_security_config.xml), ATS exceptions, cert pinning bypass |
| **PLATFORM** | Exported components (drozer), deep link injection, clipboard abuse, intent abuse |
| **CODE** | Binary protections (PIE, stack canary, ARC), debug build, PII in logs |
| **RESILIENCE** | Root/jailbreak detection bypass (Frida, objection), anti-tampering check |

**Platforms:** Android APK (apktool, jadx, MobSF, drozer) and iOS IPA (ipa-inspector, objection, Frida, keychain dumper)

**MobSF REST API** integration for automated static + dynamic analysis.

---

### 3.6 Wireless Penetration Testing

**Skill:** `wireless`

| Phase | Techniques | Tools |
|---|---|---|
| Setup | Monitor mode, kill conflicting processes | airmon-ng |
| Passive recon | All-channel AP + client discovery | airodump-ng |
| WPA2 capture (A) | Deauth + 4-way handshake | aireplay-ng + airodump-ng |
| WPA2 capture (B) | Clientless PMKID (no deauth needed) | hcxdumptool + hcxtools |
| WPA cracking | Dictionary, rule-based (best64), mask (numeric) | hashcat (GPU), aircrack-ng |
| Evil twin | Rogue AP matching target SSID | bettercap |
| WPA-Enterprise | Rogue RADIUS, PEAP downgrade, MS-CHAPv2 capture | hostapd-wpe, eaphammer |
| MS-CHAPv2 crack | Domain credential recovery | asleap, hashcat mode 5600 |
| WPA3/SAE | Transition-mode downgrade check, DragonBlood CVE-2019-9494 | airodump-ng + PoC |
| Client probing | Remembered SSID enumeration | airodump-ng |
| Bluetooth | Classic + BLE scan, ubertooth | hcitool, bettercap |

*Requires: external wireless adapter supporting monitor mode + packet injection (e.g. Alfa AWUS036ACH)*

---

### 3.7 Blockchain & Smart Contract Security

**Skill:** `blockchain-security`

| Tool | Analysis Type | Detects |
|---|---|---|
| **Slither** | Static analysis (90+ detectors) | Reentrancy, unchecked transfers, access control, arithmetic overflow |
| **Mythril** | Symbolic execution + SMT solving | Logic errors, reentrancy, integer bugs, dangerous delegatecalls |
| **Echidna** | Property-based fuzzing | Invariant violations, edge case exploitation |
| **Foundry/Forge** | Unit + fuzz testing | Custom invariant verification |

Flash loan attack vector analysis, oracle manipulation checks, access control audit.

---

### 3.8 AI / LLM Threat Testing

**Skill:** `ai-threat-testing`

| Attack Class | Techniques |
|---|---|
| Direct prompt injection | System prompt override, role switch |
| Indirect prompt injection | Document poisoning, web content injection, email body injection |
| System prompt extraction | Extraction via translation, code execution, repetition requests |
| Jailbreaks | DAN, role-play, Base64 encoding, token smuggling, crescendo escalation |
| RAG poisoning | Injecting instructions into documents ingested by RAG pipeline |
| Tool / plugin abuse | Search tool, code execution, file access plugin manipulation |
| Data extraction | PII extraction via context leakage, training data reconstruction |

---

### 3.9 DFIR

**Skill:** `dfir`

| Phase | Tools | Techniques |
|---|---|---|
| Memory acquisition | LiME, avml | Kernel module injection, SMB transfer, hashing |
| Memory analysis | Volatility3 | pslist, netstat, memmap, malfind, cmdline, filescan |
| Disk imaging | dd, dc3dd | SHA256/MD5 hash verification, write-blocker |
| Log analysis | grep, awk, journalctl | Auth failures, lateral movement, privilege escalation |
| Timeline creation | The Sleuth Kit (fls, mactime) | MFT / inode timeline |
| IOC extraction | YARA, strings, file | Malware signatures, embedded IPs, domains, hashes |
| Chain of custody | Manual documentation | Hash verification at each step |

---

### 3.10 Source Code Security Review

**Skill:** `source-code-scanning`

Operates on scanner output (no raw source required — clients share SARIF/JSON/HTML reports).

**Supported scanner types:**
- **SAST:** SonarQube, Semgrep, CodeQL, Checkmarx, Fortify, Veracode, Snyk Code, Bandit, Brakeman, gosec
- **SCA:** Dependency-Check, Trivy, Grype, Snyk, Dependabot, Black Duck, Anchore
- **DAST:** ZAP, Burp Suite, Acunetix, Qualys WAS
- **IaC:** Checkov, tfsec, Terrascan, KICS
- **Secrets:** Gitleaks, TruffleHog, detect-secrets
- **Container:** Trivy, Clair, kube-bench
- **SBOM:** CycloneDX, SPDX

**Process:** Inventory → deduplication → severity normalization → 50+ false-positive pattern eradication → SAST/DAST/SCA cross-correlation → reachability analysis → license risk → supply-chain risk → Excel dashboard (11 tabs, slicers, PivotCharts) → executive summary → consultant report with FP justifications.

---

### 3.11 CVE Intelligence

**Skills:** `cve-risk-score`, `cve-poc-generator`

**Triggered automatically** on any `CVE-YYYY-NNNNN` pattern in any executor output.

| Step | Action |
|---|---|
| NVD lookup | CVSS score, severity, description, published date (NVD 2.0 API) |
| EPSS enrichment | 30-day exploitation probability (api.first.org) |
| KEV status | CISA Known Exploited Vulnerabilities check |
| ExploitDB check | searchsploit |
| GitHub PoC discovery | Stars-ranked search |
| Risk priority | P0/P1/P2/P3 matrix (CVSS × EPSS × KEV × in-scope-component) |
| PoC generation | Review → adapt/write → test (detection-only) |
| Nuclei template | `gen-nuclei-template.py` → validate → scan |

---

## 4. Market Comparison

### 4.1 vs. AI / LLM Pentest Frameworks

| Capability | PentAGI | PentestGPT | CAI | H-mmer | **Tzar-Bot** |
|---|---|---|---|---|---|
| Architecture | 13+ specialized sub-agents, Neo4j, pgvector | 3 interacting modules | Lightweight swarm (300+ models) | 50 agents, 2 MCP servers | Coordinator / Executor / Validator |
| Domain coverage | General pentest | OWASP Top 10 | General | H1 bug bounty focus | **30 skills, 9 engagement types** |
| Cross-session memory | pgvector + Neo4j (semantic) | None | None | SQLite | **SQLite memory.db + resume briefing** |
| MCP integration | None | None | None | 2 MCP servers | **9-tool MCP server (.mcp.json)** |
| Mobile testing | None | None | None | None | **Full MASVS (7 categories)** |
| Wireless testing | None | None | None | None | **WPA2/3, EAP, evil twin, BLE** |
| Blockchain testing | None | None | None | None | **Slither + Mythril + Echidna** |
| DFIR | None | None | None | None | **Volatility3, disk imaging, IOC** |
| AI threat testing | None | None | None | None | **Prompt injection, RAG poisoning** |
| Source code review | None | None | None | 8 SAST pipeline agents | **12 scanner types, 50+ FP patterns** |
| Prompt injection defense | None | None | Agent runtime (guardrails) | None | **Content-layer (scrub-web-content.py)** |
| Scope enforcement | None | None | None | PreToolUse hook | **PreToolUse hook (scope-check.py)** |
| 5-check finding validation | None | None | None | 7-question gate | **validate-finding.py (mechanical)** |
| PDF report | None | None | None | None | **generate-report.py** |
| Self-learning loop | None | None | None | None | **/skill-update → SKILL.md** |
| Nuclei template generation | None | None | None | None | **gen-nuclei-template.py** |
| Autonomous orchestration | Full (Docker sandbox) | Semi (human gates) | Full | Full | **/web-chain (6-phase auto)** |
| Observability | Grafana + Jaeger + OTel | None | Phoenix traces | Cost tracking hooks | attack-chain.md narrative |
| GitHub stars (June 2026) | ~14,700 | ~12,100 | ~8,800 | ~681 | Private |
| Pricing | Free | Free | Free | Free | **Free (LLM API cost only)** |

---

### 4.2 vs. Commercial Platforms

| Capability | Burp Suite Pro ($499/yr) | Cobalt Strike ($3,500/yr) | NodeZero (Horizon3) | Pentera | **Tzar-Bot** |
|---|---|---|---|---|---|
| Pricing | $499/user/yr | $3,500/user/yr | Subscription (contact) | Contact | **Free** |
| Web app testing | Best-in-class manual | None | Automated | Automated | **Deep (40+ techniques)** |
| Intercepting proxy | ✅ Core feature | ❌ | ❌ | ❌ | ❌ Gap |
| Network / AD | ❌ | ✅ via Beacon | ✅ | ✅ | ✅ Deep |
| C2 infrastructure | ❌ | ✅ Core feature | ❌ | ❌ | ❌ Critical gap |
| Exploitation | Scanner only | 2,300+ (Metasploit) | Automated | Automated | Non-destructive PoC only |
| Mobile testing | ❌ | ❌ | ❌ | ❌ | ✅ Full MASVS |
| Wireless | ❌ | ❌ | ❌ | ❌ | ✅ Full WPA2/3/EAP |
| Blockchain | ❌ | ❌ | ❌ | ❌ | ✅ Slither/Mythril/Echidna |
| DFIR | ❌ | ❌ | ❌ | ❌ | ✅ Volatility3 + Sleuth Kit |
| AI threat testing | ❌ | ❌ | ❌ | ❌ | ✅ Prompt injection / RAG |
| Continuous scanning | Enterprise edition only | ❌ | ✅ Core feature | ✅ Core feature | ❌ Gap |
| Evidence chain | Manual capture | Session logs | Auto-generated | Auto-generated | **Structured finding-NNN/ + 5-check** |
| PDF report | ✅ | ✅ (limited) | ✅ Executive | ✅ | ✅ generate-report.py |
| Compliance mapping | Via extensions | ❌ | ✅ | ✅ | CVSS/CWE/OWASP per finding |
| Scope enforcement | Manual | Manual | Automated | Automated | **PreToolUse hook (scope-check.py)** |
| Chain of custody | Manual | ❌ | Auto | Auto | NDJSON logs + SQLite memory |

---

### 4.3 vs. Specialized Tools by Domain

| Domain | Market Leader | Tzar-Bot Status | Notes |
|---|---|---|---|
| DAST / web scanning | Burp Suite Pro, OWASP ZAP | ✅ Covered via Nuclei + curl skills | No intercepting proxy / request replay |
| Recon orchestration | ReconFTW, Osmedeus | ✅ Covered via recon + osint skills | Osmedeus has richer YAML workflow DSL |
| Nuclei templates | 9,000+ community templates | ✅ Nuclei integrated; gen-nuclei-template.py | Community template library not bundled |
| Vulnerability management | Nessus, Tenable, Rapid7 | ⚠️ NVD + EPSS + KEV via cve-risk-score | No continuous asset inventory |
| Bug bounty automation | XBOW (#1 HackerOne), ReconFTW | ⚠️ HackerOne skill + BugBounty/ type | No swarm/continuous mode |
| Mobile | MobSF + Frida + Objection | ✅ Full MASVS via mapt skill | No standalone dashboard UI |
| Wireless | Aircrack-ng suite, Kismet | ✅ Full WPA2/3/EAP via wireless skill | Kismet passive detection not integrated |
| Cloud (AWS) | Prowler + Pacu + ScoutSuite | ✅ All three integrated in cloud-containers | No cross-cloud unified compliance report |
| Cloud (Azure/GCP) | MicroBurst, Scout Suite | ✅ ScoutSuite covers multi-cloud | Azure AD-specific modules not deep |
| Blockchain | Slither + Mythril + Echidna | ✅ All three in blockchain-security | No Foundry invariant test integration |
| DFIR | Volatility3 + Autopsy + TheHive | ✅ Volatility3 + Sleuth Kit (no Autopsy) | No GUI forensics dashboard |
| Social engineering | GoPhish + KnowBe4 | ⚠️ GoPhish skill covers campaigns | No training module, no scale dashboard |
| C2 / Red team | Cobalt Strike, Sliver, Havoc | ❌ Not covered | Critical gap for red team engagements |
| Continuous pentest | NodeZero, Pentera | ❌ Not covered | Session-based only |

---

## 5. Advantages Over the Market

### 5.1 Unique to Tzar-Bot (no open-source equivalent)

**Broadest domain coverage in one platform**
30 skills across 9 engagement types covering web, API, network, cloud, mobile, wireless, blockchain, AI/LLM, DFIR, social engineering, code review, and CVE intelligence. No other open-source AI pentest platform is within 3x of this coverage.

**Validated evidence chain with mechanical pre-validation**
`validate-finding.py` runs five deterministic checks before human/agent validators review any finding: CVSS score-vs-severity consistency, evidence directory existence, PoC syntax verification, affected-component corroboration in evidence files, and log file cross-reference. NodeZero and Pentera do this commercially; no open-source equivalent.

**Prompt injection defense at content layer**
`scrub-web-content.py` strips adversarial instructions (instruction overrides, role hijacks, delimiter injection, exfil callbacks) from web-sourced content before it reaches executor agent prompts. 15 regex patterns, right-to-left replacement algorithm, injections documented as CWE-1336 findings. CAI defends at agent runtime; tzar-bot defends at content layer — complementary, not duplicative.

**Scope enforcement at the tool layer**
`scope-check.py` PreToolUse hook intercepts every Bash tool call and blocks commands that clearly target out-of-scope hosts — at the Claude Code harness level, before the LLM processes output. 40+ scanning tools covered. CIDR + subdomain matching. H-mmer has a comparable hook; no other open-source AI pentest framework does.

**Cross-session SQLite memory with structured resume**
`session-memory.py` persists phases, discovered services, findings, tested vectors, hypotheses, and notes across conversation resets. `load` produces a full coordinator resume briefing — current phase progress, open findings, tested vectors, next steps — in under one second. PentAGI uses pgvector + Neo4j (heavier, more powerful for semantic search); no other open-source framework has any cross-session memory.

**Self-learning via `/skill-update`**
After each engagement, successful bypasses, new default credentials, new Nuclei template patterns, and tool-specific behavior notes feed back into SKILL.md files via the skill-update workflow. The platform improves itself over engagements. No competitor has a self-improvement loop.

**Source code review without raw source**
`source-code-scanning` ingests scanner outputs (SARIF, JSON, HTML, SBOM) from 12+ tool types, deduplicates across tools, normalizes severity using a full CVSS/tool-specific conversion table, eradicates 50+ documented false-positive patterns, cross-correlates SAST ↔ DAST ↔ SCA findings, and produces an 11-tab Excel dashboard + executive summary + consultant report. Clients never share raw code. No comparable open-source capability exists.

**Nuclei template generation from CVE metadata**
`gen-nuclei-template.py` + Step 6 in `cve-poc-generator` closes the loop between CVE discovery and reusable detection: valid Nuclei v3 YAML template, auto-filled from `nvd.json` if available, validated with `nuclei -validate`. Nuclei v3.8's AI generation requires ProjectDiscovery cloud; tzar-bot does it locally.

**9-type engagement output routing**
`init-engagement.py` enforces a typed folder structure (WAPT, MAPT, API, Network, CodeReview, Cloud, RedTeam, DFIR, BugBounty) with all subdirectories and templates created from the start. No other framework structures outputs by engagement class.

**MCP server for model-agnostic access**
9 tools exposed via `.mcp.json` callable from Claude Code, Cursor, Windsurf, or any MCP client. No other open-source AI pentest framework ships an MCP server.

---

### 5.2 Ahead of Specific Competitors

| Competitor | Tzar-Bot advantage |
|---|---|
| PentAGI | 3x broader domain coverage; source code review; mobile; wireless; blockchain; DFIR; AI threat testing |
| PentestGPT | Validator triangle; scope enforcement; cross-session memory; 5-check evidence validation; PDF report |
| CAI | Structured engagement types; validator pattern; find-and-fix loop; source code review |
| H-mmer | Broader domain coverage; wireless; DFIR; blockchain; AI threat testing; MCP server |
| ReconFTW | Attack depth (exploitation, not just recon); validation; report gate |
| Osmedeus | Domain coverage beyond recon/web; LLM reasoning layer |
| Burp Suite Pro (on specific domains) | Mobile, wireless, blockchain, DFIR, AI threat testing — all free |

---

## 6. Gaps vs. the Market

### 6.1 Critical Gaps

**Gap 1 — No C2 / Red Team Infrastructure**

Zero integration with Cobalt Strike, Sliver, Havoc, or Covenant. The `RedTeam/` engagement folder exists but no dedicated skill covers post-initial-access: no Beacon/implant deployment, no malleable C2 profiles, no lateral movement chains, no persistence mechanisms, no defense evasion, no exfiltration channels.

The industry consensus (Hadrian research, June 2026) confirms that all AI agent platforms have "essentially no demonstrated capability" in defense evasion and persistence. This is not unique to tzar-bot — but it is the primary gap preventing red team engagement delivery.

*Mitigation path:* Add a `skills/red-team/SKILL.md` covering Sliver + Havoc C2 setup, beacon deployment commands, lateral movement playbooks, and credential harvesting chains.

---

**Gap 2 — No Continuous / Scheduled Scanning**

Every engagement is conversation-session-initiated and stops when the session ends. NodeZero and Pentera's core value proposition is unlimited autonomous continuous scanning — regression testing after remediation, change-detection on assets, always-on exposure monitoring.

Tzar-bot's `/schedule` skill infrastructure exists in Claude Code but is not wired into the engagement workflow.

*Mitigation path:* Wire `init-engagement.py` + `web-chain` into a cron-triggered `/schedule` job that re-runs against saved engagement targets from `memory.db`.

---

**Gap 3 — No Intercepting Proxy / Request Replay**

Burp Suite's fundamental capability — intercepting a live authenticated session, modifying a specific parameter in-flight, and replaying it — has no equivalent in tzar-bot. Complex multi-step authenticated workflows requiring live session state (OAuth flows, multi-factor enrollment, stateful wizard workflows) cannot be tested at depth.

*Mitigation path:* Playwright MCP provides partial coverage for authenticated browser sessions. A Burp Suite MCP server wrapper would be a more complete solution.

---

### 6.2 Moderate Gaps

| Gap | Business Impact | Workaround |
|---|---|---|
| Business logic detection reliability | Logic flaws require human application context; LLM judgment varies | Executor agents with full app context outperform scanners; senior review for P1 findings |
| Real-time notifications | Must poll OUTPUT_DIR for new findings during long engagements | None within platform; external file watchers possible |
| CRM / ticket integration | No SLA tracking, remediation status sync with client systems | Manual process |
| Multi-target lateral move | AD pivot chains (Target A → B) require manual coordination | Spawn separate Network engagement per target |
| Wireless hardware requirement | Alfa adapter required; not all environments allow hardware | Documented in SKILL.md; advisory to client pre-engagement |
| Single report template | tzar-bot-style only; no PCI-DSS / ISO 27001 compliance appendix | Manual addendum |
| No Autopsy GUI for DFIR | CLI-only forensics; Sleuth Kit covers critical path | Adequate for most incident response scenarios |
| HackTheBox / HackerOne skills shallow | Flag submission only; limited strategic guidance | Coordination skill fills gap; manual strategy |
| No semantic vector search in memory | SQLite LIKE search; cannot do "find similar findings from past engagements" | Adequate for single-engagement recall |

---

## 7. Engagement-Type Readiness Assessment

| Engagement Type | Readiness | Notes |
|---|---|---|
| **Web App Pentest (WAPT)** | ✅ **Production Ready** | `/web-chain` is fully autonomous. 6 deep skills. 40+ techniques. 5-check validation. PDF report gate. |
| **API Security Testing** | ✅ **Production Ready** | OWASP API Top 10 complete. REST/GraphQL/gRPC. BOLA, mass assignment, rate limiting, JWT. |
| **Mobile App Pentest (MAPT)** | ✅ **Production Ready** | Full OWASP MASVS (7 categories). Android + iOS. MobSF + Frida + drozer + objection. |
| **Wireless Penetration Testing** | ✅ **Production Ready** | WPA2/3, PMKID, evil twin, WPA-Enterprise PEAP downgrade, Bluetooth. Hardware required. |
| **Network / Infrastructure** | ✅ **Production Ready** | Full AD attack chain (enumeration → Kerberoasting → lateral movement → secretsdump). |
| **Source Code Review** | ✅ **Production Ready** | 12 scanner types. FP eradication (50+ patterns). Excel dashboard. No raw source needed. |
| **Cloud Security** | ✅ **Production Ready** | AWS/Azure/GCP. Pacu, ScoutSuite, Prowler, Trivy, K8s. IAM, metadata, container escape. |
| **DFIR** | ✅ **Production Ready** | Volatility3, disk imaging with hash verification, YARA, IOC extraction, timeline analysis. |
| **Blockchain Security** | ⚠️ **Specialist Ready** | Slither + Mythril + Echidna covers smart contract audit well. Not production hardened for DeFi protocol review. |
| **Bug Bounty (HackerOne)** | ⚠️ **Specialist Ready** | HackerOne API submission works. Missing: continuous mode, swarm, scope-change monitoring. |
| **AI / LLM Threat Testing** | ⚠️ **Specialist Ready** | Prompt injection and jailbreak vectors covered. No automated OWASP LLM Top 10 benchmark suite. |
| **Social Engineering** | ⚠️ **Specialist Ready** | GoPhish campaigns and pretexting covered. Missing: training module, scale tracking, vishing recording. |
| **Red Team** | ❌ **Not Ready** | No C2 infrastructure. No persistence. No defense evasion. No lateral movement automation. Recon + initial-access only. |

---

## 8. Overall Scoring

| Dimension | Score | Benchmark | Notes |
|---|---|---|---|
| Domain breadth | **9.5 / 10** | Best in open-source class | No other platform covers 9 engagement types |
| Technical depth per domain | **8.0 / 10** | Comparable to PentAGI | Weaker than Burp Pro on complex web; stronger on mobile/wireless/blockchain |
| Automation level | **7.0 / 10** | Mid-tier vs. NodeZero / Pentera | `/web-chain` is fully autonomous; most skills semi-automated |
| Evidence quality | **9.0 / 10** | Enterprise-grade | 5-check mechanical validation + structured finding-NNN/ is unique in open-source |
| Cross-session persistence | **7.0 / 10** | Functional | SQLite memory works; no semantic vector search (PentAGI has pgvector + Neo4j) |
| Security hardening | **9.0 / 10** | Best in open-source class | Prompt injection + scope enforcement are unique combination |
| Report quality | **7.0 / 10** | Adequate for professional delivery | Single template; no compliance appendix |
| Red team capability | **2.0 / 10** | Critical gap | No C2; no persistence; no defense evasion |
| Continuous scanning | **1.0 / 10** | Critical gap | Session-based only |
| **Overall** | **7.5 / 10** | **Top-tier open-source AI pentest platform** | Closes most gaps vs. commercial platforms; two hard limitations remain |

### Benchmark Context

| Platform | Approximate Score | Type |
|---|---|---|
| XBOW | 9.0 | Commercial AI (enterprise) |
| NodeZero | 8.5 | Commercial AI (enterprise) |
| Pentera | 8.5 | Commercial automated |
| **Tzar-Bot** | **7.5** | **Open-source AI** |
| PentAGI | 7.0 | Open-source AI |
| PentestGPT | 6.5 | Open-source AI |
| Burp Suite Pro | 7.0 | Commercial (web only) |
| CAI | 6.0 | Open-source AI |
| ReconFTW | 5.5 | Open-source (recon only) |

---

## 9. Recommendations

### Priority 1 — Close the Red Team Gap

**Action:** Create `skills/red-team/SKILL.md` covering:
- Sliver C2 setup (implant generation, HTTPS/DNS listeners, team server)
- Havoc framework (demon agents, OPSEC-safe post-exploitation)
- Lateral movement playbooks (WMI, PsExec, DCOM, SSH hopping)
- Credential harvesting chains (LSASS, DPAPI, browser credentials)
- Persistence mechanisms (scheduled tasks, registry, startup folders, cron)
- Defense evasion reference (process injection, AMSI bypass, ETW patching)
- C2 traffic profiling (domain fronting, JA3 evasion, Malleable C2 basics)

This unblocks the `RedTeam/` engagement type for professional delivery.

**Effort:** Medium (2-3 days). No new tools needed — Sliver and Havoc are on Kali.

---

### Priority 2 — Add Compliance-Mapped Report Appendix

**Action:** Extend `generate-report.py` to include a compliance appendix table:

```
Finding ID | CWE | OWASP A0X:2021 | PCI-DSS v4 | ISO 27001 | NIST SP 800-53
```

This significantly increases report value for enterprise clients operating under regulatory frameworks and is a 2-4 hour addition.

---

### Priority 3 — Wire Continuous Mode via `/schedule`

**Action:** Create a `/schedule`-compatible wrapper that runs `web-chain` against saved engagement targets from `memory.db` on a cron interval. Adds regression scanning capability after remediation without architecture changes.

**Effort:** Low. Claude Code's schedule skill + session-memory.py `list --status active` provides the targeting data.

---

### Priority 4 — Add Playwright MCP for Authenticated Session Testing

**Action:** Wire Playwright MCP into executor agent prompts for web-app-logic and authentication phases. Enables multi-step authenticated workflow testing beyond what `curl` can reach (OAuth flows, MFA enrollment, stateful wizards).

**Effort:** Medium. Playwright MCP is installable; executor-role.md needs a browser automation section.

---

### Maintain These Advantages

The following capabilities are unique market differentiators — protect and extend them:

- **Keep scope-check.py hook** — only H-mmer and tzar-bot have tool-layer scope enforcement in open-source AI pentest
- **Keep scrub-web-content.py** — prompt injection defense at content layer complements CAI's runtime-layer defense
- **Keep the 5-check validation gate** — separates tzar-bot's findings from raw scanner output that most platforms produce
- **Keep `/skill-update`** — no competitor has a self-improvement loop; it compounds value over engagements
- **Extend MCP server** as tools grow — MCP is the dominant integration pattern in 2026; maintain the `tzar-bot` server as the canonical tool interface

---

## 10. Market Landscape Reference

### AI Pentest Framework Benchmarks (2026)

| Metric | Result | Context |
|---|---|---|
| End-to-end autonomous pipeline success | 31% | Best of 9 LLMs tested (PentEval study) |
| One-day CVE exploitation (with advisory hints) | 87% | GPT-4 (controlled lab) |
| One-day CVE exploitation (no description) | 7% | GPT-4 (controlled lab) |
| HackTheBox hard challenge success | ~0% | Most LLMs |
| Sub-task completion rate | 79.17% | xOffense (fine-tuned Qwen3-32B) |
| Multi-agent vs. single-agent improvement | 4.3× | HPTSA (planner/executor/summarizer) |
| XBOW validated HackerOne bugs | 1,060+ | Commercial; #1 H1 leaderboard |
| Cost per assessment (AI vs. traditional) | $0.30–$28.50 vs. $15,000–$50,000 | 1,000× cost reduction at lower depth |

> **Lab-to-real gap:** Published benchmarks use controlled conditions that inflate results. Real-world autonomous pentesting is substantially less capable than headlines suggest. Human expertise for business logic, privilege escalation chains, and trust manipulation remains irreplaceable.

---

### Pricing Reference

| Tool | Model | Cost |
|---|---|---|
| Tzar-Bot | Free + LLM API | $0 platform cost |
| PentAGI | Free + LLM API | $0 platform cost |
| Burp Suite Pro | Annual per-user | $449–499/user/yr |
| Cobalt Strike | Annual per-user | ~$3,500/user/yr |
| Nessus Professional | Annual | $3,390–5,365/yr |
| Rapid7 InsightVM | Per-asset | $1.93–26.25/asset/month |
| Tenable WAS | Per-FQDN | ~$7,434/yr (5 FQDNs) |
| GoPhish (cloud) | Monthly | ~$350/month |
| KnowBe4 | Annual | ~$15,000/yr |
| NodeZero | Subscription | Unlimited scans, contact pricing |
| Pentera | Subscription | ~$100M ARR; contact pricing |
| XBOW | Enterprise | Contact; $237M funded |

---

### Industry Trends Relevant to Tzar-Bot Positioning (2026)

1. **MCP as infrastructure standard** — MCP-native security tools are the fastest-growing integration pattern. Tzar-bot's 9-tool MCP server is aligned with where the industry is heading.

2. **Planner/executor/validator wins** — The multi-agent pattern tzar-bot implements produces 4.3× better results than single-agent baselines across all published benchmarks.

3. **Continuous autonomous pentesting replacing point-in-time** — The economic shift ($0.30/engagement vs. $15,000) makes continuous testing viable for mid-market. Tzar-bot's session model is the primary limitation vs. this trend.

4. **Bug bounty AI integration** — 560+ autonomous AI agent HackerOne submissions in 2025; 210% jump in valid AI vulnerability reports. Tzar-bot is positioned to contribute here with the BugBounty/ engagement type.

5. **AI agent security as a new market** — MCP servers are attack surfaces; tzar-bot's prompt injection defense and scope enforcement are ahead of the market in addressing this.

---

*Report generated: 2026-06-04 | Tzar-Bot v1.0 | tzar-bot*
