# Tzar-Bot — Fix Backlog

Pick any fix and say **"apply fix N"** to implement it.

Fixes are grouped by severity. Within each group they are ordered by value delivered per effort.

---

## CRITICAL — Blocks Professional Engagement Delivery

---

### Fix 1 — Red Team C2 Skill
**Gap:** `RedTeam/` engagement type exists but the skill is missing. No C2, no persistence, no lateral movement, no defense evasion.
**Score impact:** Red Team readiness: 2/10 → 8/10
**Files created:** `skills/red-team/SKILL.md`, `.claude/skills/red-team.md` symlink, settings.json entry
**Effort:** Medium

**Covers:**
- Sliver C2 — implant generation, HTTPS/DNS listeners, armory, team server setup
- Havoc framework — demon agents, OPSEC-safe post-exploitation, sleep obfuscation
- Lateral movement — WMI, PsExec, DCOM, SSH hopping, SMB named pipes
- Credential harvesting — LSASS dump (procdump, nanodump, pypykatz), DPAPI, browser creds, SAM/SYSTEM
- Persistence — scheduled tasks, registry Run keys, WMI subscriptions, cron/init.d, startup folders
- Defense evasion — AMSI bypass, ETW patching, process injection (DLL, shellcode), PPL bypass
- C2 traffic profiling — domain fronting, JA3/JA4 evasion, Malleable C2 profile basics
- Exfiltration — HTTPS, DNS tunneling, cloud storage, steganography
- OPSEC checklist — log sources to avoid, artefact cleanup

---

### Fix 2 — Continuous / Scheduled Scanning Mode
**Gap:** Every engagement stops when the conversation ends. Cannot do regression scanning after remediation or always-on monitoring.
**Score impact:** Continuous scanning: 1/10 → 6/10
**Files created:** `tools/continuous-scan.py`, updated `skills/coordination/SKILL.md`
**Files modified:** `tools/session-memory.py` (add `targets` command)
**Effort:** Low-Medium

**Covers:**
- `tools/continuous-scan.py` — reads active engagements from memory.db, re-runs web-chain phases on a schedule
- `session-memory.py targets` subcommand — lists active engagement OUTPUT_DIRs with target URLs
- Coordinator guidance for scheduling continuous runs via `/schedule` skill
- Delta reporting — only surface new findings vs. previous run
- Automatic `status` update (active → monitored) in memory.db

---

### Fix 3 — Playwright MCP for Authenticated Session Testing
**Gap:** Cannot intercept or replay authenticated sessions. OAuth flows, MFA enrollment, multi-step wizards, stateful checkout flows cannot be tested at depth.
**Score impact:** Technical depth: 8/10 → 9/10 (web workflows)
**Files modified:** `skills/coordination/reference/executor-role.md`, `skills/web-app-logic/SKILL.md`, `skills/authentication/SKILL.md`
**Files created:** `skills/coordination/reference/playwright-guide.md`
**Effort:** Low (Playwright MCP already installable; mostly documentation)

**Covers:**
- Playwright MCP installation and registration in `.claude/settings.json`
- Executor-role.md: new "Browser Automation" section with session capture patterns
- web-app-logic skill: authenticated multi-step workflow testing via Playwright
- authentication skill: OAuth/OIDC flow testing, MFA enrollment bypass attempts
- Evidence capture: screenshot + HAR export to `OUTPUT_DIR/evidence/`
- Session cookie extraction and reuse in subsequent curl commands

---

## HIGH VALUE — Significantly Improves Deliverable Quality

---

### Fix 4 — Compliance-Mapped Report Appendix
**Gap:** Report has no regulatory mapping. Enterprise clients (PCI-DSS, ISO 27001, HIPAA, NIST) need findings mapped to their control framework.
**Score impact:** Report quality: 7/10 → 9/10
**Files modified:** `tools/generate-report.py`
**Effort:** Low-Medium

**Covers:**
- New appendix section in PDF: per-finding compliance table
- Columns: Finding ID | CWE | OWASP A0X:2021 | PCI-DSS v4 Requirement | ISO 27001:2022 Control | NIST SP 800-53 Control | HIPAA Safeguard
- Static mapping table in `tools/generate-report.py` (CWE → frameworks)
- Executive summary compliance posture paragraph (auto-generated from finding severities)
- Option flag: `--compliance pci|iso|nist|hipaa|all`

---

### Fix 5 — HackerOne Skill Depth
**Gap:** Current H1 skill only covers scope validation and API report submission. Missing: continuous scope-change monitoring, duplicate detection, CVSS-to-bounty estimation, and response tracking.
**Score impact:** Bug Bounty readiness: Specialist Ready → Production Ready
**Files modified:** `skills/hackerone/SKILL.md`
**Effort:** Low

**Covers:**
- Scope-change monitoring (poll H1 API for program updates)
- In-scope asset verification before each test (live check, not cached)
- Duplicate detection via H1 API before submission
- CVSS-to-bounty range estimation (program-specific payout tables)
- Submission status tracking (new → triaged → resolved)
- H1 Markdown report template with all required sections
- Common H1 rejection reasons and how to avoid them

---

### Fix 6 — HackTheBox Skill Depth
**Gap:** Current HTB skill is shallow — VPN connect + basic recon + flag submit. Missing machine-type strategy, writeup structure, and HTB API integration for machine info.
**Score impact:** HTB engagement quality significantly improved
**Files modified:** `skills/hackthebox/SKILL.md`
**Effort:** Low

**Covers:**
- Machine-type detection and strategy selection (Linux easy/medium/hard, Windows AD, web-focused)
- HTB API: fetch machine info, difficulty rating, hints, user/root blood
- Enumeration checklists per machine type (Linux, Windows, AD, web)
- Common HTB foothold patterns (SSTI in templates, deserialization, SQL injection, API keys in source)
- Privilege escalation decision tree (Linux: SUID → sudo → cron → capabilities → kernel; Windows: SeImpersonate → AlwaysInstallElevated → unquoted path → token impersonation)
- Writeup generation template
- Flag submission via HTB API with evidence capture

---

### Fix 7 — OWASP LLM Top 10 Benchmark Suite for AI Threat Testing
**Gap:** `ai-threat-testing` skill covers attack techniques but has no structured test suite mapped to OWASP LLM Top 10 (2025 edition). No pass/fail scoring.
**Score impact:** AI/LLM Threat Testing: Specialist Ready → Production Ready
**Files modified:** `skills/ai-threat-testing/SKILL.md`
**Files created:** `config/payloads/llm-top10/` (payload sets per category)
**Effort:** Medium

**Covers:**
- LLM01: Prompt Injection — 20 direct + 15 indirect payloads, detection criteria
- LLM02: Insecure Output Handling — XSS via LLM output, code injection via code generation
- LLM03: Training Data Poisoning — detection probes (membership inference, data extraction)
- LLM04: Model Denial of Service — adversarial inputs, context exhaustion, recursive prompts
- LLM05: Supply Chain Vulnerabilities — third-party model provenance checks
- LLM06: Sensitive Information Disclosure — PII extraction, system prompt leakage, training data recall
- LLM07: Insecure Plugin Design — tool abuse, privilege escalation via plugins
- LLM08: Excessive Agency — autonomous action scope testing
- LLM09: Overreliance — false information injection, hallucination exploitation
- LLM10: Model Theft — fingerprinting, extraction attacks
- Scoring matrix: Pass/Fail/Partial per category → overall LLM security posture score

---

### Fix 8 — Social Engineering Scale Dashboard
**Gap:** GoPhish campaigns run but metrics are read manually. No aggregated campaign dashboard, no training module integration, no vishing recording workflow.
**Score impact:** Social Engineering readiness improved
**Files modified:** `skills/social-engineering/SKILL.md`
**Files created:** `tools/se-dashboard.py`
**Effort:** Medium

**Covers:**
- `tools/se-dashboard.py` — reads GoPhish API, aggregates campaign metrics (open rate, click rate, submission rate, time-to-first-click, credential harvest count)
- Outputs: metrics.json + markdown table + bar chart (ASCII)
- Vishing: call recording workflow (sox/ffmpeg), transcript template, outcome tracking
- Pretexting: scenario library (IT support, HR, vendor, executive EA, building management)
- Phishing timeline: day-by-day send schedule, follow-up cadence
- Evidence capture: screenshot of credential harvest page, GoPhish event log export

---

## MODERATE — Improves Capability or Coverage

---

### Fix 9 — Real-Time Critical Finding Notifications
**Gap:** Findings write to disk only. No alert when a P0/P1 finding is confirmed during a long engagement.
**Files created:** `tools/notify.py`
**Files modified:** `skills/coordination/SKILL.md`, `skills/coordination/reference/executor-role.md`
**Effort:** Low

**Covers:**
- `tools/notify.py` — sends webhook notification (Slack/Discord/Teams/generic) on P0/P1 finding
- Triggered by coordinator after validator confirms critical finding
- Payload: finding title, severity, CVSS, affected component, OUTPUT_DIR path
- Config: `NOTIFY_WEBHOOK_URL` in `.env` (read via env-reader.py)
- Coordinator rule: "After validator confirms P0/P1 finding → run `python3 tools/notify.py`"

---

### Fix 10 — Multi-Target Lateral Movement Coordination
**Gap:** AD pivot chains (initial access on Target A → lateral move to Target B) require spawning separate engagements with no link between them. No shared context across targets in the same engagement.
**Files modified:** `tools/session-memory.py` (add `pivot` subcommand), `skills/infrastructure/SKILL.md`
**Effort:** Medium

**Covers:**
- `session-memory.py pivot <src_output_dir> <dst_output_dir> --credential <hash/password> --via <technique>` — links two engagements and records the pivot credential/method
- `session-memory.py load` updated to display pivot chains when showing engagement context
- `infrastructure/SKILL.md`: new "Lateral Movement" section covering pivot chain documentation
- Coordinator guidance for multi-hop engagements (separate OUTPUT_DIRs linked via pivots)
- Pass-the-hash, Pass-the-Ticket, SSH key reuse across linked engagements

---

### Fix 11 — Autopsy DFIR Integration
**Gap:** DFIR skill is CLI-only (Sleuth Kit). Autopsy provides GUI forensics with timeline, keyword search, email artifact extraction, and web artifact analysis.
**Files modified:** `skills/dfir/SKILL.md`
**Effort:** Low

**Covers:**
- Autopsy case creation from disk image (CLI mode, no GUI required)
- Autopsy ingest modules: keyword search, file type analysis, recent activity, hash lookup, email parser
- Output: HTML report export → `OUTPUT_DIR/reports/autopsy-report.html`
- Integration with existing Sleuth Kit timeline (Autopsy uses TSK under the hood)
- When to use Autopsy vs. raw Sleuth Kit (complex investigations vs. quick triage)

---

### Fix 12 — Foundry Invariant Test Integration (Blockchain)
**Gap:** `blockchain-security` skill covers Slither (static), Mythril (symbolic), Echidna (fuzzing) but not Foundry's invariant testing mode — the most developer-aligned approach.
**Files modified:** `skills/blockchain-security/SKILL.md`
**Effort:** Low

**Covers:**
- Foundry `forge test --match-test invariant_` workflow
- Writing invariant test functions targeting common DeFi attack surfaces (reentrancy, flash loan, oracle manipulation)
- Foundry coverage report generation (`forge coverage`)
- Forge script for PoC deployment on local anvil fork
- Integration with existing Echidna findings (Echidna for property-based → Foundry for PoC confirmation)

---

### Fix 13 — Azure AD Deep Modules
**Gap:** `cloud-containers` skill covers AWS deeply (Pacu, ScoutSuite, metadata SSRF) but Azure AD-specific attacks (PRT token theft, Conditional Access bypass, device code phishing) are not covered.
**Files modified:** `skills/cloud-containers/SKILL.md`
**Effort:** Medium

**Covers:**
- Azure AD enumeration (AzureHound, ROADtools)
- Primary Refresh Token (PRT) extraction and abuse
- Conditional Access policy bypass techniques
- Device code phishing flow
- Azure managed identity token theft via SSRF
- MicroBurst: credential dumping, storage enumeration, key vault access
- Azure AD Pass-the-PRT
- Illicit consent grant attack (OAuth app registration)

---

### Fix 14 — Semantic Vector Search in Memory
**Gap:** `session-memory.py` uses SQLite LIKE search. Cannot answer "find engagements where we found JWT vulnerabilities" or "what bypass worked against Cloudflare WAF before".
**Files modified:** `tools/session-memory.py`
**Files created:** `tools/memory-embed.py`
**Effort:** High

**Covers:**
- `tools/memory-embed.py` — generates embeddings for findings, vectors, notes using local model (sentence-transformers via ollama or a lightweight API call)
- Stores embeddings in SQLite `vec` extension (sqlite-vec) or a sidecar FAISS index
- `session-memory.py search --semantic "JWT algorithm confusion bypass"` — returns ranked results by cosine similarity
- Falls back to LIKE search if embedding model unavailable
- Privacy-safe: embeddings generated locally, never sent to external service

---

### Fix 15 — Kismet Passive Wireless Detection
**Gap:** `wireless` skill covers active attacks (airodump, hcxdumptool, bettercap) but not passive multi-protocol detection (Zigbee, Bluetooth LE, Z-Wave, 802.15.4).
**Files modified:** `skills/wireless/SKILL.md`
**Effort:** Low

**Covers:**
- Kismet setup and launch (drone/server/web-UI modes)
- Passive multi-protocol detection: WiFi, Bluetooth, BLE, Zigbee (with compatible SDR/adapter)
- Kismet output parsing: device list → `OUTPUT_DIR/recon/kismet-devices.json`
- IoT device fingerprinting from Kismet device records
- Correlating Kismet passive discovery with active airodump-ng targeting
- Hardware requirements for each protocol (HackRF, YARD Stick One, TI CC2531)

---

### Fix 16 — Burp Suite MCP Server Wrapper
**Gap:** No intercepting proxy capability. Playwright MCP covers browser automation but not HTTP-level request interception, modification, and replay.
**Files created:** `tools/burp-mcp-server.py` (wraps Burp REST API), updated `.mcp.json`
**Effort:** High

**Covers:**
- Burp Suite Professional REST API wrapper as MCP tools
- MCP tools exposed: `burp_start_scan`, `burp_get_issues`, `burp_send_to_repeater`, `burp_get_proxy_history`, `burp_add_scope`, `burp_export_sitemap`
- Requires Burp Suite Professional (local install)
- Executor agents can use `burp_send_to_repeater` to replay modified requests
- Evidence capture: Burp issue export → `OUTPUT_DIR/findings/finding-NNN/evidence/burp-issue.xml`
- Scope sync: Burp scope ← engagement.json scope list

---

### Fix 17 — CRM / Ticket Integration
**Gap:** No SLA tracking, remediation status sync, or client-facing ticket creation from findings.
**Files created:** `tools/ticket-create.py`
**Files modified:** `skills/coordination/SKILL.md`
**Effort:** Medium

**Covers:**
- `tools/ticket-create.py` — creates tickets from validated findings in Jira, Linear, or GitHub Issues
- Config: `TICKET_SYSTEM`, `TICKET_PROJECT_KEY`, `TICKET_API_URL`, `TICKET_TOKEN` in `.env`
- Ticket content: finding title, severity, CVSS, steps to reproduce, remediation, evidence links
- Label/priority mapping: P0 → Critical, P1 → High, P2 → Medium, P3 → Low
- Deduplication: checks if ticket already exists before creating
- Coordinator rule: run after report gate → `python3 tools/ticket-create.py "$OUTPUT_DIR"`

---

### Fix 18 — DeFi Protocol Review Hardening
**Gap:** `blockchain-security` skill covers standard smart contract audit well but is not hardened for DeFi-specific attack surfaces: flash loan composability, MEV, oracle manipulation at scale, cross-chain bridge vulnerabilities.
**Files modified:** `skills/blockchain-security/SKILL.md`
**Effort:** Medium

**Covers:**
- Flash loan attack simulation (Foundry fork testing with Aave/Compound liquidity)
- MEV front-running and sandwich attack probes
- Oracle manipulation: price feed staleness, manipulation via thin liquidity
- Cross-chain bridge verification (msg.sender spoofing, re-entrancy via callbacks)
- Governance attack vectors (vote manipulation, timelock bypass)
- Rug pull indicators (ownership, mint function, emergency withdraw, proxy upgradability)
- DeFi-specific Slither detectors and Echidna property templates

---

### Fix 19 — Multi-Report Template System
**Gap:** Single tzar-bot-style report template. Different clients need different formats (executive brief, technical deep-dive, compliance audit, remediation tracker).
**Files modified:** `tools/generate-report.py`
**Files created:** `formats/templates/` (executive.md, technical.md, compliance.md, remediation.md)
**Effort:** Medium

**Covers:**
- `generate-report.py --template executive` — 2-page C-level PDF (risk summary, top 3 findings, business impact, risk heatmap)
- `generate-report.py --template technical` — full technical report (current default)
- `generate-report.py --template compliance` — compliance-mapped appendix, framework control coverage table
- `generate-report.py --template remediation` — finding per page with step-by-step fix instructions, code snippets
- `generate-report.py --template all` — generates all four
- Markdown intermediates written to `OUTPUT_DIR/reports/` for client editing

---

### Fix 20 — IoT / Embedded Device Testing Skill
**Gap:** No skill for IoT/embedded device testing — a growing pentest domain with no good open-source coverage.
**Files created:** `skills/iot/SKILL.md`, `.claude/skills/iot.md` symlink, settings.json entry
**Effort:** Medium-High

**Covers:**
- Firmware extraction (binwalk, Flashrom, UART/JTAG dumping)
- Firmware analysis (binwalk entropy analysis, strings, file system extraction)
- Default credentials (routersploit, common IoT default lists)
- Network service enumeration (nmap + IoT-specific NSE scripts)
- Web interface testing (admin panels, CGI, LuCI, NETCONF)
- UART/serial console access (minicom, screen, baud rate detection)
- Hardware debugging: JTAG (OpenOCD), SPI flash reading (flashrom)
- Protocol testing: MQTT (mosquitto_pub, mosquitto_sub), CoAP, Modbus, DICOM
- Known CVE database for common IoT firmware (routersploit)
- Output: firmware-analysis.md + device-attack-surface.json

---

## Summary Table

| # | Fix | Category | Effort | Impact |
|---|---|---|---|---|
| 1 | Red Team C2 Skill | Critical | Medium | Unlocks RedTeam/ engagement type |
| 2 | Continuous Scanning Mode | Critical | Low-Medium | Regression scanning, always-on monitoring |
| 3 | Playwright MCP for authenticated testing | Critical | Low | Complex auth flow testing |
| 4 | Compliance-Mapped Report Appendix | High Value | Low-Medium | Enterprise client report quality |
| 5 | HackerOne Skill Depth | High Value | Low | Bug bounty production readiness |
| 6 | HackTheBox Skill Depth | High Value | Low | HTB engagement quality |
| 7 | OWASP LLM Top 10 Benchmark Suite | High Value | Medium | AI threat testing production readiness |
| 8 | Social Engineering Scale Dashboard | High Value | Medium | Campaign metrics + vishing workflow |
| 9 | Real-Time Critical Finding Notifications | Moderate | Low | Ops efficiency on long engagements |
| 10 | Multi-Target Lateral Movement | Moderate | Medium | AD pivot chain tracking |
| 11 | Autopsy DFIR Integration | Moderate | Low | Complex forensic investigation depth |
| 12 | Foundry Invariant Test Integration | Moderate | Low | Blockchain DeFi PoC confirmation |
| 13 | Azure AD Deep Modules | Moderate | Medium | Azure AD attack coverage |
| 14 | Semantic Vector Search in Memory | Moderate | High | Cross-engagement intelligence recall |
| 15 | Kismet Passive Wireless Detection | Moderate | Low | IoT/multi-protocol passive recon |
| 16 | Burp Suite MCP Wrapper | Moderate | High | HTTP interception + request replay |
| 17 | CRM / Ticket Integration | Moderate | Medium | Client SLA tracking |
| 18 | DeFi Protocol Review Hardening | Moderate | Medium | DeFi-specific blockchain testing |
| 19 | Multi-Report Template System | Moderate | Medium | Report format flexibility |
| 20 | IoT / Embedded Device Testing Skill | Moderate | Medium-High | New domain coverage |
