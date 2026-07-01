# Tzar-Bot — Capability Report

| | |
|---|---|
| **Date** | 2026-06-26 |
| **Platform** | Tzar-Bot — Claude Code + Kali Linux |
| **Skills** | 69 (+ 50 deep-dive references) |
| **Tools** | 36 Python tools |
| **MCP tools** | 18 (model-agnostic) |
| **Engagement types** | 9 |
| **Test suite** | 119 smoke tests |
| **Bundled intelligence** | MITRE ATT&CK (918 techniques, 3 matrices) · Atomic Red Team (1,811 tests) |
| **Supersedes** | `tzar-bot-capability-report-2026-06-04.md` (30 skills / 10 tools — stale) |

> This report is regenerated from the live repository. Every count above is measured, not estimated.
> The detailed per-domain payload/technique tables from the 2026-06-04 edition remain valid; this
> edition refreshes the headline numbers, architecture, tooling, and the layers added since v1.0.

---

## 1. Executive Summary

Tzar-Bot is an **AI-driven penetration-testing automation platform** built on Claude Code + Kali. Its
defining principle is **"AI decides, code enforces"**: an LLM coordinator reasons and delegates, while
deterministic Python guardrails gate every target-touching action *before* it runs.

Since the v1.0 report (2026-06-04) the platform roughly **doubled** (30→69 skills, 10→36 tools) and
matured along three axes:
1. **Knowledge depth** — bundled, offline MITRE ATT&CK (Enterprise/Mobile/ICS) and Atomic Red Team
   indexes, chained so a finding maps to ATT&CK techniques and to runnable detection tests.
2. **Orchestration robustness** — six concrete multi-agent execution-reliability gaps (timeout kills,
   resource kills, rogue executors, boundary enforcement, tooling preflight, file-list scope) closed
   and tested.
3. **Cohesion** — a codified tool/skill convention (`docs/tool-conventions.md`) so the surface reads as
   one platform rather than a script collection.

The test suite grew from 61 to **119**, including an end-to-end orchestration test of the full
surface→executor→finding→validate loop.

---

## 2. Platform Architecture

### 2.1 Agent triangle
- **Coordinator (inline)** — runs in the main session, holds context, writes reasoning to
  `attack-chain.md`, delegates to executors; **never runs scanners inline** (now code-enforced, §2.3).
- **Executors (background)** — full mission context; run tools, write findings + evidence.
- **Validators (background)** — one per finding, 5-check + adversarial-panel protocol before a finding
  is reportable.
- **Autonomous runner** (`engagement-runner.py`) — a Level-3 agentic loop on the Claude API that owns
  the loop so every tool call passes a code gate; multi-executor fan-out with claim dedup. Now shares
  the concurrency + agent-registry primitives with the inline path.

### 2.2 Security hardening stack (code-enforced)
| Control | Tool | Enforces |
|---|---|---|
| Scope | `scope.py` + `scope-check.py` (PreToolUse hook) | deny-wins, default-deny, wildcard/CIDR/regex; shell-aware; resolves `-iL`/target-file flags |
| Coordinator boundary | `coordinator-guard.py` (PreToolUse hook) | blocks scanner/exploit binaries run inline during an active engagement (incl. `shell -c` wrapping) |
| Path containment | `pathguard.py` | write-containment to OUTPUT_DIR |
| Prompt injection | `scrub-web-content.py` | strips adversarial instructions (CWE-1336) from web-sourced content |
| Pacing | `rate-limiter.py` | per-host token-bucket to avoid WAF trips |
| Credentials | `env-reader.py` | the only sanctioned way to read `.env` |
| Lifecycle | `agent-supervisor.py` | spawned-process registry, hard stop, orphan reap |

### 2.3 Tool families (36 tools)
- **Knowledge lookup** — `nvd-lookup`, `mitre-lookup`, `atomic-red` (`update/lookup/search/map/stats`).
- **Orchestration & resilience** — `agent-supervisor`, `long-run`, `concurrency`, `preflight`,
  `coordinator-guard`, `engagement-runner`.
- **Engagement & state** — `init-engagement`, `engagement-state`, `session-memory`, `continuous-scan`.
- **Findings & reporting** — `validate-finding`, `generate-report`, `report-export`, `md-to-docx`,
  `md-to-pdf`.
- **Scope & safety** — `scope`, `scope-check`, `coordinator-guard`, `pathguard`, `scrub-web-content`,
  `rate-limiter`.
- **Cost/memory** — `token-meter`, `memory-search`.
All follow one convention (`docs/tool-conventions.md`): kebab-case files, `--selftest`, `--json`,
shared subcommand vocabulary, unified engagement-dir resolution (`--output-dir` / positional / `$OUTPUT_DIR`).

### 2.4 MCP server (18 tools)
`mcp-server.py` exposes the toolset model-agnostically (JSON-RPC) to Claude Code and any MCP client:
`nvd_lookup, mitre_lookup, atomic_red, validate_finding, validate_all_findings, init_engagement,
scrub_web_content, gen_nuclei_template, read_env, scope_check, memory_search, continuous_scan,
session_memory, token_meter, report_export, rate_limiter, engagement_state` (+ a Playwright MCP server
for authenticated browser-driven testing).

---

## 3. Capability Map

### 3.1 Engagement types (9)
`WAPT` · `MAPT` · `API` · `Network` · `CodeReview` · `Cloud` · `RedTeam` · `DFIR` · `BugBounty` —
each auto-routed from the prompt to a typed OUTPUT_DIR by `init-engagement.py` (which now also writes a
`preflight.json` tooling-capability matrix).

### 3.2 Skill coverage (69 skills, 15 categories)
- **Coordination / Orchestration** — `coordination`, `web-chain`.
- **Recon / OSINT** — `reconnaissance`, `osint`, `techstack-identification`.
- **Web** — `client-side`, `server-side`, `injection`, `api-security`, `web-app-logic`, `authentication`.
- **Web vuln-class depth** — `hunt-saml/nosqli/ldap/deserialization/http-smuggling/host-header/cache-poison/open-redirect/websocket/grpc`.
- **Framework-specific** — `hunt-aspnet/laravel/nextjs/nodejs/springboot`.
- **Infrastructure** — `infrastructure`, `system`, `cloud-containers`, `cloud-iam-deep`, `hunt-cicd`,
  `hunt-tls-network`, `hunt-ntlm-info`.
- **Enterprise identity & perimeter** — `m365-entra-attack`, `okta-attack`, `vmware-vcenter-attack`,
  `enterprise-vpn-attack`, `hunt-sharepoint`, `supply-chain-attack-recon`.
- **AI/ML model governance** — `bias-fairness-testing`, `model-robustness`, `model-monitoring`,
  `incident-response`.
- **Wireless / Mobile** — `wireless`, `mapt`.
- **Red Team** — `red-team`, `redteam-report-template`, `mid-engagement-ir-detection`, `atomic-red-team`.
- **Specialized** — `blockchain-security`, `ai-threat-testing`, `social-engineering`, `dfir`, `meme-coin-audit`.
- **Bug bounty & reporting** — `bb-methodology`, `bb-local-toolkit`, `bugcrowd-reporting`, `evidence-hygiene`.
- **Tooling** — `essential-tools`, `source-code-scanning`, `cve-poc-generator`, `cve-risk-score`,
  `script-generator`, `patt-fetcher`, `mitre-attack`.
- **Platform / Workflow** — `hackthebox`, `hackerone`, `github-workflow`, `skill-update`.

> Per-domain technique/payload depth (Web, Recon, Infra/AD, Cloud, MAPT, Wireless, Blockchain, AI/LLM,
> DFIR, Source review, CVE intelligence) is detailed in the 2026-06-04 report §3 and remains accurate.

### 3.3 Knowledge layer (new — bundled & offline)
- **MITRE ATT&CK** — Enterprise (697), Mobile (124), ICS/OT (97); `mitre-lookup map "<finding>"` →
  ranked techniques; auto-built into the report's ATT&CK appendix.
- **Atomic Red Team** — 1,811 detection-validation tests keyed by technique; `atomic-red map "<finding>"`
  chains finding → ATT&CK → runnable atomics (read-only; execution is an authorized-lab step).
- **CVE intelligence** — `nvd-lookup` (CVSS/severity), `gen-nuclei-template`, `cve-risk-score`,
  `cve-poc-generator`.

---

## 4. Reliability & Quality

### 4.1 Orchestration robustness (all 6 backlog items closed)
| Gap | Resolution |
|---|---|
| Long scans killed by sub-agent Bash timeout | `long-run.py` (detached, streamed, status-tracked) |
| Resource kill at high concurrency | `concurrency.py` + `long-run --retry-on-kill` (auto-lowers workers) |
| Rogue executors / manual kill | `agent-supervisor.py` (registry + stop + reap; tzar-tool-safe) |
| Coordinator boundary self-policed | `coordinator-guard.py` hook (incl. `shell -c`; stale-engagement aware) |
| Missing tool/root surfaced late | `preflight.py` capability matrix at init |
| scope-check blind to `-iL` files | resolved + validated |

### 4.2 Testing
119 smoke tests: every tool compiles, `--help`/`--selftest` exercised, plus targeted tests
(scope-check `-iL`, coordinator-guard incl. `shell -c` bypass regression, output-dir resolution,
concurrency caps, long-run retry, agent-supervisor lifecycle + reap exclusion) and an **end-to-end
orchestration test** (surface→delegate→finding→shared-registry→validate) in the autonomous runner.

---

## 5. Honest Limitations
- **Discipline-dependent:** `agent-supervisor` registration and the `TZAR_ROLE=executor` marker rely on
  the coordinator/executor doing it; `reap`-by-pattern is the safety net (run `--dry-run` first).
- **Sub-agent hook enforcement unverified end-to-end:** `coordinator-guard`'s reach into spawned
  sub-agents hasn't been confirmed in a live multi-agent run (marker opt-out is belt-and-suspenders).
- **Environment-dependent tooling:** capability assumes Kali tools; `preflight.py` now surfaces gaps,
  but UDP and privileged scans still need root.
- **Data freshness is manual:** the ATT&CK/atomic indexes refresh on explicit `update`.
- **Integration vs unit testing:** strong unit/selftest coverage plus one e2e loop; broader
  full-engagement integration testing is still thin.

---

## 6. Bottom Line
Tzar-Bot's defining strength — **deterministic safety controls underneath an LLM operator** — is now
both deeper (a 7-control hardening stack, lifecycle management) and broader (69 skills, bundled ATT&CK +
Atomic Red Team). The platform moved from *"broad but fragile under real multi-agent load"* to
*"broad, cohesive, and hardened against the failure modes that actually occur."* The next maturity step
is convergence + integration testing of the full engagement loop, not capability breadth.
