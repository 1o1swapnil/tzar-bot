# Tzar-Bot ↔ CERT-In CIGU-2026-0003 — Compliance Mapping & Gap Analysis

**Source document:** *Guidelines regarding AI-Accelerated Vulnerability Protection and Response Requirements for Original Equipment Manufacturers (OEMs), and Technology Providers* — CERT-In, Ref. **CIGU-2026-0003**, Version 1.0, dated **10 June 2026**.
**Subject platform:** Tzar-Bot — AI-assisted penetration-testing automation platform.
**Analysis date:** 12 June 2026
**Prepared for:** internal platform governance.

---

## 0. How to read this document

### 0.1 Two lenses

The CERT-In guideline is written **for OEMs and technology providers** — organisations that *ship products* into India and must defend, patch, and disclose across that product's lifecycle. Tzar-Bot is not itself a shipped product line; it is a **security-testing capability**. So every requirement is assessed through **two lenses**:

- **Lens A — Capability provider:** Can Tzar-Bot *perform or support* the testing/assessment activity the guideline demands (so that an OEM using Tzar-Bot meets that clause)? This is where most of the platform's value lands — the guideline explicitly calls for "AI-assisted vulnerability discovery techniques which include leveraging Machine Learning, LLMs, **skills files**, reasoning and automated testing." That sentence describes Tzar-Bot almost verbatim.
- **Lens B — Self-compliance:** Does the platform's *own* engineering posture (its code, its secret handling, its AI guardrails) satisfy the clause as if Tzar-Bot were the product under audit?

Where a clause is a pure **process/governance obligation** of the OEM (e.g. "senior-management sign-off", "6-hour CERT-In reporting"), Tzar-Bot can only *feed* the process; it cannot *be* the process. Those are marked **N/A (organisational)** and called out so they are not mistaken for product gaps.

### 0.2 Status legend

| Status | Meaning |
|---|---|
| ✅ **Compliant** | Tzar-Bot already provides a concrete, named capability that satisfies the clause. |
| 🟡 **Partial** | Capability exists but is incomplete (e.g. ingest-only, no generation; or a skill exists but no enforcing tool). Needs work. |
| ❌ **Gap** | No capability exists. Build required. ("Violation" in the user's phrasing.) |
| ⚪ **N/A (organisational)** | Clause is an OEM business/legal process; Tzar-Bot can supply inputs but cannot own it. |

### 0.3 The dual-use caveat (read this first)

CIGU-2026-0003 is a **defensive** guideline whose stated enemy is "misuse of AI systems for prompt injection, **automated exploitation, malicious code generation**, credential theft … " — which is, mechanically, exactly the offensive class of activity Tzar-Bot automates. Tzar-Bot stays on the compliant side of that line **only because of its governance controls**, not by accident:

- explicit **pre-authorisation** model (every engagement is authorised; `CLAUDE.md` ethics section),
- **code-enforced scope** (`scope.py` + `scope-check.py` PreToolUse hook blocks out-of-scope targets *before* a command runs),
- **non-destructive** hard rule (no DROP/DELETE/`rm -rf`/DoS),
- **prompt-injection guardrail** (`scrub-web-content.py`) and the coordinator's hard tool-use boundary.

These controls are the platform's licence to operate against this guideline. They are itemised in §7 (Self-Compliance) and should be treated as **load-bearing for compliance**, not optional hygiene.

---

## 1. Executive summary

**Headline:** Tzar-Bot is **strongly aligned** with the *testing, discovery, validation, and reporting* half of CIGU-2026-0003 — the half the guideline most emphasises (AI-assisted VAPT). It is **weak or absent** on the *product-lifecycle* half: SBOM **generation**, native dependency/SCA scanning, threat modelling, patch-management orchestration, and the formal incident/zero-day disclosure workflow with 6-hour CERT-In reporting.

**Scorecard (counts by primary lens):**

| Status | Count | Representative areas |
|---|---|---|
| ✅ Compliant | 11 | AI-assisted discovery, pen-testing breadth, source-code analysis, CVE/CVSS/EPSS/KEV scoring, finding validation, reporting, continuous re-scan, token scanning, scope/rate guardrails, AI-threat testing, red-team/BAS |
| 🟡 Partial | 9 | SBOM (ingest-only), SCA/dependency risk, AI-misuse risk rubric, zero-day/IOC handling, continuous monitoring, automated patch *notification*, credential-hygiene audit, behavioural anomaly detection, evidence/log retention |
| ❌ Gap | 5 | SBOM **generation**, native SCA scanner, **threat-modelling** capability, **patch-management** lifecycle, formal **incident-response & disclosure** workflow (incl. 6-hour reporting) |
| ⚪ N/A (organisational) | 6 | Senior-mgmt commitment, liaison officers, OEM↔CERT-In legal reporting, periodic certification issuance, customer-facing SLAs, third-party-audit engagement |

**Top 5 things to build (detail in §6):**
1. `sbom-gen.py` — emit CycloneDX/SPDX SBOM (HW/SW/crypto/AI/quantum fields) — closes the single most concrete, repeatedly-stated obligation.
2. `sca-scan.py` — native dependency / software-composition scan with CVE correlation (wrap Trivy/Grype/osv-scanner).
3. `threat-model` skill — the one capability area with **zero** coverage today.
4. `incident-response` workflow + `ioc-extract` — formal disclosure packet (IOCs, detection guidance, containment) and a CERT-In 6-hour reporting helper.
5. `patch-advisory` generator — remediation action plan (Deliverable 2) and patch-notification feed (clause 3.3) from finding data already in `state.json`.

---

## 2. Section 2 — Security Compliance Requirements

### 2.0 (a) Comprehensive vulnerability assessment — traditional **and** AI-assisted discovery

> *"…using both traditional security testing methodologies and AI-assisted vulnerability discovery techniques which include leveraging Machine Learning, LLMs, skills files, reasoning and automated testing."*

**Status: ✅ Compliant (flagship strength).**
- **Evidence:** Coordinator → executor → validator agent triangle (`skills/coordination/`), 63 skill files (the guideline's literal "skills files"), LLM-reasoning-driven hunting, automated tool orchestration (`install-hunt-tooling.sh` provisions nmap/ffuf/nuclei/sqlmap/trufflehog/ysoserial…). "Traditional" methods are wrapped by the hunt skills; "AI-assisted" is the core architecture.
- **Note:** This single clause is the platform's strongest claim to relevance under the guideline.

### 2.0 (b) Required testing types

> *source code analysis, software composition analysis, dependency risk analysis, threat modelling, penetration testing, behavioural anomaly detection, continuous security monitoring.*

| Testing type | Status | Tzar-Bot capability |
|---|---|---|
| Source code analysis | ✅ | `source-code-scanning` skill (SAST ingest/normalise: Semgrep, SonarQube, Checkmarx, Fortify), `injection` grep patterns |
| Software composition analysis | 🟡 | `source-code-scanning` **ingests** SCA output (CycloneDX/SPDX/Snyk/Trivy/Grype) — but no native scan trigger |
| Dependency risk analysis | 🟡 | `supply-chain-attack-recon` (dependency confusion, typosquat) + SCA ingest — no native dependency-CVE scan |
| Threat modelling | ❌ | **No skill or tool.** Only capability area with zero coverage |
| Penetration testing | ✅ | 40+ skills across web/API/network/mobile/cloud/wireless + `web-chain` self-driving 6-phase test |
| Behavioural anomaly detection | 🟡 | `mid-engagement-ir-detection` (baseline drift) — engagement-scoped, not a product monitor |
| Continuous security monitoring | 🟡 | `continuous-scan.py` (delta re-scans vs prior runs) — exists but not a 24×7 monitor |

### 2.0 (c) AI-enabled-service risk assessment + guardrails

> *Risk assessment on Data sensitivity, Autonomy, Connectivity, Impact; guardrails (human oversight, monitoring & logging, dependencies review) to prevent misuse for prompt injection, automated exploitation, malicious code generation, credential theft, unauthorized access, privilege escalation, social engineering, data leakage.*

**Status: 🟡 Partial.**
- **Testing side (✅):** `ai-threat-testing` skill tests targets for exactly these failure modes (prompt injection direct/indirect, system-prompt extraction, RAG poisoning, exfil).
- **Guardrail side (✅, self):** `scrub-web-content.py` strips adversarial instructions from ingested web content; coordinator tool-use boundary enforces human-in-the-loop; logging via `logs/` NDJSON + `token-meter.py`.
- **Gap (🟡):** No formal **risk-scoring rubric** that scores an AI service on the four named parameters (Data sensitivity / Autonomy / Connectivity / Impact). That is a structured deliverable the guideline implies — currently it would be done ad-hoc in prose.

### 2.0 (d) Bill of Material (BoM) — HW / SW / crypto / AI / quantum

> *Maintain inventories of products, sw versions, exposed services, APIs, cryptography, third-party libraries, dependencies; provide HW/SW/crypto/AI/quantum BoM to Indian customers including CERT-In, updated regularly.*

**Status: 🟡 Partial → leaning ❌ on generation.**
- **Evidence:** `source-code-scanning` can **ingest and normalise** an SBOM; `techstack-identification` enumerates framework/server/libs/CDN/WAF; `engagement-state.py` tracks discovered surface/services.
- **Gap:** No tool **produces** a CycloneDX/SPDX SBOM, and nothing emits the guideline's extended fields (**cryptography / AI / quantum** BoM). This is the most concrete, machine-checkable obligation in the whole document and is currently unmet. → **Build `sbom-gen.py`** (see §6, #1).

---

## 2.1 Specific Obligations

### (a) Continuous Vulnerability Assessment Reports
**Status: 🟡 Partial.** `continuous-scan.py` performs scheduled delta re-scans and records scan history; `notify.py` raises P0/P1 webhooks; `/loop` and `/schedule` can drive cadence. Missing: a "deployed-product fleet" model (the tool is engagement-scoped, not an always-on product monitor) and a scheduled report artifact.

### (b) Immediate Disclosure of Critical (CVSS 9.0–10.0) / High (7.0–8.9)
**Status: 🟡 Partial.**
- ✅ Severity scoring: `nvd-lookup.py` (CVSS v2/3.0/3.1 + band), `cve-risk-score` (CVSS+EPSS+KEV), `validate-finding.py` enforces CVSS-band ↔ severity consistency.
- ✅ Alerting: `notify.py` filters by severity and POSTs Slack/Discord/Teams/HTTP.
- 🟡/⚪ Gap: "communicate to affected organisations **and CERT-In immediately**" is an organisational disclosure act. Tzar-Bot can *generate and push* the alert; the OEM owns the legal communication. No CERT-In-format advisory packet is produced today.

### (c) Zero-Day Vulnerability Protocol
**Status: 🟡 Partial → ❌ on workflow.**
- ✅ Inputs: `cve-poc-generator`, `script-generator`, `dfir` (IOC extraction), `mid-engagement-ir-detection`.
- ❌ Gap: No **formal zero-day packet** (interim safeguards + temporary mitigation + IOCs + detection guidance + containment) assembled as a deliverable, and no immediate-notify path tagged "zero-day / active exploitation". → part of incident-response build (§6, #4).

### (d) AI-Assisted Security Testing Certification
**Status: 🟡 Partial.**
- ✅ The activities to be certified all exist: AI-assisted code analysis, automated vuln discovery, **security token scanning** (`source-code-scanning` ingests gitleaks/trufflehog; `lint-skills.py` secret scan; `osint` GitHub secrets), dependency analysis.
- 🟡 Gap: No **evidence-bundle / certification artifact** that attests "these assessments were carried out using industry-recognised tools" with run metadata. `token-meter.py` + `logs/` hold the raw telemetry but there is no certification generator.

---

## 3. Section 3 — Accelerated Patch Management and Deployment

> This section is a **product-lifecycle** obligation. Tzar-Bot is a *testing* platform, not a software-vendor patch pipeline, so most of §3 is **N/A (organisational)** for Lens A — but Tzar-Bot feeds the front of it (exploitability/risk evaluation) and could automate the advisory/notification tail.

### 3.0(b) Technical validation, exploitability analysis, attack-surface & risk evaluation; "remotely exploitable / internet-exposed / privesc / weaponised in wild"
**Status: ✅ Compliant (inputs).** `validate-finding.py` (technical validation), `cve-risk-score` (EPSS = exploit-likelihood, **KEV = weaponised-in-wild**), `nvd-lookup.py` (CVSS exploitability vector), `engagement-state.py`/`reconnaissance` (attack surface, internet-exposure). This is squarely in Tzar-Bot's wheelhouse.

### 3.1 Patch-development timelines table + interim compensatory controls
**Status: ⚪ N/A (organisational).** The IT/OT × AI-exploitable/responsibly-disclosed timeline matrix (Critical → Emergency/…, Medium → up to 90 days) is an OEM SLA. Tzar-Bot can **stamp findings with the applicable timeline band** as report metadata (cheap enhancement) but does not develop or deploy patches. Compensatory controls (virtual patching, segmentation, IPS rules, MFA, allow-listing) are recommendations the report can carry.

### 3.2 Patch Deployment Support (docs, rollback, validation scripts, integrity verification)
**Status: ⚪ N/A (organisational)** for shipping patches. ✅ adjacent: `gen-nuclei-template.py` produces a **detection/verification template** for a CVE (useful as a "did the patch take?" check). No rollback/compatibility tooling — by design.

### 3.3 Automated Patch Notification
**Status: 🟡 Partial.** `notify.py` is the right primitive (webhook fan-out) but is finding-oriented, not patch-advisory-oriented. → **Build `patch-advisory`** that turns confirmed findings + CVE data into a remediation action plan and pushes a patch/advisory notification (§6, #5). Closes both 3.3 and Deliverable 2.

---

## 4. Section 4 — Secure Development Lifecycle (SDL) Compliance

> Lens A: Tzar-Bot **tests for** SDL failures. Lens B: Tzar-Bot's **own** SDL.

### 4.x SDL practice coverage (as a *testing* capability — Lens A)

| SDL practice | Status | Capability |
|---|---|---|
| Secure architecture review | 🟡 | Done in prose by coordinator; no dedicated skill |
| Secure coding standards | ✅ | `source-code-scanning` (SAST rulesets) |
| Threat modelling | ❌ | **Missing** |
| Source code analysis | ✅ | `source-code-scanning` |
| Dynamic security testing (DAST) | ✅ | full pen-test skill set, `web-chain` |
| Penetration testing | ✅ | comprehensive |
| Dependency validation | 🟡 | ingest-only (see 2.0b) |
| Software composition analysis | 🟡 | ingest-only |
| Supply-chain risk management | 🟡 | `supply-chain-attack-recon` (offensive recon, not governance) |
| Secrets management (testing) | ✅ | token scanning via `source-code-scanning`, `osint`, `lint-skills.py` |
| Security validation prior to release | ✅ | `validate-finding.py` + validator agents |

### 4.x "Products free from hardcoded creds / insecure defaults / exposed admin / unsupported libs / debug mechanisms / insecure auth"
**Status: ✅ Compliant (as a test target checklist).** Each maps to a skill: hardcoded creds → token scanning; insecure defaults/exposed admin → `server-side`, `reconnaissance`; unsupported libs → SCA (🟡); debug mechanisms → `hunt-laravel` (APP_DEBUG), `hunt-springboot` (Actuator), `hunt-nextjs` (debug endpoints); insecure auth → `authentication`, `hunt-*` auth chains.

### 4.x SBOM maintenance
**Status: 🟡 → ❌ on generation** — same finding as §2.0(d). Repeated obligation; raises priority of `sbom-gen.py`.

### Lens B — Tzar-Bot's own SDL
**Status: ✅ Mostly compliant.** `lint-skills.py` gates skill changes and scans for secrets (AWS keys, private keys, JWTs); test smoke suite (`tools/tests/`, 61 tests) validates tool contracts; `env-reader.py` is the *only* sanctioned secret-read path; "never commit secrets/.env" is a hard rule. Improvement: no formal dependency pin/audit of Tzar-Bot's own Python deps (reportlab, etc.) — eat-your-own-dogfood SCA once `sca-scan.py` exists.

---

## 5. Section 5 — Credential and Access Management

> Lens A (testing) is strong; Lens B (platform's own IAM) is partly applicable.

### 5.x Control checklist
| Control | Lens A (test for it) | Lens B (platform itself) |
|---|---|---|
| No hardcoded creds / embedded secrets / default passwords / insecure API keys | ✅ token scanning, `authentication`, default-cred checks across `enterprise-vpn-attack`, `infrastructure` | ✅ `env-reader.py` + `lint-skills.py` secret scan + no-commit rule |
| MFA | ✅ `authentication`, `hunt-mfa-bypass` (tests MFA enforcement) | ⚪ N/A (CLI tool, no user accounts) |
| RBAC | ✅ tested via `authentication`, `cloud-iam-deep`, `okta-attack` | ⚪ |
| Privileged access mgmt / JIT / time-bound admin | ✅ `cloud-iam-deep`, `m365-entra-attack` (test for it) | ⚪ |
| Continuous authentication monitoring | 🟡 `mid-engagement-ir-detection` | ⚪ |
| **Automated security token scanning across code repos** | ✅ `source-code-scanning` (gitleaks/trufflehog ingest), `osint` (GitHub secrets), `lint-skills.py` | ✅ self-scanned |

### 5.x Periodic credential-hygiene audits + evidence no secrets in public repos
**Status: 🟡 Partial.** Capability exists (token scanning, `osint` GitHub dorking, `supply-chain-attack-recon` leaked-token detection) but there is **no scheduled "credential hygiene audit" report artifact** with pass/fail evidence. Wrap existing scanners behind a `/schedule`d job that emits an evidence file → moves to ✅.

---

## 6 (doc §6). Section 6 — Incident Response and Transparency

> Largely **organisational**, but the most actionable **product gap** in the document lives here.

### 6.x Formal IR + disclosure process; on-exploitation actions (initiate IR, notify, preserve logs/forensics, identify IOCs, assess impact, contain, coordinate)
**Status: 🟡 Partial → ❌ on workflow.**
- ✅ Forensic inputs: `dfir` (memory acquisition LiME/avml, disk imaging, Volatility 3, **IOC extraction**, log analysis), `mid-engagement-ir-detection`.
- ❌ Gap: No **incident-response workflow** that strings these into a disclosure packet (IOCs + detection guidance + containment + impact), and no notify path tagged "incident". → **Build `incident-response` workflow + `ioc-extract.py`** (§6 roadmap, #4).

### 6.x 6-hour CERT-In reporting (Section 70B, Directions 20(3)/2022 dated 28 Apr 2022)
**Status: ⚪ N/A (organisational/legal) — but tooling can help.** The legal duty to report within 6 hours is the OEM's. Tzar-Bot can ship a **CERT-In incident-report template + a countdown/notify helper** so the human meets the deadline. Currently absent.

### 6.1 Log retention (firewall/VPN/auth/endpoint/cloud/network/admin/security logs)
**Status: 🟡 Partial.** Tzar-Bot retains *its own* engagement logs (`logs/` NDJSON, `engine.log`, `session-memory.py` DB, evidence chain). It does **not** manage a customer's production log-retention estate — that is an OEM control. `dfir` *consumes* such logs during investigation. Mark N/A for production estate, ✅ for engagement evidence integrity.

---

## 7 (doc). Section 7 — Actionable Deliverables

| Deliverable | Status | Tzar-Bot position |
|---|---|---|
| **D1 — Current Security Posture Assessment** (inventory, known vulns, CVSS, patch status, attack surface, AI risks, SDL/credential status) | 🟡 Partial | Components exist (`generate-report.py`, `engagement-state.py`, CVSS scoring, `techstack-identification`) but no single "posture assessment" artifact that also covers AI-readiness + SDL + credential-hygiene status. A composite report template would close this. |
| **D2 — Vulnerability Remediation Action Plan** (CVE IDs, CVSS, affected versions, exploitation prereqs, patch availability, interim mitigation, testing reqs, deployment timelines, rollback, operational impact) | 🟡 Partial | `generate-report.py` already has a "remediation roadmap"; CVE/CVSS via `nvd-lookup`/`cve-risk-score`. Missing structured fields: affected-version matrix, patch-availability status, deployment-timeline band, rollback. → covered by `patch-advisory` (#5). |
| **D3 — Enhanced Security Compliance Commitment** (senior-mgmt sign-off, liaison officers) | ⚪ N/A | Pure organisational/legal attestation. |
| **D4 — Continuous Security Assessment & Assurance Report** (VAPT, **BAS**, config reviews, independent audits, SBOM) | 🟡 Partial | VAPT ✅ (whole platform), BAS ✅ (`red-team`, `social-engineering`), config review ✅ (`server-side`, `cloud-containers`); SBOM 🟡 (gen gap); "independent audit" ⚪. `continuous-scan.py` + `generate-report.py` produce the report shell. |
| **D5 — SDL Compliance Certification** (code review, pen-test, dependency mgmt, token mgmt, patch validation, supply-chain controls, secure release) | 🟡 Partial | Activities exist; **certification artifact** missing (same shape as obligation 2.1(d)). |

---

## 8 (doc). Section 8 — Compliance Verification and Enforcement

> *Indian organisations including CERT-In may conduct independent assessments, request evidence, engage third-party auditors.*

**Status: ✅ Compliant (Tzar-Bot is, in effect, exactly this independent-assessment toolset).** A CERT-In-aligned auditor *could run Tzar-Bot itself* to perform the independent VAPT, patch-validation (`gen-nuclei-template.py` detection templates), and configuration review the clause authorises. The evidence chain (`evidence-hygiene`, validated/false-positive artifacts, `token-meter` telemetry, immutable engagement logs) is built to withstand exactly this kind of verification request. **Mark this clause as a Tzar-Bot strength**, not a gap.

---

## 9. Consolidated gap register & remediation roadmap

Priority = (obligation explicitness in the guideline) × (effort to close) × (reuse of existing primitives).

| # | Gap | Clauses | Status now | Build | Effort | Reuses |
|---|---|---|---|---|---|---|
| 1 | **SBOM generation** (incl. crypto/AI/quantum fields) | 2.0(d), 4.x, D4 | ❌/🟡 | `tools/sbom-gen.py` → CycloneDX/SPDX + extended fields | M | `techstack-identification`, `engagement-state` surface data |
| 2 | **Native SCA / dependency-CVE scan** | 2.0(b), 4.x SDL, D2 | 🟡 | `tools/sca-scan.py` wrapping Trivy/Grype/osv-scanner, correlate to `nvd-lookup` | M | `nvd-lookup.py`, `source-code-scanning` ingest schema |
| 3 | **Threat-modelling capability** | 2.0(b), 4.x SDL | ❌ | `skills/threat-modeling/` (STRIDE/attack-tree, data-flow, trust boundaries) | M | `techstack-identification`, attack-chain.md format |
| 4 | **Incident-response & disclosure workflow** (IOCs, detection guidance, containment, zero-day packet, 6-hr CERT-In helper) | 2.1(c), §6, 6.1 | ❌/🟡 | `skills/incident-response/` + `tools/ioc-extract.py` + CERT-In report template & countdown notify | L | `dfir`, `mid-engagement-ir-detection`, `notify.py` |
| 5 | **Patch-advisory / remediation-plan generator** | 3.3, D2, b-disclosure | 🟡 | `tools/patch-advisory.py` → remediation action plan + patch-notification feed | S–M | `notify.py`, `cve-risk-score`, `state.json`, `generate-report.py` |
| 6 | **AI-misuse risk rubric** (Data sensitivity / Autonomy / Connectivity / Impact) | 2.0(c) | 🟡 | scoring template + `ai-threat-testing` extension | S | `ai-threat-testing`, `scrub-web-content` |
| 7 | **Certification / evidence-bundle generator** | 2.1(d), D5 | 🟡 | `tools/assurance-cert.py` — attest activities + run metadata | S | `token-meter`, `logs/`, validated artifacts |
| 8 | **Composite posture-assessment report (D1)** + timeline-band stamping (3.1) | D1, 3.1 | 🟡 | extend `generate-report.py` templates | S | existing report engine |
| 9 | **Scheduled credential-hygiene audit artifact** | §5 | 🟡 | `/schedule`d wrapper emitting evidence file | S | token scanners, `osint`, `/schedule` |

**Effort key:** S ≈ ≤1 day, M ≈ 2–4 days, L ≈ 1–2 weeks.

**Suggested sequencing:** #1 and #5 first (highest explicitness, high reuse, directly map to named deliverables), then #2 (unblocks SDL/D2/D4 simultaneously), then #4 (largest but closes the entire §6 + zero-day gap), then #3, #6–#9 as polish/evidence layers.

---

## 10. Self-compliance posture (Lens B summary)

Tzar-Bot, audited *as if it were the product*, is in good standing on the clauses that apply to a CLI security tool:

| Area | Posture |
|---|---|
| Secret handling | ✅ `env-reader.py` sole path; `lint-skills.py` secret scan; no-commit-secrets hard rule |
| AI guardrails | ✅ `scrub-web-content.py` prompt-injection scrubber; coordinator tool-use boundary; executor behavioural-defence rules (CWE-1336) |
| Scope / blast-radius control | ✅ `scope.py` + `scope-check.py` PreToolUse block; non-destructive hard rule; deny-wins |
| Logging / auditability | ✅ NDJSON `logs/`, `engine.log`, `session-memory.py`, `token-meter.py` telemetry |
| Own dependency hygiene | 🟡 no self-SCA yet (close with roadmap #2 dogfooded) |
| Authorisation governance | ✅ explicit pre-authorisation model, ethics section in `CLAUDE.md` |

**The dual-use line:** because Tzar-Bot automates "automated exploitation / malicious code generation" — the exact misuse CIGU-2026-0003 warns against — its compliance is *contingent on the governance controls above remaining enforced*. Any weakening of scope enforcement, authorisation, or the non-destructive rule would flip the platform from "compliance enabler" to "the threat the guideline describes." Treat those four controls as compliance-critical.

---

## 11. Bottom line

- **Where Tzar-Bot is compliant:** AI-assisted discovery, breadth of pen-testing, source-code analysis, CVE/CVSS/EPSS/KEV scoring, finding validation, reporting, token scanning, red-team/BAS, and — notably — it *is* the independent-verification toolset §8 envisions. The guideline's own wording ("AI-assisted … skills files … automated testing", "VAPT, BAS, … independent security audits") reads like a feature list of this platform.
- **Where the violations/gaps are:** **producing** SBOMs, **native** SCA/dependency scanning, **threat modelling** (zero coverage), the **incident-response/zero-day disclosure** workflow with 6-hour CERT-In reporting, and **patch-advisory/remediation-plan** generation. Five concrete builds (§9 #1–#5) close the substance of it.
- **Where it's simply not Tzar-Bot's job:** the OEM's legal/management obligations — senior-management commitments, liaison officers, the actual patch-shipping lifecycle, and the legal act of reporting to CERT-In. Tzar-Bot can feed these but cannot own them.

*Next step is yours — say which gap(s) to start on and I'll scope the build.*
