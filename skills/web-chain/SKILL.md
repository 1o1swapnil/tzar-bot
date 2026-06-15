---
name: web-chain
description: Self-driving web penetration test — give it a URL, it runs all 6 phases hands-off
argument-hint: <target-url> [--mode blackbox|graybox] [--scope <domains>]
allowed-tools: [Bash, Read, Write, Agent, TaskCreate, TaskUpdate]
---

# Web Chain

Automated web penetration testing orchestrator. Give it a URL — it runs the full chain hands-off.

## Quick Start

```
/web-chain https://target.com
/web-chain https://target.com --mode graybox --scope target.com,api.target.com
```

Or say: *"run web chain on https://target.com"*

## What It Does

1. Creates OUTPUT_DIR: `YYMMDD_hhmmss_<host>/{recon,findings,logs,artifacts/validated,artifacts/false-positives,tools,reports}`
2. Reads `reference/phase-chain.md` for per-phase executor prompts
3. Runs 6 phases in sequence, parallel where noted
4. Validates all findings (one validator per finding)
5. Generates tzar-bot PDF report

## Phase Map

| Phase | Skills | Mode |
|-------|--------|------|
| 1 | osint + reconnaissance + techstack-identification | parallel |
| 2 | source-code-scanning | sequential (skip if no repo) |
| 3 | authentication | sequential |
| 4 | injection + server-side | parallel |
| 5 | client-side + api-security | parallel |
| 6 | web-app-logic | sequential |
| R | cve-risk-score + cve-poc-generator | reactive on CVE |
| V | validators | parallel (one per finding) |
| P | report generation | sequential |

`essential-tools` active throughout all phases.

## Orchestration Rules

- **Create OUTPUT_DIR first** — before any other action
- **Spawn parallel agents together** — single message with multiple `Agent(run_in_background=True)` calls
- **Wait for all agents in a phase** before triggering the next
- **Update `attack-chain.md`** after every phase — pass it to the next phase's executors
- **Phase 2 conditional** — skip if no source code or repo is accessible
- **CVE reactive** — any `CVE-YYYY-NNNNN` in any output triggers nvd-lookup.py immediately, then cve-risk-score + cve-poc-generator executors
- **Never ask the user** — make decisions autonomously, document reasoning in `attack-chain.md`
- **Report gate** — generate tzar-bot PDF before concluding

## Context Passing

Each executor receives in their prompt:
- `TARGET` — original target URL
- `OUTPUT_DIR` — shared output directory path
- `CHAIN_CONTEXT` — full contents of current `attack-chain.md`
- `SKILL_FILES` — contents of relevant SKILL.md files for this phase
- `BOUNDARIES` — scope constraints (in-scope domains/IPs)

## Reference Files

- `reference/phase-chain.md` — per-phase executor prompts and expected outputs
- `reference/context-template.md` — attack-chain.md structure and update rules
- `skills/coordination/reference/executor-role.md` — executor behavioral rules
- `skills/coordination/reference/validator-role.md` — validator 5-check protocol

## Output

All output in `YYMMDD_hhmmss_<host>/`:
- `recon/` — surface mapping results
- `findings/finding-NNN/` — confirmed vulnerabilities with PoC + evidence
- `artifacts/validated/` — validator-approved findings JSON
- `artifacts/false-positives/` — rejected findings with reason
- `reports/Penetration-Test-Report.pdf` — final deliverable
