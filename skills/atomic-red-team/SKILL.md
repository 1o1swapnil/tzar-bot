---
name: atomic-red-team
description: Look up Red Canary Atomic Red Team detection-validation tests by MITRE ATT&CK technique, and chain a finding to its atomic tests (purple-team / BAS). Use to validate blue-team detection coverage for techniques surfaced in an engagement, map a finding to runnable atomics, or browse tests for a technique/platform. READ-ONLY lookup — execution stays an authorized lab step. 中文触发词：原子红队、检测验证、紫队、ATT&CK测试
allowed-tools: [Bash, Read, Write]
---

# Atomic Red Team (detection validation)

Tzar-bot ships a local, offline index of [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
(Red Canary, MIT) — small, discrete tests for individual **MITRE ATT&CK techniques**, used to validate
whether blue-team detections (EDR/SIEM/SOC) actually fire. This is the **purple-team / BAS** complement to
the offensive testing and the [[mitre-attack]] mapping.

Data: `data/atomic-red/index.json` (distilled from the upstream `atomics/Indexes/index.yaml`).
Refresh with `update` (needs PyYAML) when Red Canary publishes new atomics.

## SAFETY — read-only by design
This tool **lists and displays** atomic tests and their commands; it **never executes them**. Atomic
tests run real adversary TTPs. Execute them **only in an authorized lab** via Red Canary's
`Invoke-AtomicRedTeam` framework (`Invoke-AtomicTest <Txxxx>`), never inline from an engagement.

## Quick commands
```bash
# Refresh local index (one-time / on upstream change; needs PyYAML)
python3 tools/atomic-red.py update

# Coverage
python3 tools/atomic-red.py stats

# Tests for a technique (optionally platform-filtered)
python3 tools/atomic-red.py lookup T1133
python3 tools/atomic-red.py lookup T1040 --platform linux

# Search tests by name/description
python3 tools/atomic-red.py search "packet capture" --platform linux

# Full detail incl. command + cleanup for one test
python3 tools/atomic-red.py show T1040 --test 1
python3 tools/atomic-red.py show T1003 --guid <auto_generated_guid>

# Chain: finding text -> ATT&CK techniques (mitre-lookup) -> atomic tests
python3 tools/atomic-red.py for-finding "external remote service exposed; credential sniffing" --limit 5
```
Add `--json` to any command for machine-readable output (used by the MCP `atomic_red` tool).

## Workflow (engagement → detection validation)
1. After findings are mapped to ATT&CK ([[mitre-attack]]), run
   `for-finding "<finding title + impact>"` to get the candidate techniques and their atomic tests.
2. Review each test with `show <Txxxx> --test N` — read the command, platforms, elevation, and cleanup.
3. Hand the technique IDs to the blue team to run in an **authorized lab** (`Invoke-AtomicTest <Txxxx>`)
   and confirm the detection fires; record gaps.
4. Feed detection gaps into the report's recommendations and [[mid-engagement-ir-detection]] baselines.

## Integration points
- **MCP:** `atomic_red` tool (mcp-server.py) — action = lookup|search|show|for-finding|stats.
- **Cross-tool:** `for-finding` calls `mitre-lookup map` then resolves atomics per technique; keep the
  MITRE index built (`python3 tools/mitre-lookup.py update --matrix all`).
- **Caveat:** not every ATT&CK technique has an atomic test (esp. ICS/recon); a `0 atomic test(s)` result
  is normal, not an error.
