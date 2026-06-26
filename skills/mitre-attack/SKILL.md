---
name: mitre-attack
description: Map findings to MITRE ATT&CK techniques across Enterprise, Mobile and ICS (OT) matrices using the local offline index (tools/mitre-lookup.py). Use when adding ATT&CK technique IDs to a finding, building a report's ATT&CK appendix, threat-modelling by tactic, or looking up a technique by ID/keyword. 中文触发词：MITRE、ATT&CK、攻击技术映射、战术
allowed-tools: [Bash, Read, Write]
---

# MITRE ATT&CK Mapping

Tzar-bot ships a local, offline MITRE ATT&CK index covering all three matrices:
**Enterprise**, **Mobile**, and **ICS (OT)**. Use it to attach authoritative technique
IDs to every finding and to build the ATT&CK appendix in reports.

Data lives in `data/mitre/{enterprise,mobile,ics}.json` (distilled from the official
[attack-stix-data](https://github.com/mitre-attack/attack-stix-data)). Refresh with
`update` when MITRE publishes a new version.

## Quick commands

```bash
# Refresh the local index (downloads + distills STIX; ~63 MB one-time)
python3 tools/mitre-lookup.py update --matrix all

# Coverage of the local index
python3 tools/mitre-lookup.py stats

# Look up a technique by ID (works for sub-techniques Txxxx.yyy)
python3 tools/mitre-lookup.py lookup T1133
python3 tools/mitre-lookup.py lookup T1417.001 --matrix mobile

# Keyword search within a matrix
python3 tools/mitre-lookup.py search "ssl vpn external" --matrix enterprise
python3 tools/mitre-lookup.py search "plc modbus" --matrix ics

# MAP a finding description -> candidate techniques (the core workflow)
python3 tools/mitre-lookup.py map "override portal exposed over cleartext http" --limit 8

# All techniques under a tactic (per matrix)
python3 tools/mitre-lookup.py tactic credential-access --matrix mobile
python3 tools/mitre-lookup.py tactics --matrix all
```

Add `--json` to `lookup/search/map/tactic/tactics/stats` for machine-readable output
(used by the MCP `mitre_lookup` tool and report tooling).

## When to use which matrix
- **enterprise** — network, web, API, cloud, infra, AD, identity engagements (default).
- **mobile** — Android/iOS app (MAPT) findings: device data, app permissions, SMS/OTP intercept, etc.
- **ics** — OT / SCADA / industrial engagements: PLC, Modbus, HMI, historian, safety-instrumented systems.
- **all** — let the tool surface the best match across matrices (good for `map`).

## Mapping workflow (per finding)
1. Run `map "<finding title + impact sentence>" --matrix <relevant>` to get candidate technique IDs.
2. Confirm each candidate by `lookup <Txxxx>` — read the description/tactics; keep only techniques whose
   behaviour the finding actually demonstrates (don't over-map).
3. Record the chosen `Txxxx` IDs + tactic in the finding's `description.md` (MITRE ATT&CK row) and in the
   report's ATT&CK appendix (`OUTPUT_DIR/mitre-attack-mapping.md`).
4. For latent/conditional risk (e.g. a CVE not currently exploitable), map to the technique but label it
   **latent** so it isn't read as a live finding.

## Integration points
- **MCP:** `mitre_lookup` tool (mcp-server.py) — `action` = lookup|search|map|tactic|tactics|stats.
- **Reports:** use `map`/`lookup` output to populate the ATT&CK appendix; mirrors the per-finding
  MITRE table format already used in network/infra engagements.
- **Caveat:** `map`/`search` are keyword-ranked heuristics, not ground truth — always verify a candidate
  with `lookup` before asserting it in a client report.
