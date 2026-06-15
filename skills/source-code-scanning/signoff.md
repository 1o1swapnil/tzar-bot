# Engagement Sign-off

**Engagement:** <fill>
**Client:** <fill>
**Consultant:** <fill>
**Report-driven assessment (no raw source reviewed):** Yes

---

## What we attest to

- We analyzed the scanner artifacts listed in `inventory.md` using the methodology described in `report/consultant.md` and `Methodology` tab of `dashboard.xlsx`.
- Findings shown in `findings.dedup.jsonl` and the `Findings` tab were normalized, deduplicated, and classified per the documented severity model.
- Each entry on the `Suppressed (FPs)` tab carries a written justification matching a pattern in `references/false_positive_patterns.md`.
- Each entry on the `Accepted Risk` tab is acknowledged by the named approver with expiry date.

## What we explicitly do NOT attest to

- Vulnerabilities the scanners did not produce. False negatives caused by rule-pack version, disabled rules, partial scans, or excluded paths are out of scope. See `Coverage Gaps` tab.
- Runtime exploitability beyond what cross-tool corroboration (SAST↔DAST↔SCA) demonstrates.
- Code-level review of business logic — no source code was shared.
- Future findings introduced after the scan window `<scan_start>` → `<scan_end>`.

## Required next steps

1. Re-scan after remediation; mark `status = fixed` only after a clean re-scan.
2. Refresh rule packs and rescan at least quarterly (sooner if regulated).
3. Review the `Accepted Risk` tab on each expiry date.

---

**Consultant** _________________________ Date: __________

**Client (Security Lead)** _________________________ Date: __________

**Client (Engineering Lead)** _________________________ Date: __________
