---
name: hunt-active-directory
description: Active Directory attack chain — Kerberoasting, AS-REP roasting, BloodHound, DCSync, NTLM relay/coercion (PetitPotam/PrinterBug), password spraying, ADCS ESC1-ESC8, Kerberos delegation (constrained/unconstrained/RBCD), SMB/WMI/WinRM lateral movement. Use on internal/AD engagements once a domain, foothold host, or any AD credential (user/hash/ticket) is held. Signals: ports 88/389/445/636/3268.
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere this skill references Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Hunt: Active Directory

Internal / AD engagement attack chain. This is the **quick-start router**; the full technique matrix, exact commands, and detection/OPSEC notes live in **`reference/hunt-active-directory.md`** — load it before deep testing.

> **Authorization & safety:** AD attacks are for **declared internal/RedTeam scope only**. Never run DCSync, coercion, or delegation abuse outside scope. Kerberoast/spray are noisy — spray with lockout-aware throttling (see reference). No destructive ops (no password resets on real accounts, no golden-ticket persistence on production DCs without explicit written approval).

## Entry conditions (what you need to start)

| You have | First move |
|---|---|
| **Nothing but network access** | Anonymous LDAP/SMB enum, `nxc smb <subnet>`, responder-free recon; coercion for relay |
| **Any domain creds (user/pass or hash)** | BloodHound collection → Kerberoast → AS-REP → spray → find paths to DA |
| **A foothold shell on a domain host** | Local cred harvest (LSASS/SAM), token/ticket theft, then lateral movement |
| **A machine account or NTLM hash** | RBCD, S4U, relay-to-LDAP for shadow-credentials / ADCS |
| **A domain, but no creds (external)** | Username enum via Kerberos, password spray from OSINT list, AS-REP roast |

## Attack-surface signals

```
Open ports:  88 (Kerberos)  389/636 (LDAP/S)  445 (SMB)  3268/3269 (Global Catalog)  5985/5986 (WinRM)  135 (RPC)
Hostnames:   *DC*, *ADFS*, *CA* (cert authority), WIN-XXXXXXXXXXX (default provisioning)
Leaks:       NTLM Type-2 domain/forest disclosure (chain from hunt-ntlm-info), SPNs in service banners
Recon tools: nxc (netexec), ldapsearch, kerbrute, adidnsdump, enum4linux-ng
```

## Core attack flow (depth over breadth — one path at a time)

1. **Enumerate** — `nxc`/`ldapsearch` for users, groups, computers, GPOs, trusts, password policy (lockout threshold **before** spraying).
2. **Collect the graph** — SharpHound/BloodHound (or `bloodhound-python` remote). Find shortest path from owned principal → Domain Admins / high-value.
3. **Harvest credentials** — Kerberoasting (SPN accounts), AS-REP roasting (no-preauth accounts), targeted password spray.
4. **Escalate** — ADCS ESC1-ESC8, Kerberos delegation (unconstrained/constrained/RBCD), ACL abuse (GenericAll/WriteDACL), DCSync when you reach replication rights.
5. **Move laterally** — pass-the-hash / pass-the-ticket / overpass-the-hash via SMB (`nxc`, `psexec`, `wmiexec`, `evil-winrm`).
6. **Validate & document** — prove each hop with evidence to `$OUTPUT_DIR/findings/finding-NNN/`; capture tickets/hashes to `evidence/` (redact per `evidence-hygiene`).

## Deep-dive reference (authoritative)

- `reference/hunt-active-directory.md` — full technique matrix: enumeration, Kerberoasting/AS-REP, BloodHound queries, password spraying with lockout math, coercion+relay (PetitPotam/PrinterBug/ShadowCoerce), ADCS ESC1-ESC8, delegation (unconstrained/constrained/RBCD/S4U), ACL abuse, DCSync, lateral-movement matrix, and OPSEC/detection notes.

## Related skills & chains

- **`hunt-ntlm-info`** — NTLM Type-2 leak gives you the domain/forest name to seed enumeration and spraying.
- **`privilege-escalation`** — once you have a foothold shell, local privesc (SeImpersonate → SYSTEM, token abuse) feeds AD credential harvest.
- **`hunt-ldap`** — anonymous/authenticated LDAP enumeration primitives feed step 1.
- **`m365-entra-attack` / `okta-attack`** — hybrid-identity pivot: on-prem AD → Entra Connect / federation → cloud.
- **`cloud-iam-deep`** — if a domain-joined host holds cloud credentials, pivot AD → cloud.
- **`red-team` / `redteam-report-template`** — engagement framing and reporting; **`evidence-hygiene`** for redacting captured tickets/hashes.
