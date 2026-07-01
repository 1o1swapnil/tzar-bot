---
name: privilege-escalation
description: Local privilege escalation on a foothold host, Linux + Windows. Linux — SUID/sudo (GTFOBins), capabilities, cron/PATH, writable systemd, kernel exploits, container-escape signals. Windows — SeImpersonate/potato → SYSTEM, unquoted service paths, weak service/registry ACLs, AlwaysInstallElevated, DLL hijack, UAC bypass, LSASS/SAM/DPAPI harvest. Use with a low-priv shell to reach root/SYSTEM.
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere this skill references Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Privilege Escalation (local, post-exploitation)

You have a foothold — a low-privilege shell from RCE, an SSH cred, a webshell, or a reverse shell. Goal: escalate to **root / SYSTEM** or to a more useful service/domain account. This is the **quick-start router**; full enumeration commands and per-vector exploitation live in `reference/privesc-linux.md` and `reference/privesc-windows.md`.

> **Authorization & safety:** foothold host must be **in declared scope**. Prefer **non-destructive** vectors. Kernel/service exploits can crash hosts — get approval before running anything that may reboot or corrupt a production box; snapshot first if possible. Never leave persistence or backdoors; clean up any dropped binaries and record them in the report.

## First 60 seconds (situational awareness)

| Question | Linux | Windows |
|---|---|---|
| Who am I / what groups? | `id; sudo -l` | `whoami /all` |
| What OS/patch level? | `uname -a; cat /etc/os-release` | `systeminfo` |
| Am I in a container? | `/.dockerenv`, cgroup, cap set | (rare) |
| Any obvious creds nearby? | history, `.env`, config files | `cmdkey /list`, Unattend.xml, registry |

Then run an automated enumerator to triage, and **verify by hand** before exploiting (auto-scanners produce false positives).

## Enumeration entrypoints

```bash
# Linux — stage a static binary, run, save output to engagement dir
./linpeas.sh -a | tee $OUTPUT_DIR/loot/linpeas.txt
# manual quick wins:
sudo -l; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; cat /etc/crontab
```
```powershell
# Windows
.\winPEASx64.exe > $env:TEMP\winpeas.txt      # or PowerUp.ps1 / Seatbelt.exe
whoami /priv    # look for SeImpersonatePrivilege / SeAssignPrimaryToken → potato to SYSTEM
```

## Decision flow

1. **Enumerate** (auto + manual), dump results to `$OUTPUT_DIR/loot/`.
2. **Rank vectors** by reliability & blast radius: config/ACL/sudo misconfigs first (safe, deterministic) → token/potato → **kernel exploit last** (can crash).
3. **Exploit one vector**, confirm the new privilege (`id` / `whoami`), capture proof.
4. **Harvest** creds/hashes/tickets from the elevated context → feed `hunt-active-directory` (domain) or lateral movement.
5. **Document & clean up** — evidence to `$OUTPUT_DIR/findings/finding-NNN/`, remove any dropped tools, note remediation.

## Deep-dive references (authoritative)

- `reference/privesc-linux.md` — SUID/GTFOBins, sudo, capabilities, cron/PATH/wildcard injection, writable systemd/services, NFS no_root_squash, kernel exploits, container escape, credential locations.
- `reference/privesc-windows.md` — SeImpersonate/potato chain, unquoted service paths, weak service & registry ACLs, AlwaysInstallElevated, DLL hijack/search-order, autoruns, UAC bypass, and LSASS/SAM/DPAPI/LSA-secrets harvesting.

## Related skills & chains

- **`hunt-active-directory`** — after local SYSTEM, harvest domain creds/tickets → pivot into the domain.
- **`injection` (hunt-rce)** — the RCE that got you the shell; this skill is the next hop.
- **`cloud-containers` (hunt-k8s)** — container/K8s escape has its own deep skill; this covers host-level signals only.
- **`cloud-iam-deep`** — if the elevated host holds cloud creds (IMDS, `~/.aws`), pivot host → cloud.
- **`evidence-hygiene`** — redact harvested hashes/tokens before they enter the report; **`red-team`** for engagement framing.
