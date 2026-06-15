# Network — Network & Infrastructure Penetration Testing

Tests targeting internal networks, Active Directory, network devices, VPNs, and services.

## When to Use This Folder

- Internal network penetration tests
- Active Directory / domain assessments
- External network perimeter testing
- VPN and firewall configuration review
- Wireless network security testing
- OT/SCADA network assessments (with caution)

## Skills Used

`infrastructure` · `system` · `reconnaissance` · `osint` · `essential-tools`

## Tools Required

```bash
crackmapexec --version   # AD/SMB testing
impacket-secretsdump -h  # Credential extraction
bloodhound-python -h     # AD graph mapping
kerbrute -h              # Kerberos attacks
enum4linux-ng -h         # SMB/LDAP enum
```

## Quick Start

```
# Internal network test:
"run internal network pentest against 192.168.1.0/24"

# Active Directory:
"test the AD domain at dc.corp.local (192.168.1.10)"

# External perimeter:
"external network assessment for target.com IP range 203.0.113.0/24"
```

## Output Structure

```
Network/
└── <client-network>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/
        │   ├── nmap-full.txt         # port + service scan
        │   ├── nmap-vulns.txt        # NSE vuln scripts
        │   ├── enum4linux.json       # SMB/LDAP enumeration
        │   └── bloodhound/           # AD attack paths
        ├── findings/
        ├── artifacts/
        │   ├── hashes.txt            # NEVER commit to git
        │   └── dcsync/               # credential dumps
        ├── logs/
        └── reports/Network-Pentest-Report.pdf
```

## Common Attack Paths

- SMB null session → user enumeration → password spray
- Kerberoasting → offline crack → lateral movement
- AS-REP roasting → offline crack
- Pass-the-Hash → remote admin
- BloodHound path → Domain Admin
