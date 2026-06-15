# DFIR — Digital Forensics & Incident Response

Memory analysis, disk forensics, log investigation, malware analysis, and IOC extraction.

## When to Use This Folder

- Incident response investigations
- Memory acquisition and analysis
- Disk image forensics
- Log analysis (SIEM exports, raw logs)
- Malware triage
- IOC extraction and threat hunting
- Post-breach forensics
- Timeline reconstruction

## Skills Used

`dfir` · `essential-tools`

## Tools Required

```bash
volatility3 -h            # Memory analysis
autopsy                   # Disk forensics GUI
foremost --help           # File carving
yara --version            # Malware pattern matching
strings --version         # Binary strings
avml --help               # Memory acquisition
dc3dd --version           # Forensic disk imaging
```

## Quick Start

```
# Memory analysis:
"analyze this memory dump for signs of compromise: /path/to/memory.lime"

# Incident response:
"investigate this system for indicators of compromise — logs at /var/log/"

# Log analysis:
"analyze these SIEM exports for the incident timeline: /path/to/logs/"

# Malware triage:
"triage this suspicious binary: /path/to/file.exe"
```

## Output Structure

```
DFIR/
└── <incident-name>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md           # investigation timeline
        ├── evidence/
        │   ├── memory.lime           # memory image (if acquired)
        │   ├── disk.img.gz           # disk image (if acquired)
        │   └── chain-of-custody.md   # evidence handling log
        ├── analysis/
        │   ├── pslist.txt            # process list
        │   ├── netstat.txt           # network connections
        │   ├── timeline.csv          # filesystem timeline
        │   └── yara-matches.txt      # malware signatures
        ├── artifacts/
        │   ├── iocs.json             # structured IOC list
        │   └── malware-samples/      # isolated samples
        ├── logs/
        └── reports/DFIR-Report.pdf
```

## Chain of Custody

Always document in `evidence/chain-of-custody.md`:
- Who acquired the evidence
- When and where
- Hash values (MD5 + SHA256) of all images
- Storage and transfer method
