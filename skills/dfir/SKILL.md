---
name: dfir
description: Digital forensics and incident response — memory acquisition, disk imaging, log analysis, IOC extraction
allowed-tools: [Bash, Read, Write]
---

# DFIR — Digital Forensics and Incident Response

## Memory Acquisition

```bash
# Linux — LiME kernel module
sudo insmod /path/to/lime.ko "path=OUTPUT_DIR/artifacts/memory.lime format=lime"

# Linux — avml (no kernel module needed)
sudo avml OUTPUT_DIR/artifacts/memory.avml

# Verify acquisition
sha256sum OUTPUT_DIR/artifacts/memory.lime > OUTPUT_DIR/artifacts/memory.lime.sha256
```

## Memory Analysis (Volatility 3)

```bash
vol_cmd="python3 /opt/volatility3/vol.py"
MEM="OUTPUT_DIR/artifacts/memory.lime"

# System info
$vol_cmd -f $MEM windows.info 2>/dev/null || $vol_cmd -f $MEM linux.info

# Process list
$vol_cmd -f $MEM windows.pslist > OUTPUT_DIR/logs/pslist.txt
$vol_cmd -f $MEM linux.pslist >> OUTPUT_DIR/logs/pslist.txt

# Network connections
$vol_cmd -f $MEM windows.netstat > OUTPUT_DIR/logs/netstat.txt
$vol_cmd -f $MEM linux.netstat >> OUTPUT_DIR/logs/netstat.txt

# Dump suspicious process
$vol_cmd -f $MEM windows.memmap --pid SUSPICIOUS_PID --dump
```

## Disk Imaging

```bash
# Full disk image
sudo dd if=/dev/sda bs=4M conv=sync,noerror status=progress \
  | gzip > OUTPUT_DIR/artifacts/disk.img.gz

# dc3dd with hash verification
sudo dc3dd if=/dev/sda hash=sha256 \
  hof=OUTPUT_DIR/artifacts/disk.img \
  log=OUTPUT_DIR/artifacts/dc3dd.log

# Mount image read-only for analysis
sudo mount -o ro,noexec,noload OUTPUT_DIR/artifacts/disk.img /mnt/evidence
```

## Log Analysis

```bash
# Auth log analysis — failed logins, sudo, new accounts
grep -E "Failed|Invalid|sudo|useradd|passwd" /var/log/auth.log | \
  tee OUTPUT_DIR/logs/auth-events.txt

# Web server log — brute force, scanning, exploitation attempts
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20 \
  > OUTPUT_DIR/logs/top-ips.txt

grep -E "(union|select|exec|cmd|system|eval|base64_decode|\.\./)" /var/log/nginx/access.log \
  > OUTPUT_DIR/logs/potential-exploitation.txt

# Systemd journal
journalctl --since "2026-01-01" --until "2026-06-03" -o json | \
  jq 'select(.PRIORITY <= "3")' > OUTPUT_DIR/logs/critical-journal.json
```

## Timeline Creation

```bash
# Linux filesystem timeline (The Sleuth Kit)
fls -r -m / /dev/sda1 > OUTPUT_DIR/logs/fls-body.txt
mactime -b OUTPUT_DIR/logs/fls-body.txt -d > OUTPUT_DIR/logs/timeline.csv

# Recent file access
find / -newer /tmp/reference-file -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null \
  | sort > OUTPUT_DIR/logs/recently-modified.txt
```

## IOC Extraction

```bash
# YARA scan
yara -r /usr/share/yara-rules/ /path/to/analyze > OUTPUT_DIR/logs/yara-matches.txt

# Strings from suspicious files
strings -a suspicious-file | tee OUTPUT_DIR/logs/strings.txt | grep -E "http|exe|cmd|powershell"

# Network IOCs from logs
grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" OUTPUT_DIR/logs/*.txt | \
  sort -u > OUTPUT_DIR/artifacts/ip-iocs.txt

grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" OUTPUT_DIR/logs/*.txt | \
  sort -u > OUTPUT_DIR/artifacts/email-iocs.txt
```

## Autopsy Forensic Analysis

Autopsy provides GUI forensics with timeline, keyword search, email artifact extraction, and web artifact analysis. Use for complex investigations or when CLI output needs to be presented to non-technical stakeholders.

```bash
# Install if needed
sudo apt-get install -y autopsy

# CLI mode: create case and ingest disk image (no GUI required)
CASE_DIR="$OUTPUT_DIR/artifacts/autopsy-case"
DISK_IMAGE="$OUTPUT_DIR/artifacts/disk.dd"

# Create Autopsy case directory
mkdir -p "$CASE_DIR"

cat > "$CASE_DIR/case.aut" << EOF
<?xml version="1.0"?>
<AutopsyCase>
  <Number>1</Number>
  <CreatedDate>$(date -u +"%Y-%m-%d %H:%M:%S")</CreatedDate>
  <CaseName>DFIR Investigation</CaseName>
  <CaseDirectory>$CASE_DIR</CaseDirectory>
</AutopsyCase>
EOF

# Run Autopsy ingest in headless mode
autopsy --nosplash --nogui \
  --dataSourcePath="$DISK_IMAGE" \
  --outputDir="$CASE_DIR" 2>/dev/null || true

# Alternative: use Sleuth Kit directly (Autopsy uses TSK under the hood)
# List file system
fls -r -m "/" "$DISK_IMAGE" > "$CASE_DIR/file-listing.txt"

# Generate timeline from file listing
mactime -b "$CASE_DIR/file-listing.txt" -d \
  | sort > "$CASE_DIR/timeline.csv"

# Keyword search on image
ils "$DISK_IMAGE" | grep -i "password\|secret\|credential" > "$CASE_DIR/keyword-hits.txt" 2>/dev/null || true

# Recover deleted files
tsk_recover -e "$DISK_IMAGE" "$CASE_DIR/recovered/" 2>/dev/null
ls "$CASE_DIR/recovered/"

# Export Autopsy HTML report (if GUI was used)
# File → Generate Report → HTML Report → OUTPUT_DIR/reports/autopsy-report.html
```

**When to use Autopsy vs. Sleuth Kit directly:**

| Scenario | Tool |
|---|---|
| Quick triage, scripted analysis | Sleuth Kit CLI (fls, mactime, icat) |
| Complex investigation, deleted file recovery | Autopsy GUI |
| Client-facing deliverable with screenshots | Autopsy HTML report |
| Email artifact extraction | Autopsy (has built-in email parser) |
| Browser history, recent activity | Autopsy (Recent Activity module) |

## Output

- `OUTPUT_DIR/logs/dfir-timeline.md` — human-readable incident timeline
- `OUTPUT_DIR/artifacts/iocs.json` — structured IOC list (IPs, domains, hashes, emails)
- `OUTPUT_DIR/artifacts/memory.lime` — memory image
- `OUTPUT_DIR/artifacts/autopsy-case/` — Autopsy case directory
- `OUTPUT_DIR/reports/autopsy-report.html` — Autopsy HTML report (if GUI used)
- Chain of custody: `OUTPUT_DIR/artifacts/chain-of-custody.md`
