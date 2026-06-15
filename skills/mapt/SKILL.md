---
name: mapt
description: Mobile app security testing — Android APK and iOS IPA static/dynamic analysis, traffic interception, runtime manipulation
allowed-tools: [Bash, Read, Write]
---

# Mobile Application Penetration Testing (MAPT)

Test Android APK and iOS IPA applications for OWASP MASVS/MSTG vulnerabilities: insecure data storage, traffic interception, binary protections, runtime manipulation, and deep-link/intent abuse.

## Tools

| Tool | Purpose |
|------|---------|
| apktool | APK decompile/recompile |
| jadx | APK decompile to Java/Kotlin |
| MobSF | Static + dynamic analysis (Docker) |
| frida | Runtime instrumentation |
| objection | Frida-based runtime exploration |
| adb | Android Debug Bridge |
| apksigner / apkleaks | Signing verification / secret scanning |
| drozer | Android attack surface analysis |
| ssl-kill-switch2 | iOS TLS bypass (jailbroken) |
| ipa-inspector | IPA static inspection |

## Phase 0 — Setup

```bash
# Android: start MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Android: verify ADB device
adb devices

# iOS: verify connected device (requires libimobiledevice)
ideviceinfo | grep -E "DeviceName|ProductVersion|ProductType"

# Extract APK from connected device
adb shell pm list packages | grep TARGET_PACKAGE
adb shell pm path TARGET_PACKAGE
adb pull $(adb shell pm path TARGET_PACKAGE | cut -d: -f2 | tr -d '\r') OUTPUT_DIR/artifacts/app.apk
```

## Phase 1 — Static Analysis (Android)

```bash
APK=OUTPUT_DIR/artifacts/app.apk

# Decompile to smali + resources
apktool d "$APK" -o OUTPUT_DIR/artifacts/apktool-out/ 2>&1 | tee OUTPUT_DIR/logs/apktool.log

# Decompile to Java/Kotlin
jadx "$APK" -d OUTPUT_DIR/artifacts/jadx-out/ 2>&1 | tee OUTPUT_DIR/logs/jadx.log

# Scan for hardcoded secrets (API keys, tokens, passwords)
apkleaks -f "$APK" -o OUTPUT_DIR/logs/apkleaks.json

# Manual secret grep across source
grep -rEi \
  "api[_-]?key|secret[_-]?key|access[_-]?token|password\s*=|Bearer |-----BEGIN|firebase|aws_|AKID" \
  OUTPUT_DIR/artifacts/jadx-out/ | tee OUTPUT_DIR/logs/secrets-grep.txt

# Check network security config (allows cleartext?)
cat OUTPUT_DIR/artifacts/apktool-out/res/xml/network_security_config.xml 2>/dev/null

# Check exported components (attack surface)
grep -E "exported=\"true\"|android:exported" \
  OUTPUT_DIR/artifacts/apktool-out/AndroidManifest.xml | tee OUTPUT_DIR/logs/exported-components.txt

# Check dangerous permissions
grep -E "WRITE_EXTERNAL_STORAGE|READ_CONTACTS|READ_CALL_LOG|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION" \
  OUTPUT_DIR/artifacts/apktool-out/AndroidManifest.xml

# Check backup flag (true = adb backup extracts data)
grep "allowBackup" OUTPUT_DIR/artifacts/apktool-out/AndroidManifest.xml
```

## Phase 1 — Static Analysis (iOS)

```bash
IPA=OUTPUT_DIR/artifacts/app.ipa

# Unpack IPA
mkdir -p OUTPUT_DIR/artifacts/ipa-out
cp "$IPA" OUTPUT_DIR/artifacts/ipa-out/app.zip
unzip -q OUTPUT_DIR/artifacts/ipa-out/app.zip -d OUTPUT_DIR/artifacts/ipa-out/

PAYLOAD_DIR=$(find OUTPUT_DIR/artifacts/ipa-out/Payload -name "*.app" -type d | head -1)
BINARY=$(find "$PAYLOAD_DIR" -type f -perm +111 | head -1)

# Scan for hardcoded secrets
grep -rEai "api[_-]?key|secret|token|password|Bearer |-----BEGIN" "$PAYLOAD_DIR" \
  --include="*.plist" --include="*.json" --include="*.strings" \
  | tee OUTPUT_DIR/logs/ios-secrets-grep.txt

# Check Info.plist for ATS (App Transport Security) exceptions
plutil -p "$PAYLOAD_DIR/Info.plist" | grep -A5 "NSAppTransportSecurity" 2>/dev/null

# Check if binary is encrypted (Mach-O cryptid)
otool -l "$BINARY" 2>/dev/null | grep -A5 "LC_ENCRYPTION_INFO" | grep cryptid

# List linked frameworks
otool -L "$BINARY" 2>/dev/null | tee OUTPUT_DIR/logs/ios-linked-libs.txt

# Decode provisioning profile + entitlements (get-task-allow, aps-environment, associated-domains)
openssl smime -inform der -verify -noverify -in "$PAYLOAD_DIR/embedded.mobileprovision" 2>/dev/null \
  | tee OUTPUT_DIR/logs/ios-entitlements.txt
# Flag: get-task-allow=true (debuggable), aps-environment=development (non-prod build),
#       associated-domains containing '*' (wildcard universal-link hijack — report as a finding),
#       broad keychain-access-groups, ad-hoc ProvisionedDevices on a "production" build.

# Bundled cert/pinning hygiene — check every shipped .pem/.cer/.der for expiry & owner mismatch
find "$PAYLOAD_DIR" \( -name '*.pem' -o -name '*.cer' -o -name '*.der' \) | while read c; do
  echo "=== $c ==="; openssl x509 -in "$c" -noout -subject -issuer -enddate 2>/dev/null \
    || openssl x509 -inform der -in "$c" -noout -subject -issuer -enddate 2>/dev/null
done | tee OUTPUT_DIR/logs/ios-bundled-certs.txt
# Flag: expired certs, or a pinned cert whose CN belongs to an unrelated org (stale copy-paste).

# Check binary protections: PIE, stack canary, ARC
checksec --file="$BINARY" 2>/dev/null || python3 -c "
import subprocess, sys
b = sys.argv[1]
for flag, arg in [('PIE','MH_PIE'),('Stack Canary','___stack_chk_guard'),('ARC','_objc_release')]:
    r = subprocess.run(['nm','--no-sort',b], capture_output=True, text=True)
    print(f'{flag}: {\"YES\" if arg in r.stdout else \"NO\"}')" "$BINARY" \
  | tee OUTPUT_DIR/logs/ios-binary-protections.txt
```

### iOS tooling on Kali/Linux (macOS tools absent)

`otool`/`nm`/`strings`/`plutil`/`lief` are usually NOT installed on Kali. Set up first:

```bash
pip3 install lief --break-system-packages --quiet     # Mach-O: cryptid, PIE, NX, libs, segments
sudo apt-get install -y binutils                       # provides strings + nm
# Parse plists with python3 plistlib (binary plists too) — NEVER assume plutil exists:
#   python3 -c "import plistlib,sys;print(plistlib.load(open(sys.argv[1],'rb')))" Info.plist
# If `strings` is still missing, extract printable runs with grep:
#   grep -aoE '<pattern>' "$BINARY"
```

### Flutter apps — ALWAYS mine the Dart AOT snapshot (critical)

Flutter business logic, API endpoints, and **hardcoded secrets live in the Dart AOT blob**, not the
host Mach-O. Automated scanners (incl. MobSF) regex the host binary + plists and **miss JWTs/secrets
embedded in the Dart snapshot**. If `Frameworks/Flutter.framework` exists, this step is mandatory:

```bash
DART="$PAYLOAD_DIR/Frameworks/App.framework/App"   # the Dart AOT snapshot

# Endpoints / hosts (the real API surface — far deeper than Info.plist URL schemes)
grep -aoE 'https?://[A-Za-z0-9._:/?=&%-]+' "$DART" | sort -u | tee OUTPUT_DIR/logs/ios-dart-endpoints.txt

# JWTs (header.payload.signature) — decode every hit, check role/exp/iss
grep -aoE 'eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}' "$DART" | sort -u | \
while read t; do echo "$t"; python3 -c "
import base64,json,sys
h,p,s=sys.argv[1].split('.'); d=lambda x:json.loads(base64.urlsafe_b64decode(x+'='*(-len(x)%4)))
print(' header:',d(h)); print(' payload:',d(p))" "$t"; done | tee OUTPUT_DIR/logs/ios-dart-jwts.txt

# Other secrets/creds in the blob
grep -aoiE 'Bearer [A-Za-z0-9._-]+|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|api[_-]?key|client_secret|password|firebaseio|amazonaws' "$DART" \
  | sort -u | tee -a OUTPUT_DIR/logs/ios-secrets-grep.txt
```

> A hardcoded `role:Admin` JWT was found this way on a Flutter banking app that MobSF rated clean on secrets. Decode and report `role`, `exp`, `iss`/`aud` — a long-lived privileged token is High severity.

### Breadth hygiene checks (parity with MobSF — don't skip)

```bash
# Per-framework binary protections — loop over EVERY embedded dylib, not just the main binary
for fw in "$PAYLOAD_DIR"/Frameworks/*.framework/* "$PAYLOAD_DIR"/PlugIns/*.appex/*; do
  [ -f "$fw" ] && file "$fw" | grep -q Mach-O && python3 - "$fw" <<'PY'
import lief,sys; b=lief.parse(sys.argv[1])
if b: print(sys.argv[1].split('/')[-1], 'PIE' if b.is_pie else 'NO-PIE',
  'NX' if b.has_nx else 'NO-NX', 'encrypted' if b.has_encryption_info and b.encryption_info.crypt_id else 'unencrypted')
PY
done | tee OUTPUT_DIR/logs/ios-framework-protections.txt

# Insecure logging (CWE-532) — NSLog leaks sensitive data to device console
grep -aoE '_?NSLog' "$BINARY" | sort -u | tee OUTPUT_DIR/logs/ios-logging.txt

# @rpath / Runpath search path (CWE-426/427 dylib-hijack & code-exec surface)
otool -l "$BINARY" 2>/dev/null | grep -A2 LC_RPATH \
  || python3 -c "import lief,sys;b=lief.parse(sys.argv[1]);print('RPATHs:',[c.path for c in b.commands if c.command==lief.MachO.LOAD_COMMAND_TYPES.RPATH])" "$BINARY" \
  | tee OUTPUT_DIR/logs/ios-rpath.txt

# Dangerous C functions (CWE-676: strcpy/memcpy/sprintf/system/...)
grep -aoE '_(strcpy|strcat|sprintf|gets|memcpy|system|popen|vfork)' "$BINARY" | sort -u

# Privacy trackers / analytics SDKs (Exodus-style) — from Frameworks/ + plists
ls "$PAYLOAD_DIR"/Frameworks | grep -iE 'admob|crashlytics|clevertap|appsflyer|facebook|firebase|adjust|amplitude|mixpanel|branch' \
  | tee OUTPUT_DIR/logs/ios-trackers.txt
```

> **Lesson learned (cross-validated vs MobSF):** our deep Dart-blob mining beats MobSF on critical
> secrets/endpoints, but MobSF wins on breadth hygiene — NSLog logging, @rpath, per-framework
> protections, tracker enumeration, domain reputation. Run BOTH and merge. When MobSF is available,
> use it for breadth; always do the Flutter/entitlement/cert-hygiene depth manually.

## Phase 2 — MobSF Automated Scan

```bash
# Upload to MobSF and scan (REST API)
MOBSF_URL="http://127.0.0.1:8000"
MOBSF_KEY=$(python3 tools/env-reader.py MOBSF_API_KEY | cut -d= -f2)

# Upload
SCAN_HASH=$(curl -s -F "file=@OUTPUT_DIR/artifacts/app.apk" \
  "$MOBSF_URL/api/v1/upload" \
  -H "Authorization: $MOBSF_KEY" | jq -r '.hash')

# Trigger scan
curl -s -X POST "$MOBSF_URL/api/v1/scan" \
  -H "Authorization: $MOBSF_KEY" \
  -d "hash=$SCAN_HASH" | jq '.' > OUTPUT_DIR/logs/mobsf-scan.json

# Fetch JSON report
curl -s -X POST "$MOBSF_URL/api/v1/report_json" \
  -H "Authorization: $MOBSF_KEY" \
  -d "hash=$SCAN_HASH" > OUTPUT_DIR/logs/mobsf-report.json

echo "MobSF score: $(jq '.average_cvss' OUTPUT_DIR/logs/mobsf-report.json)"
```

## Phase 3 — Traffic Interception

```bash
# Android: set proxy via ADB (emulator or rooted device)
adb shell settings put global http_proxy 127.0.0.1:8080

# Android: install Burp CA cert
openssl x509 -inform DER -in burp-ca.der -out burp-ca.pem
CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp-ca.pem | head -1)
cp burp-ca.pem "${CERT_HASH}.0"
adb push "${CERT_HASH}.0" /sdcard/
adb shell "su -c 'mount -o remount,rw /system && cp /sdcard/${CERT_HASH}.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/${CERT_HASH}.0'"

# Android: clear proxy after testing
adb shell settings put global http_proxy :0

# iOS: set proxy via WiFi settings (manual) or:
# Burp → Proxy → Options → Export CA → install via Settings → General → VPN & Device Management
```

## Phase 4 — Certificate Pinning Bypass

```bash
# Objection (Frida-based): bypass SSL pinning
objection --gadget "TARGET_PACKAGE" explore

# Inside objection shell:
# android sslpinning disable
# ios sslpinning disable

# Direct Frida script
frida -U -f TARGET_PACKAGE \
  --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida \
  --no-pause 2>&1 | tee OUTPUT_DIR/logs/frida-ssl-bypass.log

# Repack APK with network security config allowing user certs (no root needed)
# 1. apktool d app.apk -o app-out
# 2. Edit res/xml/network_security_config.xml — add <trust-anchors><certificates src="user"/></trust-anchors>
# 3. apktool b app-out -o app-patched.apk
# 4. Sign: apksigner sign --ks debug.keystore --out app-signed.apk app-patched.apk
# 5. adb install app-signed.apk
```

## Phase 5 — Runtime Analysis (Android)

```bash
# Objection: explore app internals
objection --gadget "TARGET_PACKAGE" explore

# Inside objection:
# android hooking list classes
# android hooking list class_methods TARGET.CLASS
# android hooking watch class TARGET.CLASS
# android heap search instances TARGET.CLASS
# android intent launch_activity TARGET.ACTIVITY
# env                                  ← data dirs, files on device
# android keystore list                ← Android Keystore contents

# Drozer: attack surface enumeration
drozer console connect
# run app.package.info -a TARGET_PACKAGE
# run app.activity.info -a TARGET_PACKAGE -u     ← exported activities
# run app.provider.info -a TARGET_PACKAGE        ← content providers
# run app.broadcast.info -a TARGET_PACKAGE       ← broadcast receivers
# run scanner.provider.injection -a TARGET_PACKAGE  ← SQL injection in providers
# run scanner.provider.traversal -a TARGET_PACKAGE  ← path traversal in providers
```

## Phase 5 — Runtime Analysis (iOS)

```bash
# Objection on iOS (jailbroken device)
objection --gadget TARGET_APP_NAME explore

# Inside objection:
# ios sslpinning disable
# ios jailbreak disable                          ← bypass jailbreak detection
# ios keychain dump                              ← keychain contents
# ios nsuserdefaults get                         ← NSUserDefaults
# ios plist cat Info.plist
# ios hooking list classes
# ios hooking watch method "+[ClassName method:]" --dump-args --dump-return

# Dump keychain (jailbroken, on-device)
# Use keychain-dumper: https://github.com/ptoomey3/Keychain-Dumper
```

## Phase 6 — Insecure Data Storage

```bash
# Android: pull app data directory (rooted)
adb shell "su -c 'cp -r /data/data/TARGET_PACKAGE /sdcard/app-data'"
adb pull /sdcard/app-data OUTPUT_DIR/artifacts/app-data/

# Check for sensitive data in:
find OUTPUT_DIR/artifacts/app-data/ -name "*.db" -o -name "*.sqlite" | while read db; do
  echo "=== $db ===" && sqlite3 "$db" .tables 2>/dev/null
done | tee OUTPUT_DIR/logs/sqlite-tables.txt

find OUTPUT_DIR/artifacts/app-data/ \( -name "*.xml" -o -name "*.json" \) -exec \
  grep -lEi "password|token|key|secret|credential" {} \; \
  | tee OUTPUT_DIR/logs/plaintext-storage.txt

# iOS: pull app container (jailbroken)
# SSH to device: scp -r root@DEVICE_IP:/var/mobile/Containers/Data/Application/UUID/ OUTPUT_DIR/artifacts/ios-container/
# Check NSUserDefaults, .plist, Core Data, SQLite, Keychain
```

## Phase 7 — Deep Link / Intent Abuse (Android)

```bash
# List deep link schemes from manifest
grep -Ei "scheme|host|pathPrefix" \
  OUTPUT_DIR/artifacts/apktool-out/AndroidManifest.xml | tee OUTPUT_DIR/logs/deeplinks.txt

# Fire exported activity directly
adb shell am start -n "TARGET_PACKAGE/TARGET_PACKAGE.TargetActivity"

# Fire deep link
adb shell am start -a android.intent.action.VIEW \
  -d "TARGET_SCHEME://TARGET_HOST/path?param=value"

# Send malicious broadcast to exported receiver
adb shell am broadcast -a "TARGET_PACKAGE.EXPORTED_ACTION" \
  --es "key" "injected_value"

# Start exported service
adb shell am startservice -n "TARGET_PACKAGE/TARGET_PACKAGE.ExportedService"
```

## Phase 8 — Root / Jailbreak Detection Bypass

```bash
# Frida — bypass root detection (Android)
frida -U -f TARGET_PACKAGE -l - --no-pause <<'EOF'
Java.perform(function() {
  var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
  RootBeer.isRooted.overload().implementation = function() { return false; };
  RootBeer.isRootedWithoutBusyBox.overload().implementation = function() { return false; };
});
EOF

# Objection one-liner (iOS jailbreak detection)
objection --gadget TARGET_APP_NAME explore --startup-command "ios jailbreak disable"
```

## Key Checks by MASVS Category

| MASVS | Check | Tools |
|-------|-------|-------|
| MASVS-STORAGE | Plaintext credentials in SharedPrefs/NSUserDefaults/SQLite | adb pull, grep |
| MASVS-CRYPTO | Hardcoded keys, weak algorithms (DES, MD5, ECB) | jadx, grep |
| MASVS-AUTH | JWT validation, biometric bypass, session fixation | objection, frida |
| MASVS-NETWORK | Cleartext traffic, cert pinning absent, weak TLS | Burp, network_security_config |
| MASVS-PLATFORM | Exported components, deep link injection, clipboard abuse | drozer, adb |
| MASVS-CODE | Binary protections absent, debug build, logging PII | apkleaks, checksec |
| MASVS-RESILIENCE | Root/jailbreak detection, anti-tampering absent | frida, objection |

## Output

APK/IPA artifacts → `OUTPUT_DIR/artifacts/`
Static analysis logs → `OUTPUT_DIR/logs/mobsf-report.json`, `apkleaks.json`, `secrets-grep.txt`
Runtime captures → `OUTPUT_DIR/screenshots/`, `OUTPUT_DIR/evidence/`
Findings → `OUTPUT_DIR/findings/finding-NNN/`

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/apk-redteam-pipeline.md` — End-to-end Android APK red-team pipeline…
