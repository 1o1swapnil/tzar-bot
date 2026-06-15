# MAPT — Mobile Application Penetration Testing

Tests targeting Android APKs and iOS IPA files following OWASP Mobile Top 10.

## When to Use This Folder

- Android APK security testing
- iOS IPA security testing
- Hybrid mobile app testing (React Native, Flutter, Ionic)
- Mobile API backend testing
- Certificate pinning bypass
- Root/jailbreak detection bypass

## Skills Used

`reconnaissance` · `authentication` · `api-security` · `injection` · `essential-tools`

## Tools Required

```bash
# Android
apktool --version       # APK decompilation
jadx --version          # Java decompilation
adb devices            # Device connection
frida --version        # Dynamic instrumentation

# iOS
objection explore      # Runtime manipulation
frida-ps -Ua           # Running processes
```

## Quick Start

```
# Android APK test:
"test this APK for security issues: /path/to/app.apk"

# iOS IPA test:
"run mobile pentest on /path/to/app.ipa"
```

## Output Structure

```
MAPT/
└── <app-name>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/           # manifest analysis, decompiled source, strings
        ├── findings/
        ├── screenshots/     # Frida output, traffic captures
        ├── logs/
        └── reports/Mobile-App-Security-Report.pdf
```

## OWASP Mobile Top 10 Coverage

- M1: Improper Credential Usage
- M2: Inadequate Supply Chain Security
- M3: Insecure Authentication/Authorization
- M4: Insufficient Input/Output Validation
- M5: Insecure Communication
- M6: Inadequate Privacy Controls
- M7: Insufficient Binary Protections
- M8: Security Misconfiguration
- M9: Insecure Data Storage
- M10: Insufficient Cryptography
