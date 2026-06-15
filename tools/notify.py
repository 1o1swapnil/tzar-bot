#!/usr/bin/env python3
"""
notify.py — Send a webhook notification when a P0/P1 finding is confirmed.

Usage:
    python3 tools/notify.py --finding "$OUTPUT_DIR/findings/finding-NNN" [--level critical]
    python3 tools/notify.py --text "Custom message" [--level high]

Supported destinations (configure in .env):
    NOTIFY_WEBHOOK_URL   — Slack / Discord / Teams / generic HTTP POST URL
    NOTIFY_SLACK_CHANNEL — (optional) override channel for Slack webhooks

Exit codes: 0 = sent, 1 = no webhook configured, 2 = send failed
"""

import sys
import os
import re
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path

REPO_DIR = Path(__file__).parent.parent.resolve()


def _env(key: str) -> str:
    """Read a single env var via env-reader.py."""
    import subprocess
    r = subprocess.run(
        [sys.executable, str(REPO_DIR / "tools" / "env-reader.py"), key],
        capture_output=True, text=True, cwd=REPO_DIR
    )
    for line in r.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            if k.strip() == key and v.strip() != "NOT_SET":
                return v.strip()
    return ""


def _parse_finding(finding_dir: Path) -> dict:
    """Extract key fields from findings/finding-NNN/description.md."""
    desc = finding_dir / "description.md"
    if not desc.exists():
        return {"title": finding_dir.name, "severity": "Unknown", "cvss": "?", "affected": ""}
    text = desc.read_text(encoding="utf-8", errors="replace")

    def tf(key):
        m = re.search(rf'\|\s*{re.escape(key)}\s*\|\s*(.+?)\s*\|', text, re.I)
        return m.group(1).strip() if m else ""

    title_m = re.match(r'#\s+Finding[:\s\d—-]*(.+)', text)
    return {
        "title":    title_m.group(1).strip() if title_m else finding_dir.name,
        "severity": tf("Severity") or "Unknown",
        "cvss":     tf("CVSS Score") or "?",
        "affected": tf("Affected Component") or tf("Affected URL") or "",
        "id":       finding_dir.name,
    }


def _build_payload(message: str, finding: dict, level: str, output_dir: str, webhook_url: str) -> dict:
    """Build webhook payload. Auto-detects Slack vs. generic."""
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(level.lower(), "⚪")

    title   = finding.get("title", message)
    fid     = finding.get("id", "")
    sev     = finding.get("severity", level.title())
    cvss    = finding.get("cvss", "")
    aff     = finding.get("affected", "")
    out_dir = output_dir or ""

    text = (
        f"{sev_emoji} *[{sev}] {title}*\n"
        f"{'CVSS: ' + cvss + '  ' if cvss else ''}"
        f"{'Finding: ' + fid + '  ' if fid else ''}\n"
        f"{'Affected: ' + aff + chr(10) if aff else ''}"
        f"{'OUTPUT_DIR: `' + out_dir + '`' if out_dir else ''}"
    ).strip()

    # Slack incoming webhook format
    if "hooks.slack.com" in webhook_url or "slack.com" in webhook_url:
        return {"text": text}

    # Discord webhook format
    if "discord.com" in webhook_url or "discordapp.com" in webhook_url:
        return {"content": text}

    # Teams (simple card)
    if "office.com" in webhook_url or "microsoft.com" in webhook_url:
        return {
            "@type":    "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary":  f"[{sev}] {title}",
            "title":    f"{sev_emoji} Pentest Finding: [{sev}] {title}",
            "text":     text.replace("*", "**"),
        }

    # Generic JSON POST
    return {"text": text, "level": level, "finding": finding, "output_dir": out_dir}


def send_notification(webhook_url: str, payload: dict) -> bool:
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        webhook_url,
        data    = data,
        headers = {"Content-Type": "application/json", "User-Agent": "tzar-bot/notify"},
        method  = "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status < 400
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP {e.code}: {e.read().decode()[:200]}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[!] Send failed: {e}", file=sys.stderr)
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--finding", default="", help="Path to finding directory")
    ap.add_argument("--text",    default="", help="Custom message text")
    ap.add_argument("--level",   default="high",
                    choices=["critical", "high", "medium", "low"],
                    help="Severity level (default: high)")
    ap.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR", ""),
                    help="Engagement OUTPUT_DIR")
    ap.add_argument("--webhook", default="", help="Override webhook URL (else reads NOTIFY_WEBHOOK_URL)")
    args = ap.parse_args()

    webhook_url = args.webhook or _env("NOTIFY_WEBHOOK_URL")
    if not webhook_url:
        print("[!] No webhook URL — set NOTIFY_WEBHOOK_URL in .env or pass --webhook", file=sys.stderr)
        sys.exit(1)

    finding = {}
    if args.finding:
        finding_path = Path(args.finding).resolve()
        if finding_path.exists():
            finding = _parse_finding(finding_path)
            # Only notify on P0/P1 (critical/high) unless level explicitly overridden
            sev = finding.get("severity", "").lower()
            if sev in ("critical", "high"):
                args.level = sev
    elif args.text:
        finding = {"title": args.text}

    if not finding and not args.text:
        print("[!] Provide --finding PATH or --text MESSAGE", file=sys.stderr)
        sys.exit(1)

    payload = _build_payload(
        args.text or finding.get("title", ""),
        finding, args.level, args.output_dir, webhook_url
    )

    success = send_notification(webhook_url, payload)
    if success:
        print(f"[+] Notification sent: [{args.level.upper()}] {finding.get('title', args.text)}")
        sys.exit(0)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
