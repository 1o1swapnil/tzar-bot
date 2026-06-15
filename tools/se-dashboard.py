#!/usr/bin/env python3
"""
se-dashboard.py — Social Engineering campaign metrics aggregator.

Reads GoPhish API results and produces:
  - JSON metrics summary (OUTPUT_DIR/artifacts/se-metrics.json)
  - ASCII dashboard printed to stdout
  - CSV export (OUTPUT_DIR/artifacts/se-metrics.csv)

Usage:
    python3 tools/se-dashboard.py --campaign-id 1 [--output-dir OUTPUT_DIR]
    python3 tools/se-dashboard.py --all [--output-dir OUTPUT_DIR]

Requires: GOPHISH_API_KEY and GOPHISH_URL in .env
"""

import sys
import os
import json
import csv
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

REPO_DIR = Path(__file__).parent.parent.resolve()


def _env(*keys):
    import subprocess
    r = subprocess.run(
        [sys.executable, str(REPO_DIR / "tools" / "env-reader.py")] + list(keys),
        capture_output=True, text=True, cwd=REPO_DIR
    )
    result = {}
    for line in r.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            if v.strip() != "NOT_SET":
                result[k.strip()] = v.strip()
    return result


def gophish_get(url: str, api_key: str):
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {api_key}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP {e.code}: {url}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        return None


def compute_metrics(campaign: dict, results: list) -> dict:
    total = len(results)
    if total == 0:
        return {"error": "No recipients"}

    sent       = sum(1 for r in results if r.get("status") != "Email Bounced")
    opened     = sum(1 for r in results if any(e["message"] == "Email Opened"   for e in r.get("timeline", [])))
    clicked    = sum(1 for r in results if any(e["message"] == "Clicked Link"   for e in r.get("timeline", [])))
    submitted  = sum(1 for r in results if any(e["message"] == "Submitted Data" for e in r.get("timeline", [])))
    reported   = sum(1 for r in results if any(e["message"] == "Email Reported" for e in r.get("timeline", [])))

    # Time-to-first-click (minutes from send to first click)
    ttc_list = []
    for r in results:
        timeline = r.get("timeline", [])
        send_time  = next((e["time"] for e in timeline if e["message"] == "Email Sent"), None)
        click_time = next((e["time"] for e in timeline if e["message"] == "Clicked Link"), None)
        if send_time and click_time:
            try:
                t0 = datetime.fromisoformat(send_time.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(click_time.replace("Z", "+00:00"))
                ttc_list.append((t1 - t0).total_seconds() / 60)
            except Exception:
                pass

    avg_ttc = sum(ttc_list) / len(ttc_list) if ttc_list else None
    min_ttc = min(ttc_list) if ttc_list else None

    return {
        "campaign_id":       campaign.get("id"),
        "campaign_name":     campaign.get("name"),
        "status":            campaign.get("status"),
        "launch_date":       campaign.get("launch_date"),
        "completed_date":    campaign.get("completed_date"),
        "total_recipients":  total,
        "emails_sent":       sent,
        "emails_opened":     opened,
        "links_clicked":     clicked,
        "data_submitted":    submitted,
        "emails_reported":   reported,
        "open_rate_pct":     round(opened / sent * 100, 1) if sent else 0,
        "click_rate_pct":    round(clicked / sent * 100, 1) if sent else 0,
        "submit_rate_pct":   round(submitted / sent * 100, 1) if sent else 0,
        "report_rate_pct":   round(reported / sent * 100, 1) if sent else 0,
        "avg_time_to_click_min": round(avg_ttc, 1) if avg_ttc else None,
        "min_time_to_click_min": round(min_ttc, 1) if min_ttc else None,
        "credentials_harvested": [
            {
                "email":     r.get("email"),
                "first_name": r.get("first_name"),
                "last_name":  r.get("last_name"),
                "data": [e.get("details") for e in r.get("timeline", [])
                         if e["message"] == "Submitted Data"]
            }
            for r in results
            if any(e["message"] == "Submitted Data" for e in r.get("timeline", []))
        ],
    }


def print_dashboard(metrics_list: list):
    sep = "═" * 68
    print(f"\n{sep}")
    print(f"  SOCIAL ENGINEERING CAMPAIGN DASHBOARD")
    print(sep)

    for m in metrics_list:
        if "error" in m:
            continue
        print(f"\n  Campaign: {m['campaign_name']} (#{m['campaign_id']}) [{m['status']}]")
        print(f"  {'─' * 64}")
        print(f"  {'Recipients:':25s} {m['total_recipients']}")
        print(f"  {'Emails Sent:':25s} {m['emails_sent']}")
        print(f"  {'Opened:':25s} {m['emails_opened']:4d}  ({m['open_rate_pct']}%)")
        print(f"  {'Clicked:':25s} {m['links_clicked']:4d}  ({m['click_rate_pct']}%)")
        print(f"  {'Submitted Credentials:':25s} {m['data_submitted']:4d}  ({m['submit_rate_pct']}%)")
        print(f"  {'Reported as Phishing:':25s} {m['emails_reported']:4d}  ({m['report_rate_pct']}%)")
        if m['avg_time_to_click_min'] is not None:
            print(f"  {'Avg Time-to-Click:':25s} {m['avg_time_to_click_min']} min")
            print(f"  {'Fastest Click:':25s} {m['min_time_to_click_min']} min")

        # ASCII bar chart
        print(f"\n  {'Metric':<20} {'Rate':>6}  Bar")
        print(f"  {'─' * 50}")
        for label, rate in [
            ("Open Rate",    m['open_rate_pct']),
            ("Click Rate",   m['click_rate_pct']),
            ("Submit Rate",  m['submit_rate_pct']),
        ]:
            bar = "█" * int(rate / 2) + "░" * (50 - int(rate / 2))
            print(f"  {label:<20} {rate:>5.1f}%  {bar[:30]}")

        if m['credentials_harvested']:
            print(f"\n  [!] Credentials harvested: {len(m['credentials_harvested'])}")
            for c in m['credentials_harvested'][:3]:
                print(f"    {c.get('email', '?')} — {c.get('first_name','')} {c.get('last_name','')}")
            if len(m['credentials_harvested']) > 3:
                print(f"    ... +{len(m['credentials_harvested'])-3} more (see se-metrics.json)")

    print(f"\n{sep}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--campaign-id", type=int, default=0, help="Specific campaign ID")
    ap.add_argument("--all", action="store_true", help="Fetch all campaigns")
    ap.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR", ""),
                    help="Engagement OUTPUT_DIR for saving reports")
    args = ap.parse_args()

    envs = _env("GOPHISH_API_KEY", "GOPHISH_URL")
    api_key    = envs.get("GOPHISH_API_KEY", "")
    base_url   = envs.get("GOPHISH_URL", "https://localhost:3333").rstrip("/")

    if not api_key:
        print("[!] GOPHISH_API_KEY not set. Add it to .env", file=sys.stderr)
        sys.exit(1)

    # Fetch campaigns
    if args.all:
        campaigns = gophish_get(f"{base_url}/api/campaigns/", api_key) or []
    elif args.campaign_id:
        c = gophish_get(f"{base_url}/api/campaigns/{args.campaign_id}", api_key)
        campaigns = [c] if c else []
    else:
        campaigns = gophish_get(f"{base_url}/api/campaigns/", api_key) or []
        if campaigns:
            campaigns = [campaigns[-1]]  # latest

    metrics_list = []
    for campaign in campaigns:
        cid     = campaign.get("id")
        results = gophish_get(f"{base_url}/api/campaigns/{cid}/results", api_key)
        rows    = results.get("results", []) if results else []
        m       = compute_metrics(campaign, rows)
        metrics_list.append(m)

    print_dashboard(metrics_list)

    # Save outputs
    if args.output_dir:
        out_dir = Path(args.output_dir) / "artifacts"
        out_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        json_path = out_dir / "se-metrics.json"
        json_path.write_text(json.dumps(metrics_list, indent=2))
        print(f"[+] JSON saved: {json_path}")

        # CSV
        csv_path = out_dir / "se-metrics.csv"
        flat_keys = [k for k in metrics_list[0].keys() if k != "credentials_harvested"] if metrics_list else []
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=flat_keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(metrics_list)
        print(f"[+] CSV saved:  {csv_path}")


if __name__ == "__main__":
    main()
