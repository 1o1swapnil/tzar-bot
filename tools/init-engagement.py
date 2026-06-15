#!/usr/bin/env python3
"""
init-engagement.py — Initialise a new engagement OUTPUT_DIR.

Creates the full directory tree, writes attack-chain.md from the template,
and prints the coordinator checklist so nothing is skipped.

Usage:
    python3 tools/init-engagement.py --type WAPT --project acme-corp \\
        --target https://target.com [--mode blackbox] [--scope target.com,api.target.com]

Engagement types:
    WAPT  MAPT  API  Network  CodeReview  Cloud  RedTeam  DFIR  BugBounty
"""

import sys
import os
import re
import argparse
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).parent.parent.resolve()

VALID_TYPES = ["WAPT", "MAPT", "API", "Network", "CodeReview",
               "Cloud", "RedTeam", "DFIR", "BugBounty"]

SUBDIRS = [
    "recon",
    "findings",
    "logs",
    "artifacts/validated",
    "artifacts/false-positives",
    "tools",
    "reports",
    "evidence",
    "screenshots",
]

ATTACK_CHAIN_TEMPLATE = """\
# Attack Chain — {target}

## Engagement
- **Target:** {target}
- **Type:** {eng_type}
- **Mode:** {mode}
- **Scope:** {scope}
- **Started:** {started}
- **OUTPUT_DIR:** {output_dir}
- **Author:** Swapnil Khandekar — tzar-bot

---

## Coordinator Rules (read before every action)

> YOU ARE THE COORDINATOR. You MUST NOT run nmap, curl, ffuf, gobuster, sqlmap,
> nuclei, nikto, masscan, katana, or any scanning/exploitation tool directly.
> Spawn an executor Agent for ALL target interaction. Your job is to READ results,
> REASON about next steps, and WRITE this document before spawning the next batch.

---

## Phase Progress
| Phase | Status | Agents | Findings |
|-------|--------|--------|----------|
| 1 — Recon | pending | — | — |
| 2 — Source Code | pending | — | — |
| 3 — Authentication | pending | — | — |
| 4 — Injection / Server-Side | pending | — | — |
| 5 — Client-Side / API | pending | — | — |
| 6 — Business Logic | pending | — | — |
| V — Validation | pending | — | — |
| R — Report | pending | — | — |

---

## Discovered Services
| Port | Service | Version | Notes |
|------|---------|---------|-------|
| — | — | — | (populated after Phase 1) |

---

## Tech Stack
- **Framework:** (populated after Phase 1)
- **Database:** (populated after Phase 1)
- **WAF:** (populated after Phase 1)
- **Auth mechanism:** (populated after Phase 1)

---

## Findings Summary
| ID | Title | Severity | Status |
|----|-------|----------|--------|
| — | (none yet) | — | — |

---

## Tested Vectors
| Vector | Endpoint | Result | Notes |
|--------|----------|--------|-------|
| — | (none yet) | — | — |

---

## Active Hypotheses
1. (none yet — populate after Phase 1 recon)

---

## Next Steps
- [ ] Spawn Phase 1 executors: osint-agent, recon-agent, techstack-agent
"""

COORDINATOR_CHECKLIST = """\
╔══════════════════════════════════════════════════════════════════╗
║  ENGAGEMENT INITIALISED                                          ║
╠══════════════════════════════════════════════════════════════════╣
║  OUTPUT_DIR: {output_dir:<50}║
╠══════════════════════════════════════════════════════════════════╣
║  COORDINATOR CHECKLIST                                           ║
║                                                                  ║
║  1. Read skills/coordination/SKILL.md                            ║
║  2. Read the relevant skill SKILL.md files for this engagement   ║
║  3. attack-chain.md is initialised at OUTPUT_DIR/attack-chain.md ║
║  4. Update Phase Progress table before spawning each batch       ║
║  5. Write reasoning to attack-chain.md BEFORE every Agent() call ║
║  6. NEVER run target tools inline — spawn executor agents        ║
║  7. After all phases: python3 tools/validate-finding.py \\        ║
║       OUTPUT_DIR --all                                           ║
║  8. After validation: python3 tools/generate-report.py \\         ║
║       OUTPUT_DIR --client "CLIENT" --target "URL"                ║
╠══════════════════════════════════════════════════════════════════╣
║  BOUNDARY RULE (enforced)                                        ║
║  The coordinator reads files and spawns agents.                  ║
║  Executors run tools and write to OUTPUT_DIR.                    ║
║  If you are about to run a scanning tool — STOP. Spawn an agent. ║
╚══════════════════════════════════════════════════════════════════╝
"""


def sanitize_project(name):
    return re.sub(r'[^a-z0-9-]', '-', name.lower().strip()).strip('-')


def detect_type_from_target(target):
    t = target.lower()
    if any(k in t for k in ("api", "rest", "graphql", "grpc", "swagger", "endpoint")):
        return "API"
    if any(k in t for k in ("s3", "aws", "azure", "gcp", "k8s", "docker", "cloud")):
        return "Cloud"
    if any(k in t for k in ("apk", "ipa", "android", "ios", "mobile")):
        return "MAPT"
    if any(k in t for k in ("network", "vpn", "firewall", "ad.", "ldap", "smb")):
        return "Network"
    return "WAPT"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--type",    choices=VALID_TYPES,
                    help="Engagement type (auto-detected from target if omitted)")
    ap.add_argument("--project", required=True,
                    help="Project/client name (sanitised to lowercase-hyphen)")
    ap.add_argument("--target",  required=True,
                    help="Primary target URL or IP")
    ap.add_argument("--mode",    default="blackbox",
                    choices=["blackbox", "graybox", "whitebox"])
    ap.add_argument("--scope",   default="",
                    help="Comma-separated in-scope domains/IPs (supports *.x, CIDR, re:)")
    ap.add_argument("--out-of-scope", default="",
                    help="Comma-separated out-of-scope rules (deny wins over in-scope)")
    args = ap.parse_args()

    eng_type = args.type or detect_type_from_target(args.target)
    project  = sanitize_project(args.project)
    started  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    scope    = args.scope or args.target

    output_dir = BASE_DIR / eng_type / project / ts

    # Create directory tree
    for sub in SUBDIRS:
        (output_dir / sub).mkdir(parents=True, exist_ok=True)

    # Write attack-chain.md from template
    chain_path = output_dir / "attack-chain.md"
    chain_path.write_text(ATTACK_CHAIN_TEMPLATE.format(
        target=args.target,
        eng_type=eng_type,
        mode=args.mode,
        scope=scope,
        started=started,
        output_dir=str(output_dir),
    ))

    # Write engagement metadata JSON
    meta_path = output_dir / "engagement.json"
    import json
    in_scope_list = [s.strip() for s in scope.split(",") if s.strip()] if scope and scope.strip() else [args.target]
    out_of_scope_list = [s.strip() for s in args.out_of_scope.split(",") if s.strip()]
    meta_path.write_text(json.dumps({
        "target":       args.target,
        "type":         eng_type,
        "project":      project,
        "mode":         args.mode,
        "scope":        in_scope_list,        # legacy key (kept for back-compat)
        "in_scope":     in_scope_list,        # canonical key read by scope.py
        "out_of_scope": out_of_scope_list,    # deny-wins rules enforced in code
        "started":      started,
        "output_dir":   str(output_dir),
        "tester":       "Swapnil Khandekar",
        "org":          "tzar-bot",
    }, indent=2))

    # Register in session memory DB
    import subprocess as _sp
    _mem = _sp.run(
        [sys.executable, str(BASE_DIR / "tools" / "session-memory.py"), "save", str(output_dir)],
        capture_output=True
    )
    if _mem.returncode != 0:
        print(f"  [warn] session-memory registration failed: {_mem.stderr.decode().strip()}", file=sys.stderr)

    # Print checklist
    pad = str(output_dir)
    if len(pad) > 50:
        pad = "…" + pad[-49:]
    print(COORDINATOR_CHECKLIST.format(output_dir=pad))
    print(f"  OUTPUT_DIR={output_dir}")
    print(f"  attack-chain.md initialised")
    print(f"  engagement.json written")
    print(f"  session memory registered (memory.db)")
    print()

    # Emit shell-exportable OUTPUT_DIR for scripting
    print(f"export OUTPUT_DIR='{output_dir}'")


if __name__ == "__main__":
    main()
