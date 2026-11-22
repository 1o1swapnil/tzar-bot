# Benchmarks

How good is tzar-bot, measured rather than claimed: run it against deliberately vulnerable
targets with known answers, and score it on the same answer key as Burp, ZAP, nuclei or a
human tester.

| Target | Runs here? | Answer key | What it measures |
|---|---|---|---|
| `juice-shop` | yes (Docker, arm64/amd64) | 33 entries + live scoreboard (118 challenges) | modern SPA + REST: injection, XSS, access control, JWT, business logic |
| `dvwa` | yes | 18 entries (one per module, security=low) | classic web vuln classes, easy baseline |
| `crapi` | yes, but heavy (~8 containers, ~3 GB RAM) | 14 entries | OWASP API Top 10: BOLA, BFLA, mass assignment, SSRF |
| `goad` | no — needs x86 Windows VMs, 24 GB+ RAM | template only | Active Directory (build on a separate lab host) |

Targets bind **127.0.0.1 only** (enforced in code and tests); never expose them.

## Run one

```bash
python3 tools/benchmark.py up juice-shop            # hook asks you: it starts a container
python3 tools/benchmark.py init juice-shop          # prints the init-engagement command
# → run tzar-bot normally against http://127.0.0.1:3000 (e.g. "run web chain on ..."),
#   validate findings (validate-finding.py --all), then:
python3 tools/benchmark.py score juice-shop tzar:"$OUTPUT_DIR" --label tzar-2026-11
python3 tools/benchmark.py solved juice-shop        # objective scoreboard
python3 tools/benchmark.py down juice-shop
```

Restart Juice Shop right before each run (`down` + `up`): its state lives in memory, so this
resets the scoreboard. `verify-gt` probes solve a couple of challenges by themselves.

## Baselines on the same key

```bash
python3 tools/benchmark.py score juice-shop burp:burp-issues.xml   --label burp-pro-active-scan
python3 tools/benchmark.py score juice-shop zap:zap-report.json    --label zap-full-scan
python3 tools/benchmark.py score juice-shop nuclei:nuclei.jsonl    --label nuclei-default
python3 tools/benchmark.py score juice-shop csv:human-tester.csv   --label human-2d
python3 tools/benchmark.py compare juice-shop
```

- **Burp**: Target → Issues → select all → *Report selected issues* → XML.
- **ZAP**: `zap.sh -cmd -quickurl http://127.0.0.1:3000 -quickout zap-report.json` (or the JSON report).
- **nuclei**: `nuclei -u http://127.0.0.1:3000 -jsonl -o nuclei.jsonl`.
- **Human**: CSV with `id,title,url,severity,cwe,class,description` (class optional; see the
  taxonomy in `tools/benchmark.py`). Time-box the human run and record the hours in the label.

## How scoring works

A finding matches an answer-key entry when the vulnerability classes overlap (families:
`xss` covers `xss-dom`, `access-control` covers `idor`/`bfla`, …) **and** a URL in the finding
matches one of the entry's endpoint patterns. Entries without patterns match on class alone.

- **recall**: entries found ÷ total; **weighted recall** weights critical 4, high 3, medium 2, low 1.
- **precision (raw)**: matched findings ÷ (matched + unmatched). Unmatched findings may be real
  bugs the key doesn't list. Mark them in an adjudication file
  (`{"finding-007": "valid", "finding-009": "invalid"}`, passed with `--adjudicate`) to get
  **precision (adjudicated)**. Add real ones to the key so the next run counts them.
- **hygiene**: missing headers, cookie flags, TLS, banners, clickjacking. Counted separately,
  excluded from precision and recall, so scanner noise doesn't decide the score.
- tzar-bot runs are scored twice: **all findings** and **report** (VALIDATED only — what the
  client would get), plus the verdict mix and wall-clock duration.

Results land in `benchmarks/results/<target>/` as JSON + Markdown.

## Answer keys are curated, not official

`ground-truth.json` lists what a competent tester should *report*, written from the targets'
public challenge lists. Entries marked `"verify": true` were curated from memory and still need
confirming on a real run. `benchmark.py verify-gt <target>` checks the endpoints with harmless GET
probes. Juice Shop 20.4.0: all probed endpoints present (2026-11-22). Improve the keys as you
learn; bump `version` when you do, and compare only runs scored against the same version.
