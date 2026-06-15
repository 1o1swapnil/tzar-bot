# Tzar-Bot — Operations Reference

On-demand companion to `CLAUDE.md`. CLAUDE.md holds the always-on rules; this file holds
the full command syntax and procedures. Read the relevant section when you perform that task.

---

## Engagement initialisation (full)

```bash
eval $(python3 tools/init-engagement.py \
  --type WAPT \
  --project acme-corp \
  --target https://target.com \
  --mode blackbox \
  --scope target.com,api.target.com,*.lab.target.com,10.0.0.0/24 \
  --out-of-scope admin.target.com)
# OUTPUT_DIR is now exported into the shell
echo $OUTPUT_DIR
```

- `--type`: one of WAPT MAPT API Network CodeReview Cloud RedTeam DFIR BugBounty (auto-detected from target if omitted).
- `--scope`: comma-separated. Supports apex+subdomain (`target.com`), wildcard (`*.lab.target.com`), CIDR (`10.0.0.0/24`), regex (`re:^staging[0-9]+\.target\.com$`).
- `--out-of-scope`: comma-separated; **deny wins** over in-scope.
- Writes the directory tree, `attack-chain.md` (from template), and `engagement.json`; prints the coordinator checklist. The `eval $()` exports `OUTPUT_DIR`. Never use a manual `mkdir -p` block — `init-engagement.py` is the only correct way to start.

**Example paths**
- `WAPT/acme-corp/20260603_143022/reports/Penetration-Test-Report.pdf`
- `API/stripe-integration/20260603_090000/findings/finding-001/`
- `Network/internal-ad/20260603_120000/recon/nmap-full.txt`
- `BugBounty/hackerone-program-xyz/20260603_150000/findings/finding-001/`

---

## Tooling pre-flight

The hunt/recon skills assume a stocked toolchain (nmap, ffuf, nuclei, subfinder, httpx, katana, gf, qsreplace, `interactsh-client` for OOB callbacks, trufflehog, sqlmap, ysoserial, …). On a fresh box these are often missing. Before the first executor batch on a new environment:

```bash
bash tools/install-hunt-tooling.sh --check    # report what's missing (installs nothing)
bash tools/install-hunt-tooling.sh            # provision (apt + go install + pipx + git clone)
```

Idempotent, grouped by installer, resilient (one failure never aborts). After first install ensure `~/go/bin` and `~/.local/bin` are on `PATH`. **`interactsh-client` is the OOB-callback mechanism** referenced throughout the hunt skills — install it before any SSRF/blind-injection/OOB testing.

---

## Scope enforcement & engagement state (code-enforced)

Scope is enforced in **code** (not by trusting the model). Canonical authority: `tools/scope.py` — `Scope` class with deny-wins, default-deny, wildcard/CIDR/regex, suffix-confusion guard. Wired into two boundaries:

- **`tools/scope-check.py`** — PreToolUse hook. Every `Bash` command's target hosts/IPs are checked through `Scope`; out-of-scope commands are **blocked (exit 2)** before they run. Infra/tooling hosts (GitHub, NVD, mirrors, localhost) and safe prefixes always allowed. The safe-prefix allow-list is the built-in defaults **plus** anything in `config/safe-prefixes.txt` (operator-editable; merge-only, never removes a default).
- **`tools/engagement-state.py`** — resumable, scope-guarded ledger (`state.json` + `logs/engine.log` under `$OUTPUT_DIR`): surface / worklist / tested / candidates / confirmed / **claims**. Drops out-of-scope discoveries in code. Survives context compaction; auditable and resumable. Vuln-class ranking normalises aliases/verbose names (`sql-injection`→`sqli`, `remote-code-execution`→`rce`); unknown classes get a default weight (kept, ranked last).

```bash
python3 tools/scope.py --engagement "$OUTPUT_DIR/engagement.json" https://api.target.com   # check a target
python3 tools/scope.py --selftest

python3 tools/engagement-state.py summary
python3 tools/engagement-state.py set-phase hunt
python3 tools/engagement-state.py add-surface --json '[{"url":"https://api.target.com/u?id=1","param":"id","vuln_class":"idor"}]'
python3 tools/engagement-state.py worklist --top 10 --agent exec-1   # impact-ranked, not-yet-tested, hides items other agents hold
python3 tools/engagement-state.py confirm --url <u> --vuln-class idor --real true --severity high --reason "verified"
```

**Executor work-claim dedup** — so two parallel executors don't re-test the same surface, each claims an item before working it (exit 1 = already held):

```bash
python3 tools/engagement-state.py claim   --url <u> --param id --vuln-class idor --agent exec-1   # exit 0 acquired / 1 denied
python3 tools/engagement-state.py release --url <u> --param id --vuln-class idor --agent exec-1
python3 tools/engagement-state.py claims                                                          # JSON of current holders
```

**Request pacing** — to keep parallel executors from tripping a WAF or getting the source IP banned, gate scan traffic through a per-host token bucket (state persists across processes under `$OUTPUT_DIR/.ratelimit/`):

```bash
python3 tools/rate-limiter.py acquire --key target.com --rps 5 --burst 10   # blocks until a slot is free
python3 tools/rate-limiter.py acquire --key target.com --rps 5 --no-wait    # exit 1 if throttled (caller backs off)
```

The coordinator writes prose reasoning to `attack-chain.md` and structured state to the ledger.

---

## Validation & report gates

```bash
# Mechanical pre-check (run before spawning agent validators, and before the report gate)
python3 tools/validate-finding.py "$OUTPUT_DIR/findings/finding-NNN"   # single
python3 tools/validate-finding.py "$OUTPUT_DIR" --all                  # all findings

# PDF report (after validation)
/home/kali/Documents/tzar-bot/tools/.venv/bin/python3 \
  /home/kali/Documents/tzar-bot/tools/generate-report.py \
  "$OUTPUT_DIR" --client "CLIENT_NAME" --target "TARGET_URL"
# -> OUTPUT_DIR/reports/Penetration-Test-Report.pdf  +  OUTPUT_DIR/artifacts/pentest-report.json

# Offline JSON/HTML export — no reportlab, no network (air-gapped box / CI / quick preview)
python3 tools/report-export.py "$OUTPUT_DIR" --format both   # -> reports/report.json + reports/report.html
```

Validators run 5 checks (CVSS consistency, evidence exists, PoC validation, claims-vs-raw-evidence, log corroboration); ALL must pass or the finding is rejected to `OUTPUT_DIR/artifacts/false-positives/`. The mechanical pre-check catches CVSS/severity mismatches, missing evidence, PoC syntax errors, and absent logs — only escalate to an agent validator when it flags `evidence_exists` or `claims_vs_evidence` (human/LLM judgment). Validators follow `skills/coordination/reference/validator-role.md`.

---

## Token accounting & cost telemetry

The fan-out architecture (coordinator → N executors → M validators) makes token spend invisible by default. `tools/token-meter.py` records actual per-agent usage into `memory.db` and reports a per-role/phase/model breakdown with USD cost. Feed it the API `usage` object (`input_tokens`, `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`).

```bash
# Record one agent batch's usage (run after each executor/validator returns)
python3 tools/token-meter.py record "$OUTPUT_DIR" --role executor --agent recon-1 \
  --phase recon --model claude-opus-4-8 --in 80000 --out 25000 --cache-read 40000

# Semi-auto: executors drop a usage.json (their API usage object + role/agent/phase/model)
# anywhere under OUTPUT_DIR; the coordinator records them all in one call (then files are
# renamed *.recorded so a re-run never double-counts):
python3 tools/token-meter.py ingest "$OUTPUT_DIR"

# Set a ceiling — record warns at >=80% / >=100%
python3 tools/token-meter.py budget "$OUTPUT_DIR" --set-tokens 2000000 --set-usd 25

# Breakdown by role / phase / agent / model + totals + cost
python3 tools/token-meter.py report "$OUTPUT_DIR"

# Pre-flight: heuristic token+cost of a reference file BEFORE loading it
python3 tools/token-meter.py estimate skills/injection/reference/hunt-rce.md

python3 tools/token-meter.py list       # totals across all engagements
python3 tools/token-meter.py pricing    # model rate card (input/output/cache)
```

`estimate` is a heuristic gauge only — the authoritative count is the `count_tokens` API (never tiktoken for Claude). Pricing is cached from the claude-api model catalogue; Opus tiers carry a 1M context window at standard pricing (no long-context premium).

---

## Tool smoke tests

Hermetic pytest smoke suite for the `tools/` CLIs (compiles, `--help`, self-tests, happy paths, scope hook allow/block, MCP `tools/list`, token-meter cycle against an isolated DB). No network, no browser, no writes to the real `memory.db`.

```bash
python3 -m venv tools/.venv-test && tools/.venv-test/bin/pip install -q pytest   # once
tools/.venv-test/bin/python -m pytest tools/tests/ -q
```

Details: `tools/tests/README.md`.

---

## Credential / NVD detail

`python3 tools/env-reader.py VAR1 VAR2` is the ONLY approved way to read env vars/keys/tokens. Common: `HTB_TOKEN`, `HACKERONE_TOKEN`, `ANTHROPIC_API_KEY`, `SHODAN_API_KEY`, `NVD_API_KEY`.

`NVD_API_KEY` raises the NVD rate limit (5 → 50 req/10 s):
```bash
NVD_API_KEY=$(python3 tools/env-reader.py NVD_API_KEY | cut -d= -f2)
python3 tools/nvd-lookup.py CVE-YYYY-NNNNN --api-key "$NVD_API_KEY"
# or set NVD_API_KEY in .env — nvd-lookup.py reads it automatically.
```

---

## Skill maintenance (dev tasks)

**Lint** — after editing any skill, before committing:
```bash
python3 tools/lint-skills.py            # all skills + reference files
python3 tools/lint-skills.py skills/injection
python3 tools/lint-skills.py --strict   # warnings fail too (CI)
```
Enforces frontmatter structure, `name`==dir, the 400-char description routing-token budget, real-secret scan, resolvable `reference/` links, and import invariants (ERRORs on `recon/$TARGET/`, `mcp__burp__`, `~/.claude/`, `# INSTALLATION`; WARNs on residual BugHunter slash-commands or Collaborator mentions lacking the interactsh OOB note).

**BugHunter sync** — imported skills are a snapshot; check for upstream drift:
```bash
python3 tools/sync-bughunter.py            # report changed/new upstream skills since baseline
python3 tools/sync-bughunter.py --pull     # git pull upstream first, then report
python3 tools/sync-bughunter.py --diff NAME
python3 tools/sync-bughunter.py --accept NAME   # after re-importing + re-applying adaptations
```
Compares upstream-then vs upstream-now via `tools/bughunter-sync.manifest.json`, so local adaptations aren't mistaken for drift. When re-importing, re-apply conventions (`recon/$TARGET`→`$OUTPUT_DIR/recon`, neutralize Burp MCP, add interactsh OOB note, trim the description to the routing-token budget) before `--accept`.

**Two-tier skill structure** — a broad skill's `SKILL.md` is the quick-start + router; deep per-class material lives in `reference/hunt-*.md` (the source of truth, listed under each broad skill's "Deep-dive references (authoritative)"). Don't duplicate deep content back into the broad SKILL.md.

---

## Directory structure (per engagement run)

```
/home/kali/Documents/tzar-bot/
├── WAPT/ MAPT/ API/ Network/ CodeReview/ Cloud/ RedTeam/ DFIR/ BugBounty/
│   └── <project>/<timestamp>/          ← OUTPUT_DIR (created by init-engagement.py)
│       ├── attack-chain.md             ← coordinator's living document (prose)
│       ├── state.json                  ← engagement-state.py ledger (structured)
│       ├── engagement.json             ← scope + metadata (read by scope.py)
│       ├── recon/                      ← nmap, whatweb, gobuster, ffuf output
│       ├── findings/finding-NNN/       ← description.md, poc.py, evidence/
│       ├── screenshots/  evidence/     ← captures
│       ├── logs/                       ← NDJSON executor logs + engine.log
│       ├── artifacts/validated/        ← validator-approved findings JSON
│       ├── artifacts/false-positives/  ← rejected findings with reason
│       └── reports/                    ← Penetration-Test-Report.pdf + .json
├── skills/    ← all SKILL.md + reference/ files
├── tools/     ← init-engagement, scope, engagement-state, scope-check, validate-finding,
│              ←  generate-report, nvd-lookup, env-reader, lint-skills, sync-bughunter,
│              ←  install-hunt-tooling, scrub-web-content, session-memory, token-meter, ingest,
│              ←  report-export (offline JSON/HTML), rate-limiter (per-host pacing), mcp-server, …
├── formats/   ← report templates and schemas
├── config/    ← payloads, wordlists, headers
└── docs/      ← this file
```
