# Tzar-Bot — Usage & Command Guide

> How to install and run Tzar-Bot, with the commands you'll use day to day.
> For the deep reference see `docs/operations.md`; for a live autonomous run see
> `docs/lab-run-runbook.md`; for how it's built see `docs/tzar-bot-architecture.pdf`.

> ⚠️ **Authorized testing only.** Run Tzar-Bot solely against targets you own or are
> explicitly authorized to test. Scope is enforced in code, but that is defense-in-depth,
> not a licence — stay within your declared scope regardless.

---

## 1. What you can do with it

| Goal | How |
|---|---|
| Start a scoped engagement | `init-engagement` → exports `OUTPUT_DIR` |
| Check a target is in scope | `scope` |
| Track what's tested / claim work | `engagement-state` |
| Validate a finding | `validate-finding` |
| Generate a report | `generate-report` / `report-export` |
| Run an engagement autonomously | `engagement-runner` |
| Use the tools from Claude Code / any MCP client | the two MCP servers (`.mcp.json`) |
| Look up a CVE | `nvd-lookup` |
| Read secrets safely | `env-reader` |

Two ways to invoke every tool:

```bash
python3 tools/<tool>.py [args]      # direct
tzar <tool> [args]                  # after `pip install .` — see §2
```

---

## 2. Install

**Core is stdlib-first — it runs with zero third-party dependencies.** Optional features
(PDF, DOCX, browser automation, the autonomous runner) are packaging extras.

```bash
git clone https://github.com/1o1swapnil/tzar-bot.git
cd tzar-bot
cp .env.example .env        # then add your ANTHROPIC_API_KEY etc. (see §10)

# Editable install gives you the `tzar` CLI on PATH:
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # core (no deps)
pip install -e ".[runner]"  # + autonomous runner (anthropic SDK)
pip install -e ".[all]"     # + PDF, DOCX, browser
```

On Kali (PEP 668 / externally-managed) install into a venv as above, or use the
per-tool venvs the project already ships (`tools/.venv`, `tools/.venv-docx`).

The `tzar` umbrella CLI:

```bash
tzar list                   # list all available tools
tzar --version              # 0.1.0
tzar <tool> [args]          # run tools/<tool>.py  (hyphen or underscore accepted)
```

---

## 3. The core engagement workflow

Every engagement follows the same arc. Run it as a coordinator: init, then act.

```
init-engagement  →  (recon / test)  →  validate-finding  →  generate-report
                         ▲
                  scope + engagement-state guard every step
```

### 3.1 Initialise an engagement

Creates the full typed output tree, `engagement.json` (the code-enforced scope),
`attack-chain.md`, and **exports `OUTPUT_DIR`** into your shell:

```bash
eval $(python3 tools/init-engagement.py \
  --type WAPT --project acme-corp \
  --target https://acme.com --mode blackbox \
  --scope acme.com,api.acme.com \
  --out-of-scope admin.acme.com)

echo "$OUTPUT_DIR"     # e.g. WAPT/acme-corp/<timestamp>/
```

| Flag | Meaning |
|---|---|
| `--type` | engagement type → folder: WAPT, MAPT, API, Network, CodeReview, Cloud, RedTeam, DFIR, BugBounty |
| `--project` | client / project name (required) |
| `--target` | primary target URL or IP (required) |
| `--mode` | `blackbox` (default), `graybox`, `whitebox` |
| `--scope` | comma-separated in-scope rules (apex+subdomain, `*.wildcard`, CIDR, `re:` regex) |
| `--out-of-scope` | comma-separated deny rules (deny wins) |

> Never `mkdir` engagement folders by hand — always use `init-engagement`. All outputs go
> under the typed folder, never the repo root.

### 3.2 Check scope

```bash
python3 tools/scope.py --engagement "$OUTPUT_DIR/engagement.json" https://api.acme.com
# IN   https://api.acme.com
python3 tools/scope.py --engagement "$OUTPUT_DIR/engagement.json" https://evil.com
# OUT  https://evil.com (… no in-scope rule (default deny))

python3 tools/scope.py --in-scope acme.com --out-of-scope admin.acme.com host.acme.com
python3 tools/scope.py --selftest          # verify the engine
```

The same engine backs the `scope-check.py` PreToolUse hook, so out-of-scope Bash commands
are blocked before they run.

### 3.3 Track surface, worklist & work-claims

`engagement-state` is the resumable ledger (`state.json`) that records what's discovered,
what's tested, and which executor is working on what.

```bash
ES="python3 tools/engagement-state.py --output-dir $OUTPUT_DIR"

$ES summary                                            # counts + current phase
$ES set-phase test
$ES add-surface --json '[{"url":"https://api.acme.com/x?id=1","param":"id","vuln_class":"idor"}]'
$ES worklist --top 20                                  # impact-ranked, untested surface
$ES claim   --url https://api.acme.com/x?id=1 --agent exec-1 --param id --vuln-class idor
$ES mark-tested --url https://api.acme.com/x?id=1 --param id --vuln-class idor
$ES release --url https://api.acme.com/x?id=1 --agent exec-1 --param id --vuln-class idor
$ES claims                                             # active claims
```

`claim` exits 0 if granted, 1 if another agent already holds it — that's the dedup that
keeps two executors off the same surface.

### 3.4 Validate findings

Findings live in `$OUTPUT_DIR/findings/finding-NNN/`. Run the mechanical 5-check protocol:

```bash
python3 tools/validate-finding.py "$OUTPUT_DIR/findings/finding-001"   # one finding
python3 tools/validate-finding.py "$OUTPUT_DIR" --all                  # every finding
python3 tools/validate-finding.py "$OUTPUT_DIR" --all --strict         # WARN counts as fail
```

### 3.5 Generate the report

```bash
# Offline JSON + HTML (stdlib only, no deps):
python3 tools/report-export.py "$OUTPUT_DIR" --format both \
  --client "Acme Corp" --target https://acme.com

# Full PDF (uses the reportlab venv; auto-bootstrapped):
python3 tools/generate-report.py "$OUTPUT_DIR" \
  --client "Acme Corp" --target https://acme.com --tester "You" --mode blackbox
```

---

## 4. The autonomous engagement runner

`engagement-runner` runs the whole coordinator → executor → validator loop unattended.
**Full walkthrough (with a lab target) is in `docs/lab-run-runbook.md`.**

```bash
# 0. safety self-test — no API key / network / target needed
python3 tools/engagement-runner.py --selftest

# 1. dry-run — real agent reasoning + gate decisions, target untouched
python3 tools/engagement-runner.py run \
  --output-dir "$OUTPUT_DIR" --target https://acme.com --dry-run --budget 40000

# 2. live — executors actually run gated scanners against in-scope targets
python3 tools/engagement-runner.py run \
  --output-dir "$OUTPUT_DIR" --target https://acme.com --live --budget 60000

# 3. validate findings with the adversarial panel
python3 tools/engagement-runner.py validate --output-dir "$OUTPUT_DIR" --votes 3
```

| Command / flag | Meaning |
|---|---|
| `--selftest` | exercise the tool gate + validator logic offline |
| `run` | drive the coordinator loop |
| `--dry-run` | gate-only; never execute (default if `--live` absent) |
| `--live` | actually run scanners / HTTP requests (in-scope only) |
| `--budget N` | stop at N coordinator output tokens |
| `validate` | run the adversarial validator over findings |
| `--finding DIR` / `--votes N` | validate one finding / refuter panel size |

Requires `pip install .[runner]` and `ANTHROPIC_API_KEY` in `.env` for the live/dry-run loop.

---

## 5. Using the tools from Claude Code (MCP)

Two MCP servers are registered in `.mcp.json`:

| Server | What it exposes |
|---|---|
| `tzar-bot` (`tools/mcp-server.py`) | 15 tools — nvd_lookup, scope_check, validate_finding, init_engagement, engagement_state, token_meter, report_export, … — model-agnostic |
| `playwright` (`tools/playwright-mcp-server.py`) | scope-gated browser automation (navigate, click, screenshot, export session/HAR) |

In Claude Code these appear as `mcp__tzar-bot__*` / `mcp__playwright__*` tools, and the
skills are available as slash commands (`/recon`, `/hunt`, `/report`, …). Start them
manually for any MCP client with:

```bash
python3 tools/mcp-server.py            # stdio JSON-RPC
python3 tools/playwright-mcp-server.py
```

---

## 6. Credentials (secrets)

**Read environment variables only through `env-reader`** — never read `.env` directly. Only
allow-listed variable names are returned; anything else is refused.

```bash
python3 tools/env-reader.py ANTHROPIC_API_KEY NVD_API_KEY HTB_TOKEN
# ANTHROPIC_API_KEY=...
# NVD_API_KEY=NOT_SET
```

Put your keys in `.env` (gitignored, never committed). Extend the allow-list via
`config/env-allowlist.txt` or declare new vars in `.env.example`.

---

## 7. Supporting tools

```bash
# CVE lookup (CVSS / severity / description) — required whenever a CVE appears
python3 tools/nvd-lookup.py CVE-2024-12345

# Strip prompt-injection patterns from web content before using it in a prompt
python3 tools/scrub-web-content.py --text "<scraped html>" --json

# Generate a Nuclei v3 detection template
python3 tools/gen-nuclei-template.py --cve CVE-2024-12345 \
  --description "RCE in X" --path /api/v1/exec --severity high

# Token / cost telemetry and budgets
python3 tools/token-meter.py report "$OUTPUT_DIR"
python3 tools/token-meter.py budget "$OUTPUT_DIR" --set-usd 50
python3 tools/token-meter.py pricing

# Per-host request pacing (token bucket)
python3 tools/rate-limiter.py acquire --key api.acme.com --rps 5

# Cross-engagement memory
python3 tools/session-memory.py save "$OUTPUT_DIR"
python3 tools/session-memory.py list
python3 tools/memory-search.py "JWT bypass cloudflare" --limit 20

# Continuous / delta rescans
python3 tools/continuous-scan.py list
```

---

## 8. Testing & maintenance

```bash
# Hermetic smoke suite (no network) — 92 tests across the toolchain
tools/.venv-test/bin/pytest tools/tests/ -q
#   …or: python3 -m pytest tools/tests/ -q

# Built-in self-tests of the safety-critical engines
python3 tools/scope.py --selftest
python3 tools/pathguard.py
python3 tools/engagement-state.py selftest
python3 tools/engagement-runner.py --selftest

# Lint skills before committing skill changes
python3 tools/lint-skills.py
```

---

## 9. Quick reference (cheat sheet)

```bash
# Start
eval $(python3 tools/init-engagement.py --type WAPT --project NAME \
        --target https://TARGET --scope DOMAIN --out-of-scope DENY)

# Scope check
python3 tools/scope.py --engagement "$OUTPUT_DIR/engagement.json" URL

# Plan / track
python3 tools/engagement-state.py --output-dir "$OUTPUT_DIR" worklist --top 20

# Validate
python3 tools/validate-finding.py "$OUTPUT_DIR" --all

# Report
python3 tools/generate-report.py "$OUTPUT_DIR" --client NAME --target https://TARGET

# Autonomous (lab target)
python3 tools/engagement-runner.py run --output-dir "$OUTPUT_DIR" \
        --target https://TARGET --live --budget 60000
python3 tools/engagement-runner.py validate --output-dir "$OUTPUT_DIR"
```

---

## 10. Safety rules (always on)

- Only test what you're authorized to; stay inside the declared scope.
- Never run destructive operations (DROP/DELETE/`rm -rf`/DoS) — the gate blocks them, but
  don't rely on that.
- Secrets: only via `env-reader`; never commit `.env`, keys, or `*.db`.
- All output goes into the typed engagement folder — never the repo root.
- The code-enforced scope gate is defense-in-depth, not a network boundary; for the
  autonomous runner, bind lab targets to loopback.
