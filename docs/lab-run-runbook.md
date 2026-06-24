# Lab-Run Runbook — first live run of the autonomous engagement runner

> Purpose: drive the full **coordinator → executor → validator** triangle against a
> **safe, self-owned lab target**, and watch the code-enforced gate keep it in scope.
> This is the first time the real Claude API loop drives the runner end-to-end.

**What this proves (and what it does not):** it proves the *machinery* — the
coordinator plans and delegates, executors claim work and run gated scanners, every
out-of-scope/destructive action is denied by code, findings are written and then
adversarially validated. It is **not** a complete pentest: the MVP coordinator seeds
surface from its own knowledge of the target rather than deep crawling (that's a later
milestone). Judge it on "did the triangle work and did the gate hold," not on coverage.

> ⚠️ **Only ever point this at a target you own and are authorized to test.** The whole
> point of the lab is a throwaway, intentionally-vulnerable box bound to localhost.

---

## 0. One-time sanity check (no API, no target, no cost)

Confirm the safety core works before spending a cent:

```bash
cd /home/kali/Documents/tzar-bot
python3 tools/engagement-runner.py --selftest
# expect: ... engagement-runner selftest: PASS
```

That exercises the scope gate, path containment, scanner allowlist, claim dedup, and
the validator vote logic — all offline.

---

## 1. Stand up a lab target (OWASP Juice Shop)

Single container, no DB setup, intentionally vulnerable. Bind it to **loopback only** so
it is never exposed off-box:

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# leave this running in its own terminal; Ctrl-C to tear down
```

Verify it's up: open `http://127.0.0.1:3000` or `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000` → `200`.

No Docker? Any local DVWA / Juice Shop / WebGoat works — just keep it on `127.0.0.1`
and adjust the port below.

---

## 2. Credentials (.env, read only via env-reader)

The runner reads `ANTHROPIC_API_KEY` through `env-reader.py` (allow-listed; never read
`.env` directly). Put your key in `.env` at the repo root:

```bash
# .env  (gitignored — never commit it)
ANTHROPIC_API_KEY=sk-ant-...
```

Confirm the runner can see it (prints the value or NOT_SET, never DENIED):

```bash
python3 tools/env-reader.py ANTHROPIC_API_KEY | sed 's/=.*/=<present>/'
```

`ANTHROPIC_API_KEY` is already on the allow-list (declared in `.env.example`).

---

## 3. Install the runner extra

```bash
python3 -m venv .venv-runner && . .venv-runner/bin/activate
pip install -e ".[runner]"       # pulls the anthropic SDK; core stays stdlib-only
```

(Or `pip install anthropic` into whatever environment you run from.) If the live loop
later errors on `output_config` or adaptive thinking, your SDK is too old — `pip install
-U anthropic` and bump the floor in `pyproject.toml`.

---

## 4. Initialize the engagement (scope = loopback)

This creates `OUTPUT_DIR`, writes `engagement.json` with the scope the gate enforces, and
exports `$OUTPUT_DIR`:

```bash
eval $(python3 tools/init-engagement.py \
  --type WAPT --project juice-lab \
  --target http://127.0.0.1:3000 --mode blackbox \
  --scope 127.0.0.1,localhost \
  --out-of-scope metadata.google.internal)
echo "OUTPUT_DIR=$OUTPUT_DIR"
```

The gate now allows only `127.0.0.1` / `localhost`; everything else is denied in code.

---

## 5. Dry-run first — watch the agents think, target untouched

`--dry-run` runs the **real** coordinator/executor loops (so you see the reasoning and
every gate decision) but the gate **simulates** tool execution instead of running scanners
or sending requests. Best first look; small budget caps cost:

```bash
python3 tools/engagement-runner.py run \
  --output-dir "$OUTPUT_DIR" \
  --target http://127.0.0.1:3000 \
  --dry-run --budget 40000
```

Watch the gate decisions stream on stderr (`[gate] ALLOW …` / `[gate] DENY …`). You should
see the coordinator `add_surface` / `delegate`, executors claim items, and dry-run
"would run" lines — with anything off-scope denied.

**Optional adversarial check:** confirm the gate denies an out-of-scope target even when
asked, by initializing a second engagement scoped to something else and watching a probe
get blocked — or just trust the offline selftest, which already proves it.

---

## 6. Live run — executors actually scan the lab

When the dry-run looks right, run for real. `--live` lets the gate execute allow-listed
scanners and HTTP requests **against the in-scope lab only**:

```bash
python3 tools/engagement-runner.py run \
  --output-dir "$OUTPUT_DIR" \
  --target http://127.0.0.1:3000 \
  --live --budget 60000
```

Scanners must be installed (Kali has them: nmap, ffuf, nuclei, httpx, curl…). The gate
still enforces scope/allowlist/path on every call; `--budget` stops the coordinator at N
output tokens.

---

## 7. Validate the findings (adversarial panel)

After the run, validate everything the executors wrote:

```bash
python3 tools/engagement-runner.py validate --output-dir "$OUTPUT_DIR" --votes 3
# CONFIRMED      finding-001  (3/3 votes, mechanical=pass)
# FALSE POSITIVE finding-002  (1/3 votes, mechanical=pass)
```

Confirmed findings land in `artifacts/validated/`, rejected ones in
`artifacts/false-positives/`, each with the per-lens verdicts.

---

## 8. What to watch / where things land

```
$OUTPUT_DIR/
├── engagement.json              # scope the gate enforces
├── audit.log                    # append-only: every tool call + ALLOW/DENY decision
├── state.json                   # worklist + claims (engagement-state)
├── findings/finding-NNN/        # what executors wrote
│   └── description.md
└── artifacts/
    ├── validated/finding-NNN.json
    └── false-positives/finding-NNN.json
```

Live-tail the gate's decisions and findings as it runs:

```bash
tail -f "$OUTPUT_DIR/audit.log"
watch -n2 'ls "$OUTPUT_DIR"/findings/*/ 2>/dev/null'
```

**Success for this runbook =** the run completes, `audit.log` shows executors scanning the
lab while **every out-of-scope/destructive attempt is DENIED**, at least one finding is
written, and the validator routes it to validated/ or false-positives/. That's the whole
triangle working under code-enforced scope.

---

## 9. Safety & teardown

- Keep the lab on `127.0.0.1`; never point a live run at anything you don't own.
- The gate is defense-in-depth, **not** a network boundary — the loopback bind is your
  real containment. Don't run this on a box with other in-scope-looking services.
- Tear down: `Ctrl-C` the Juice Shop container (it's `--rm`). The engagement folder under
  `WAPT/juice-lab/` is yours to keep or delete; it's gitignored output, never committed.
- Rotate the API key if it was ever exposed.

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `pip install anthropic … to run the live loop` | `pip install -e ".[runner]"` (step 3) |
| `ANTHROPIC_API_KEY not available via env-reader` | key missing from `.env`, or not on the allow-list — see step 2 |
| `AttributeError: output_config` / thinking 400 | SDK too old → `pip install -U anthropic`; bump floor in `pyproject.toml` |
| every action DENIED, nothing runs | scope too tight or wrong target — check `engagement.json` scope vs `--target` host |
| `no active scope` | `$OUTPUT_DIR` unset or `engagement.json` missing — re-run step 4 |
| executor: `<tool> not installed` | install the scanner (e.g. `apt install ffuf`) or let the model use `http_request` |
| coordinator finds little | expected for the MVP (shallow recon) — proves the machinery, not coverage |

---

### One-liner recap

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop &      # lab
python3 tools/engagement-runner.py --selftest                       # safety core (offline)
eval $(python3 tools/init-engagement.py --type WAPT --project juice-lab \
        --target http://127.0.0.1:3000 --scope 127.0.0.1,localhost) # scope
python3 tools/engagement-runner.py run --output-dir "$OUTPUT_DIR" \
        --target http://127.0.0.1:3000 --dry-run --budget 40000     # watch it think
python3 tools/engagement-runner.py run --output-dir "$OUTPUT_DIR" \
        --target http://127.0.0.1:3000 --live --budget 60000        # scan the lab
python3 tools/engagement-runner.py validate --output-dir "$OUTPUT_DIR"  # validate
```
