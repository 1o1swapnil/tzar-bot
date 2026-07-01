# Tzar-Bot — Security Remediation Backlog

Findings from the expert security review of the platform's own tooling (not engagement
targets). Ordered by severity, then by value-per-effort. This is the *security* backlog;
feature/capability gaps live in `fixes-backlog.md`.

Each item: **status**, the issue, file:line, impact, and the fix. Say **"fix SEC-N"** to action one.

Legend: ✅ done · 🔴 open-critical · 🟠 open-high · 🟡 open-medium · ⚪ open-low

---

## ✅ SEC-1 — Scope enforcement bypassable (FIXED 2026-06-18)

- **Was:** `scope-check.py` used `command.startswith(prefix)` + `tokens[0]` anchoring. Any
  operator, wrapper, assignment, or pipe slipped an out-of-scope target past the hook —
  `cd /tmp && nmap OOS`, `X=1 nmap OOS`, `bash -c "nmap OOS"`, `H=OOS; nmap $H`,
  `echo OOS | xargs nmap` all reached the network. This contradicted the product's central
  "out-of-scope commands are blocked before they run" claim.
- **Fix:** rewrote the extractor to be shell-aware — `shlex` tokenization, split on
  operators/pipes, strip env-assignments and wrappers (`sudo`/`env`/`timeout`/`xargs`/`bash -c`),
  resolve `$VAR`, check every stage, with pipeline-aware host harvesting. 10/10 obfuscation
  vectors now blocked, 0 false positives.
- **Files:** `tools/scope-check.py`, regression tests in `tools/tests/test_smoke.py`
  (`test_scope_check_blocks_obfuscated_bypasses`, `test_scope_check_allows_in_scope_and_benign`).
- **Residual (accepted):** cannot read targets inside files (`-iL targets.txt`); single-label
  bare hosts (no dot) not harvested; not an egress control. Docs (README + CLAUDE.md) now frame
  it as defense-in-depth. See SEC-8 to harden the residual.

---

## 🟠 SEC-2 — `generate-report.py` download-and-execute bootstrap

- **Issue:** `_bootstrap_venv()` downloads `get-pip.py` from `bootstrap.pypa.io` to a predictable
  `/tmp` path and executes it with no integrity/hash check, then `os.execv`.
- **File:** `tools/generate-report.py` (~`:43-49`)
- **Impact:** remote-code-fetch + `/tmp` symlink-clobber race on a multi-user host → arbitrary
  code execution as the operator.
- **Fix:** ship `reportlab`/`Pillow` via `requirements.txt` into `tools/.venv` (now documented);
  remove the network bootstrap. If a fallback is kept, pin a SHA-256 of `get-pip.py` and verify
  before exec, and use `tempfile.mkdtemp()` (0700) instead of a fixed `/tmp` name.
- **Effort:** Low.

## 🟠 SEC-3 — Path traversal in playwright MCP file writers

- **Issue:** MCP args `name` / `output_dir` are joined into filesystem paths unsanitized, so a
  screenshot/file `name="../../etc/x"` escapes the engagement directory.
- **File:** `tools/playwright-mcp-server.py` (~`:154, 225, 258`)
- **Impact:** arbitrary file write outside `$OUTPUT_DIR` driven by tool input.
- **Fix:** resolve the final path and assert it is inside `$OUTPUT_DIR`
  (`Path(base).resolve()` is a parent of `target.resolve()`); reject `..`, absolute paths, and
  path separators in `name`.
- **Effort:** Low.

## 🟡 SEC-4 — playwright MCP DoS / crash on malformed Content-Length

- **Issue:** `int(headers.get(b"content-length", 0))` raises on a non-numeric header, and
  `read(length)` trusts an attacker-controlled length (memory exhaustion).
- **File:** `tools/playwright-mcp-server.py` (~`:467`)
- **Fix:** wrap the `int()` in try/except, cap the read at a sane maximum, stream/`readexactly`.
- **Effort:** Low.

## 🟡 SEC-5 — YAML template injection in nuclei template generator

- **Issue:** `--description` / `--body` / `--match-word` / `--cvss` are `.format()`-interpolated
  into a YAML template with no quoting/escaping; quotes or newlines break or inject fields.
- **File:** `tools/gen-nuclei-template.py` (~`:175-192`); also `os.makedirs(os.path.dirname(...))`
  crashes when `--output` has no directory component (~`:195`).
- **Fix:** build the template as a Python dict and `yaml.safe_dump` it; guard the dirname.
- **Effort:** Low–Medium.

## 🟡 SEC-6 — CSV formula injection + KeyError in SE dashboard

- **Issue:** GoPhish campaign/email/harvested values are written to CSV without neutralizing a
  leading `= + - @` (formula injection when opened in a spreadsheet); untrusted API data is
  indexed (`e["message"]`, `e["time"]`) and raises `KeyError`.
- **File:** `tools/se-dashboard.py` (~`:67-76, 111-115, 213-217`)
- **Fix:** prefix risky cells with `'`, use `.get()` with defaults, validate API shape.
- **Effort:** Low.

## ⚪ SEC-7 — Robustness: unguarded JSON loads + one f-string SQL

- **Issue:** several tools `json.loads` engagement/state/nvd files with no guard and crash on a
  corrupt file (`init-engagement.py`, `engagement-state.py`, `session-memory.py`,
  `gen-nuclei-template.py`); `token-meter.py:296` interpolates a column name into SQL (currently
  caller-locked to literals, so not injectable today).
- **Fix:** wrap loads in try/except with a clear error; keep the token-meter column caller-locked
  or map it through an allow-list.
- **Effort:** Low.

## ⚪ SEC-8 — Harden the residual scope gaps (depth-in-defense)

- **Issue:** post-SEC-1, the hook still can't see file-list targets (`-iL`, `xargs` from a file)
  and single-label bare hosts are not harvested.
- **Fix (optional):** for scanning tools, parse `-iL/--input-file` values and scope-check the
  file's contents at hook time; pair the hook with OS-level egress restriction (firewall / network
  namespace) for engagements that need a hard boundary.
- **Effort:** Medium.

---

## Secret hygiene (operational, not a code change)

- **Leaked GitHub PATs in `.claude/settings.local.json`** (git-ignored but live on disk, baked
  into permission rules). This violates the project's own "read tokens only via env-reader.py"
  rule. **Action:** rotate both `ghp_…` tokens now; stop persisting tokens into settings; use
  `gh auth login` / `env-reader.py` instead. (No repo file to commit — operator task.)

---

## Suggested order

SEC-2 → SEC-3 (the two open HIGHs, both Low effort) → SEC-4/5/6 → SEC-7 → SEC-8.
Rotate the leaked tokens independently and immediately.
