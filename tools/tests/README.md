# tools/tests — smoke suite

Fast, hermetic smoke tests for the `tools/` CLI utilities. Catches the cheap,
high-value regressions: a tool that stops compiling, crashes on `--help`, or
breaks its core happy path. **Not** a full functional suite — no network, no
browser, no GoPhish/NVD/webhook calls, and no writes to the real `memory.db`.

## Run

```bash
# Isolated venv that has pytest (created once; gitignored)
python3 -m venv tools/.venv-test && tools/.venv-test/bin/pip install -q pytest
tools/.venv-test/bin/python -m pytest tools/tests/ -q

# …or, if pytest is already on PATH
python3 -m pytest tools/tests/ -q
```

## What it covers

| Layer | Tests |
|-------|-------|
| Compiles | every `tools/*.py` (20) via `py_compile` |
| `--help` exits 0 | all argparse tools except `generate-report` (it builds a venv at import) |
| Self-tests | `scope.py --selftest`, `engagement-state.py selftest` |
| Happy paths | env-reader, scrub-web-content (flag + pass), lint-skills, nvd usage error |
| Scope hook | `scope-check.py` allow (safe cmd) + block (out-of-scope, exit 2) |
| Read-only DB | `session-memory list`, `memory-search`, `continuous-scan list` |
| token-meter | record → report → budget(warn) → estimate → pricing, against an isolated DB |
| MCP servers | `mcp-server` `tools/list` (>=12, incl `token_meter`) + a `token_meter pricing` call; `playwright-mcp-server` initialize handshake (no browser) |

## Isolation

- `token-meter.py` is pointed at a throwaway DB via the `TZAR_MEMORY_DB` env var,
  so token/cost tests never touch the shared `memory.db`.
- `scope-check` block test builds a temp `engagement.json` in a `tmp_path`.
- Read-only memory tools (`list`/`search`) may read the real `memory.db` but never mutate it.
