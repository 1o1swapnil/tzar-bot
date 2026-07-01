# Tzar-Bot — Tool & Skill Naming Conventions

The `tools/` collection should read as **one platform**, not a pile of independent scripts.
Every new tool follows the conventions below; existing tools are aligned to them (with
documented exceptions for a few legacy single-action tools).

---

## 1. Files & invocation
- **Filename:** lowercase `kebab-case.py` (e.g. `mitre-lookup.py`, `agent-supervisor.py`).
- **Invocation:** `python3 tools/<name>.py …` (stdlib-first; a tool may shell out to a venv).
- **MCP name:** snake_case mirror of the tool — `mitre-lookup.py` → `mitre_lookup`,
  `atomic-red.py` → `atomic_red`. The MCP `action` enum mirrors the CLI subcommands.

## 2. Self-test — always `--selftest`
Every tool exposes a `--selftest` flag returning exit 0 on success. (Tools that historically
had a `selftest` *subcommand* keep it as a back-compat alias.)

## 3. Machine output — always `--json`
Read/query commands accept `--json` for machine-readable output. The MCP layer always passes
`--json`.

## 4. Shared subcommand vocabulary
Tools that take subcommands draw verbs from one vocabulary so behaviour is predictable:

| Verb | Meaning |
|------|---------|
| `update` | refresh a local data set / index from upstream |
| `lookup <id>` | fetch one item by its identifier |
| `search <terms>` | keyword search |
| `map <text>` | map a finding / description → ranked suggestions |
| `list` | enumerate items |
| `show <id>` | full detail of one item |
| `stats` | coverage / summary |
| `recommend` | compute a recommendation |
| `check` | probe / validate current state |
| `register` · `claim` · `start` · `status` · `stop` · `reap` | lifecycle control |

**Do not** invent a synonym for an existing verb (e.g. use `map`, never `for-finding`).

## 5. The engagement directory — one resolution everywhere
Every engagement-scoped tool resolves the OUTPUT_DIR the same way, in this order:

1. **`--output-dir DIR`** flag (canonical), then
2. **positional** argument (back-compat for tools that historically took it positionally), then
3. **`$OUTPUT_DIR`** environment variable (exported by `init-engagement.py`).

So all of these are equivalent and accepted:
```bash
python3 tools/validate-finding.py --output-dir "$OUTPUT_DIR" --all
python3 tools/validate-finding.py "$OUTPUT_DIR" --all          # positional, still works
OUTPUT_DIR=… python3 tools/validate-finding.py --all           # env, no arg needed
```
Aligned tools: `generate-report`, `report-export`, `validate-finding`, `token-meter`,
`session-memory` (save/load), plus the already-flagged `preflight`, `agent-supervisor`,
`engagement-state`, `notify`, `gen-nuclei-template`, `se-dashboard`.

**Multi-dir exception:** `continuous-scan.py` operates on *two* dirs (`delta NEW BASE`), so it keeps
positional arguments — there is no single OUTPUT_DIR to flag.

## 5b. Other standard flags
| Flag | Use |
|------|-----|
| `--json` | machine-readable output |
| `--selftest` | internal self-test |
| `--limit N` | cap result count for `search` / `map` |
| `--matrix` / `--platform` | data-set filters (ATT&CK matrix, OS platform) |
| `--dry-run` | show what would happen without doing it |

## 6. Exit codes
`0` success · `1` usage/runtime error · `2` blocked / not-found · `3` conflict (e.g. ownership
collision). PreToolUse hooks (`scope-check.py`, `coordinator-guard.py`) use `2` to block.

---

## Tool families (current)
- **Knowledge lookup** — `nvd-lookup`, `mitre-lookup`, `atomic-red`: `update / lookup / search / map / stats` + `--json`.
- **Orchestration & resilience** — `agent-supervisor`, `long-run`, `concurrency`, `preflight`, `coordinator-guard`.
- **Engagement & state** — `init-engagement`, `engagement-state`, `session-memory`, `continuous-scan`.
- **Findings & reporting** — `validate-finding`, `generate-report`, `report-export`, `md-to-docx`, `md-to-pdf`.
- **Scope & safety** — `scope`, `scope-check`, `coordinator-guard`, `pathguard`, `scrub-web-content`, `rate-limiter`.

## Skills
- **Skill dir / `name:`** — lowercase `kebab-case`, matching the SKILL.md `name:` field exactly.
- A skill backed by a tool names the **domain**, the tool names the **action**:
  `mitre-attack` (skill) ↔ `mitre-lookup.py` (tool); `atomic-red-team` (skill) ↔ `atomic-red.py` (tool).
- Every native skill declares `allowed-tools:` and is listed in the CLAUDE.md Skills Overview.
