# Tzar-Bot — Orchestration Robustness Backlog

Backlog of multi-agent **execution-reliability** gaps observed during a live Network VAPT
(30-host full-TCP scan, 2026-06-25). These are not capability gaps — the platform's breadth is
strong — they are reliability gaps in how long-running, parallel, target-touching work is driven.

Pick any item and say **"apply fix N"** to implement it. Grouped by severity; within a group,
ordered by value-per-effort.

> **Provenance:** every item below has a concrete reproduction from the BFL engagement
> (`Network/bfl-external-vapt/20260625_203206/attack-chain.md` reasoning log).

---

## HIGH — Breaks reliable autonomous / multi-agent runs

### Fix 1 — Long-running executor tasks killed by the sub-agent Bash timeout  ✅ DONE (2026-06-26)
**Implemented:** `tools/long-run.py` (detached run + streamed incremental log + `.status` sidecar with
exit code; `start`/`status`/`--selftest`). Executor role (rule 8) and coordinator spawning guidance now
mandate explicit Bash `timeout` for ≤10 min tasks and `long-run.py start|status` for longer ones.
Smoke tests added (102 passing).

**Gap:** Background `Agent`-spawned executors run their tool via the Bash tool, which has a
**default ~2-minute timeout**. A full `-p-` scan (or any multi-minute tool) is silently killed
mid-run; because the scanner only persisted results after a *complete* host sweep, **all output
was lost** and the agent reported a generic failure. Took several wasted rounds to diagnose.
**Impact:** Any executor task >2 min is unreliable. Autonomous runs stall on the most common
operation (a port scan). Reliability of multi-agent execution: 3/10 → 8/10.
**Files:** `skills/coordination/reference/executor-role.md` (mandate explicit `timeout=` or
`run_in_background`), `skills/coordination/SKILL.md` (spawning guidance), optional helper in
`tools/` to wrap long tools with incremental output.
**Effort:** Low (guidance) / Medium (helper).
**Approach:**
- Executor role MUST set an explicit Bash `timeout` (up to the 600 s max) for any scan/exploit
  tool, OR launch it with `run_in_background` and poll.
- Long-running tool scripts MUST write **incremental** output (per-host / per-step), so a kill
  loses at most the in-flight unit, not the whole run.
- Coordinator guidance: prefer harness-tracked `run_in_background` for anything historically >90 s.

---

### Fix 2 — High-concurrency resource kill (no concurrency cap / adaptive sizing)
**Gap:** Running 5 parallel scan batches × 1200 worker threads (~6000 concurrent sockets)
triggered an **external `exit 144` kill** of the processes. There is no platform-level cap on
concurrent executors or per-executor resource footprint; the operator must discover the limit by
crashing into it.
**Impact:** Parallel fan-out (the whole point of the executor model) is unsafe above an unknown
threshold. Caused a full restart of the scan. Parallel-execution safety: 4/10 → 8/10.
**Files:** `tools/engagement-runner.py` (executor concurrency cap), `skills/coordination/SKILL.md`
(batch-size guidance), a shared scan-helper default (`MAX_WORKERS`).
**Effort:** Medium.
**Approach:**
- Default executor fan-out cap = `min(cpu_count-2, N)`; make batch size a documented knob.
- Custom scan helpers default to a conservative worker count (≈300–400) with a documented override.
- Runner should detect signal-kills (137/143/144) and auto-retry the unit at lower concurrency.

---

### Fix 3 — Executor lifecycle: rogue re-runs, stand-down not enforced
**Gap:** After the coordinator told `Agent`-spawned executors to **stand down**, one autonomously
**re-launched a scan** (colliding with the coordinator's own re-run and corrupting shared output
dirs). Stand-down was advisory; only an explicit `shutdown_request` actually stopped the agents,
and their orphaned OS processes had to be `kill -9`'d by hand. No central registry of
spawned-process PIDs / output-dir ownership.
**Impact:** Loss of control over delegated work; duplicate/colliding writes; manual cleanup.
Orchestration determinism: 3/10 → 8/10.
**Files:** `tools/engagement-runner.py` (process/agent registry + ownership), `tools/` new
`agent-supervisor.py` (track spawned PIDs, enforce stop, reap orphans),
`skills/coordination/reference/executor-role.md` (stand-down = hard stop).
**Effort:** Medium-High.
**Approach:**
- Register every spawned executor with its PID(s) and exclusive output sub-dir; coordinator can
  enumerate/terminate them deterministically.
- Make output writes idempotent + ownership-scoped (skip-if-exists guard, per-agent subdir) so a
  stray re-run cannot corrupt another's data.
- "Stand down" maps to a real terminate + orphan-reap, not a polite request.

---

## MEDIUM — Hardening & graceful degradation

### Fix 4 — Inline coordinator's "never run scanners" boundary is convention-only
**Gap:** The HARD BOUNDARY (coordinator never runs nmap/curl/sqlmap/etc. inline) is enforced for
the autonomous `engagement-runner` but, for the **inline Claude Code coordinator**, it is only a
CLAUDE.md instruction the model must self-police. Under pressure (failed delegation), the
boundary is easy to cross.
**Impact:** Inconsistent guarantee between the two execution modes. Boundary integrity: 5/10 → 9/10.
**Files:** `tools/scope-check.py` (or a sibling PreToolUse hook) to flag/deny target-touching
scanner binaries when run from the coordinator context; `.claude/settings.json` hook wiring.
**Effort:** Medium.
**Approach:**
- A PreToolUse hook classifies scanner/exploit binaries; in coordinator context it warns or blocks
  and prints "spawn an executor". Reuses the existing safe-prefix/argument-parsing machinery.

---

### Fix 5 — Tooling preflight & graceful degradation
**Gap:** The engagement assumed Kali tooling (nmap) and root; neither was present. There was **no
preflight** — failures surfaced only when a tool was invoked, and the UDP requirement was dropped
late. Fallbacks (Python connect-scan) were improvised mid-engagement.
**Impact:** Wasted cycles; silent capability loss (UDP). Environment resilience: 4/10 → 8/10.
**Files:** new `tools/preflight.py` (probe for nmap/masscan/root/required binaries per engagement
type), `init-engagement.py` (run preflight + record capability matrix), report note for dropped
coverage.
**Effort:** Low-Medium.
**Approach:**
- At `init-engagement`, probe required tools per engagement type; emit a capability matrix
  (present / missing / needs-root) and the documented fallback for each gap.
- Auto-record dropped coverage (e.g. "UDP: requires root — deferred") as a residual-scope item
  that flows into the report.

---

### Fix 6 — Scope-check blind to file-list (`-iL`) and stdin targets (documented limitation)
**Gap:** `scope-check.py` parses targets from the command line but **cannot see targets inside a
file** (`nmap -iL targets.txt`) or piped via stdin. Acknowledged in CLAUDE.md as defense-in-depth,
not a boundary — but worth closing for the common `-iL` case.
**Impact:** A file-driven scan could include out-of-scope hosts undetected. Scope-enforcement
completeness: 7/10 → 9/10.
**Files:** `tools/scope-check.py` (resolve `-iL <file>` / `--target-file` and validate each line
against `scope.py`), tests in `tools/tests/`.
**Effort:** Low-Medium.
**Approach:**
- Detect known target-file flags, read the file, and run every entry through `Scope.in_scope_host`;
  deny if any line is out of scope. Leave network-egress controls as the real boundary.

---

## Summary table
| # | Severity | Gap | Effort |
|---|----------|-----|--------|
| 1 | High | Executor tasks killed by 2-min Bash timeout | ✅ DONE |
| 2 | High | Resource kill at high concurrency (no cap) | Med |
| 3 | High | Rogue executor re-runs; stand-down not enforced | Med–High |
| 4 | Medium | Inline coordinator boundary is convention-only | Med |
| 5 | Medium | No tooling/root preflight or graceful degradation | Low–Med |
| 6 | Medium | Scope-check blind to `-iL` file targets | Low–Med |
