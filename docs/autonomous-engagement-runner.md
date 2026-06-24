# Architecture — Autonomous Engagement Runner

> Status: design draft · 2026-06-24 · Target: Level-3 autonomy (give it `{target, scope, rules}`,
> it runs an entire engagement unattended and returns a validated report).
>
> This is the component that moves tzar-bot from **Level 2** (AI-orchestrated inside a Claude Code
> session) to **Level 3** (AI-autonomous, no human in the loop). It owns the agent loop instead of
> renting it from Claude Code.

---

## 1. The principle this must preserve

**AI decides, code enforces.** The runner is autonomous, but autonomy never bypasses the
deterministic guardrails. Every tool the model invokes is intercepted by *our* code and run through
`scope.py` / `pathguard.py` / the validator gates **before** it executes. The LLM proposes; the
harness disposes. This is exactly what makes an autonomous offensive tool *sellable* rather than
dangerous — and it maps cleanly onto the Claude API's **manual agentic loop**, which exists for
precisely this ("fine-grained control: approval gates, custom logging, conditional execution").

## 2. Surface choice — Claude API + manual tool-use loop

| Option | Verdict |
|---|---|
| **Claude API + tool use, manual loop** (we host compute, we run the loop) | ✅ **Chosen** |
| Managed Agents (Anthropic runs the loop + hosts the tool sandbox) | ❌ for the offensive core |
| Stay on Claude Code | ❌ — that's Level 2; we don't control the loop |

**Why the manual loop, not Managed Agents:** the whole product thesis is *we gate every tool call
through our scope engine before execution*. Managed Agents runs the loop and executes bash/tools in
Anthropic's container — we'd lose the interception point where scope enforcement lives. We must hold
the loop ourselves so that between "model emits a `tool_use` for `nmap …`" and "nmap actually runs,"
our `scope-check` fires. (Managed Agents remains a fine option later for *non-offensive* side agents
— e.g. a report-formatting agent — where there's nothing to gate.)

Models (from the Claude API skill — current IDs):

| Role | Model | $/1M in·out | Why |
|---|---|---|---|
| Coordinator | `claude-opus-4-8` | $5 / $25 | long-horizon planning, holds engagement context |
| Executor | `claude-sonnet-4-6` | $3 / $15 | adaptive, high-volume testing; cheaper per call |
| Validator | `claude-sonnet-4-6` | $3 / $15 | structured 5-check verdict |
| Triage / classify | `claude-haiku-4-5` | $1 / $5 | cheap yes/no calls (is-this-in-scope, dedupe) |

## 3. High-level architecture

```
                 engagement-runner.py  (the loop we own)
   ┌───────────────────────────────────────────────────────────────┐
   │  inputs: {target, scope, rules, type, budget}                  │
   │     │                                                          │
   │     ▼                                                          │
   │  init_engagement() ──▶ OUTPUT_DIR, engagement.json (scope)     │
   │     │                                                          │
   │  ┌──┴── COORDINATOR loop (Opus 4.8, adaptive thinking) ──────┐ │
   │  │  system = CLAUDE.md routing + mounted skills (CACHED)     │ │
   │  │  loop: messages.create(tools=[plan, spawn_executor,      │ │
   │  │         advance_phase, finish]) until end_turn           │ │
   │  └──────────┬───────────────────────────────────────────────┘ │
   │             │ spawns (separate API conversations)              │
   │     ┌───────┴────────┐                                         │
   │     ▼                ▼                                         │
   │  EXECUTOR loop    EXECUTOR loop      (Sonnet 4.6)              │
   │  tools=[bash*, http*, scope_check, write_finding]             │
   │     │                                                          │
   │     │  ╔═══════════════════════════════════════════════╗      │
   │     └─▶║  TOOL GATE (our code, every call):             ║      │
   │        ║   scope.py  → out-of-scope? deny               ║      │
   │        ║   pathguard → write outside sandbox? deny      ║      │
   │        ║   rate-limiter → throttle per host             ║      │
   │        ║   token-meter → over budget? stop              ║      │
   │        ║   audit log → append every decision            ║      │
   │        ╚═══════════════════════════════════════════════╝      │
   │             │ findings/finding-NNN/                            │
   │             ▼                                                  │
   │  VALIDATOR loop (Sonnet 4.6, structured output)               │
   │   → 5 checks → validated/ | false-positives/                  │
   │             │                                                  │
   │             ▼                                                  │
   │  generate-report.py ─▶ report.pdf                             │
   └───────────────────────────────────────────────────────────────┘
```

`bash*` / `http*` = tools whose execution is wrapped by the TOOL GATE. The model never touches a
socket directly — it emits a `tool_use`, our gate decides, our code runs the command.

## 4. The control loop (the heart)

The coordinator is a textbook manual agentic loop. Pseudocode (Python, `anthropic` SDK):

```python
import anthropic
client = anthropic.Anthropic()  # ANTHROPIC_API_KEY via env (read through env-reader allowlist)

SYSTEM = build_system_prompt(claude_md, mounted_skills)   # large, STABLE → cache it
messages = [{"role": "user", "content": kickoff(target, scope, rules)}]

while True:
    resp = client.messages.create(
        model="claude-opus-4-8",
        max_tokens=32000,
        thinking={"type": "adaptive"},               # let it plan
        output_config={"effort": "high"},
        system=[{"type": "text", "text": SYSTEM,
                 "cache_control": {"type": "ephemeral"}}],   # 90% cheaper reads
        tools=COORDINATOR_TOOLS,
        messages=messages,
    )
    token_meter.record(resp.usage)                   # cost telemetry + budget check
    if resp.stop_reason == "refusal":                # safety classifier declined
        handle_refusal(resp); break
    if resp.stop_reason == "end_turn":
        break                                        # coordinator says engagement done

    messages.append({"role": "assistant", "content": resp.content})
    tool_results = []
    for block in resp.content:
        if block.type == "tool_use":
            result, is_error = TOOL_GATE.dispatch(block.name, block.input)  # ← enforcement
            tool_results.append({"type": "tool_result", "tool_use_id": block.id,
                                 "content": result, "is_error": is_error})
    messages.append({"role": "user", "content": tool_results})

    if token_meter.over_budget() or engagement_state.phase == "done":
        break
```

The **executor** and **validator** are the same shape with their own tool sets and the cheaper
model. The coordinator spawns them by starting a *separate* `messages.create` conversation (keeps the
Opus loop's cache intact — switching models mid-conversation would invalidate it).

## 5. How existing tzar-bot assets plug in (almost everything is reused)

| New runner needs | Already have | Change |
|---|---|---|
| Engagement bootstrap | `init-engagement.py` | call it from the runner instead of a shell |
| Scope enforcement at the tool gate | `scope.py` | call `Scope.reject_reason()` in `TOOL_GATE.dispatch` |
| Write containment | `pathguard.py` | wrap every file-writing tool |
| Per-host pacing | `rate-limiter.py` | gate calls; throttle instead of blocking |
| Budget / cost ceiling | `token-meter.py` | feed every `resp.usage`; stop at limit |
| Worklist / what-to-test-next | `engagement-state.py` (`worklist`, `claim`) | the coordinator's planning memory |
| Finding validation | `validate-finding.py` | the validator agent's mechanical pre-check |
| Cross-engagement recall | `memory.db` + `session-memory.py` | seed the system prompt; persist learnings |
| Prompt-injection defense | `scrub-web-content.py` | scrub tool output before it re-enters context |
| Expert methodology | the 67 **skills** | the system prompt + on-demand loaded references |
| Report | `generate-report.py` | final step, unchanged |
| Tool exposure | `mcp-server.py` tool schemas | reuse the JSON schemas as Claude API `tools` |

**The skills are the moat and they carry over verbatim** — they become the coordinator's system
prompt (and on-demand context). The orchestration loop is the only genuinely new code.

## 6. Tool surface — bash for breadth, dedicated tools for the gate

Per the agent-design guidance ("start with bash for breadth; promote to dedicated tools when you need
to gate, render, audit, or parallelize"):

- **`run_scanner`** (dedicated, not raw bash) — typed input `{tool, target, args}`. The gate parses
  `target`, runs it through `scope.py`, applies `rate-limiter`, then executes `nmap`/`ffuf`/`sqlmap`/…
  in an isolated sandbox. Typed args let us audit and scope every invocation — a raw bash string
  can't be scoped reliably (the existing scope-check already warns it can't see `-iL targets.txt`).
- **`http_request`** (dedicated) — `{method, url, headers, body}`; gate scopes the URL host, paces
  it, scrubs the response with `scrub-web-content.py` before returning it to the model.
- **`write_finding`** (dedicated) — gated by `pathguard` to `OUTPUT_DIR/findings/`.
- **`scope_check`**, **`worklist`**, **`mark_tested`**, **`claim`** — thin wrappers over
  `engagement-state.py` so the model plans against real state.
- **`bash`** — only inside the isolated sandbox, allowlisted, last resort. Anthropic-defined
  (`{"type":"bash_20250124","name":"bash"}`), but **commands are untrusted model output**: isolated
  container, executable allowlist, reject shell operators, timeouts, full audit. (This is the same
  posture the skill mandates for the bash tool.)

## 7. Safety & governance — the part that makes it a *product*

Autonomy raises the stakes, so the gate is non-negotiable. Every `tool_use` passes through, in order:

1. **Scope** — `scope.py` deny-wins/default-deny. Out-of-scope host → tool returns `is_error`, the
   model sees the denial and re-plans. (Same authority as the Bash hook + the Playwright guard.)
2. **Path containment** — `pathguard` for any write.
3. **Rate limit** — `rate-limiter` per host (don't trip a WAF / get banned).
4. **Budget** — `token-meter`; also use the API's **Task Budgets** (`task_budget` in `output_config`,
   beta `task-budgets-2026-03-13`) so the model *sees* its remaining budget and winds down gracefully
   instead of being cut off.
5. **Destructive-action gate** — a denylist (DROP/DELETE/`rm -rf`/DoS) that hard-blocks regardless of
   model intent; optionally **human-approval** for a configurable risk tier (the manual loop makes a
   confirmation round-trip trivial).
6. **Audit log** — append-only record of every tool call + gate decision. This is both a safety
   control and the enterprise-grade artifact the product-readiness checklist flagged as missing.

Plus **adversarial self-verification**: the validator agent is prompted to *refute* each finding
(structured-output verdict), and is a *separate* conversation/context so it can't rubber-stamp the
executor. This is the #1 defense against the hallucinated-finding failure mode that kills trust in AI
security tools.

```python
# Validator returns a guaranteed-valid verdict via structured outputs
VERDICT_SCHEMA = {"type": "object", "additionalProperties": False,
  "required": ["is_real","cvss_consistent","evidence_exists","poc_valid","reasoning"],
  "properties": {"is_real":{"type":"boolean"}, "cvss_consistent":{"type":"boolean"},
                 "evidence_exists":{"type":"boolean"}, "poc_valid":{"type":"boolean"},
                 "reasoning":{"type":"string"}}}
resp = client.messages.create(model="claude-sonnet-4-6", max_tokens=4000,
        output_config={"format": {"type":"json_schema","schema":VERDICT_SCHEMA}},
        messages=[{"role":"user","content": refute_prompt(finding)}])
```

## 8. State machine & resumability

Phases drive the loop and make runs resumable (a long engagement *will* be interrupted):

```
recon → enumerate → test → validate → report → done
```

- Phase + worklist + claims live in `engagement-state.py` (`state.json`) — already built, already
  scope-guarded.
- The runner checkpoints after each coordinator turn (messages + phase + budget spent). On restart it
  reloads `state.json` and the message history and continues — no work lost.
- Stop conditions (any): phase == `done`, budget exhausted, worklist dry for K rounds, human stop,
  or a hard error.

## 9. Cost model (rough, one WAPT engagement)

With the big skills system prompt **cached** (reads at ~0.1×), a medium engagement is roughly:

- Coordinator: ~40 turns, mostly cached input → dominated by output tokens on Opus ($25/1M out).
- Executors: ~10 spawns × multi-turn on Sonnet ($15/1M out).
- Validators: ~1 per finding, short, structured.

Ballpark **$3–$15 per autonomous engagement** depending on depth — and `token-meter` enforces a hard
ceiling you set up front. (The Level-2 metaharness estimate was ~$0.024/run for a single tool call;
a full autonomous engagement is orders of magnitude more work, hence the jump.) The point: it's
**bounded and measured**, not open-ended.

## 10. The MVP — smallest thing that proves it

A single file, one engagement type, one safe target, no UI:

**`tools/engagement-runner.py`** — drives **one autonomous WAPT loop** against a lab target
(e.g. a local DVWA / juice-shop you own):

1. `init-engagement.py --type WAPT --scope <lab>` → OUTPUT_DIR.
2. Coordinator loop on Opus 4.8 with the `web-chain` skill as system prompt + 3 tools:
   `run_scanner`, `http_request`, `write_finding` — all behind the TOOL GATE (scope + pathguard +
   token-meter).
3. One executor spawn (Sonnet) for the actual testing.
4. One validator pass (structured verdict) → `validated/`.
5. `generate-report.py` → PDF.

If that runs end-to-end against a lab box, finds a real planted bug, the validator confirms it, and
**every out-of-scope probe is denied by the gate** — the autonomy thesis is proven. Everything after
that (more engagement types, more executors, the control plane, multi-tenancy) is scaling, not
risk.

**~1–2 weeks** for the MVP because the hard parts (scope, validation, state, tools, skills) already
exist — you're writing the loop and the gate, not the security engine.

## 11. Build milestones

1. **MVP loop** (above) — prove autonomy + the gate on one lab target.
2. **Multi-executor + worklist** — coordinator fans out via `engagement-state` claims; loop-until-dry.
3. **Adversarial validation pass** — N refuters per finding, majority gate.
4. **Resumability + audit log** — checkpoint/restore; append-only audit.
5. **Budget/Task-Budget integration** — graceful wind-down at the ceiling.
6. **Remaining engagement types** — reuse skills; the loop is type-agnostic.
7. *(Product layer, separate track)* — API/control plane, auth, multi-tenant isolation
   (see `product-readiness-checklist.md` Path B).

## 12. Open decisions (need a human call)

- **Own runtime vs Claude Code** — this design owns the runtime (Path B). Confirm that's the
  direction; if you want to stay Level 2, none of this is needed.
- **Human-approval tier** — fully autonomous, or pause-for-approval on a risk tier (destructive /
  out-of-original-scope discovery / exploitation that changes server state)? The loop supports both;
  it's a policy decision.
- **Compute sandbox** — where do `nmap`/`sqlmap` actually run? (container per engagement is the clean
  answer; ties into the multi-tenant isolation gap.)
- **Self-hosted vs hosted** — does the runner run on the operator's box (single-tenant, today) or as a
  hosted service (multi-tenant, the product)? Decides how much of §7's isolation you build now.
