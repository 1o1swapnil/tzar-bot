# Tzar-Bot — Product-Readiness Gap Checklist

> Assessment date: 2026-06-24 · Branch: `harden/scope-check-shlex-and-ci`
> Honest scoring of where tzar-bot sits vs. a pitchable product. Grounded in the
> actual repo (225 tracked files: 174 markdown / 29 Python, 2 MCP stdio servers,
> no packaging manifest, no version tags, single-user by construction).

**One-line verdict:** a strong **open-source framework** with above-average
engineering taste and real domain depth — **not yet a product**. The gaps below
are not polish; they are the missing *product layer* (packaging, multi-user
service, isolation, support) plus the strategic "thin layer on Claude Code"
question.

Legend — Status: ✅ done · 🟡 partial · ❌ missing  ·  Effort: S (days) / M (weeks) / L (months)

---

## Scorecard (by category)

| # | Category | Score | Headline gap |
|---|----------|:-----:|--------------|
| 1 | Packaging & Distribution | 🔴 1/5 | clone-only; no installable/containerized artifact |
| 2 | Versioning & Release | 🔴 1/5 | no semver, no tags, no changelog |
| 3 | Architecture & Multi-tenancy | 🔴 1/5 | single-user; no service/auth/isolation layer |
| 4 | Runtime / Platform dependency | 🟠 2/5 | bet on Claude Code runtime; no abstraction |
| 5 | Security & Compliance | 🟢 4/5 | strong controls; no SBOM/secrets-scan/audit log |
| 6 | Data & State management | 🟠 2/5 | local SQLite + folders; no org-level store |
| 7 | Testing & Quality | 🟠 2/5 | one smoke suite (88 tests) for 25 tools + 67 skills |
| 8 | Documentation | 🟢 3.5/5 | excellent operator docs; no API/user/onboarding docs |
| 9 | Observability & Support | 🔴 1/5 | token-meter only; no logging/metrics/error reporting |
| 10 | Licensing / IP / Legal | 🟡 2.5/5 | MIT + auth disclaimer; no ToS, CLA, or content provenance |
| 11 | GTM / Productization | 🔴 1/5 | no pricing, packaging tiers, or onboarding path |

**Aggregate: ~2.0 / 5 — "credible framework, pre-product."**

---

## 1. Packaging & Distribution — 🔴

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Installable package (`pyproject.toml`) | ❌ | none present; install = `git clone` | S |
| Pinned, hash-locked deps | 🟡 | `requirements.txt` exists, unpinned; stdlib-first mitigates | S |
| Container image (Dockerfile) | ❌ | no Dockerfile/.dockerignore | M |
| Reproducible build | ❌ | no lockfile, no build step | M |
| Versioned releases / artifacts | ❌ | no GitHub Releases, no PyPI/registry | S |
| One-command bootstrap | 🟡 | `init-engagement.py` good; full setup is manual venv juggling | S |

**Action:** add `pyproject.toml` (console-scripts entry points for the tools), pin deps, ship a Dockerfile bundling Kali toolchain + Python. This is the single highest-leverage, lowest-effort jump.

## 2. Versioning & Release Management — 🔴

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Semantic versioning | ❌ | no tags (`git tag` empty); MCP server hardcodes "1.0.0" | S |
| CHANGELOG | ❌ | none | S |
| Release automation | ❌ | CI runs tests only; no release job | M |
| Deprecation policy | ❌ | n/a | — |
| Skill/tool compat contract | 🟡 | smoke tests assert tool surface; not formalized | M |

**Action:** adopt semver, tag `v0.1.0`, add `CHANGELOG.md` + a release workflow. Your commit hygiene is already conventional-commits-shaped — automate from it.

## 3. Architecture & Multi-tenancy / Isolation — 🔴

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Multi-user model | ❌ | single operator; no user concept | L |
| AuthN / AuthZ | ❌ | none | L |
| Tenant isolation | ❌ | engagement dirs + SQLite are shared local FS | L |
| Service / control plane | ❌ | only 2 MCP stdio scripts; no API server | L |
| Job/queue orchestration | 🟡 | coordinator/executor pattern exists, but in-process via Claude Code | L |
| Per-engagement secret isolation | 🟡 | `.env` global; allowlist added, but one keystore for all | M |

**Action:** this is the **product-vs-framework fork**. Genuine multi-tenancy is a 6–12 month re-architecture (API + auth + isolated workers + per-tenant store). Don't half-build it; decide Path A vs Path B first (see Roadmap).

## 4. Runtime / Platform Dependency — 🟠

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Own orchestration loop | ❌ | agent loop = Claude Code; you don't control it | L |
| Runtime abstraction | ❌ | hooks/skills bind directly to CC internals (PreToolUse, `.mcp.json`) | L |
| Model portability | 🟡 | MCP tools are model-agnostic; the *agents* are not | M |
| Resilience to CC API changes | ❌ | a hook-API change can break scope enforcement | M |

**Action:** the honest pitch must own this: "we are the scope-safe pentest **layer** for Claude Code." If you want independence, abstract the orchestration behind an interface so the same skills/tools can run on a self-hosted agent runtime later. Strategic, not urgent.

## 5. Security & Compliance — 🟢 (your strongest area)

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Code-enforced scope | ✅ | `scope.py` deny-wins + PreToolUse hook; now covers MCP browser too | — |
| Secret handling | ✅ | `env-reader` allowlist; `.env` gitignored; no secrets committed | — |
| Input/path/arg hardening | ✅ | MCP audit closed (scope, timeouts, path containment, arg-injection) | — |
| Prompt-injection defense | ✅ | `scrub-web-content.py` + executor behavioral rules | — |
| SBOM / dependency scanning | ❌ | no SBOM, no Dependabot/`pip-audit` in CI | S |
| Secrets scanning in CI | ❌ | no gitleaks/trufflehog gate | S |
| Tamper-evident audit log | ❌ | no immutable per-action audit trail (needed to sell to enterprises) | M |
| Compliance posture (SOC2-ish) | ❌ | none; expected the moment you host customer data | L |

**Action:** cheap wins now — add `pip-audit` + `gitleaks` to CI, generate an SBOM. Audit log + compliance come with Path B.

## 6. Data & State Management — 🟠

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Structured state | ✅ | `engagement-state.py` (state.json), `memory.db` (FTS5) | — |
| Migrations / schema versioning | ❌ | SQLite schema implicit; no migration tooling | M |
| Backup / retention / purge | ❌ | no lifecycle for engagement data (incl. captured cookies/PII) | M |
| Central org store | ❌ | per-machine local files; no shared backend | L |
| PII / evidence handling policy | 🟡 | `evidence-hygiene` skill exists; not enforced in code | M |

**Action:** for a security product, **data retention + evidence purge is table-stakes** (you store other people's cookies and PII). Define a lifecycle now even in framework mode.

## 7. Testing & Quality — 🟠

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Smoke tests | ✅ | `test_smoke.py`, 88 tests, multi-Python CI | — |
| Unit coverage of tools | ❌ | one file for 25 tools; logic largely untested | M |
| Skill validation | 🟡 | `lint-skills.py` structural lint only | M |
| Integration / e2e | ❌ | no end-to-end engagement test (mock target) | M |
| Coverage measurement | ❌ | no coverage gate | S |
| Regression suite for findings | ❌ | no golden-output tests for report/validator | M |

**Action:** raise unit coverage on the trust-critical core first — `scope.py`, `validate-finding.py`, `init-engagement.py`, `pathguard.py`. Add a coverage gate.

## 8. Documentation — 🟢

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Operator docs | ✅ | `docs/operations.md`, CLAUDE.md routing, README | — |
| Architecture docs | 🟡 | implicit in CLAUDE.md; no diagram / ADRs | S |
| API / tool reference | 🟡 | tool schemas in MCP server; no generated reference | M |
| User onboarding / quickstart | 🟡 | README install present; no "first engagement in 10 min" | S |
| Contributor guide / boundaries | ❌ | no CONTRIBUTING; unclear what's in/out of scope (see §11) | S |

## 9. Observability & Support — 🔴

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Cost/usage telemetry | 🟡 | `token-meter.py` (good!) — but local only | — |
| Structured logging | ❌ | ad-hoc stderr; no log levels/format | S |
| Metrics / health endpoints | 🟡 | MCP servers respond to handshake only | M |
| Error reporting | ❌ | no Sentry-equivalent; failures are silent locally | M |
| Support / SLA / status page | ❌ | n/a for a product | L |

## 10. Licensing / IP / Legal — 🟡

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| OSS license | ✅ | MIT | — |
| Authorized-use disclaimer | ✅ | strong, in README + CLAUDE.md | — |
| Terms of Service / AUP | ❌ | required before anyone else runs it as a service | M |
| Third-party content provenance | 🟡 | skills derive from public bug-bounty reports; attribution informal | M |
| CLA / contribution terms | ❌ | none | S |
| Trademark / name clearance | ❌ | "Tzar-Bot" not cleared | S |

## 11. GTM / Productization — 🔴

| Item | Status | Evidence / Gap | Effort |
|------|:------:|----------------|:------:|
| Clear ICP / positioning | 🟡 | "AI pentest platform" is broad; not yet a wedge | S |
| Pricing / tiers | ❌ | none | M |
| Onboarding funnel | ❌ | none | M |
| Competitive differentiation | 🟡 | code-enforced scope + skill depth are real; not articulated for buyers | S |
| Demo / reference engagement | ❌ | no canned demo against a safe target | M |

---

## Recommended sequencing

### Path A — Framework-first (recommended near-term, weeks not months)
Make it the credible OSS "scope-safe pentest layer for Claude Code." Highest ROI, lowest risk.
1. `pyproject.toml` + entry points + pinned deps (§1)
2. Semver + `v0.1.0` tag + `CHANGELOG` + release workflow (§2)
3. CI security gates: `pip-audit`, `gitleaks`, SBOM (§5)
4. Dockerfile bundling toolchain (§1)
5. Unit tests on trust-critical core + coverage gate (§7)
6. CONTRIBUTING + boundary doc (what's yours vs pulled-in `.claude/` sprawl) (§8, §11)
7. Data retention / evidence-purge policy (§6) — do this even in OSS mode; you store PII
8. Quickstart + one canned demo engagement (§8, §11)

### Path B — Productization (the big bet, 6–12 months)
Only after deciding the strategic question in §3/§4. Adds the entire product layer:
- API/control plane + AuthN/Z + multi-tenant isolation (§3)
- Isolated worker execution + job orchestration you control (§3, §4)
- Org-level data store + migrations + backup/retention + tamper-evident audit log (§5, §6)
- Observability stack (logging/metrics/error reporting) (§9)
- ToS/AUP, compliance roadmap (SOC2), content provenance cleanup (§10)
- Pricing, onboarding, billing (§11)

### The decision that gates everything
**Do you own the agent runtime, or stay a layer on Claude Code?** (§4)
- Stay a layer → Path A, faster, but your ceiling is "best CC pentest extension" and you carry vendor risk.
- Own the runtime → Path B, much larger lift, but it's the difference between a project and a defensible company.

Answer that first; it determines whether half this checklist is even in scope.
