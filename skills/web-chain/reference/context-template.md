# attack-chain.md — Structure and Update Rules

## Template

```markdown
# Attack Chain — <TARGET>

## Engagement
- **Target:** https://target.com
- **Mode:** blackbox / graybox
- **Scope:** target.com, api.target.com
- **Started:** YYYY-MM-DD HH:MM UTC
- **OUTPUT_DIR:** YYMMDD_hhmmss_target/

---

## Phase Progress
| Phase | Status | Agents | Findings |
|-------|--------|--------|----------|
| 1 — Recon | completed | recon-agent, osint-agent, tech-agent | 3 interesting paths |
| 2 — Source | skipped (no repo) | — | — |
| 3 — Auth | in_progress | auth-agent | — |
| 4 — Injection | pending | — | — |
| 5 — Client/API | pending | — | — |
| 6 — Logic | pending | — | — |

---

## Discovered Services
| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 80 | HTTP | nginx/1.24 | Redirects to 443 |
| 443 | HTTPS | nginx/1.24 | Main app |
| 8443 | HTTPS | Tomcat 9.0.65 | Admin panel at /manager |

---

## Tech Stack
- **Framework:** Laravel 10.x (PHP 8.2)
- **Database:** MySQL (inferred from errors)
- **WAF:** Cloudflare (detected by wafw00f)
- **Auth:** JWT (RS256), session cookies with HttpOnly

---

## Findings Summary
| ID | Title | Severity | Status |
|----|-------|----------|--------|
| finding-001 | Reflected XSS in search parameter | High | validated |
| finding-002 | SQL injection in /api/product | Critical | pending-validation |

---

## Tested Vectors
| Vector | Endpoint | Result | Notes |
|--------|----------|--------|-------|
| SQLi | /login | negative | Parameterized queries, no injection |
| XSS | /search?q= | **positive** | Reflected in HTML body, no encoding |
| IDOR | /api/user/ID | negative | UUIDs, sequential not used |
| JWT alg:none | /api/auth | negative | Signature properly validated |

---

## Active Hypotheses
1. Admin panel at /manager may accept default Tomcat credentials (tomcat:tomcat)
2. File upload at /profile-pic may allow SVG upload → stored XSS
3. GraphQL at /graphql — introspection enabled, schema not reviewed yet

---

## Next Steps
- [ ] Phase 3: Test admin panel login with default creds
- [ ] Phase 5: Enumerate GraphQL schema, test for BOLA
- [ ] Phase 6: Test file upload endpoint (hypothesis 2)
```

---

## Update Rules

### When to Update

- **After every executor batch completes** — before spawning the next phase
- **When a CVE is discovered** — add to Findings Summary immediately
- **When a hypothesis is disproven** — mark as negative in Tested Vectors

### What Each Section Means

| Section | Purpose |
|---------|---------|
| Phase Progress | Track which phases are done, skip reasons |
| Discovered Services | All ports/services found by nmap |
| Tech Stack | Framework, DB, WAF — drives which skills to use |
| Findings Summary | All confirmed + pending-validation findings |
| Tested Vectors | Every attack vector tried, with result — prevents re-testing |
| Active Hypotheses | Numbered list — assign to next executor batch |
| Next Steps | Concrete tasks for the next batch of executors |

### How to Pass Context to Executors

Paste the **full contents** of attack-chain.md into each executor's prompt under `CHAIN_CONTEXT:`. Do not summarize — executors need the full picture to avoid duplicate work.

### File Location

Always at: `OUTPUT_DIR/attack-chain.md`

Update with: Read current → append new section → Write back.
