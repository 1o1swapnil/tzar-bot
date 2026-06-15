# Risk Scoring Model

## Severity weights

| Severity | Weight |
|----------|-------:|
| Critical | 10 |
| High     | 7  |
| Medium   | 4  |
| Low      | 1  |
| Info     | 0  |

## Exploitability multiplier

| Signal | Multiplier |
|--------|-----------:|
| CISA KEV listed | 1.5 |
| EPSS ≥ 0.7 | 1.3 |
| Public PoC available | 1.2 |
| Authenticated exploit only | 0.8 |
| Unreachable per tool | 0.6 |

Multipliers stack multiplicatively, capped at 2.0× and floored at 0.4×.

## Asset criticality (set in `scope.yaml`)

| Tier | Multiplier | Examples |
|------|-----------:|----------|
| T0 (Crown jewel) | 1.5 | Auth service, payment gateway, customer PII store |
| T1 (Production)  | 1.2 | Customer-facing app, public API |
| T2 (Internal)    | 1.0 | Internal tools, employee portals |
| T3 (Sandbox/dev) | 0.5 | Dev environments, throwaway clusters |

## Per-finding risk

```
finding_risk = severity_weight × exploitability_multiplier × asset_multiplier
```

Truncate to one decimal.

## Per-application risk score (0–100)

```
raw  = Σ(finding_risk_i)
norm = min(100, 100 × (1 - exp(-raw / 50)))
```

The asymptotic form prevents a single Critical from saturating the score and rewards reducing the long tail. Worked example:

| Findings | raw | score |
|----------|----:|------:|
| 1 Critical (KEV) | 10 × 1.5 × 1.2 = 18 | 30 |
| 5 High, exposed | 5 × 7 × 1.2 = 42 | 57 |
| 20 Medium | 20 × 4 = 80 | 80 |
| 1 Crit KEV + 5 High + 20 Med (mixed) | 140 | 94 |

## Remediation ROI

```
roi = severity_weight × exploitability_multiplier / effort_days
```

Sort the **Remediation Roadmap** tab descending by `roi`. The top quartile is "ship this sprint."

## Effort estimation (hours → days)

| Effort tag | Hours | Examples |
|------------|------:|----------|
| XS | 1 | Library upgrade with no breaking changes |
| S  | 4 | Config change, single-file fix |
| M  | 16 | Refactor a module, add canonicalization + tests |
| L  | 40 | Cross-cutting auth/authz rework |
| XL | 120+ | Framework migration, data model change |

These are *engineering* hours, not calendar time. Multiply by 1.5× for review/QA overhead when planning.
