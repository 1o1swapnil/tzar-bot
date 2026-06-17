---
name: bias-fairness-testing
description: AI/ML model bias and fairness testing — demographic parity, equalized odds, disparate-impact (Four-Fifths) and individual-fairness checks for credit-scoring / loan / KYC decision models. Use when the target is an AI-driven financial decision endpoint (RBI / fair-lending context) or any model that scores people.
allowed-tools: [Bash, Read, Write]
---

# Bias and Fairness Testing

Evaluate AI/ML models — especially financial decision models (credit scoring, loan
approval, KYC risk, insurance pricing) — for biased outcomes across protected
demographics. This is the **fair-lending / RBI model-governance** lens: a model that
denies one demographic at a materially different rate is a regulatory and reputational
finding, not just an accuracy bug.

## Conventions

- `OUTPUT_DIR` is exported by `init-engagement.py` — route every artifact under it.
- `TARGET_API` is the model-inference endpoint, set by the operator for the engagement,
  e.g. `export TARGET_API="https://target.example/api"`. Keep it in scope (the
  `scope-check.py` hook blocks out-of-scope hosts before the request runs).
- These are **executor** playbooks (they send live requests). Run them from an executor
  agent, never inline from the coordinator.

```bash
mkdir -p "$OUTPUT_DIR/artifacts/fairness" "$OUTPUT_DIR/logs"
```

## Test Categories

### 1. Demographic Parity (Statistical Parity)

Tests whether the outcome is independent of a sensitive attribute (gender, race, age,
caste, region). Identical financial profiles differing only in the protected attribute
should approve at statistically equal rates.

```bash
# Generate identical profiles that vary ONLY in the sensitive attribute
python3 -c "
import json
profiles = [
  {'id': 1, 'income': 50000, 'credit_score': 700, 'demographic': 'Group A'},
  {'id': 2, 'income': 50000, 'credit_score': 700, 'demographic': 'Group B'},
  {'id': 3, 'income': 50000, 'credit_score': 700, 'demographic': 'Group C'},
]
print(json.dumps(profiles))
" > "$OUTPUT_DIR/artifacts/fairness/synthetic_profiles.json"

# Send to the model endpoint (bulk if supported, else iterate per profile)
echo "Testing demographic parity against $TARGET_API ..."
curl -s -X POST "$TARGET_API/predict" \
  -H "Content-Type: application/json" \
  -d @"$OUTPUT_DIR/artifacts/fairness/synthetic_profiles.json" \
  > "$OUTPUT_DIR/logs/predictions_demo_parity.json"

# Analyse approval rate per demographic — a gap flags potential disparate treatment
```

### 2. Equalized Odds & Disparate Impact (Four-Fifths Rule)

Compares favorable-outcome rates for an unprivileged vs a privileged group. The US/EEOC
**Four-Fifths rule** (ratio ≥ 0.8) is the common bright line; ratios below it indicate
adverse impact on the protected class.

```bash
python3 -c "
def disparate_impact(priv_approved, priv_total, unpriv_approved, unpriv_total):
    priv_rate = priv_approved / priv_total
    unpriv_rate = unpriv_approved / unpriv_total
    return unpriv_rate / priv_rate if priv_rate > 0 else 0

# Example: privileged 45/50, unprivileged 30/50
di = disparate_impact(45, 50, 30, 50)
print(f'Disparate Impact Score: {di:.2f}')
print('FAIL: protected class adversely impacted (< 0.8 Four-Fifths threshold).'
      if di < 0.8 else 'PASS: within Four-Fifths threshold.')
" | tee "$OUTPUT_DIR/artifacts/fairness/disparate_impact_analysis.txt"
```

### 3. Individual Fairness (Counterfactual Flip)

Two profiles identical except for the protected attribute must receive the same outcome.
A differing decision is a direct, demonstrable individual-fairness violation.

```bash
PAYLOAD_A='{"income": 80000, "age": 35, "gender": "male"}'
PAYLOAD_B='{"income": 80000, "age": 35, "gender": "female"}'

RESP_A=$(curl -s -X POST "$TARGET_API/predict" -H "Content-Type: application/json" -d "$PAYLOAD_A")
RESP_B=$(curl -s -X POST "$TARGET_API/predict" -H "Content-Type: application/json" -d "$PAYLOAD_B")

echo "Outcome A (male):   $RESP_A"
echo "Outcome B (female): $RESP_B"
# Differing decision/probability on an otherwise-identical profile == finding
```

## Reporting

A confirmed disparity is a real finding — write it to `OUTPUT_DIR/findings/finding-NNN/`
with the synthetic inputs, the raw model responses, and the computed metric (parity gap
or DI score) as the evidence chain. Severity tracks impact: a credit/loan model failing
the Four-Fifths rule on a protected class is typically High.

## Tools and Libraries (Python)

For richer CSV-driven analysis use `aif360` (IBM AI Fairness 360) or `fairlearn`. If those
libraries are unavailable, the inline `python3 -c` snippets above are dependency-free and
sufficient for parity / disparate-impact / counterfactual checks.
