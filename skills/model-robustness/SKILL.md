---
name: model-robustness
description: ML model robustness and adversarial-perturbation testing — input noise injection, out-of-bounds / boundary inputs, evasion-attack resistance and graceful-failure checks for decision models. Use to verify a model is stable under perturbed, edge-case, or distribution-shifted input rather than producing catastrophic or crash-inducing predictions.
allowed-tools: [Bash, Read, Write]
---

# Model Robustness Testing

Adversarial / resilience testing for classical ML decision models — evaluate resistance
to evasion, perturbation, and edge-case input. A robust model gives stable predictions
under small input changes and **fails gracefully** (validation error, fallback) on
out-of-bounds input rather than emitting a confident, catastrophic decision or crashing.

## Conventions

- `OUTPUT_DIR` from `init-engagement.py`; `TARGET_API` is the operator-set model endpoint
  (`export TARGET_API=...`), kept in scope. Run from an executor, not the coordinator.

```bash
mkdir -p "$OUTPUT_DIR/artifacts/robustness" "$OUTPUT_DIR/logs"
```

## Test Categories

### 1. Input Perturbation (Noise Injection)

Inject small statistical noise into a known-good input and verify the prediction stays
within its confidence boundary. A decision that flips under tiny, semantically-irrelevant
perturbation indicates an unstable / adversarially-fragile model.

```bash
python3 - "$TARGET_API/predict" <<'PY'
import json, random, urllib.request, sys
target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost/api/predict'
baseline = 100
random.seed(1337)  # deterministic perturbations for reproducible evidence
for i in range(5):
    noise = random.randint(-15, 15)
    payload = json.dumps({'feature_value': baseline + noise}).encode()
    print(f'Sending perturbed input: feature_value={baseline + noise}')
    # req = urllib.request.Request(target, data=payload, headers={'Content-Type':'application/json'})
    # resp = urllib.request.urlopen(req, timeout=10).read()
    # Compare the prediction/confidence vs the baseline outcome — flag any decision flip
PY
```

### 2. Edge-Case & Boundary Testing

Send out-of-bounds, zeroed, null, and empty parameters to confirm the model rejects them
cleanly (4xx / validation error) rather than returning a confident garbage decision or
500/crash.

```bash
PAYLOADS=(
  '{"amount": -1000}'
  '{"amount": 99999999999999}'
  '{"amount": null}'
  '{}'
)
for p in "${PAYLOADS[@]}"; do
  echo "Testing edge boundary: $p"
  curl -s -X POST "$TARGET_API/predict" -H "Content-Type: application/json" -d "$p" -D - -o /dev/null \
    | head -n 1
done
```

### 3. Distribution-Shift Defense Check

Feed inputs resembling a seasonal drift or sudden demographic variance and verify the
model **logs / flags** the shift rather than confidently scoring far-out-of-distribution
data. (Pairs with `model-monitoring` for the continuous version of this check.)

```bash
echo "Simulating distribution shift against $TARGET_API ..."
# Send a batch sampled from a deliberately shifted distribution and record whether the
# model flags low confidence / triggers review, or silently returns a high-confidence score.
```

## Reporting

A flipped decision under trivial perturbation, an unhandled crash on boundary input, or a
high-confidence score on far-out-of-distribution data are all findings — write the input,
the model response, and the expected-vs-actual behaviour to
`OUTPUT_DIR/artifacts/robustness/` and escalate confirmed cases to
`OUTPUT_DIR/findings/finding-NNN/`.
