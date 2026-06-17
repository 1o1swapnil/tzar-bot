---
name: model-monitoring
description: Continuous AI/ML model drift and degradation monitoring — covariate shift, concept drift, prediction-latency SLA and fallback-trigger checks. Use for always-on / periodic assurance of a deployed decision model (RBI continuous-monitoring obligation) or to verify a model degrades gracefully under shifting input distributions.
allowed-tools: [Bash, Read, Write]
---

# Continuous Model Monitoring

Detects data drift and model degradation over time. Designed to run as a periodic /
background check (drive cadence with `/schedule` or `/loop`) so a deployed decision model
stays within its assured envelope — the continuous-monitoring half of AI model governance.

## Conventions

- `OUTPUT_DIR` from `init-engagement.py`; `TARGET_API` is the operator-set model endpoint
  (`export TARGET_API=...`), kept in scope. Run from an executor, not the coordinator.

```bash
mkdir -p "$OUTPUT_DIR/artifacts/monitoring" "$OUTPUT_DIR/logs"
```

## Test Categories

### 1. Data Drift (Covariate Shift) Detection

Detects when the incoming request distribution has skewed from the training / recent
baseline — the input the model sees no longer resembles what it was validated on.

```bash
# Compare current feature distributions against a stored baseline.
# Swap the simulated logic for a real KS / PSI test once a baseline sample exists.
python3 -c "
def covariate_shift_check(feature, baseline_mean, current_mean, threshold=0.10):
    if baseline_mean == 0:
        return
    delta = abs(current_mean - baseline_mean) / baseline_mean
    if delta > threshold:
        print(f'[ALERT] Covariate shift in {feature!r}: {delta*100:.1f}% off baseline.')
    else:
        print(f'[OK] {feature!r} within {threshold*100:.0f}% of baseline.')

covariate_shift_check('monthly_spend', baseline_mean=1000, current_mean=1150)
" | tee "$OUTPUT_DIR/artifacts/monitoring/data_drift_report.txt"
```

### 2. Concept Drift / Fallback Validation

Concept drift = the feature→outcome relationship itself shifts, so accuracy decays even
when inputs look normal. Validate that the system **alerts or falls back to manual /
rule-based review** when confidence drops, rather than silently emitting bad decisions.

```bash
echo "Simulating gradual concept drift against $TARGET_API ..."
for batch in 1 2 3; do
    echo "Sending batch $batch (progressively noisier data)"
    # Send increasingly out-of-distribution batches and record confidence per batch
done
echo "[*] Verify in target logs that the fallback / manual-review trigger fired."
```

### 3. Prediction Latency & Performance SLA

Confirms degradation is not happening at the inference/resource level — a latency breach
can itself be a denial-of-service or availability finding for a decisioning service.

```bash
python3 - "$TARGET_API/predict" <<'PY'
import urllib.request, time, json, sys
target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost/api/predict'
payload = json.dumps({'feature': 'value'}).encode()
req = urllib.request.Request(target, data=payload, headers={'Content-Type': 'application/json'})
try:
    start = time.time()
    urllib.request.urlopen(req, timeout=10).read()
    latency = time.time() - start
    print(f'Prediction Latency: {latency:.3f}s')
    if latency > 2.0:
        print('[FAIL] Latency SLA breached ( > 2.0s )')
except Exception as e:
    print(f'Request Failed: {e}')
PY
```

## Reporting

Drift and SLA breaches go to `OUTPUT_DIR/artifacts/monitoring/`. A confirmed,
silently-unhandled drift (no alert / no fallback) on a production decision model is a
governance finding — capture the baseline, the drifted batch, and the absence of any
fallback signal as evidence.
