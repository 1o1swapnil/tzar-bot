# Cloud — Cloud Security Assessment

Security assessments of AWS, Azure, GCP environments, containers, and Kubernetes clusters.

## When to Use This Folder

- AWS security posture review
- Azure tenant security assessment
- GCP project security review
- Kubernetes cluster hardening review
- Docker / container image scanning
- Serverless function security testing
- Cloud misconfiguration assessments
- SSRF to cloud metadata exploitation (in-scope engagements)

## Skills Used

`cloud-containers` · `reconnaissance` · `server-side` · `source-code-scanning` · `cve-risk-score`

## Tools Required

```bash
aws sts get-caller-identity      # AWS CLI
az account show                  # Azure CLI
gcloud config list               # GCP CLI
pacu                             # AWS exploitation framework
ScoutSuite --help                # Multi-cloud auditing
prowler -h                       # AWS best practices
trivy image --help               # Container image scanning
kubectl version                  # Kubernetes CLI
```

## Quick Start

```
# AWS assessment (with credentials in .env):
"run cloud security assessment on our AWS account"

# Container image:
"scan this Docker image for vulnerabilities: nginx:1.18"

# Kubernetes:
"assess the Kubernetes cluster at https://k8s.internal:6443"

# SSRF to metadata (in web engagement):
"test SSRF to cloud metadata at 169.254.169.254"
```

## Output Structure

```
Cloud/
└── <cloud-account-or-project>/
    └── YYYYMMDD_HHMMSS/
        ├── attack-chain.md
        ├── recon/
        │   ├── scoutsuite-report/    # HTML report
        │   ├── prowler-output/       # JSON findings
        │   └── trivy-images/         # image scan results
        ├── findings/
        ├── artifacts/
        │   ├── iam-policies/         # NEVER commit
        │   └── secrets-found/        # NEVER commit
        ├── logs/
        └── reports/Cloud-Security-Report.pdf
```

## Cloud Security Focus Areas

- IAM: over-permissioned roles, wildcard policies, unused credentials
- Storage: public S3/blob/GCS buckets, unencrypted data
- Network: security groups, firewall rules, exposed services
- Compute: unpatched AMIs, public snapshots, metadata exposure
- Logging: CloudTrail/audit log disabled, monitoring gaps
