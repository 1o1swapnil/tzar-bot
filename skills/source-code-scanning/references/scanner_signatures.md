# Scanner Output Signatures

Quick identification of scanner outputs without executing them. Read the first 100–300 lines only.

## SARIF (universal)
- Top-level keys: `$schema` containing `sarif-schema-2.1.0`, `runs[]`.
- Tool name lives at `runs[0].tool.driver.name`. Always read this **first** — it tells you which sub-format below applies.
- Common producers writing SARIF: CodeQL, Semgrep, Snyk Code, Sonar (export), Checkov, KICS, gosec, Bandit (with formatter), trivy-sarif.

## SAST

| Tool | Telltale fields |
|------|-----------------|
| **SonarQube/SonarCloud** | JSON: `issues[].rule` like `java:S2076`, `key`, `component`, `creationDate`. Export tabs include `hotspots`, `measures`. |
| **Semgrep** | JSON: top-level `results[].check_id` (e.g., `python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use`), `extra.metadata.cwe`, `extra.severity` in ERROR/WARNING/INFO. SARIF: `tool.driver.name == "Semgrep"`. |
| **CodeQL** | SARIF: `tool.driver.name == "CodeQL"`, rule IDs `java/path-injection`, `js/xss`, `py/sql-injection`. |
| **Checkmarx CxSAST** | XML root `<CxXMLResults>` with `<Query name=...><Result ...><Path>`. JSON (CxOne): `scanResults[].queryName`, `severity`. |
| **Fortify SCA** | FPR is a ZIP — inside, `audit.fvdl` (XML). Look for `<FVDL>`, `<Vulnerability>`, `<ClassInfo><Type>`. |
| **Veracode** | XML root `<detailedreport>` with `<severity level="...">`, `<flaw>`, `cweid` attribute. |
| **Snyk Code** | JSON: `runs[].results` SARIF; native `snyk code test --json` produces `runs[0].tool.driver.name == "SnykCode"`. |
| **Coverity** | JSON: `issues[].checker`, `subcategory`, `mainEventFilePathname`. |
| **Bandit** | JSON: `results[].test_id` like `B602`, `issue_severity`, `issue_confidence`. |
| **Brakeman** | JSON: `warnings[].warning_type`, `confidence`, `fingerprint`. |
| **gosec** | JSON: `Issues[].rule_id` like `G401`, `severity`, `confidence`. |
| **SpotBugs/FindSecBugs** | XML root `<BugCollection>`, `<BugInstance type="...">`. |
| **ESLint security plugins** | JSON: `messages[].ruleId` `security/detect-object-injection` etc. |

## SCA / SBOM

| Tool | Telltale fields |
|------|-----------------|
| **OWASP Dependency-Check** | JSON: top-level `reportSchema`, `dependencies[].vulnerabilities[].name` (CVE), `cvssv3.baseScore`. XML root `<analysis>`. HTML: contains "OWASP Dependency-Check". |
| **Snyk Open Source** | JSON: `vulnerabilities[].id` like `SNYK-JAVA-...`, `packageName`, `from`, `upgradePath`. |
| **Trivy** | JSON: `Results[].Vulnerabilities[].VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`. |
| **Grype** | JSON: `matches[].vulnerability.id`, `artifact.name`, `artifact.purl`. |
| **Syft (SBOM)** | JSON: `artifacts[].purl`, `descriptor.name == "syft"`. |
| **Black Duck** | JSON exports vary by version; signature: `bdio` or `vulnerabilityRiskProfile`. |
| **Mend (WhiteSource)** | JSON: `libraries[].vulnerabilities`, `policies`. |
| **CycloneDX SBOM** | JSON: `bomFormat == "CycloneDX"`, `specVersion`, `components[].purl`. XML namespace `cyclonedx.org`. |
| **SPDX SBOM** | JSON: `spdxVersion == "SPDX-2.3"`, `packages[].SPDXID`. Tag-value text begins with `SPDXVersion:`. |

## DAST

| Tool | Telltale fields |
|------|-----------------|
| **OWASP ZAP** | JSON: `site[].alerts[].alertRef`, `pluginid`, `riskcode`. XML root `<OWASPZAPReport>`. |
| **Burp Suite** | XML root `<issues burpVersion="...">`, `<issue>` with `<type>`, `<severity>`, `<confidence>`. HTML reports contain "Burp Scanner". |
| **Acunetix** | XML root `<ScanGroup>` or JSON with `vulnerabilities[].vuln_id`. |
| **Invicti/Netsparker** | XML root `<netsparker-cloud>` or `<netsparker>`. |
| **AppScan** | XML root `<XmlReport>`, namespace `appscan`. |

## IaC

| Tool | Telltale fields |
|------|-----------------|
| **Checkov** | JSON: `results.failed_checks[].check_id` like `CKV_AWS_20`. |
| **tfsec** | JSON: `results[].rule_id` like `aws-s3-enable-bucket-encryption`. |
| **Terrascan** | JSON: `results.violations[].rule_id`. |
| **KICS** | JSON: `queries[].query_id` (UUID), `severity`. |
| **cfn-nag** | JSON: `file_results[].file_results.violations[].id` like `W19`, `F1`. |

## Secrets

| Tool | Telltale fields |
|------|-----------------|
| **Gitleaks** | JSON array of `{RuleID, Match, Secret, File, Commit}`. |
| **TruffleHog** | JSON-lines, each line `{SourceMetadata, DetectorName, Raw, Verified}`. |
| **detect-secrets** | JSON: `results.{path}[].type`, baseline `version`. |
| **GitGuardian** | JSON: `incidents[].detector.name`, `severity`. |

## Containers

| Tool | Telltale fields |
|------|-----------------|
| **Trivy (image)** | Same as Trivy SCA but `ArtifactType == "container_image"`. |
| **Clair** | JSON: `Layer.Features[].Vulnerabilities`. |
| **Docker Scout** | JSON: `cves[]`, `policyEvaluation`. |
| **kube-bench** | JSON: `Controls[].tests[].results[].test_number` like `1.1.1`. |

## When in doubt

1. `head -c 400 file` to read the first chunk safely.
2. Search for any of: `"$schema"`, `<?xml`, `bomFormat`, `spdxVersion`, `SPDXVersion:`, tool names in the first 200 lines.
3. If still ambiguous, ask the user.
