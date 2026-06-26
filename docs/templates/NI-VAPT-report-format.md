# Network Intelligence — VA & PT Report Format (Template)

> Reusable house format extracted from `NI_Lighthouse_Canton_API_initial_Report_v1.0`.
> CERT-In-aligned empanelled-auditor layout. Fill every `<<...>>` placeholder.
> **Conventions:**
> - Severity is driven by **CVSS v4.0** (vector form `CVSS:4.0/AV:.../AC:.../AT:.../PR:.../UI:.../VC:.../VI:.../VA:.../SC:.../SI:.../SA:...`).
> - Findings are numbered `8.01`, `8.02`, … under section 8.
> - Document ID format: `NII/<Project>/<Type>/<Month><Year>` (e.g. `NII/Lighthouse_Canton/API/June2026`).
> - Auditing organisation: **Network Intelligence**.
> - Each finding's remediation block ends with: *"Note: It is recommended to implement this fix to all the reported endpoints/assets."* (where applicable).

---

## COVER PAGE
```
Report on <<Asset/Scope>> VA & PT
For:    <<Client / Auditee Organisation>>
From:   Network Intelligence
Report Release Date     <<DD-MM-YYYY>>
Type of Audit           <<e.g. API / Web App / Network>> Vulnerability Assessment and Penetration Testing
Type of Audit Report    <<First Audit Report | Re-Audit / Closure Report>>
Period                  <<DD-MM-YYYY>> to <<DD-MM-YYYY>>
```

---

## Document Control

### Document Preparation
| Field | Value |
|---|---|
| Document Title | <<...>> Vulnerability Assessment & Penetration Testing |
| Document ID | NII/<<Project>>/<<Type>>/<<MonthYear>> |
| Document Version | <<1.0>> |
| Prepared By | <<Name>> |
| Reviewed By | <<Name>> |
| Approved By | <<Name>> |
| Released By | <<Name>> |
| Release Date | <<DD-MM-YYYY>> |

### Document Change History
| Version | Date | Remarks / Reason of Change |
|---|---|---|
| 1.0 | <<DD-MM-YYYY>> | NA |

### Document Distribution List
| Name | Organization | Designation | Email ID |
|---|---|---|---|
| <<Name>> | <<Org>> | <<Designation>> | <<email>> |

---

## Table of Contents
1. Introduction
2. Engagement Scope
3. Details of Auditing Team
4. Audit Activities and Timelines
5. Audit Methodology and Criteria
6. Tools / Software Used
7. Executive Summary
8. Detailed Observations
- Appendix A: OWASP Top Ten 2021
- Appendix B: Types of Assessments
- Appendix C: Severity Rating Details

---

## 1. Introduction
<<Client>> engaged Network Intelligence to carry out <<assessment type>> assessment as included in the scope
of the work. The goal of the test was to determine security vulnerabilities in their <<target>>. The tests were
carried out assuming the identity of an attacker or a user with malicious intent. Due care was taken not to harm
the target <<application/infrastructure>>.

### 1.1 Caveats
<<Out-of-scope functionalities / constraints, e.g. "As per discussion with <Client> Team, modules X, Y, Z are out of scope.">>

### 1.2 Sampling Criteria (if any)
<<NA or sampling description>>

---

## 2. Engagement Scope
| Sr. No | Asset Description | Criticality of Asset | Endpoints / IPs |
|---|---|---|---|
| 1 | <<asset>> | <<Critical/High/...>> | <<endpoint or IP>> |

---

## 3. Details of Auditing Team
| Sr. No. | Name | Designation | Email ID | Professional Qualifications / Certifications | Listed in Snapshot information published on CERT-In's Website (Yes/No) |
|---|---|---|---|---|---|
| 1 | <<Name>> | <<Designation>> | <<email@networkintelligence.ai>> | <<certs>> | <<Yes/No>> |

---

## 4. Audit Activities and Timelines
| Sr. No | Audit Phase | Start Date | End Date |
|---|---|---|---|
| 1 | Recon/Walkthrough | <<DD-MM-YYYY>> | <<DD-MM-YYYY>> |
| 2 | Automated Scan | | |
| 3 | Manual Verification | | |
| 4 | Report Writing | | |
| 5 | Report Review | | |
| 6 | Report Submission | | |

---

## 5. Audit Methodology and Criteria

### 5.1 TYPE OF ASSESSMENT
For this engagement, the assessment was limited to the following categories:
1. <<Gray Box / Black Box / White Box>> Assessment
2. Penetration Testing
3. Risk Based Penetration Testing
4. Vulnerability Assessment

It is highly recommended to go in for other types of security assessments to further assess and enhance the overall
security posture of your organization. (See Appendix B.)

### 5.2 APPROACH
<<Narrative / diagram of the testing approach: recon → enumeration → vulnerability identification → exploitation → reporting.>>

### 5.3 STANDARDS AND FRAMEWORK FOLLOWED
Our testing methodology adapts from the following security frameworks and vulnerability categories:
1. Open Web Application Security Project Framework (OWASP)
2. Web Application Security Consortium (WASC)
3. National Institute of Standards and Technology (NIST)
<<Add for network/infra engagements: NIST SP 800-115, PTES, MITRE ATT&CK.>>

### 5.4 SEVERITY RATING
Network Intelligence follows the CVSS scoring system to rate vulnerabilities. (CVSS v4.0 base-metric rating unless
otherwise stated.) Scores range 0–10; see Appendix C for the qualitative scale.

---

## 6. Tools / Software Used
| Sr. No. | Name of Tool/Software Used | Version of Tool/Software Used | Open Source/Licensed |
|---|---|---|---|
| 1 | <<tool>> | <<version>> | <<Open Source / Licensed>> |

---

## 7. Executive Summary
| Vulnerability | CVSS 4.0 | Severity | Description | Remediation | Affected Assets |
|---|---|---|---|---|---|
| 8.01 - <<Title>> | <<score>> | <<Critical/High/Medium/Low>> | <<short description>> | <<short remediation>> | <<count>> |

---

## 8. Detailed Observations

### 8.0N - <<Vulnerability Title>>
<<Full description of the vulnerability class and why it matters.>>

**Affected Assets / API Endpoints / IPs:**
<<list of affected endpoints or IPs (and count)>>

**Classification**
- **Severity:** <<Critical/High/Medium/Low/Informational>>

**Impact:**
<<What an attacker achieves; business/technical impact.>>

**CVSS 4.0:** <<score>> (CVSS:4.0/AV:.../AC:.../AT:.../PR:.../UI:.../VC:.../VI:.../VA:.../SC:.../SI:.../SA:...)

**Issue details**
<<Observation narrative + step-by-step evidence:>>
- Step 1: <<...>>
- Step 2: <<...>>
- (Embed screenshots / request-response evidence here.)

**Recommendations / Remediation**
It is recommended to implement following measures:
- <<measure 1>>
- <<measure 2>>

*Note: It is recommended to implement this fix to all the reported endpoints/assets.*

**References:** <<CWE / OWASP / CVE / MITRE ATT&CK>>

---

## Appendix A: OWASP Top Ten 2021
<<Standard OWASP Top 10 2021 list mapping.>>

## Appendix B: Types of Assessments
<<Short overview of Black/Gray/White-box, VA, PT, Risk-based PT, etc.>>

## Appendix C: Severity Rating Details
CVSS qualitative severity rating scale (per FIRST.org):

| Rating | CVSS Range | Traits |
|---|---|---|
| **Critical** | 9.0 – 10.0 | Complete system compromise; remotely exploitable over untrusted network; trivial to exploit; severe C/I/A impact. |
| **High** | 7.0 – 8.9 | Significant impact; exploitation may need some conditions/privileges. |
| **Medium** | 4.0 – 6.9 | Moderate impact; often needs adjacent access, user interaction, or partial privileges. |
| **Low** | 0.1 – 3.9 | Little impact on C/I/A; hard to exploit / needs excessive privilege; exploits not public. |
| **Informational / None** | 0.0 | No direct security risk; informational or unverifiable. |
