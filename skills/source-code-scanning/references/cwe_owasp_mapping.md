# CWE ↔ OWASP-2021 ↔ ASVS ↔ LLM-Top-10 Mapping

Pragmatic lookup table for normalization. Not exhaustive — extend per engagement.

## OWASP Top 10 2021

| OWASP | Theme | Primary CWEs |
|-------|-------|--------------|
| A01:2021 | Broken Access Control | CWE-22, CWE-23, CWE-35, CWE-200, CWE-201, CWE-219, CWE-264, CWE-275, CWE-276, CWE-284, CWE-285, CWE-352, CWE-359, CWE-377, CWE-402, CWE-425, CWE-441, CWE-497, CWE-538, CWE-540, CWE-552, CWE-566, CWE-601, CWE-639, CWE-651, CWE-668, CWE-706, CWE-862, CWE-863, CWE-913, CWE-922, CWE-1275 |
| A02:2021 | Cryptographic Failures | CWE-261, CWE-296, CWE-310, CWE-319, CWE-321, CWE-322, CWE-323, CWE-324, CWE-325, CWE-326, CWE-327, CWE-328, CWE-329, CWE-330, CWE-331, CWE-335, CWE-336, CWE-337, CWE-338, CWE-340, CWE-347, CWE-523, CWE-720, CWE-757, CWE-759, CWE-760, CWE-780, CWE-818, CWE-916 |
| A03:2021 | Injection | CWE-20, CWE-74, CWE-75, CWE-77, CWE-78, CWE-79, CWE-80, CWE-83, CWE-87, CWE-88, CWE-89, CWE-90, CWE-91, CWE-93, CWE-94, CWE-95, CWE-96, CWE-97, CWE-98, CWE-99, CWE-100, CWE-113, CWE-116, CWE-138, CWE-184, CWE-470, CWE-471, CWE-564, CWE-610, CWE-643, CWE-644, CWE-652, CWE-917 |
| A04:2021 | Insecure Design | CWE-73, CWE-183, CWE-209, CWE-213, CWE-235, CWE-256, CWE-257, CWE-266, CWE-269, CWE-280, CWE-311, CWE-312, CWE-313, CWE-316, CWE-419, CWE-430, CWE-434, CWE-444, CWE-451, CWE-472, CWE-501, CWE-522, CWE-525, CWE-539, CWE-579, CWE-598, CWE-602, CWE-642, CWE-646, CWE-650, CWE-653, CWE-656, CWE-657, CWE-799, CWE-807, CWE-840, CWE-841, CWE-927, CWE-1021, CWE-1173 |
| A05:2021 | Security Misconfiguration | CWE-2, CWE-11, CWE-13, CWE-15, CWE-16, CWE-260, CWE-315, CWE-520, CWE-526, CWE-537, CWE-541, CWE-547, CWE-611, CWE-614, CWE-756, CWE-776, CWE-942, CWE-1004, CWE-1032, CWE-1174 |
| A06:2021 | Vulnerable & Outdated Components | CWE-937, CWE-1035, CWE-1104 (plus any CVE on a dependency) |
| A07:2021 | Identification & Authentication Failures | CWE-255, CWE-259, CWE-287, CWE-288, CWE-290, CWE-294, CWE-295, CWE-297, CWE-300, CWE-302, CWE-304, CWE-306, CWE-307, CWE-346, CWE-384, CWE-521, CWE-613, CWE-620, CWE-640, CWE-798, CWE-940, CWE-1216 |
| A08:2021 | Software & Data Integrity Failures | CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-830, CWE-915 |
| A09:2021 | Security Logging & Monitoring Failures | CWE-117, CWE-223, CWE-532, CWE-778 |
| A10:2021 | Server-Side Request Forgery | CWE-918 |

## OWASP LLM Top 10 (2025)

| LLM | Theme | Signals in scanner output |
|-----|-------|---------------------------|
| LLM01 | Prompt Injection | Untrusted input concatenated into prompt strings; tool may flag as taint sink. |
| LLM02 | Sensitive Information Disclosure | PII patterns in logs from LLM responses; secret scanners flagging API outputs. |
| LLM03 | Supply Chain | SCA findings on model libraries, plugin packages, model registries. |
| LLM04 | Data & Model Poisoning | Detected when training pipeline lacks input validation (SAST on pipeline code). |
| LLM05 | Improper Output Handling | LLM output rendered without sanitization → XSS, RCE via shell escape, SQLi via generated SQL. |
| LLM06 | Excessive Agency | Agent frameworks calling tools without auth checks (config review). |
| LLM07 | System Prompt Leakage | Prompts stored in code/secrets scanners catching them. |
| LLM08 | Vector & Embedding Weaknesses | Insecure vector DB configuration in IaC scans. |
| LLM09 | Misinformation | Not source-detectable; runtime concern. |
| LLM10 | Unbounded Consumption | Missing rate limits, token caps — config/SAST flags. |

## ASVS 4.0.3 quick map (most-used controls)

| Topic | ASVS | Typical scanner rule |
|-------|------|----------------------|
| Input validation | V5 | Most injection rules |
| Encoding/escaping | V5.3 | XSS rules |
| Authentication | V2 | Auth rules |
| Session mgmt | V3 | Session rules |
| Access control | V4 | IDOR / authz rules |
| Cryptography | V6 | Weak crypto, TLS rules |
| Errors & logging | V7 | Logging rules |
| Data protection | V8 | Sensitive data exposure |
| Communications | V9 | TLS rules |
| Malicious code | V10 | RCE / deser |
| Business logic | V11 | (rarely automated) |
| Files & resources | V12 | Upload / path rules |
| API & web service | V13 | API auth, mass assignment |
| Configuration | V14 | IaC / config rules |

## Pragmatic lookup pattern

When normalizing a finding without an explicit OWASP tag:

1. Take its CWE.
2. Walk the table above top-down; first OWASP category that lists the CWE wins.
3. If multiple CWEs, take the highest-impact category (Injection > Auth > Misconfiguration > Logging).
4. Record both the matched OWASP and the inference reason (`mapping_source: cwe-table` vs `mapping_source: vendor-tagged`).
