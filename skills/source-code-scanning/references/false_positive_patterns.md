# False-Positive Eradication Playbook

> Every suppression must be recorded with a written reason. The patterns below are the *common* cases — they are not licenses to suppress blindly. Always confirm against the rule message, the evidence snippet, and the framework version in scope.

## How to use this file

For each finding:

1. Identify the **CWE family** and **tool rule ID**.
2. Look it up below.
3. Check whether the listed *FP conditions* apply, using only the evidence in the report.
4. If FP: set `status = fp-confirmed`, populate `fp_reasoning` with the matching pattern number and the snippet substring that proves it.
5. If unclear: set `status = fp-suspected` and add a 1-line runtime check request to the client section of the report.

---

## Injection family (CWE-89, CWE-78, CWE-77, CWE-94, CWE-91)

### 1. SQL Injection through ORM/parameterized API
**FP if** snippet shows:
- JDBC `PreparedStatement.setX(...)`
- JPA `setParameter(...)`, `@Query` with `:param`
- SQLAlchemy `text(sql, bindparams=...)`, `session.execute(stmt, params)`
- Sequelize `where: {col: value}` (no `Sequelize.literal`)
- Dapper `execute(sql, new {x = y})`
- Entity Framework LINQ-to-SQL with parameterized predicates
**NOT FP if** the snippet shows string concatenation into the query, `eval`-style query builders, or `raw()` calls with interpolation.

### 2. NoSQL Injection
**FP if** Mongo driver uses BSON document form `{field: userInput}` (driver escapes), and `$where`, `mapReduce`, or `eval` are absent.
**NOT FP if** snippet contains `JSON.parse(userInput)` feeding the query object.

### 3. OS Command Injection
**FP if**:
- Java `ProcessBuilder(List.of("cmd", arg1, arg2))` (array form)
- Python `subprocess.run([...], shell=False)` (list form, shell off)
- Go `exec.Command(name, args...)` with args separate
- Node `child_process.execFile(file, [args])`
**NOT FP if**: `Runtime.exec(String)`, `subprocess.*(..., shell=True)`, `exec` (Node) with a single string, backtick shell expansion.

### 4. LDAP Injection (CWE-90)
**FP if** filter uses parameterized API (`new EqualsFilter(attr, value)`, `ldap3` `Connection.search` with `search_filter` and pre-escaped args).
**NOT FP if** filter is built by `String.format("(%s=%s)", attr, value)` with user input.

### 5. XPath/XML/XSLT Injection
**FP if** XPath compiled with `XPath.compile(expr).evaluate(doc, vars)` and variables bound via `XPathVariableResolver`.
**NOT FP if** XPath is concatenated from user input. **Always confirm** parser is hardened against XXE (see #20).

---

## Cross-Site family (CWE-79, CWE-352, CWE-601, CWE-1021)

### 6. Reflected/Stored XSS — auto-escaping framework
**FP if** output is via auto-escaped channel:
- Thymeleaf `th:text` (NOT `th:utext`)
- Razor `@Model.X` (NOT `@Html.Raw`)
- Jinja2 with autoescape on (`Environment(autoescape=True)`) and no `|safe` filter
- React `{value}` (NOT `dangerouslySetInnerHTML`)
- Angular `{{value}}` (NOT `[innerHTML]` with bypass)
- Vue `{{value}}` (NOT `v-html`)
**NOT FP** when the bypass directives above appear.

### 7. CSRF
**FP if**: Spring Security CSRF enabled (default in `WebSecurityConfig`), Django `CsrfViewMiddleware` present, Rails `protect_from_forgery` active, ASP.NET `[ValidateAntiForgeryToken]` on POST handlers, Express with `csurf` and `csrf-protection` cookie set.
**NOT FP** when methods are state-changing and the framework's CSRF is explicitly disabled or scoped out (`@CsrfIgnore`, `csrf_exempt`, `skip_before_action :verify_authenticity_token`).

### 8. Open Redirect
**FP if** redirect target is checked against an allow-list, or framework helper enforces same-origin (`redirect_to allow_other_host: false` in Rails 7+).
**NOT FP** for `Response.Redirect(Request["url"])` and equivalents.

### 9. Clickjacking
**FP if** application sends `X-Frame-Options: DENY` / `SAMEORIGIN` or `Content-Security-Policy: frame-ancestors 'none'`. Check DAST headers report.
**NOT FP** if neither header is present.

---

## Path & Resource (CWE-22, CWE-23, CWE-73, CWE-434, CWE-918)

### 10. Path Traversal
**FP if** snippet shows canonicalization + base-path check:
- Java `Paths.get(base).resolve(name).normalize().startsWith(base)`
- Node `path.resolve(base, name).startsWith(path.resolve(base))`
- Python `os.path.realpath(os.path.join(base, name)).startswith(os.path.realpath(base))`
**NOT FP** if any of the above is missing.

### 11. Arbitrary File Upload
**FP if** upload handler enforces: content-type allow-list **and** magic-byte check **and** filename sanitization (UUID rename) **and** storage outside web root.
**NOT FP** if even one of those is missing. File-extension-only checks are not sufficient.

### 12. Server-Side Request Forgery
**FP if** target URL/host is validated against an allow-list **before** request issuance, **and** redirects are not followed (`allowAutoRedirect = false`, `redirect: 'manual'`).
**Likely FP, mark for runtime confirmation** if a `URI` parse + `getHost()` check is present without a clear allow-list — many such checks are bypassable.
**NOT FP** for raw `httpClient.get(userUrl)` patterns.

---

## Crypto & Secrets (CWE-327, CWE-328, CWE-330, CWE-321, CWE-798, CWE-322)

### 13. Weak hash for non-security use
**FP if** the snippet/context indicates ETag, cache key, dedup key, content-addressed storage. **Recommend** SHA-256 anyway for portability and future-proofing — but mark FP.
**NOT FP** for password hashing, signatures, MAC, integrity-critical chains.

### 14. Insecure Random
**FP if** RNG is used for jitter, sampling, shuffle, animation, retry backoff.
**NOT FP** for token generation, session IDs, password reset tokens, OAuth state, CSRF tokens, IV/nonce generation, key derivation.

### 15. Hardcoded credentials
**FP if** path matches `**/test/**`, `**/tests/**`, `**/__tests__/**`, `**/fixtures/**`, `**/examples/**`, `**/docs/**`, or the value is an obvious placeholder (`changeme`, `your-token-here`, `xxxxxxxx`).
**NOT FP** otherwise, even if "we rotate it".

### 16. Insecure cipher (DES, RC4, ECB)
**Almost never FP.** Only suppress if the data is publicly published anyway and the cipher is part of a legacy interop requirement that is on a written deprecation plan.

### 17. TLS misconfiguration
**FP if** the disabled-validation snippet is gated behind `if (devMode)` and the build doesn't ship dev mode (confirm via build flags in artifact). Otherwise NOT FP.

---

## Deserialization & Unsafe Reflection (CWE-502, CWE-470)

### 18. Unsafe deserialization
**FP if** deserializer is type-restricted:
- Java `ObjectInputFilter` configured
- .NET `BinaryFormatter` is **never FP** (deprecated, treat as Critical regardless)
- Python `pickle.loads(...)` is **never FP** on untrusted input — only suppress if input is strictly process-internal
- YAML loaded with `yaml.safe_load` (NOT `yaml.load` without Loader)
**NOT FP** otherwise.

---

## XXE / XML (CWE-611, CWE-776)

### 19. XML External Entity
**FP if** parser is hardened — snippet shows any of:
- `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`
- `XMLInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false)`
- Python `defusedxml.*`
- .NET `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }`
**NOT FP** otherwise. XXE FPs are rare; require strong evidence.

---

## Logging & Output (CWE-117, CWE-209, CWE-532)

### 20. Log injection
**FP if** logging framework is Logback ≥ 1.3 with `%enc{}{CRLF}` or default replace-newlines, log4j2 ≥ 2.17 with pattern restriction.
**NOT FP** for `System.out.println(user)`, `Console.WriteLine`, custom log writers.

### 21. Information disclosure in error pages
**FP if** environment-aware error handler hides stack traces in prod (`server.error.include-stacktrace=never`, ASP.NET `<customErrors mode="On">`, Rails `config.consider_all_requests_local = false`).
**NOT FP** if globally on.

---

## Authentication & Session (CWE-287, CWE-384, CWE-613, CWE-352)

### 22. Missing session timeout / fixation
**FP if** framework default session timeout < 30 minutes and `Session.Abandon()` / `request.session.cycle_key()` / `httpSession.invalidate()` is called on auth-state changes.
**NOT FP** if "remember me" is unbounded or sessions are not regenerated on login.

### 23. JWT — algorithm `none` / weak `HS256` secret
**Never FP.** Verify alg pinning and secret strength via the rule's evidence; if either is missing, escalate.

---

## SCA-specific FP patterns

### 24. Vulnerable transitive but unreachable
**Downgrade, do not fully suppress.** If the SCA tool exposes `reachable: false` or a SARIF `kind=pass`, mark `severity` one level lower with reason "unreachable per tool" — keep open until upgrade.

### 25. Disputed CVE
If NVD or vendor advisory marks the CVE as **Disputed** or **Rejected**, suppress with reason "CVE disputed: <link>". Confirm with the user before fully removing.

### 26. Test/build-only dependency
**FP for runtime exposure** if PURL is in `test`, `devDependency`, `buildSrc`, `tools/` scope and the runtime artifact does not include it (check Trivy `Layer` field or Snyk `from[]` chain for the runtime image).
Still record for developer-environment hygiene.

### 27. Ghost CVE (rule-pack drift)
If an older scan flags a CVE but a newer scan with updated DB does not, prefer the newer scan and tag the finding "resolved by rule-pack update" — but verify the package version actually changed.

---

## Containers & IaC

### 28. CVE in unused OS package
Some Trivy/Grype findings hit packages installed in the base image but never invoked (e.g., `bash` in a distroless app). Container CVEs are hard to call FPs without runtime telemetry. Default: **downgrade**, do not suppress, recommend rebuild on a slimmer base.

### 29. IaC: "encryption at rest" already enforced by organizational policy
**FP if** the cloud account has an SCP or Azure Policy that enforces encryption regardless of template. Provide evidence of the policy in `fp_reasoning`.

---

## What is **never** an FP justification

- "Internal-only network."
- "WAF blocks it."
- "We monitor for it."
- "It's been there for years."
- "The pentester didn't exploit it."
- "Developer says it's fine."

Those are *accepted risk* at best (separate tab) — they are not FPs.

---

## Accepted-Risk vs FP — the two-question test

1. *Is the tool wrong about the technical condition?* → If yes, it's an FP.
2. *Is the tool right, but we choose to live with it?* → That's accepted risk. Different tab, different approver, expiry date required.

Never blur these two.
