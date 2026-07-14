# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-07-14 (scheduled security routine)
**Scope:** All files at repository root and `.github/workflows/`
**Method:** Manual static review of source, IaC templates, Dockerfiles, dependency manifests, and CI workflow

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2     |
| High     | 4     |
| Medium   | 4     |
| Low / Informational | 4 |

The most urgent items are **hardcoded credentials committed to the repository** (`secret.tf`, `tesr`, `package.json`) and a **publicly-principaled Elasticsearch access policy**. Credentials in git history remain exposed even after deletion — rotation is required, not just removal.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform — `secret.tf:2-3`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
- The access key ID matches AWS's documentation example key, but the secret key does **not** match the standard docs placeholder (`...EXAMPLEKEY`), so this must be treated as a potentially real secret until confirmed otherwise.
- **Action:** Confirm whether the secret key is live; rotate immediately if so. Remove the file, purge from git history (`git filter-repo`), and switch the provider block to environment variables, shared credentials file, or an assumed role. Never commit provider credentials.

### C2. Flask app runs with `debug=True` bound to all interfaces — `tesr:21`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
- Werkzeug's debug mode exposes an interactive debugger that allows **remote code execution** on any unhandled exception, and it is bound to `0.0.0.0` (all interfaces). This is a well-known RCE pattern (CWE-489 / CWE-94).
- Also note the hardcoded token `"sa74io0!"` at `tesr:14` (which is additionally a Python syntax error — the file cannot run as-is).
- **Action:** Set `debug=False` (or drive from an env var defaulting to off), bind to localhost or put behind a proper WSGI server, remove the hardcoded token and rotate it wherever it is valid.

---

## High

### H1. AWS access key IDs embedded in npm manifest — `package.json:10,28`
```json
"accesskey": "AKIASGHPORST",
"access key": "AKIAXYGHKLYPQGRRS"
```
- Two AKIA-prefixed access key IDs are committed (one hiding inside `dependencies`, one inside `devDependencies`). These are not valid npm dependency entries, which strongly suggests accidental paste of real credentials. The second entry also makes the JSON invalid (missing comma at line 28).
- **Action:** Verify/rotate both keys in AWS IAM, remove the entries, purge history. Fix the JSON syntax.

### H2. Critically outdated `jsonwebtoken` — `package.json:9`
- `"jsonwebtoken": "^1.1.1"` predates the fixes for the algorithm-confusion / `alg:none` verification bypass (CVE-2015-9235 class). Any service verifying JWTs with this version can be trivially forged against. `async ^0.8.0` and `restify ^2.8.1` are similarly ancient with known CVEs (e.g., restify path traversal / ReDoS advisories).
- **Action:** Upgrade `jsonwebtoken` to ≥9.x, restify to a maintained release, and run `npm audit`.

### H3. Elasticsearch domain access policy allows `Principal: "*"` with `es:*` — `echo-elasticsearch (1).yaml:272-280`
- The domain access policy grants every AWS principal full `es:*` on the domain. VPC placement reduces exposure, but any principal with network reachability into those subnets gets unauthenticated full control (read/write/delete indices, config changes).
- Related hardening gaps in the same resource: `NodeToNodeEncryptionOptions` not enabled, `DomainEndpointOptions.EnforceHTTPS` not set, and ES 6.x versions (long EOL) are still in `AllowedValues`.
- **Action:** Scope the principal to specific IAM roles, enable node-to-node encryption and HTTPS enforcement, drop EOL engine versions.

### H4. Spring Boot 2.2.4.RELEASE parent — `pom (2).xml:15`, `pom254.xml`, `POM`/`package1.json` (juice-shop 14.1.1)
- Spring Boot 2.2.x is EOL and its dependency tree includes versions affected by later high-severity CVEs (e.g., Spring Framework RCE class issues fixed in 2.5.12+/2.6.6+, plus vulnerable embedded Tomcat/Jackson). `spring-boot-devtools` is also declared as a runtime-visible dependency, which must never ship to production.
- The `POM`/`package1.json` manifest is OWASP Juice Shop 14.1.1 — an intentionally vulnerable application; confirm it is present only as test material and is never deployed.
- **Action:** Move to a supported Spring Boot 3.x line; scope devtools out of production builds.

---

## Medium

### M1. CI workflow uses mutable/deprecated action refs — `.github/workflows/devsec.yml`
- `microsoft/security-devops-action@preview` is a mutable tag (supply-chain risk: the tag can be repointed to malicious code with full repo-token access); `actions/checkout@v2`, `setup-dotnet@v1`, and `codeql-action/upload-sarif@v1` are deprecated/broken (upload-sarif v1 is disabled by GitHub).
- **Action:** Pin actions to full commit SHAs, upgrade to `checkout@v4`, `setup-dotnet@v4`, `codeql-action/upload-sarif@v3`. Add a top-level least-privilege `permissions:` block (`security-events: write`, `contents: read`).

### M2. Container runs as root — `Dockerfile (1)`
- No `USER` directive; the Spring Boot app runs as root inside the container, amplifying any app-level compromise. (Contrast with `dockerarm` and `doc`, which correctly drop privileges.)
- **Action:** Add a non-root user and `USER` directive.

### M3. EOL base images — `dockerarm:1,9` and `Dockerfile (1):5`
- `node:14` / `node:14-alpine` are end-of-life (no security patches since 2023). The JDK 17 Ubuntu base should be re-pinned/refreshed regularly.
- **Action:** Move to a maintained LTS base (node 20/22-alpine), enable image scanning in CI.

### M4. Proxy configuration baked into image env — `doc:7-9`
- `ENV http_proxy/https_proxy` persists build-time proxy endpoints into the final image metadata (internal infrastructure disclosure; can also silently route runtime traffic through the proxy). Note `https_proxy` is incorrectly set from `$HTTP_PROXY_ARG`.
- **Action:** Use build-time-only `ARG` (or `--build-arg` with per-`RUN` scoping) instead of persistent `ENV`; fix the copy-paste bug.

---

## Low / Informational

- **L1. Internal infrastructure identifiers committed** — AWS account IDs, subnet IDs, security-group IDs, role ARNs, and internal hostnames appear in `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`, and `package.json` (`git.fpd.cat.com`). Not directly exploitable but useful reconnaissance; prefer parameterizing per environment.
- **L2. KMS key policy breadth** — `echo-elasticsearch (1).yaml` grants the management role near-`kms:*` (including `ScheduleKeyDeletion`); consider separating key-admin from key-user permissions.
- **L3. `securityaudits3.py` code defects** — the module docstring is unterminated (whole file is currently a string literal / non-functional), `Today_date` vs `today_date` case mismatch, `raise e` before the error-handling lines makes them unreachable, and `print(error)` references an undefined name in `publish_msg_security_team`. The audit Lambda this represents is silently broken.
- **L4. Repo hygiene** — duplicate manifests (`POM`≡`package1.json`, `pom (2).xml`≈`pom254.xml`), invalid JSON in `package.json`, and files with spaces/parentheses in names complicate scanning and review; several SAST tools will skip or crash on the malformed files, hiding the findings above from automated pipelines.

---

## Escalation & recommended immediate actions

1. **Rotate now:** the `secret.tf` secret key (if live), both AKIA keys in `package.json`, and the `tesr` token. Removal from HEAD is insufficient — they persist in git history.
2. **Purge history** for the three credential-bearing files (`git filter-repo` or BFG), then force-push and invalidate clones per your incident process.
3. **Enable GitHub secret scanning + push protection** on the repository to prevent recurrence.
4. Fix the Elasticsearch wildcard access policy before any (re)deployment of that stack.
5. Repair `devsec.yml` (M1) so the MSDO/SARIF pipeline actually runs — it is the repo's only automated security control, and the disabled `codeql-action/upload-sarif@v1` means findings no longer reach the Security tab.
