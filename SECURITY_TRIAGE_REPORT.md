# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-07-20 (automated scheduled review)
**Scope:** All 16 tracked files (full manual review of source, IaC, Dockerfiles, CI, and manifests)

## Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High     | 6 |
| Medium   | 5 |
| Low      | 4 |

The most urgent items are hardcoded credentials committed to the repository
(`secret.tf`, `package.json`, `tesr`) and a Flask app configured with
`debug=True` bound to `0.0.0.0`, which exposes the Werkzeug debugger
(remote code execution) if ever deployed as-is.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."
```
Credentials committed directly in a provider block. The access key ID matches
the AWS documentation example key, and the secret is a near-copy of the docs
example, so these are very likely placeholder/test values — but they are
indistinguishable from real leaked credentials to scanners and attackers, and
the pattern itself is the vulnerability.
**Action:** Remove the file or replace with environment variables /
`AWS_PROFILE` / IAM roles. If these were ever real values, rotate immediately
and purge from git history (`git filter-repo`), since deletion alone does not
remove them from history.

### C2. Flask app runs with `debug=True` on `0.0.0.0` — `tesr:21`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
Debug mode exposes the Werkzeug interactive debugger, which allows arbitrary
code execution on the host if the console PIN is bypassed or leaked. Binding
to all interfaces makes it network-reachable.
**Action:** Set `debug=False` (or drive via env var) and bind to a specific
interface behind a reverse proxy. Note: `tesr:14` also contains a stray line
`token "sa74io0!"` — a hardcoded token that is additionally a Python syntax
error; remove it and rotate the token if it is real.

### C3. AWS access key IDs embedded in npm manifest — `package.json:10,28`
```json
"accesskey": "AKIASGHPORST",
"access key": "AKIAXYGHKLYPQGRRS"
```
AWS access key IDs placed inside `dependencies`/`devDependencies`. Both are
shorter than the 20-character AKIA format, so they appear to be planted/test
values, but they trip secret scanners and normalize the leak pattern. The file
is also invalid JSON (missing comma after line 28), so `npm install` fails.
**Action:** Remove both entries; if they correspond to real keys, rotate and
purge from history.

---

## High

### H1. EOL Spring Boot parent, Spring4Shell exposure — `pom (2).xml:15`, `pom254.xml:15`
Both POMs use `spring-boot-starter-parent` **2.2.4.RELEASE** (Spring Framework
5.2.3), end-of-life since 2020 with numerous CVEs. Combined with the
`Dockerfile (1)` base image running **JDK 17**, the app meets the conditions
for **CVE-2022-22965 (Spring4Shell, CVSS 9.8)** — Spring MVC on JDK 9+.
**Action:** Upgrade to a supported Spring Boot 3.x line.

### H2. Vulnerable pinned npm dependencies — `package.json:7-12`
- `jsonwebtoken ^1.1.1` — vulnerable to algorithm-confusion signature bypass
  (CVE-2015-9235 class); current is 9.x.
- `async ^0.8.0` — prototype pollution (CVE-2021-43138 affects <2.6.4).
- `restify ^2.8.1` — years EOL with known ReDoS/path issues.
**Action:** Upgrade all three; `jsonwebtoken` upgrade is the priority (auth bypass).

### H3. Elasticsearch domain access policy allows `Principal: "*"` with `es:*` — `echo-elasticsearch (1).yaml:272-280`
The domain policy grants every AWS principal full `es:*` on the domain. VPC
placement reduces exposure, but any principal with network reachability gets
full data-plane and admin access — no IAM authentication boundary.
**Action:** Restrict `Principal` to the specific roles/accounts that need access.

### H4. EOL Elasticsearch versions — `echo-elasticsearch (1).yaml:12-27`
Default ES **7.4**, with 6.x versions allowed. All are end-of-life and predate
the Log4Shell-era patching baseline. Node-to-node encryption
(`NodeToNodeEncryptionOptions`) and HTTPS enforcement
(`DomainEndpointOptions/EnforceHTTPS`) are also not configured.
**Action:** Move to a supported OpenSearch version; enable node-to-node
encryption and enforce HTTPS.

### H5. EOL Node.js 14 base images — `dockerarm:1,9`
`node:14` / `node:14-alpine` are end-of-life (April 2023): no security patches
for OS packages or the runtime. (This is the OWASP Juice Shop image —
intentionally vulnerable by design; confirm it is only used in isolated
training environments.) The `POM` file (a copy of Juice Shop's
`package.json`, duplicated as `package1.json`) pins known-vulnerable packages
on purpose: `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`,
deprecated `request`, etc.
**Action:** If this is training material, isolate/label it clearly; otherwise
upgrade the base image and dependencies.

### H6. Spring Boot container runs as root — `Dockerfile (1)`
No `USER` directive; the JVM runs as root, so any app compromise (see H1) is
a root-in-container compromise. `spring-boot-devtools` is also included in the
POMs, which must never ship in production images.
**Action:** Add a non-root `USER`; mark devtools `<scope>runtime</scope>`
excluded from the production build.

---

## Medium

### M1. Deprecated/unpinned GitHub Actions — `.github/workflows/devsec.yml:17,32`
`actions/checkout@v2` and `github/codeql-action/upload-sarif@v1` are
deprecated (v1 SARIF upload no longer functions); actions are pinned by mutable
tag rather than commit SHA, enabling tag-rewrite supply-chain attacks.
**Action:** Bump to current majors and pin by SHA; add `permissions:` block
with least privilege (`security-events: write`, `contents: read`).

### M2. Proxy credentials baked into image env — `doc:7-9`
`ENV http_proxy=$HTTP_PROXY_ARG` persists build-time proxy settings (which
often embed credentials) into every layer and the running container.
`https_proxy` is also incorrectly set from `$HTTP_PROXY_ARG`. Base image
`FROM Doc` is not a valid reference, and `pip install` runs unpinned without
hashes.
**Action:** Use `--build-arg` only at build time (or BuildKit secrets); fix
the base image; pin requirements with hashes.

### M3. Internal infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
AWS account IDs (063586453409, 900182000710, 460510738068, 070133345649,
478226638351), subnet IDs, security group IDs, role ARNs, SNS topic ARNs, and
internal hostnames (`git.fpd.cat.com`) are committed to a public-looking repo.
Individually low-risk, collectively useful for targeting/recon.
**Action:** Parameterize per environment; keep environment maps in private
config, not source.

### M4. Broken/unsafe audit Lambda — `securityaudits3.py`
The module docstring opened at line 2 is never closed, so the file is
syntactically broken (imports are swallowed by the string). Additional issues:
`Today_date` vs `today_date` NameError, bare `except:` clauses that mask
credential/permission failures silently (lines 45, 237), `print(error)` on an
undefined name in the SNS error path — meaning **security alerting failures
are themselves silent**. A security-audit pipeline that fails open is a
monitoring gap.
**Action:** Fix syntax, add real error handling, add a dead-man-switch alarm
on the Lambda.

### M5. ECS task definition passes registry credentials but no secrets hygiene — `ecs-task-definition-xray.yaml:165-167`
Environment variables are injected as plain CFN parameters
(`EnvironmentVariableValue1`) rather than `Secrets` from Secrets
Manager/SSM — any secret passed this way lands unencrypted in the task
definition and CloudTrail.
**Action:** Use the `Secrets` container definition property for sensitive values.

---

## Low

- **L1.** `Dockerfile (1):1-2` — commented `openjdk:9-jdk-alpine` suggestion; openjdk:9 is long EOL, remove the suggestion.
- **L2.** `package.json:24` — empty `license` field; `git://` protocol (unauthenticated, tamperable) for the repository URL (`package.json:21`).
- **L3.** `POM`/`package1.json` — duplicated 9KB Juice Shop manifest committed twice; repo hygiene (files named `POM`, `pom (2).xml`, `pom254.xml`, `Dockerfile (1)`, `tesr`, `doc` with spaces/no extensions defeat scanners that key on filenames — several SAST tools will skip them).
- **L4.** `echo-elasticsearch (1).yaml:307-308` — `rest.action.multi.allow_explicit_index: "true"` permits cross-index access in multi-search requests; set to `false` unless required.

---

## Escalation & recommended immediate actions

1. **Now:** Remove `secret.tf` credentials, the `tesr` token, and the
   `package.json` access-key entries; rotate any real values; purge git history.
2. **Now:** Run GitHub secret scanning / push protection on the repo to catch
   recurrences.
3. **This week:** Fix Flask debug config (C2), upgrade Spring Boot (H1) and
   the npm auth libraries (H2), lock down the Elasticsearch access policy (H3).
4. **This sprint:** Refresh the CI workflow (M1) so automated scanning (MSDO)
   actually functions again — the deprecated SARIF upload action means current
   scan results are likely not reaching the Security tab at all.
