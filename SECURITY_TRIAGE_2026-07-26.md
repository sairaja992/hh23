# Security Triage Report — hh23

**Scan date:** 2026-07-26 (scheduled run)
**Scope:** All files in repository + full git history
**Context:** README states "Used for testing only" — findings triaged accordingly, but several items would be critical if any config is reused in real environments.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform — `secret.tf:2-3`
`access_key`/`secret_key` embedded directly in the AWS provider block. The access key (`AKIAIOSFODNN7EXAMPLE`) is the AWS documentation example key, so this is almost certainly a dummy — but the secret key string is not the verbatim docs example. Both are present in **every commit in history**.
**Action:** Confirm the pair was never valid; if there is any doubt, rotate immediately. Remove the file and purge history (`git filter-repo`), then move to environment variables / IAM roles. Enable GitHub secret-scanning push protection on the repo.

### C2. Elasticsearch domain open to the world — `echo-elasticsearch (1).yaml:272-280`
The domain access policy grants `es:*` to `Principal: AWS: "*"` — any AWS principal (effectively anonymous over the internet if the domain is public) gets full read/write/admin on the domain. Encryption-at-rest with KMS is configured, but that does not mitigate an open access policy.
**Action:** Restrict the principal to specific IAM roles/accounts, or add an IP-based `Condition`, and prefer VPC-only deployment.

## High

### H1. Flask app: debug mode on all interfaces + hardcoded token — `tesr`
`app.run(debug=True, host="0.0.0.0", port=8080)` exposes the Werkzeug interactive debugger, which is **remote code execution** for anyone who can reach the port. A hardcoded token (`sa74io0!`) also sits in the source (stray line, would additionally crash the app).
**Action:** Never run with `debug=True` outside localhost; move the token to a secret store.

### H2. AWS-access-key-like strings in `package.json` (lines 10, 28)
`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` inside dependencies/devDependencies. Both are invalid lengths for real AKIA keys (likely planted test data), but they trip secret scanners and normalize a dangerous pattern. The file is also malformed JSON (missing comma at line 28), so `npm install` fails.
**Action:** Remove both entries; purge from history along with C1.

### H3. Critically outdated npm dependencies — `package.json`
- `jsonwebtoken ^1.1.1` — pre-4.2.2, vulnerable to the classic `alg=none` / algorithm-confusion auth bypass (CVE-2015-9235 class).
- `async ^0.8.0`, `restify ^2.8.1`, `mocha ^1.21.4`, `supertest ^0.14.0` — all ~2014-era with multiple known CVEs (e.g., prototype pollution in async < 2.6.4, CVE-2021-43138).
**Action:** Upgrade all, or delete the manifest if the service is dead.

### H4. End-of-life Spring Boot with devtools — `pom (2).xml`, `pom254.xml`
Spring Boot `2.2.4.RELEASE` (Spring Framework 5.2.3) is long EOL: exposed to CVE-2022-22965 (Spring4Shell, on JDK9+ WAR deployments — note `Dockerfile (1)` uses JDK 17), CVE-2020-5398 (RFD), and numerous transitive CVEs. `spring-boot-devtools` is included, which must never reach a production image.
**Action:** Move to a supported Spring Boot 3.x line; drop devtools from packaged builds.

### H5. Intentionally vulnerable app manifest — `POM` / `package1.json` (OWASP Juice Shop 14.1.1) and `dockerarm`
Juice Shop is deliberately insecure and its Dockerfile builds on `node:14` (EOL April 2023). Acceptable for a test/CTF repo, but ensure it is never deployed on shared or internet-facing infrastructure.

## Medium

### M1. Container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root. Add a non-root user (the `doc` Dockerfile does this correctly with `www-data`).

### M2. Internal infrastructure disclosure — `template.yaml`, `ecs-task-definition-xray.yaml`, `securityaudits3.py`
Real AWS account IDs (`063586453409`, `478226638351`), IAM role ARNs, subnet IDs, security-group IDs, SNS topic ARNs, and S3 bucket names are committed to a public-facing repo. Not directly exploitable, but materially aids targeting and phishing.
**Action:** Parameterize account-specific values; scrub if these accounts are live.

### M3. Deprecated / unpinned GitHub Actions — `.github/workflows/devsec.yml`
`actions/checkout@v2` and `codeql-action/upload-sarif@v1` are deprecated (v1 upload-sarif is disabled and will fail); `microsoft/security-devops-action@preview` is a mutable tag — a supply-chain risk. Pin actions to current majors or commit SHAs.

### M4. Proxy settings baked into image — `doc`
`ENV http_proxy/https_proxy` from build args persist in image layers; if a proxy URL ever carries credentials they are permanently in the image. Also `https_proxy` is incorrectly set from `HTTP_PROXY_ARG`, and `pip install` is unpinned/unverified.

## Low

- `securityaudits3.py` is non-functional as committed: the module docstring is unterminated (imports are inside the string), `Today_date` vs `today_date` NameError, `raise e` before the alert append makes it dead code, bare `except:` clauses swallow errors, and `f.close()` references an out-of-scope handle. Broad DynamoDB `list_tables` substring match (`if table in ...`) can silently pick the wrong table.
- `package.json` has an empty `license` field and a private git URL (`git.fpd.cat.com`) disclosing internal hostnames.

---

## Escalation summary

| # | Finding | Severity | Immediate owner action |
|---|---------|----------|------------------------|
| C1 | AWS creds in `secret.tf` (all history) | Critical | Verify dummy / rotate; purge history; enable push protection |
| C2 | ES domain `Principal:*` + `es:*` | Critical | Lock down access policy before any deploy |
| H1 | Flask debug RCE + hardcoded token | High | Fix before any exposure |
| H2/H3 | Key-like strings + EOL vulnerable deps | High | Remove/upgrade |
| H4 | EOL Spring Boot + devtools | High | Upgrade to supported line |

No evidence of *additional* secrets in git history beyond C1/H2 (full-history grep for key patterns, private keys, and passwords came back clean otherwise).
