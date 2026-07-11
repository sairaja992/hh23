# Security Vulnerability Triage Report

- **Repository:** sairaja992/hh23
- **Scan date:** 2026-07-11 (scheduled security triage run)
- **Scope:** All 14 tracked files at commit `be86016`
- **Context note:** README states "Used for testing only" — this repo appears to be a security-scanner test bed. Several findings look intentionally planted; severities below assume the artifacts could still be copied into real projects.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High     | 4 |
| Medium   | 4 |
| Low/Info | 3 |

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
The AWS provider block embeds `access_key` and `secret_key` directly in source control.
- **Triage:** The access key `AKIAIOSFODNN7EXAMPLE` is AWS's documentation example key, so this is almost certainly a planted test secret rather than a live credential. It still trips every secret scanner and normalizes a dangerous pattern.
- **Remediation:** Remove credentials from the provider block. Use environment variables, shared credentials files, or (preferably) IAM roles/instance profiles. If any real key was ever committed here, rotate it — git history retains it permanently.

### C2. AWS access key IDs embedded in `package.json:10,28`
`"accesskey": "AKIASGHPORST"` in `dependencies` and `"access key": "AKIAXYGHKLYPQGRRS"` in `devDependencies`.
- **Triage:** Both are shorter than the 20-character AKIA format, so they are malformed/fake — but they match the AKIA prefix pattern and will (correctly) be flagged by secret scanning. They are also invalid npm dependency entries.
- **Remediation:** Delete both entries. Credentials never belong in a package manifest. (See also L3 — this file is not even valid JSON.)

### C3. Hardcoded token in application code — `tesr:14`
`token "sa74io0!"` embedded in the Flask app source.
- **Triage:** Planted secret (the line is not even syntactically valid Python). Treat as a leaked-credential-class finding; rotate if it was ever real.
- **Remediation:** Remove; load tokens from a secret manager or environment at runtime.

---

## High

### H1. Elasticsearch domain access policy allows any principal — `echo-elasticsearch (1).yaml:272-280`
The domain `AccessPolicies` grant `es:*` to `Principal: AWS: "*"` on the whole domain.
- **Triage:** Partially mitigated by VPC placement (`VPCOptions` restricts network reachability to the configured subnets/SG), but any principal that can reach the endpoint gets full admin (`es:*`), including delete. Also `rest.action.multi.allow_explicit_index: "true"` weakens index-level isolation.
- **Remediation:** Scope the policy to specific IAM roles/ARNs and restrict actions to what clients need (e.g. `es:ESHttp*`).

### H2. Flask app runs with `debug=True` bound to `0.0.0.0` — `tesr:21`
The Werkzeug debug console is enabled and the app listens on all interfaces on port 8080 (and `doc` Dockerfile EXPOSEs 8080 for it).
- **Impact:** The Werkzeug interactive debugger provides remote code execution to anyone who can reach the port and triggers an exception.
- **Remediation:** `debug=False` in anything deployable; gate debug on an env var; never combine debug with `0.0.0.0`.

### H3. Severely outdated dependencies with known CVEs — `package.json` (wmic-service)
- `jsonwebtoken ^1.1.1` — vulnerable to algorithm-confusion / signature-verification bypass (CVE-2015-9235 class); JWTs can be forged.
- `restify ^2.8.1` and `async ^0.8.0` — many years EOL with multiple known advisories.
- **Remediation:** Upgrade `jsonwebtoken` to >=9.x, current restify/async; run `npm audit` in CI.

### H4. OWASP Juice Shop manifests (intentionally vulnerable app) — `package1.json`, `POM`, `dockerarm`
These are copies of the Juice Shop 14.1.1 manifest/Dockerfile — a deliberately insecure application (e.g. `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `unzipper 0.9.15`, deprecated `request`).
- **Triage:** Expected content for a scanner test repo; must never be deployed to any real environment or copied as a dependency baseline.
- **Remediation:** None if kept purely as test fixtures; label clearly and exclude from any build/deploy pipeline.

---

## Medium

### M1. End-of-life base images and unsafe npm flags — `dockerarm:1,5,9`
`node:14` / `node:14-alpine` are EOL (no security patches since April 2023); `npm install --unsafe-perm` allows install scripts to run as root in the builder stage.
- **Remediation:** Move to a supported LTS (node 20/22); drop `--unsafe-perm`.

### M2. Container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root inside the container.
- **Remediation:** Add a non-root user (as `dockerarm` correctly does with `USER 1001`).

### M3. CI workflow uses deprecated/unpinned actions — `.github/workflows/devsec.yml`
- `github/codeql-action/upload-sarif@v1` is retired — SARIF upload will fail, meaning findings never reach the Security tab (silent loss of security signal).
- `actions/checkout@v2` and `actions/setup-dotnet@v1` are deprecated (Node 12/16 runtimes).
- `microsoft/security-devops-action@preview` is a mutable tag — supply-chain risk; the action can change under you without review.
- **Remediation:** Bump to `codeql-action/upload-sarif@v3`, `checkout@v4`, `setup-dotnet@v4`; pin third-party actions to a full commit SHA.

### M4. Internal infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
Hardcoded AWS account IDs (e.g. 063586453409, 900182000710, 478226638351…), subnet IDs, security-group IDs, role ARNs, and SNS topic ARNs.
- **Triage:** Information disclosure that aids targeting/enumeration if the repo is public; also makes templates non-portable.
- **Remediation:** Parameterize via SSM/Mappings kept out of public repos.

---

## Low / Informational

### L1. `securityaudits3.py` is broken and fragile
The module docstring opened on line 2 is never closed before the imports, `today_date` vs `Today_date` casing mismatch (`securityaudits3.py:33-34`) would raise `NameError`, `publish_msg_security_team` prints undefined `error` on failure, and `writedatatodynamodb` has unreachable code after `raise e`. Bare `except:` clauses swallow real errors. Not directly exploitable, but this is a security-audit Lambda that would fail silently — an availability risk for the security pipeline itself.

### L2. Overly permissive KMS key policy — `echo-elasticsearch (1).yaml:193-198`
Root-account `kms:*` grant is standard AWS practice, but combined with the broad management grant, review whether all listed roles need `kms:Delete*`/`ScheduleKeyDeletion`.

### L3. Malformed manifests
`package.json` is invalid JSON (missing comma after line 28) and has an empty `license` field; `doc` Dockerfile references base image `FROM Doc` (not a real image) and maps `https_proxy` to the HTTP proxy arg (`doc:8`).

---

## Escalation & recommended next steps

1. **Immediate:** Confirm the planted credentials (C1–C3) were never real; if any were, rotate now — removal from HEAD does not remove them from git history.
2. **This week:** Fix the CI workflow (M3) so scanner results actually land in the GitHub Security tab; enable GitHub secret scanning + push protection on the repo.
3. **Ongoing:** If this repo is intentionally a vulnerable test bed, add a prominent README warning and keep it private/archived so its manifests are never reused.
