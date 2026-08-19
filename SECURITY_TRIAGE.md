# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-19 (scheduled automated scan)
**Scope:** All files at HEAD of `main` (be86016)

## Summary

| Severity | Count | Highlights |
|----------|-------|------------|
| Critical | 3 | Hardcoded AWS credentials, hardcoded app token + Flask debug RCE, critically vulnerable `jsonwebtoken` |
| High | 4 | EOL Spring Boot (Spring4Shell exposure), EOL Node 14 images, vulnerable `restify`/`async`, deliberately vulnerable Juice Shop artifacts |
| Medium | 3 | CI supply-chain pinning, deprecated/disabled CodeQL action, infra identifiers exposed |
| Low | 2 | Malformed manifests, code-quality defects in audit Lambda |

---

## Critical

### C1. Hardcoded AWS credentials in Terraform — `secret.tf`
The AWS provider block embeds an `access_key` and `secret_key` directly in source control.

- `access_key = "AKIAIOSFODNN7EXAMPLE"` is the canonical AWS documentation example key, and the secret key is a near-copy of the docs example, so these are **likely placeholders — but that must be verified**, and the pattern itself is a policy violation that normalizes committing credentials.
- **Triage:** Confirm neither value is (or ever was) a live credential; if any real key was ever committed here, rotate it immediately — git history retains it (`Add files via upload`, cc8b7f9).
- **Remediation:** Remove static keys; use an IAM role, AWS SSO, or environment variables via `~/.aws/credentials`. Add secret-scanning pre-commit hooks (gitleaks/trufflehog).

### C2. Hardcoded token + Flask debug mode on all interfaces — `tesr`
- Line `token "sa74io0!"` embeds what appears to be a credential in source (it is also a syntax error — stray line inside `elapsed()`).
- `app.run(debug=True, host="0.0.0.0", port=8080)` enables the Werkzeug interactive debugger while listening on every interface. The Werkzeug debug console permits **remote code execution** (the console PIN is brute-forceable/derivable), and debug mode leaks stack traces and environment details.
- **Remediation:** Rotate/remove the token; never enable `debug=True` outside localhost dev; front with a production WSGI server (gunicorn/uwsgi).

### C3. Critically vulnerable `jsonwebtoken ^1.1.1` — `package.json` (wmic-service)
Versions of `jsonwebtoken` before 4.2.2 are subject to **authentication bypass** (CVE-2015-9235 class: `alg=none` / HMAC–RSA key-confusion attacks allow forging valid tokens). Any service verifying JWTs with this version is trivially bypassable.
- Also in this file: two `AKIA…`-prefixed strings embedded as fake "dependency" entries (`accesskey: "AKIASGHPORST"`, `"access key": "AKIAXYGHKLYPQGRRS"`). Both are shorter than a real 20-char AWS access key ID, so they look synthetic/test — but treat like C1: verify and purge; secret scanners will (correctly) flag them.
- **Remediation:** Upgrade `jsonwebtoken` to ≥9.x; remove the credential-shaped entries.

## High

### H1. End-of-life Spring Boot 2.2.4.RELEASE — `pom (2).xml`, `pom254.xml`
Spring Boot 2.2.x is long past EOL (no security fixes since 2020) and pulls Spring Framework 5.2.3, which is in the vulnerable range for **CVE-2022-22965 (Spring4Shell, RCE)** on JDK 9+ (the companion `Dockerfile (1)` runs JDK 17), plus numerous other Spring/Tomcat/Jackson CVEs. `spring-boot-devtools` is also included as a runtime-optional dependency — it must never reach production images (remote restart/livereload endpoints).
- **Remediation:** Upgrade to a supported Spring Boot line (3.3+); ensure devtools is excluded from packaged artifacts.

### H2. EOL Node.js 14 base images — `dockerarm`
`FROM node:14` and `node:14-alpine`: Node 14 reached end-of-life April 2023; the images carry unpatched OS and runtime CVEs. `npm install --unsafe-perm` additionally allows install scripts to run as root during build.
- **Remediation:** Move to a supported LTS image (node:20/22-alpine) and drop `--unsafe-perm`.

### H3. Vulnerable legacy dependencies — `package.json` (wmic-service)
- `restify ^2.8.1` (2014-era): multiple known advisories (path traversal, ReDoS in dependencies).
- `async ^0.8.0`: prototype-pollution advisory range (fixed in 2.6.4 / 3.2.2).
- `mocha ^1.21.4`, `supertest ^0.14.0`: ancient dev deps with vulnerable transitive trees.
- **Remediation:** Full dependency refresh; run `npm audit` in CI.

### H4. Intentionally vulnerable OWASP Juice Shop artifacts — `POM`, `package1.json`, `dockerarm`
`POM` and `package1.json` are identical copies of the Juice Shop 14.1.1 manifest, which **pins deliberately vulnerable versions** (e.g., `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `vm2 3.9.11` — the last has known sandbox-escape RCE CVEs). Fine if this repo is a security-training/demo sandbox; a real risk if any of these manifests feed an actual build or deploy pipeline.
- **Triage:** Confirm the repo's purpose. If it is a demo/lab repo, label it clearly in `README.md` and ensure nothing here deploys to real infrastructure. If not, remove these files.

## Medium

### M1. CI supply-chain: unpinned / deprecated actions — `.github/workflows/devsec.yml`
- `microsoft/security-devops-action@preview` — mutable tag; a compromised or changed tag executes arbitrary code in your CI with repo-token access. Pin to a full commit SHA.
- `actions/checkout@v2` and `actions/setup-dotnet@v1` — deprecated (Node 12 runtime removed).
- `github/codeql-action/upload-sarif@v1` — **deprecated and disabled by GitHub** (v1/v2 sunset); the SARIF upload step will fail, meaning findings are silently not reaching the Security tab. Upgrade to `@v3`.

### M2. Cloud identifiers hardcoded in templates — `template.yaml`, `securityaudits3.py`
AWS account IDs (`063586453409`, `478226638351`), subnet IDs, security-group IDs, IAM role ARNs, SNS topic ARNs, and bucket names are committed. Not directly exploitable, but valuable reconnaissance and it couples templates to specific accounts.
- **Remediation:** Parameterize via CFN Parameters/SSM.

### M3. ECS task/exec role reuse — `template.yaml`
`ExecutionRoleArn` and `TaskRoleArn` use the same role (`q-gen-ECSServiceRole`), merging image-pull/log permissions with application runtime permissions — over-privilege by construction. Use separate, least-privilege roles.

## Low

### L1. Malformed/broken manifests
- `package.json` is invalid JSON (missing comma after the `"access key"` line) — any tooling parsing it fails.
- `doc` Dockerfile begins `FROM Doc` (not a real image) and won't build.
- `tesr` won't run (stray `token` line is a Python syntax error).

### L2. Code-quality defects in `securityaudits3.py`
- `today_date` used but only `Today_date` is defined → NameError at import time (module top level), so the Lambda never runs — a **failed security-audit pipeline is itself a monitoring gap**.
- Bare `except:` clauses swallow real errors; `publish_msg_security_team` references undefined `error` in its handler; unreachable `alrt` mutation after `raise` in `writedatatodynamodb`.
- Positive notes: no injection sinks; data flows only to DynamoDB/SNS.

## Clean / acceptable

- `echo-elasticsearch (1).yaml`: KMS encryption with key rotation enabled, encryption-at-rest wired to the domain — no findings of note in scanned sections.
- `Dockerfile (1)` (Spring Boot): minimal, no root-avoidance (`USER` unset — consider adding a non-root user), but no secrets.
- `ecs-task-definition-xray.yaml`: credentials pulled from Secrets Manager by ARN (correct pattern), optional CMK for logs.

## Recommended escalation order

1. **Verify and rotate** anything touching real AWS accounts (C1, C3 key-shaped strings) and purge from git history if real.
2. Fix or remove the Flask app's debug/token exposure (C2).
3. Decide the repo's purpose: if it's a security-demo sandbox, label it; if not, remove Juice Shop manifests and upgrade all EOL stacks (H1–H4).
4. Repair the CI pipeline (M1) — the SARIF upload is currently broken, so automated scanning results are not landing in the Security tab.
