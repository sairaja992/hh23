# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-07-27 (scheduled automated triage)
**Scope:** All 15 files in the repository (Dockerfiles, IaC templates, package manifests, Python audit script, CI workflow)

---

## Summary

| Severity | Count | Themes |
|----------|-------|--------|
| Critical | 3 | Hardcoded cloud credentials / secrets committed to source control |
| High | 4 | Remote-code-execution debug config, severely outdated vulnerable dependencies, wide-open Elasticsearch access policy |
| Medium | 4 | EOL base images, container running as root, mutable CI action tags, missing transport encryption settings |
| Low | 3 | Internal infrastructure disclosure, code defects in the audit Lambda, unpinned pip installs |

**Escalation recommended for the three Critical findings** — committed secrets require rotation and history purge regardless of whether they are still valid.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
The AWS provider block embeds `access_key` and `secret_key` literals. The access key ID matches AWS's documented example value (`AKIAIOSFODNN7EXAMPLE`) and the secret is a mutated example string, so these are likely placeholders — but the pattern normalizes committing real keys, and secret scanners will (correctly) flag it forever.
**Action:** Delete the credentials, use an IAM role / environment credentials / AWS SSO profile. If any real key was ever committed in history, rotate it and purge history.

### C2. AWS access key IDs embedded in `package.json:9,27`
`"accesskey": "AKIASGHPORST"` in `dependencies` and `"access key": "AKIAXYGHKLYPQGRRS"` in `devDependencies`. These are AKIA-format access key IDs sitting in a dependency manifest. The file is also invalid JSON (missing comma after the `supertest` line), so npm would reject it — but the keys are still exposed in the repo.
**Action:** Confirm whether these key IDs correspond to real IAM users in any account; deactivate/rotate if so, then remove from the file and from git history.

### C3. Hardcoded token in Flask app — `tesr:15`
`token "sa74io0!"` is embedded in the source (it is also a Python syntax error — the file cannot run as-is).
**Action:** Remove the token, source secrets from environment/secret manager, rotate if it was ever a live credential.

---

## High

### H1. Flask debug mode exposed on all interfaces — `tesr:24`
`app.run(debug=True, host="0.0.0.0", port=8080)` enables the Werkzeug interactive debugger while binding to every interface. The debugger console allows arbitrary Python execution — this is remote code execution if the port is reachable.
**Action:** `debug=False` (or environment-gated), bind to localhost or run behind a real WSGI server.

### H2. Elasticsearch domain access policy allows `Principal: "*"` — `echo-elasticsearch (1).yaml:272-281`
The domain policy grants `es:*` on the domain to any AWS principal. VPC placement (`VPCOptions`) reduces exposure, but inside the VPC/peered networks any caller has full admin on the domain. The template also lacks `NodeToNodeEncryptionOptions` and `DomainEndpointOptions.EnforceHTTPS`, and pins EOL Elasticsearch versions (6.0–7.4).
**Action:** Scope the principal to specific IAM roles, enable node-to-node encryption and enforced HTTPS, move to a supported OpenSearch version.

### H3. Known-vulnerable dependency pins — `package.json`, `POM` / `package1.json`
- `package.json`: `jsonwebtoken ^1.1.1` (pre-4.x — algorithm-confusion signature bypass class, CVE-2015-9235 era), `restify ^2.8.1` and `async ^0.8.0` (2014-era, multiple advisories).
- `POM` and `package1.json` are the manifest of OWASP Juice Shop 14.1.1 — an *intentionally* vulnerable app (`jsonwebtoken 0.4.0`, `sanitize-html 1.4.2`, `express-jwt 0.1.3`, deprecated `request`, `vm-notevil`, etc.). If this repo is a security-testing lab, these are expected; they must never be deployed to a real environment or reused as a dependency baseline.
**Action:** Confirm lab intent; if any of these manifests feeds a real build, upgrade the JWT/sanitizer stack immediately.

### H4. Spring Boot 2.2.4 parent — `pom (2).xml`, `pom254.xml`
Spring Boot 2.2.x is EOL (since 2020) and its dependency tree includes versions affected by later CVEs (e.g. Spring Framework RCE class fixed in 5.2.20+/5.3.18+, snakeyaml, jackson advisories). `spring-boot-devtools` is also included, which must not ship in production images.
**Action:** Move to a supported Spring Boot 3.x line; mark devtools `runtime`-excluded for prod packaging.

---

## Medium

### M1. Containers run as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root in the container. (Contrast: `dockerarm` and `doc` correctly drop to non-root users.)
**Action:** Add a non-root user before `ENTRYPOINT`.

### M2. EOL base images — `dockerarm:1,9`
`node:14` / `node:14-alpine` are end-of-life (April 2023) and no longer receive security patches.
**Action:** Rebuild on a maintained LTS (node 20/22) image.

### M3. Mutable / deprecated CI action refs — `.github/workflows/devsec.yml`
`microsoft/security-devops-action@preview` is a mutable tag (supply-chain risk — the referenced code can change under you), and `actions/checkout@v2`, `actions/setup-dotnet@v1`, `codeql-action/upload-sarif@v1` are deprecated majors that GitHub has sunset (v1 upload-sarif no longer works).
**Action:** Pin actions to full commit SHAs; bump to current majors so the security scan actually runs.

### M4. Proxy credentials baked into image env — `doc:6-8`
Build args are persisted as `ENV http_proxy/https_proxy` in the final image. If the proxy URL carries credentials, they ship in every layer/`docker inspect`. Note also the bug: `https_proxy` is set from `$HTTP_PROXY_ARG` instead of `$HTTPS_PROXY_ARG`.
**Action:** Use `--build-arg` only during RUN steps (or BuildKit secrets); fix the variable mix-up.

---

## Low

### L1. Internal infrastructure disclosure — `template.yaml`, `securityaudits3.py`, `ecs-task-definition-xray.yaml`
Real-looking AWS account IDs (`063586453409`, `478226638351`), subnet/SG IDs, ECR URIs, SNS topic ARNs, and internal bucket names (`ue2-scout2-prod-history`) are committed. Not directly exploitable, but useful recon material.
**Action:** Parameterize account-specific values; keep them in per-env config, not source.

### L2. Defects in the audit Lambda — `securityaudits3.py`
`Today_date` is assigned but `today_date` is referenced (NameError at import/run), `raise e` before the error-string append makes that code unreachable, `print(error)` in `publish_msg_security_team` references an undefined name, and bare `except:` clauses swallow real failures. The security-audit pipeline this script implements is therefore silently broken.
**Action:** Fix the casing/name bugs and narrow the exception handling so audit failures alert instead of vanish.

### L3. Unpinned dependency installs — `doc:11`, `dockerarm`
`pip install -r requirements.txt` with no hashes/pins and `npm install --unsafe-perm` widen the supply-chain surface.
**Action:** Pin versions (and hashes for pip); drop `--unsafe-perm`.

---

## Escalation & next steps

1. **Immediately:** verify/rotate the credentials in C1–C3 and purge them from git history (they remain retrievable from old commits even after deletion).
2. **This week:** fix H1 (debug RCE config) and H2 (ES access policy) — both are one-line-class changes.
3. **Backlog:** dependency and base-image upgrades (H3, H4, M1–M4), parameterize the IaC identifiers (L1), repair the audit Lambda (L2).
4. If this repository is intentionally a vulnerable-config lab (several files come from OWASP Juice Shop), mark that clearly in the README so scanners and reviewers can triage accordingly.
