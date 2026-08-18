# Security Triage Report — hh23

**Scan date:** 2026-08-18 (automated scheduled review)
**Scope:** All 15 tracked files at commit `be86016`
**Repo context:** This repository appears to be a security-tooling test bed (MSDO workflow, OWASP Juice Shop artifacts, seeded secret-scanner fixtures). Findings are triaged accordingly — items that look like intentional test fixtures are noted, but each should be confirmed and the pattern remediated regardless.

---

## Severity summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High     | 5 |
| Medium   | 4 |
| Low / hygiene | 4 |

---

## Critical

### C1. Hardcoded AWS credentials in Terraform — `secret.tf:2-3`
An AWS access key and secret key are committed directly in the provider block.
**Triage:** The access key ID is `AKIAIOSFODNN7EXAMPLE` — AWS's published documentation example — and the secret is a variant of the doc example, so these are almost certainly placeholders / scanner-test seeds, not live credentials. The pattern is still Critical because this file normalizes committing credentials and will keep tripping secret scanners.
**Action:** Remove the file or replace with a provider block using environment variables / IAM roles (`provider "aws" {}` with credentials from the default chain). If any real key was ever committed in this repo's history, rotate it.

### C2. Flask app runs with `debug=True` bound to `0.0.0.0` — `tesr:21`
`app.run(debug=True, host="0.0.0.0", port=8080)` exposes the Werkzeug interactive debugger on all interfaces. The debugger console gives **remote code execution** to anyone who can reach the port (the PIN is brute-forceable and derived from guessable machine facts).
Also: a hardcoded token `"sa74io0!"` sits on line 14 (which is additionally a Python syntax error — the file cannot run as-is).
**Action:** Never enable debug in a network-exposed app; bind to localhost or gate behind `FLASK_DEBUG` env var; remove the hardcoded token.

### C3. Elasticsearch domain access policy allows `Principal: "*"` with `es:*` — `echo-elasticsearch (1).yaml:272-280`
The domain resource policy grants every AWS principal full Elasticsearch API access. VPC placement (`VPCOptions`) limits network reachability, but the resource policy itself provides no authentication boundary — any principal with network path to the VPC endpoint (peered VPCs, compromised workload in the same subnets) gets full read/write/admin on the domain, including the "Grief Management" data set tagged `dataclassification: Yellow`.
**Action:** Scope `Principal` to the specific task/app roles, or add IAM/SigV4 conditions. Encryption-at-rest (present, KMS) does not mitigate this.

### C4. AWS access-key-style secrets embedded in `package.json:10,28`
`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` are committed inside the dependencies/devDependencies maps.
**Triage:** Both strings are shorter than a valid 20-character AWS access key ID, so these are malformed — likely deliberate secret-scanner test seeds. They also make the file **invalid JSON** (missing comma after line 28's entry and keys in dependency maps that npm would reject), so any real `npm install` fails.
**Action:** Confirm they are fixtures; if so, move them to a clearly-labeled test-fixtures directory. If not, treat as leaked credentials and rotate.

---

## High

### H1. Critically vulnerable `jsonwebtoken` pins
- `package.json:9` — `jsonwebtoken ^1.1.1`
- `POM` / `package1.json` (Juice Shop manifest) — `jsonwebtoken 0.4.0` and `express-jwt 0.1.3`

These versions predate the fixes for the algorithm-confusion / `alg:none` signature-bypass class (CVE-2015-9235 era) and the later CVE-2022-23529/23539/23540/23541 set. Any service actually using them has forgeable auth tokens.
**Action:** Upgrade to `jsonwebtoken >= 9.x` (Juice Shop files are intentionally vulnerable — see triage note below).

### H2. EOL / vulnerable base images and runtimes
- `dockerarm:1,9` — `node:14` / `node:14-alpine` (Node 14 EOL April 2023, no security patches).
- `pom (2).xml` / `pom254.xml:15` — Spring Boot `2.2.4.RELEASE` (EOL since 2020; pulls Spring Framework 5.2.3 with numerous CVEs, and ships `spring-boot-devtools` as a dependency).
- `doc:1` — `FROM Doc` is not a resolvable image (broken build), and pip/apt installs are unpinned.

**Action:** Move to supported bases (Node 20/22 LTS, Spring Boot 3.x), drop devtools from non-dev profiles.

### H3. Juice Shop application files (`POM`, `package1.json`, `dockerarm`)
These are OWASP Juice Shop 14.1.1 — an intentionally vulnerable application (dozens of known-vulnerable pins: `sanitize-html 1.4.2`, `unzipper 0.9.15`, `express-jwt 0.1.3`, etc.).
**Triage:** Intentional if this repo feeds scanner demos. The risk is accidental deployment — the `dockerarm` Dockerfile builds a runnable image.
**Action:** Confirm intent; keep clearly labeled and never wire into CI/CD deploy paths.

### H4. Container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root in the container. Combined with H2's EOL concerns, container escape blast radius is maximized.
**Action:** Add a non-root user (the `dockerarm` file at lines 25-32 shows the correct pattern).

### H5. CI workflow uses deprecated/unpinned actions with default token permissions — `.github/workflows/devsec.yml`
- `actions/checkout@v2` and `codeql-action/upload-sarif@v1` are deprecated; `v1` of the CodeQL action has been disabled by GitHub, so the SARIF upload step likely fails silently or errors — meaning **findings never reach the Security tab**, defeating the workflow's purpose.
- `microsoft/security-devops-action@preview` is a mutable tag — supply-chain risk (the referenced code can change under you).
- No `permissions:` block — the workflow runs with the default (potentially write-all) `GITHUB_TOKEN`.

**Action:** Bump to `checkout@v4`, `codeql-action/upload-sarif@v3`, pin actions to full commit SHAs, and add a least-privilege `permissions:` block (`security-events: write`, `contents: read`).

---

## Medium

### M1. Hardcoded infrastructure identifiers — `template.yaml:17-32`, `echo-elasticsearch (1).yaml:154-177`
AWS account IDs, subnet IDs, security-group IDs, and role ARNs are committed. Not credentials, but they aid reconnaissance and make the templates environment-brittle.
**Action:** Parameterize or move to SSM/parameter files.

### M2. Mutable `:latest` image tag in ECS task definition — `template.yaml:17`
`q-gen-01:latest` means deploys are non-reproducible and a poisoned/regressed image is picked up silently.
**Action:** Pin image digests or immutable version tags.

### M3. Shared Task/Execution role — `template.yaml:18-20`
`TaskRoleArn` and `ExecutionRoleArn` are the same role (`q-gen-ECSServiceRole`), so the application inherits ECR-pull/log-write permissions and vice versa — violates least privilege.
**Action:** Split into separate scoped roles.

### M4. KMS key policy grants broad admin — `echo-elasticsearch (1).yaml:199-220`
The management statement includes `kms:Delete*` / `kms:ScheduleKeyDeletion` for the CI (Azure DevOps CFN) role. A compromised pipeline can schedule deletion of the key encrypting the ES domain — a data-destruction path.
**Action:** Remove deletion permissions from the pipeline role; reserve for a break-glass admin role.

---

## Low / hygiene

- **`securityaudits3.py` cannot run:** the module docstring opened at line 2 is never closed (imports at lines 12-22 are swallowed by it / file ends mid-string), `Today_date` vs `today_date` NameError at line 34, `f.close()` at line 167 references an out-of-scope handle, and `raise e` at line 305 makes the error-handling lines below it unreachable. If this Lambda is believed to be auditing S3 findings in production, **it is not actually running** — worth verifying, since it silently removes a detective control.
- **`package.json` invalid JSON** (see C4) — the manifest is unusable, so its `jsonwebtoken ^1.1.1` pin (H1) is currently dormant.
- **`doc` Dockerfile** copies the entire build context (`COPY . ./`) with no `.dockerignore`, risking secret files (like `secret.tf`) landing in image layers.
- **Loose file hygiene:** duplicate manifests (`POM` = `package1.json`, `pom (2).xml` ≈ `pom254.xml`), names with spaces/parentheses, and a `tesr` script with syntax errors suggest untracked drift; consider pruning to reduce false-positive noise in scanners.

---

## Escalation queue

1. **C2 (Flask debug RCE pattern)** — if `tesr` is deployed anywhere in fixed form, treat as an incident-grade exposure.
2. **C3 (ES `Principal:*` policy)** — verify whether any deployed stack was created from this template; if so, restrict the access policy now.
3. **C1/C4 (committed secrets)** — confirm fixture status; run secret scanning over full git history; rotate anything real.
4. **H5 (broken SARIF upload)** — the security pipeline itself is likely not delivering findings; fix first since it gates visibility of everything else.

*Report generated by automated scheduled security triage.*
