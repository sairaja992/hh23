# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-11 (automated scheduled scan)
**Scope:** All 15 files in the repository (Dockerfiles, CloudFormation/Terraform IaC, package manifests, Python audit script, CI workflow)

> Context note: `README.md` states "Used for testing only", and several files originate from OWASP Juice Shop (an intentionally vulnerable app). Severity below reflects the risk *if any of these configs are used against real infrastructure*; likely-test-fixture findings are marked as such.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform — `secret.tf`
```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."
}
```
- Credentials committed directly in the provider block and present in git history.
- **Triage:** The access key is the AWS documentation example key (`AKIAIOSFODNN7EXAMPLE`) and the secret is a mutated docs example — *probably not live*. However, committed-credential patterns must be treated as compromised until proven otherwise.
- **Action:** Verify the pair is inert (AWS console / `aws sts get-access-key-info`). If ever real, rotate immediately. Remove the file or replace with variables + a secrets manager; purge from history if a real key is confirmed.

### C2. Flask app: hardcoded token + debug mode on all interfaces — `tesr`
- `token "sa74io0!"` — a hardcoded secret embedded in source (also a syntax error, so it's dead code today, but the secret is still disclosed in the repo).
- `app.run(debug=True, host="0.0.0.0", port=8080)` — Werkzeug debug mode bound to all interfaces. If this ever runs exposed, the interactive debugger allows **remote code execution** (debugger PIN is routinely bypassable in containers).
- **Action:** Remove the token, disable debug outside local dev, bind to localhost or put behind a real WSGI server.

---

## High

### H1. AWS access key IDs embedded in `package.json`
- `"accesskey": "AKIASGHPORST"` (dependencies) and `"access key": "AKIAXYGHKLYPQGRRS"` (devDependencies).
- **Triage:** Both are malformed (real AKIA IDs are 20 chars) and no secret key accompanies them — likely planted test fixtures for secret scanners. Still a policy violation and a secret-scanner tripwire.
- Bonus: the file is **invalid JSON** (missing comma after the devDependencies access-key line), so any tooling consuming it fails.

### H2. Elasticsearch domain with wildcard principal — `echo-elasticsearch (1).yaml`
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: ["es:*"]
```
- Any AWS principal is granted full `es:*` on the domain. Partially mitigated by VPC-only placement (`VPCOptions` + security group), but inside the VPC there is no identity-based control at all: any compromised workload in those subnets gets full admin on the domain.
- Also: Elasticsearch 7.4 (and allowed versions down to 6.0) are long end-of-life and unpatched.
- **Action:** Scope the principal to the specific roles that need access; upgrade to a supported OpenSearch version.

### H3. Severely outdated, known-vulnerable dependencies — `package.json` (wmic-service)
- `jsonwebtoken ^1.1.1` — pre-dates fixes for algorithm-confusion / auth-bypass issues (CVE-2015-9235 class; current fixed line is 9.x).
- `restify ^2.8.1` and `async ^0.8.0` — ~2014-era, multiple known advisories.
- **Action:** If this service is real anywhere, upgrade all three; `jsonwebtoken` at that version is an authentication bypass waiting to happen.

### H4. EOL base images and intentionally vulnerable app — `dockerarm`
- Builds **OWASP Juice Shop 14.1.1** ("probably the most modern and sophisticated insecure web application") on `node:14` / `node:14-alpine` — Node 14 is end-of-life (April 2023), no security patches.
- `npm install --production --unsafe-perm` allows install scripts to run as root during build.
- **Triage:** Juice Shop is vulnerable *by design* — fine for training/CTF, must never be deployed to shared or production infrastructure.

---

## Medium

### M1. Spring Boot container runs as root, EOL framework — `Dockerfile (1)` + `pom (2).xml` / `pom254.xml`
- No `USER` directive — the Spring Boot app runs as **root** in the container.
- Parent `spring-boot-starter-parent 2.2.4.RELEASE` (Feb 2020) — EOL, carries known CVEs in embedded Tomcat and Spring (predates the Spring4Shell-era patch lines).
- `spring-boot-devtools` included as a dependency — must not ship in production images.

### M2. CI workflow uses deprecated/unpinned actions — `.github/workflows/devsec.yml`
- `github/codeql-action/upload-sarif@v1` — **deprecated and disabled by GitHub**; SARIF upload will fail, meaning the security scanning this workflow exists for silently stops reporting.
- `actions/checkout@v2`, `actions/setup-dotnet@v1` — deprecated (Node 12/16 runtimes).
- `microsoft/security-devops-action@preview` — mutable tag, not pinned to a SHA (supply-chain risk).
- **Action:** Bump to `codeql-action/upload-sarif@v3`, `checkout@v4`/`v5`, and pin third-party actions by commit SHA.

### M3. Infrastructure details disclosed in templates — `template.yaml`, `ecs-task-definition-xray.yaml`, `echo-elasticsearch (1).yaml`
- Real-looking AWS account IDs (`063586453409`, `900182000710`, `460510738068`, `070133345649`), IAM role ARNs, subnet IDs, and security-group IDs are committed to a public-facing repo. Not directly exploitable, but valuable reconnaissance for targeting those accounts.
- `template.yaml` pulls nested stacks from a predictable S3 bucket name (`azdo-q-gen-dev-<region>`); if that bucket is ever unclaimed in a region, an attacker could squat it and supply malicious templates.

### M4. Broken security-audit Lambda — `securityaudits3.py`
- The module docstring is **never closed** — every `import` and client initialization is inside the string literal, so the Lambda fails at runtime (`NameError`). Also `Today_date` vs `today_date` case mismatch.
- Operational risk: if this is (or models) the real Scout2→DynamoDB findings pipeline, it has been silently doing nothing.
- Hardcoded bucket name (`ue2`) and account ID (`478226638351`) in code.

---

## Low / Informational

- **`POM` / `package1.json`** — copies of Juice Shop's `package.json` (v14.1.1): dozens of known-vulnerable pinned deps (`vm2 3.9.11` — critical sandbox-escape CVE-2023-37466 class, `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, etc.). Intentional for Juice Shop; do not reuse in real services.
- **`doc` Dockerfile** — `FROM Doc` is not a valid/resolvable base image reference; build is broken. Proxy args handled reasonably; runs as `www-data` (good).
- **KMS key policy** (`echo-elasticsearch (1).yaml`) — root-account `kms:*` plus broad management grants; standard pattern but worth scoping if the domain holds sensitive data.

---

## Triage summary & escalation

| # | Finding | Severity | Likely test fixture? | Escalate? |
|---|---------|----------|----------------------|-----------|
| C1 | AWS keys in `secret.tf` | Critical | Probably (docs example key) | Yes — verify & rotate |
| C2 | Token + Flask debug RCE in `tesr` | Critical | Partly | Yes if deployed |
| H1 | AKIA strings in `package.json` | High | Yes (malformed) | Confirm inert |
| H2 | ES `Principal: *` | High | No | Yes if deployed |
| H3 | jsonwebtoken 1.x etc. | High | Unclear | Yes if service exists |
| H4 | Juice Shop / Node 14 EOL | High | Intentional | Only if deployed |
| M1–M4 | Root container, dead CI upload, infra disclosure, broken Lambda | Medium | Mixed | Fix in normal cycle |

**Immediate recommended actions:**
1. Confirm the `secret.tf` credential pair and the two AKIA strings are inert; rotate anything real and purge from git history.
2. Fix `devsec.yml` (`upload-sarif@v1` is disabled) so the security pipeline actually reports again.
3. Never deploy `tesr` (debug=True) or the Juice Shop images outside an isolated lab.
4. Scope the Elasticsearch access policy and retire EOL versions (ES 7.4, Node 14, Spring Boot 2.2.4).
