# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-02 (automated scheduled review)
**Scope:** All 15 tracked files (IaC templates, Dockerfiles, dependency manifests, Python scripts, CI workflow)

**Context note:** The README states this repo is "Used for testing only," and `POM` / `package1.json` / `dockerarm` are copies of OWASP Juice Shop manifests (an intentionally vulnerable app). Severity below is triaged for the realistic risk: secrets and internal AWS environment details in a repository are exposures regardless of test intent.

---

## Critical

### C1. Hardcoded AWS credentials — `secret.tf`
```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."
}
```
- The access key is AWS's published documentation example key, so these are almost certainly placeholders — but the file normalizes a pattern (credentials inline in a provider block) that secret scanners will continuously flag, and any copy-paste reuse with real keys is a full account compromise.
- **Action:** Delete the file or replace with an assume-role / environment-variable provider config. If real keys were ever committed in this file's history, rotate them.

### C2. Flask debug server exposed on all interfaces — `tesr` (line 21)
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
- `debug=True` enables the Werkzeug interactive debugger; combined with `host="0.0.0.0"` this gives any network peer a path to **remote code execution** via the debugger console.
- **Action:** `debug=False` in anything deployable; bind to localhost or run behind a WSGI server.

### C3. Hardcoded token — `tesr` (line 14)
```python
token "sa74io0!"
```
- A credential literal committed to source (also a Python syntax error — the file cannot run as-is).
- **Action:** Remove; source secrets from environment/secret manager. Rotate the token if it was ever live.

## High

### H1. AKIA-format access keys embedded in `package.json` (lines 10, 28)
- `"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` sit inside the dependency maps. Both are shorter than a valid 20-char AWS key ID, so likely seeded test data — but they are secret-scanner hits and the second one also makes the file **invalid JSON** (missing comma), so `npm install` fails outright.
- **Action:** Remove both entries.

### H2. Elasticsearch domain access policy open to any principal — `echo-elasticsearch (1).yaml` (lines 272–280)
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: ["es:*"]
```
- `Principal: "*"` with `es:*` grants every AWS principal full domain control. VPC placement reduces exposure, but any principal that can reach the VPC endpoint (or a future config drift to public access) gets unrestricted read/write/admin. Also runs EOL Elasticsearch 7.4 with 6.x versions still allowed.
- **Action:** Scope the principal to specific role ARNs and restrict actions; use IAM-signed access or fine-grained access control.

### H3. Known-vulnerable auth/sanitization dependencies
- `package.json`: `jsonwebtoken ^1.1.1` — pre-dates fixes for algorithm-confusion / signature-bypass issues (CVE-2015-9235 class); `restify ^2.8.1` and `async ^0.8.0` are ~10 years old.
- `POM` / `package1.json` (Juice Shop): `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `unzipper 0.9.15` — intentionally vulnerable upstream; do not deploy anywhere reachable.
- **Action:** For anything derived from `package.json` that is a real service, upgrade `jsonwebtoken` to ≥9.x and modernize the stack.

### H4. End-of-life runtimes and base images
- `dockerarm`: `FROM node:14` / `node:14-alpine` (EOL April 2023, no security patches) plus `npm install --unsafe-perm` (allows lifecycle scripts as root during build).
- `pom (2).xml` / `pom254.xml`: Spring Boot `2.2.4.RELEASE` (EOL; ships Spring Framework 5.2.3, in the vulnerable range for CVE-2022-22965 "Spring4Shell" under WAR/JDK9+ deployment) and bundles `spring-boot-devtools` as a non-test dependency.
- `Dockerfile (1)`: commented suggestion of `openjdk:9-jdk-alpine` (EOL) — the active JDK17 base is fine.
- **Action:** Move to node:20+/22 LTS and Spring Boot 3.x; drop devtools from production builds; remove `--unsafe-perm`.

## Medium

### M1. Internal AWS environment details committed to the repo
- Real-looking account IDs (`063586453409`, `478226638351`, `900182000710`, `460510738068`, `070133345649`), IAM role ARNs, subnet IDs, security group IDs, ECR URIs, S3 bucket names, and SNS topic ARNs appear across `template.yaml`, `echo-elasticsearch (1).yaml`, and `securityaudits3.py`.
- Not credentials, but valuable reconnaissance if the repo is public and these correspond to live environments.
- **Action:** Parameterize identifiers or confirm the repo stays private; treat the listed accounts as enumerable.

### M2. Deprecated/broken CI security pipeline — `.github/workflows/devsec.yml`
- `actions/checkout@v2` and `github/codeql-action/upload-sarif@v1` are deprecated (v1 of codeql-action is disabled by GitHub), so the MSDO scan workflow likely fails and no alerts reach the Security tab — the repo's own security scanning is silently dead.
- **Action:** Bump to `checkout@v4` and `codeql-action/upload-sarif@v3`.

### M3. Broken security Lambda — `securityaudits3.py`
- Unterminated module docstring at line 2: the entire file is a `SyntaxError` (confirmed with `py_compile`) — the Scout2 findings-ingestion Lambda cannot execute at all. Additional latent bugs once fixed: `today_date` used but defined as `Today_date` (line 33/34), `raise e` before the error-alert append makes the alert unreachable (lines 305–306), bare `except:` clauses swallow real errors.
- If this Lambda is deployed elsewhere from this source, S3 audit findings are not being written to DynamoDB and missing-report alerts are not firing — a monitoring blind spot.
- **Action:** Close the docstring, fix the variable name, move `raise` after the alert append.

## Low

- `tesr` leaks the full Python version string in its HTTP response (banner disclosure).
- `Dockerfile (1)` / `dockerarm` run fine as non-root (`USER 1001`, `www-data`) — noted as good practice; no action.
- `package.json` has an empty `license` field and a `git://` (unencrypted, integrity-unverified) repository URL.

---

## Triage summary

| # | Severity | File | Issue | Disposition |
|---|----------|------|-------|-------------|
| C1 | Critical | secret.tf | Hardcoded AWS keys (AWS doc example values) | Remove file; rotate if ever real |
| C2 | Critical | tesr | Flask debug=True on 0.0.0.0 → RCE | Fix before any deploy |
| C3 | Critical | tesr | Hardcoded token | Remove + rotate |
| H1 | High | package.json | AKIA keys in manifest; invalid JSON | Remove entries |
| H2 | High | echo-elasticsearch (1).yaml | ES policy Principal "*" + es:* | Scope principals |
| H3 | High | package.json, POM, package1.json | EOL/vulnerable jwt & sanitizer libs | Upgrade (Juice Shop files: do not deploy) |
| H4 | High | dockerarm, pom*.xml | EOL node:14, Spring Boot 2.2.4, devtools in prod | Upgrade bases/frameworks |
| M1 | Medium | template.yaml, echo-es, securityaudits3.py | Internal AWS IDs/ARNs exposed | Parameterize / keep private |
| M2 | Medium | .github/workflows/devsec.yml | Deprecated actions → dead security scanning | Bump action versions |
| M3 | Medium | securityaudits3.py | SyntaxError — audit Lambda cannot run | Fix syntax + logic bugs |

**Escalation:** C1–C3 and H1 (secrets/RCE class) reported to repository owner via notification on 2026-08-02. No confirmed-live credential was identified (C1 uses AWS documentation example values; H1 keys are invalid length), so no emergency rotation was triggered — but removal is still recommended, and rotation is required if any of these values were ever real.
