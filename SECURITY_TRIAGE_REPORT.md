# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-07-18 (automated scheduled scan)
**Scope:** All files on `main` (13 files — IaC templates, Dockerfiles, package manifests, Lambda script, CI workflow)

> Note: `README.md` marks this repo as "Used for testing only", and several files are
> intentionally vulnerable fixtures (OWASP Juice Shop manifest/Dockerfile). Findings are
> still triaged at face value so scanner baselines and real exposure are both covered.

---

## Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 3 | Hardcoded cloud credentials, secrets in manifests, RCE-capable debug config |
| High | 4 | EOL/vulnerable dependencies, wide-open Elasticsearch access policy |
| Medium | 4 | EOL base images, unpinned CI actions, root container user, infra detail disclosure |
| Low | 2 | Broken/unrunnable code, deprecated resource types |

---

## Critical

### C1. Hardcoded AWS credentials in Terraform — `secret.tf:2-3`
An AWS `access_key`/`secret_key` pair is committed directly in the provider block.
The access key is AWS's documentation example key (`AKIAIOSFODNN7EXAMPLE`) and the
secret is a near-copy of the docs example, so these are almost certainly not live —
but the pattern is exactly what secret scanners must catch, and the file normalizes
committing credentials.
**Triage:** Likely test fixture, not live. **Action:** Confirm keys are inert; move to
environment variables / assumed roles; keep the file only if it is a deliberate
scanner test case, and label it as such.

### C2. AWS access-key-format strings in `package.json:10,28`
`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` are embedded in
the dependencies/devDependencies blocks. Both match the AWS access-key-ID prefix
(`AKIA…`) though they are short of the full 20-char format. The file is also invalid
JSON (missing comma after line 28), so these entries would break `npm install`.
**Triage:** Planted secrets for scanner testing. **Action:** Rotate if ever real;
otherwise document as fixture.

### C3. Hardcoded token + Flask debug server exposed — `doc:14,21`
The Flask app embeds `token "sa74io0!"` (a hardcoded credential, also a Python syntax
error) and runs `app.run(debug=True, host="0.0.0.0", port=8080)`. Werkzeug's debug
mode on all interfaces gives interactive code execution (RCE) to anyone who reaches
the port and computes the debugger PIN.
**Triage:** Real anti-pattern; would be exploitable if deployed. **Action:** Never ship
`debug=True`; bind to localhost or run behind a WSGI server; remove the token.

---

## High

### H1. Ancient, vulnerable Node dependencies — `package.json`
- `jsonwebtoken ^1.1.1` — pre-4.2.2 versions are subject to algorithm-confusion /
  signature-verification bypass (CVE-2015-9235 class).
- `restify ^2.8.1` and `async ^0.8.0` — many years EOL with known advisories.

### H2. OWASP Juice Shop manifest (intentionally vulnerable) — `package1.json`
`jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2` (XSS bypasses),
`unzipper 0.9.15` (zip-slip), deprecated `request`, Node 14–18 engines (EOL).
**Triage:** This is Juice Shop 14.1.1, vulnerable by design — expected finding, no
remediation; ensure it is never deployed outside training contexts.

### H3. EOL Spring Boot parent — `pom (2).xml:15`, `pom254.xml:15`
`spring-boot-starter-parent 2.2.4.RELEASE` (Feb 2020) is long past EOL and pulls
Spring Framework 5.2.x, in scope for Spring4Shell (CVE-2022-22965) and numerous other
CVEs. `spring-boot-devtools` is also included, which must not reach production images.
**Action:** Move to a supported Spring Boot 3.x line; drop devtools from prod builds.

### H4. Elasticsearch domain access policy allows any principal — `echo-elasticsearch (1).yaml:272-280`
The domain policy grants `es:*` to `Principal: AWS: "*"`. VPC placement limits blast
radius, but any principal with network reach in those subnets gets full admin on the
domain. ES 7.4 is also EOL (superseded by OpenSearch), and the template sets no
node-to-node encryption or `EnforceHTTPS` domain endpoint options.
**Action:** Scope the policy to specific role ARNs; enable NodeToNodeEncryptionOptions
and DomainEndpointOptions.EnforceHTTPS; migrate to a supported OpenSearch version.

---

## Medium

### M1. EOL container base images — `dockerarm:1,9`
`node:14` / `node:14-alpine` reached end of life in 2023; no security patches.
(Juice Shop fixture — same caveat as H2.)

### M2. Container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root inside the container. The
Juice Shop Dockerfile (`dockerarm`) does this correctly with `USER 1001`.

### M3. Unpinned / deprecated GitHub Actions — `.github/workflows/devsec.yml`
`actions/checkout@v2` and `codeql-action/upload-sarif@v1` are deprecated (v1 SARIF
upload is disabled by GitHub), and `microsoft/security-devops-action@preview` is a
mutable tag — a supply-chain risk. Pin actions to commit SHAs and upgrade to
`checkout@v4` / `codeql-action@v3`.

### M4. Internal infrastructure details committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
Real-looking AWS account IDs (063586453409, 478226638351, 900182000710, …), subnet
IDs, security-group IDs, role ARNs, SNS topic ARNs, and bucket names are hardcoded.
Not directly exploitable, but useful reconnaissance if this repo is public.
**Action:** Parameterize; verify these accounts/resources are not live.

---

## Low

### L1. `securityaudits3.py` is unrunnable and fragile
The module docstring opened on line 2 is never closed, so all imports are swallowed
by the string and the script cannot run. Additional defects: `Today_date` vs
`today_date` NameError, bare `except:` clauses, unreachable code after `raise`,
hardcoded region/account values.

### L2. `AWS::Elasticsearch::Domain` resource type is legacy
Superseded by `AWS::OpenSearchService::Domain`; new security features land only there.

---

## Escalation & recommended next steps

1. **Verify no live credentials** — C1/C2 strings look like fixtures; confirm and run
   GitHub secret scanning on the repo to establish a clean baseline.
2. **If any template here feeds a real deployment** (ECS task, ES domain), fix H4 and
   M4 before next deploy — the open ES access policy is the highest real-world risk.
3. **Patch the CI workflow (M3)** — the SARIF upload at `@v1` likely fails silently,
   meaning the MSDO scanner results never reach the Security tab.
4. Treat Juice Shop files (`package1.json`, `dockerarm`) as intentional fixtures and
   exclude them from remediation SLAs.
