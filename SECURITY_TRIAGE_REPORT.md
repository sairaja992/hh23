# Security Triage Report — hh23

- **Scan date:** 2026-08-04 (automated scheduled scan)
- **Scope:** all files at HEAD (`be86016`) of repository `sairaja992/hh23`
- **Result:** 15 findings — 4 Critical, 4 High, 4 Medium, 3 Low

> Context note: the repo README says "Used for testing only" and several files are
> OWASP Juice Shop / AWS-documentation samples, so some findings appear intentionally
> seeded for scanner testing. They are triaged below at face value; validity notes are
> included per finding so genuinely dangerous items can be separated from planted ones.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "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"
```
Credentials committed to source control grant anyone with repo access the keys.
**Validity:** the access key ID is AWS's official documentation example and the secret
is a near-copy of the docs example — almost certainly a planted test secret, not live.
**Action:** remove the file or replace with variables/instance-profile auth; if these were
ever real, rotate immediately and audit CloudTrail. CWE-798.

### C2. Flask debug server exposed on all interfaces — `tesr:23`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
`debug=True` enables the Werkzeug interactive debugger; combined with binding to
`0.0.0.0`, anyone who can reach port 8080 gets arbitrary remote code execution via the
debug console. **Action:** never run the Werkzeug dev server with debug in anything
deployed; gate on an env var and bind to localhost. CWE-94 / CWE-489.

### C3. Hardcoded token in source — `tesr:16`
```python
token "sa74io0!"
```
A password-like token committed to the repo (the line is also a syntax error — see L2).
**Action:** remove, rotate if it was ever a real credential, load secrets from env/secret
manager. CWE-798.

### C4. AWS access key IDs embedded in `package.json` (lines 9, 26)
`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` are stored as
fake "dependencies". **Validity:** both are shorter than a real 20-character AKIA key,
so they are likely planted for secret-scanner testing — but they will (correctly) trip
scanners forever. **Action:** remove; keys never belong in a package manifest. CWE-798.

## High

### H1. Elasticsearch domain access policy allows `Principal: "*"` with `es:*` — `echo-elasticsearch (1).yaml` (~line 275)
The domain resource policy grants every AWS principal full Elasticsearch API access to
the domain. VPC placement is the only mitigating control; defense-in-depth is absent, and
any misconfigured/peered network path exposes all data. The domain also lacks
`NodeToNodeEncryptionOptions` and `DomainEndpointOptions.EnforceHTTPS`, and permits
EOL versions 6.0–7.4. **Action:** scope the policy to specific IAM roles, enable
node-to-node encryption and enforced HTTPS/TLS 1.2, require a current OpenSearch version.

### H2. EOL Spring Boot with known RCE exposure — `pom (2).xml`, `pom254.xml`
`spring-boot-starter-parent 2.2.4.RELEASE` pulls Spring Framework 5.2.3, in the
vulnerable range for Spring4Shell **CVE-2022-22965** (RCE) plus numerous other
framework/Tomcat CVEs; the 2.2.x line is long past end-of-life. `spring-boot-devtools`
is also declared as a runtime dependency (remote-restart attack surface if packaged).
**Action:** upgrade to a supported Spring Boot 3.x line; drop devtools from production builds.

### H3. Critically outdated `jsonwebtoken ^1.1.1` — `package.json:11`
Versions before 4.2.2 are vulnerable to algorithm-confusion / signature-verification
bypass (CVE-2015-9235 class): attackers can forge tokens (e.g. `alg=none` or HMAC/RSA
confusion), defeating authentication entirely. `async ^0.8.0` and `restify ^2.8.1`
are similarly ancient. **Action:** upgrade jsonwebtoken to ≥9.x and modernize the rest.

### H4. Intentionally vulnerable app manifests/images in repo — `POM`, `package1.json`, `dockerarm`
`POM` and `package1.json` are the OWASP Juice Shop 14.1.1 manifest ("probably the most
modern and sophisticated insecure web application"); `dockerarm` builds it on the EOL
`node:14` base with `npm install --unsafe-perm`. Fine for training/scanner testing —
dangerous if any pipeline ever builds and deploys them. **Action:** keep quarantined in a
clearly-labeled test area; ensure no CI/CD deploys these artifacts.

## Medium

### M1. Container runs as root — `Dockerfile (1)`
No `USER` directive, so the Spring Boot app runs as root in the container; base image tag
is mutable (`jdk:17-ubuntu`). **Action:** add a non-root user and pin the base by digest.

### M2. Proxy settings baked into image ENV — `doc`
`http_proxy`/`https_proxy` are set via `ENV` from build args, so they persist in image
layers and `docker history` — a credential leak if authenticated proxy URLs are used.
`pip install -r requirements.txt` is unpinned/unhashed, and `FROM Doc` is not a valid
base image. (Credit: it does set `USER www-data`.) **Action:** use `--mount=type=secret`
or build-time-only proxy config; pin dependencies.

### M3. CI workflow uses deprecated/mutable actions — `.github/workflows/devsec.yml`
`actions/checkout@v2` and `github/codeql-action/upload-sarif@v1` are deprecated (v1
upload-sarif no longer functions on current GitHub), and
`microsoft/security-devops-action@preview` tracks a mutable tag — a supply-chain risk
and a silent way for the security scan itself to stop working. **Action:** bump to
current majors and pin third-party actions by commit SHA.

### M4. Internal infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
AWS account IDs (063586453409, 478226638351, 900182000710, 460510738068, 070133345649),
subnet/security-group IDs, IAM role ARNs, SNS topic ARNs, and internal bucket names are
hardcoded. Not directly exploitable, but useful reconnaissance and a spear-phishing aid
if the repo is/becomes public. **Action:** parameterize per environment; keep IDs out of
public repos.

## Low

### L1. `securityaudits3.py` is non-functional as committed
The module docstring opened at line 2 is never closed, so all imports (lines 12–22) sit
inside the string and the handler would fail at runtime; `today_date` is used (line 34)
but defined as `Today_date` (line 33); `publish_msg_security_team` prints an undefined
`error` variable, masking SNS failures; `writedatatodynamodb` has dead code after `raise`.
If this is a real audit Lambda elsewhere, its alerting error-paths are unreliable.

### L2. `package.json` is invalid JSON
Missing comma after the `"access key"` entry in `devDependencies` (and a credential-like
key mixed into dependencies) — `npm install` would fail to parse. `license` is empty.

### L3. `tesr` is syntactically invalid Python
The stray `token "sa74io0!"` line inside `elapsed()` is a syntax error; unreachable code
after `return` in the same function.

---

## Escalation & recommended next steps

1. **Immediate:** confirm none of the committed credentials (C1, C3, C4) were ever live;
   rotate anything that was and review CloudTrail for the exposed account IDs.
2. **This week:** fix the Elasticsearch access policy (H1) anywhere this template is
   actually deployed — it is the one finding that maps to live infrastructure risk.
3. **Backlog:** dependency upgrades (H2, H3), Dockerfile hardening (M1, M2), CI action
   pinning (M3).
4. If this repo exists purely as scanner-test fixtures, add a prominent README note per
   file so automated triage (like this one) and human reviewers can tell seeded findings
   from real ones.
