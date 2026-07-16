# Security Vulnerability Triage Report

- **Repository:** sairaja992/hh23
- **Scan date:** 2026-07-16 (automated scheduled review)
- **Scope:** Full repository (all 15 tracked files at commit `be86016`)
- **Method:** Manual static review of all source, IaC, container, and CI files

## Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High     | 5 |
| Medium   | 5 |
| Low      | 3 |

The most urgent items are **hardcoded credentials committed to source control** in three
separate files. Even where values appear to be placeholders, they must be treated as
exposed until rotated/verified, because the repository history preserves them permanently.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider block
- **File:** `secret.tf:2-3`
- **CWE:** CWE-798 (Hardcoded Credentials)
- **Detail:** `access_key = "AKIAIOSFODNN7EXAMPLE"` and a `secret_key` are embedded
  directly in the `provider "aws"` block. The access key matches AWS's documented
  example key and the secret is a near-copy of the documented example secret, so these
  are *probably* not live — but that must be confirmed, not assumed.
- **Triage:** Confirmed present; likely non-live placeholder, treat as exposed until verified.
- **Remediation:** Remove the credentials block entirely. Use an IAM role, AWS SSO, or
  environment variables / shared credentials file. If any real key was ever committed
  here, rotate it and purge git history (`git filter-repo`).

### C2. AWS access-key-style secrets embedded in `package.json`
- **File:** `package.json:10` (`"accesskey": "AKIASGHPORST"`) and `package.json:28`
  (`"access key": "AKIAXYGHKLYPQGRRS"`)
- **CWE:** CWE-798
- **Detail:** Two AKIA-prefixed strings are stored as fake "dependency" entries. Both are
  shorter than a valid 20-character AWS access key ID, so they appear to be planted/test
  values — but they will (correctly) trip every secret scanner, and any paired secret
  elsewhere would make them exploitable.
- **Triage:** Confirmed present; malformed key format suggests seeded test data.
- **Remediation:** Delete both entries. Note the file is also **invalid JSON** (missing
  comma after line 28's entry), so `npm install` fails outright.

### C3. Hardcoded token in Flask application
- **File:** `tesr:14` — `token "sa74io0!"`
- **CWE:** CWE-798
- **Detail:** A literal token/password string sits inside `elapsed()`. It is also not
  valid Python syntax, so the file both leaks a credential and cannot run.
- **Triage:** Confirmed present.
- **Remediation:** Remove the line; load secrets from a secret manager or environment.

---

## High

### H1. Flask app runs with `debug=True` bound to all interfaces
- **File:** `tesr:21` — `app.run(debug=True, host="0.0.0.0", port=8080)`
- **CWE:** CWE-489 (Active Debug Code) / CWE-215
- **Detail:** The Werkzeug debug console allows **remote code execution** if reachable,
  and `0.0.0.0` exposes it on every interface. The `/` route also leaks the full Python
  version string to callers.
- **Remediation:** `debug=False` in anything deployable; bind to localhost or gate
  behind a reverse proxy; drop the version string from the response.

### H2. Elasticsearch domain access policy allows any AWS principal
- **File:** `echo-elasticsearch (1).yaml:275-280`
- **CWE:** CWE-284 (Improper Access Control)
- **Detail:** `Principal: AWS: "*"` with `Action: es:*` on the domain. VPC placement
  reduces exposure, but any principal with network reach gets full domain control —
  no IAM authentication at all. Additionally `NodeToNodeEncryptionOptions` and
  `DomainEndpointOptions.EnforceHTTPS` are not enabled, and legacy ES versions
  (down to 6.0) are allowed by the `ESVersion` parameter.
- **Remediation:** Scope the principal to specific role ARNs, enable node-to-node
  encryption and HTTPS enforcement, and restrict allowed versions to supported ones.

### H3. Severely outdated, known-vulnerable Node.js dependencies (wmic-service)
- **File:** `package.json:8-11`
- **CWE:** CWE-1104 (Use of Unmaintained Third-Party Components)
- **Detail:**
  - `jsonwebtoken ^1.1.1` — vulnerable to authentication bypass via algorithm
    confusion / missing verification (fixed in 4.2.2+; CVE-2015-9235 class).
  - `async ^0.8.0` — prototype pollution (CVE-2021-43138 affects < 2.6.4).
  - `restify ^2.8.1` — circa 2014, multiple known issues, long unsupported.
- **Remediation:** Upgrade all three; `jsonwebtoken` ≥ 9.x, `async` ≥ 3.x, modern restify
  or replace.

### H4. OWASP Juice Shop manifest — intentionally vulnerable dependency set
- **File:** `POM` (actually a copy of juice-shop `package.json` v14.1.1)
- **Detail:** Contains deliberately vulnerable pins: `jsonwebtoken 0.4.0`,
  `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `unzipper 0.9.15`, deprecated `request`,
  `vm2`-class sandbox escapes via `notevil`, etc. This is expected for Juice Shop
  (a training target), but it should never be deployed outside an isolated lab.
- **Triage:** By-design vulnerable artifact; confirm it is lab-only.

### H5. EOL base images and unsafe npm install in Dockerfile
- **File:** `dockerarm:1,9` (`node:14`, `node:14-alpine`), `dockerarm:5`
  (`npm install --production --unsafe-perm`)
- **CWE:** CWE-1104
- **Detail:** Node.js 14 reached end-of-life April 2023 — no security patches for
  three years of CVEs. `--unsafe-perm` runs package lifecycle scripts as root during
  build.
- **Remediation:** Move to a maintained LTS base (`node:20-alpine`/`node:22-alpine`);
  drop `--unsafe-perm`.

---

## Medium

### M1. Spring Boot container runs as root
- **File:** `Dockerfile (1)` — no `USER` directive; the JVM runs as root in the container.
- **Remediation:** Add a non-root user (compare `dockerarm:25-32`, which does this correctly).

### M2. EOL Spring Boot 2.2.4.RELEASE parent
- **Files:** `pom (2).xml:15`, `pom254.xml:15`
- **Detail:** Spring Boot 2.2.x went EOL in 2020; pulls Spring Framework 5.2.3 with
  multiple subsequent CVEs in the 5.2.x line. `spring-boot-devtools` is also declared
  as a runtime dependency (`<optional>true</optional>` mitigates in repackaged jars,
  but it should be scoped out of production builds explicitly).
- **Remediation:** Upgrade to a supported Spring Boot line (3.3+ / Java 17+).

### M3. Mutable `:latest` image tag and hardcoded infrastructure IDs
- **File:** `template.yaml:17` (`q-gen-01:latest`), plus hardcoded account IDs, subnet
  and security-group IDs throughout `template.yaml` and `echo-elasticsearch (1).yaml`.
- **Detail:** `:latest` defeats provenance/rollback and can silently deploy a
  compromised image; hardcoded IDs leak account topology and prevent review of what
  actually deploys.
- **Remediation:** Pin images by digest or immutable tag; parameterize IDs.

### M4. CI workflow uses deprecated/unpinned actions
- **File:** `.github/workflows/devsec.yml:17,27,32`
- **Detail:** `actions/checkout@v2` and `codeql-action/upload-sarif@v1` are deprecated
  (Node 12 runtimes, removed API surface — `upload-sarif@v1` no longer functions);
  `microsoft/security-devops-action@preview` is a mutable tag. None are pinned to a
  commit SHA, leaving the pipeline open to tag-rewrite supply-chain attacks.
- **Remediation:** Upgrade to `checkout@v4`, `codeql-action/upload-sarif@v3`, a released
  MSDO version, and pin all third-party actions to full commit SHAs. Also add an
  explicit least-privilege `permissions:` block (`security-events: write` is required
  for SARIF upload and is currently inherited implicitly).

### M5. Secrets/PII-adjacent data paths in ECS task definition
- **File:** `ecs-task-definition-xray.yaml:57-64,165-167`
- **Detail:** Environment variables are passed as plain CloudFormation string
  parameters and land unencrypted in the task definition (visible to anyone with
  `ecs:DescribeTaskDefinition`). Log-group KMS encryption is optional and off by default.
- **Remediation:** Use `Secrets` (valueFrom Secrets Manager/SSM) instead of `Environment`
  for sensitive values; default a CMK for the log group.

---

## Low

### L1. `securityaudits3.py` is non-functional and error-suppressing
- **File:** `securityaudits3.py`
- **Detail:** The module docstring opened on line 2 is never closed, so the imports and
  much of the file are swallowed/broken; `today_date` vs `Today_date` NameError at
  line 34; bare `except:` at line 45 hides real failures; `publish_msg_security_team`
  references undefined `error` at line 212; unreachable code after `raise` at line 305-306.
  A broken *security audit* script means the audit silently isn't running — an
  operational security gap rather than a direct vulnerability.
- **Detail (info leak):** Hardcoded internal account IDs, SNS topic ARNs, and bucket
  names throughout.

### L2. Internal hostnames/topology in `package.json`
- **File:** `package.json:21` — `git://git.fpd.cat.com/...` uses the unauthenticated,
  unencrypted `git://` protocol and leaks an internal hostname.

### L3. Commented root-port docker run guidance
- **File:** `Dockerfile (1):20-21` — comments recommend publishing on ports 80/443 with
  `sudo docker run`, encouraging running the container with root-level port binding.

---

## Escalation & recommended next steps (priority order)

1. **Now:** Verify C1-C3 secrets are not live; rotate anything real; purge from history.
2. **Now:** Enable GitHub secret scanning + push protection on the repository.
3. **This week:** Fix H1 (Flask debug), H2 (ES access policy), upgrade H3/H5 dependencies
   and base images.
4. **This week:** Repair the CI security pipeline (M4) — the SARIF upload step is
   currently broken (`upload-sarif@v1`), so scanner findings are not reaching the
   Security tab at all.
5. **Backlog:** M1-M3, M5, L1-L3.

> Note: this repository appears to be a DevSecOps testing/hackathon target (juice-shop
> manifest, planted malformed secrets, MSDO workflow). If that is its purpose, the
> planted findings above are working as intended — but the repo should stay private and
> the *real*-looking internal identifiers (account IDs, subnets, internal hostnames)
> should still be scrubbed or confirmed as fake.
