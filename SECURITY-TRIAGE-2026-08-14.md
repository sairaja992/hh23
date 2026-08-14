# Security Triage Report — 2026-08-14

Automated vulnerability identification and triage sweep of `sairaja992/hh23` (branch `main` @ `be86016`).
Every file in the repository was reviewed. Findings are ranked by severity with remediation guidance.

**Totals: 2 Critical · 7 High · 5 Medium · 2 Low**

---

## CRITICAL

### C1. Hardcoded AWS credentials committed to source control — `secret.tf`
The Terraform AWS provider block embeds an access key and secret key directly:

```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/..."
}
```

The access key ID matches AWS's documentation example, but the secret key is a
modified variant — it must be treated as a potentially live credential until proven
otherwise. Credentials in git remain in history even after deletion.

**Remediation:** Verify in IAM whether any key with this prefix exists and rotate/deactivate it. Remove the file, purge it from git history (`git filter-repo`), and switch to IAM roles / environment variables / AWS SSO. Enable GitHub secret scanning + push protection on the repo.

### C2. Elasticsearch domain access policy open to any AWS principal — `echo-elasticsearch (1).yaml`
The `AWS::Elasticsearch::Domain` resource grants full access to everyone:

```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal:
        AWS: "*"
      Action:
        - "es:*"
```

VPC placement reduces exposure, but any principal that can reach the VPC endpoint
(any role in the account, peered networks, compromised workloads) gets full
`es:*` — including delete-domain — on a cluster tagged for "Grief Management" data.

**Remediation:** Scope `Principal` to the specific task/application roles and restrict `Action` to the read/write operations required. Also note: Elasticsearch 7.4 is end-of-life (see H7), and the template defines no `EncryptionAtRestOptions` / `NodeToNodeEncryptionOptions` despite provisioning a KMS key.

---

## HIGH

### H1. Flask app runs with debug mode bound to all interfaces — `tesr`
`app.run(debug=True, host="0.0.0.0", port=8080)` exposes the Werkzeug interactive
debugger to the network. The debugger console allows **arbitrary remote code
execution** on any unhandled exception page. The Dockerfile (`Dockerfile (1)`)
packages and exposes this same app on port 8080.

**Remediation:** `debug=False` (or drop the kwarg), serve via gunicorn/uwsgi, bind to localhost unless external exposure is required.

### H2. Hardcoded application token — `tesr`
Line `token "sa74io0!"` embeds a credential in source. Move to environment variables or a secrets manager and rotate the token.

### H3. AWS access key IDs embedded in `package.json`
`"accesskey": "AKIASGHPORST"` (dependencies) and `"access key": "AKIAXYGHKLYPQGRRS"`
(devDependencies). These are AKIA-prefixed key IDs sitting in a dependency manifest —
exactly the pattern credential scanners and attackers grep for.

**Remediation:** Remove both entries, confirm the corresponding IAM keys don't exist or rotate them.

### H4. Critically outdated npm dependencies — `package.json` (wmic-service)
- `jsonwebtoken ^1.1.1` — vulnerable to algorithm-confusion **authentication bypass** (CVE-2015-9235 class); ~9 years and multiple critical advisories behind current (9.x).
- `async ^0.8.0`, `restify ^2.8.1`, `mocha ^1.21.4`, `supertest ^0.14.0` — all far past EOL with known advisories.

**Remediation:** Upgrade all pins; add `npm audit` / Dependabot to CI.

### H5. OWASP Juice Shop manifest with intentionally vulnerable pins — `POM` and `package1.json` (identical files)
These are the manifest of the deliberately insecure Juice Shop app: `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `unzipper 0.9.15`, `notevil`, etc. If this repo feeds any real build, none of this must ship. If it exists as scanner test fixture, move it under a clearly-named `test-fixtures/` directory so triage tooling can suppress it deliberately.

### H6. End-of-life Spring Boot parent — `pom (2).xml`, `pom254.xml`
`spring-boot-starter-parent 2.2.4.RELEASE` (Jan 2020) is long past EOL and pulls Spring Framework/Tomcat versions with multiple known RCE- and DoS-class CVEs. `spring-boot-devtools` is also included as a runtime-optional dependency. **Remediation:** Move to a supported Spring Boot 3.x line; ensure devtools is excluded from production packaging.

### H7. End-of-life base images and engine versions
- `dockerarm`: `node:14` / `node:14-alpine` (EOL April 2023) plus `npm install --unsafe-perm` (runs lifecycle scripts as root).
- `doc`: comment suggests `openjdk:9-jdk-alpine` (EOL).
- `echo-elasticsearch (1).yaml`: Elasticsearch 7.4 default, allowed values down to 6.0 — all EOL.

**Remediation:** Rebase images on current LTS (node:20/22-alpine, Temurin 21), migrate to OpenSearch, and pin images by digest.

---

## MEDIUM

### M1. `Dockerfile (1)` issues
`FROM Doc` is not a valid base image (build is broken); proxy values baked in via `ENV` persist in image layers and leak internal proxy endpoints; `pip install -r requirements.txt` is unpinned/unhashed; apt cache is not cleaned. Positive: it does drop to `USER www-data`.

### M2. Broken security-scanning workflow — `.github/workflows/devsec.yml`
`github/codeql-action/upload-sarif@v1` has been **shut off by GitHub** (v1/v2 deprecated), and `actions/checkout@v2` / `setup-dotnet@v1` run on deprecated Node runtimes. Net effect: the repo's only security pipeline fails or silently uploads nothing — the alerting this repo relies on is not functioning. Upgrade to `codeql-action/upload-sarif@v3`, `checkout@v4`, and `microsoft/security-devops-action@latest` (pin by SHA), and set `security-events: write` permissions explicitly.

### M3. Infrastructure identifiers hardcoded in templates
`template.yaml` and `echo-elasticsearch (1).yaml` expose account IDs (063586453409, 900182000710, 460510738068, 070133345649, 478226638351), subnet IDs, security-group IDs, and role ARNs. Not directly exploitable, but valuable reconnaissance; parameterize per environment.

### M4. `securityaudits3.py` is non-functional — the audit tool itself is broken
The module docstring opened on line 2 is never closed, so **all imports are swallowed by the string literal** and the script cannot run as written. Additional defects: `Today_date` defined but `today_date` referenced (NameError), `print(error)` references an undefined name in `publish_msg_security_team`'s handler (so SNS failures crash silently), bare `except:` clauses, `f.close()` outside the `with` scope, and code after `raise` is unreachable. If this Lambda is deployed anywhere, S3 audit findings are **not** being written to DynamoDB and alerts are not being sent.

### M5. ECS task definition — `ecs-task-definition-xray.yaml`
X-Ray sidecar marked `Essential: true` (daemon failure kills the task); no `ReadonlyRootFilesystem`/`User` hardening in container definitions. Secrets handling via Secrets Manager ARN is done correctly.

---

## LOW

- **L1.** `package.json` is invalid JSON (missing comma after the `"access key"` entry) and has an empty `license` field — any tooling consuming it fails.
- **L2.** `echo-elasticsearch (1).yaml` sets `rest.action.multi.allow_explicit_index: "true"`, which weakens index-level access control granularity.

---

## Escalation summary

| Priority | Action | Owner suggestion |
|---|---|---|
| P0 | Rotate/verify AWS credentials in `secret.tf` + purge git history; enable secret scanning & push protection | Cloud/IAM admin |
| P0 | Lock down `Principal: "*"` / `es:*` Elasticsearch access policy | Platform team |
| P1 | Disable Flask debug mode; remove hardcoded token; remove AKIA keys from `package.json` | App owner |
| P1 | Fix broken `devsec.yml` scanning workflow (deprecated actions) — restore security visibility | DevSecOps |
| P2 | Dependency/base-image upgrades (Spring Boot, node:14, jsonwebtoken, ES 7.4) | App/platform owners |
| P3 | Repair `securityaudits3.py`; quarantine Juice Shop fixture files | Security tooling owner |
