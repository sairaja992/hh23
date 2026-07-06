# Security Vulnerability Triage Report

- **Repository:** `sairaja992/hh23`
- **Branch reviewed:** `claude/loving-wright-0jwbec`
- **Date:** 2026-07-06
- **Scope:** All committed files (IaC, Dockerfiles, CI workflow, application source, dependency manifests)
- **Method:** Static review of source, configuration, and dependency manifests. No running infrastructure was reachable, so cloud/runtime findings are assessed from declared configuration only.

> This repo (`README.md` = "Used for testing only") is a grab-bag of DevSecOps
> test artifacts, including a vendored copy of OWASP Juice Shop manifests that
> are *intentionally* vulnerable. Findings below separate **real, actionable
> exposure** (hardcoded secrets, unsafe runtime config, open cloud policies)
> from **expected / by-design** vulnerabilities in the deliberately-insecure
> training material.

---

## Severity summary

| # | Finding | File | Severity | Status |
|---|---------|------|----------|--------|
| 1 | Flask app runs with `debug=True` bound to `0.0.0.0` (Werkzeug debugger RCE) | `tesr` | **Critical** | Escalate |
| 2 | Hardcoded application token in source | `tesr` | **High** | Escalate |
| 3 | Hardcoded AWS provider credentials in Terraform | `secret.tf` | **High** (likely example keys — verify) | Escalate |
| 4 | Elasticsearch access policy allows `Principal: "*"` with `es:*` | `echo-elasticsearch (1).yaml` | **High** | Escalate |
| 5 | `spring-boot-devtools` shipped as a runtime dependency | `pom (2).xml`, `pom254.xml` | **Medium** | Fix |
| 6 | Outdated Spring Boot 2.2.4.RELEASE (multiple CVEs) | `pom (2).xml`, `pom254.xml` | **Medium** | Fix |
| 7 | Known-vulnerable / EOL npm dependencies (Juice Shop) | `package.json`, `package1.json`, `POM` | **Medium** (by design) | Acknowledge |
| 8 | EOL base image `node:14`; invalid/unpinned base `FROM Doc` | `dockerarm`, `doc` | **Medium** | Fix |
| 9 | ECS task pins container image to `:latest` | `template.yaml` | **Low** | Fix |
| 10 | Deprecated GitHub Actions (`checkout@v2`, `codeql-action@v1`, `setup-dotnet@v1`, `@preview`) | `.github/workflows/devsec.yml` | **Low** | Fix |
| 11 | Hardcoded AWS account IDs / subnet / SG IDs in IaC | `template.yaml`, `securityaudits3.py`, `echo-elasticsearch (1).yaml` | **Low / Info** | Acknowledge |

---

## Detailed findings

### 1. Flask debug server exposed on all interfaces — **Critical**
**File:** `tesr`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
`debug=True` enables the Werkzeug interactive debugger. If an unhandled
exception is triggered, an attacker on the network can execute arbitrary Python
via the debugger console (the PIN is bypassable/derivable in many setups).
Binding to `0.0.0.0` exposes it on every interface. This is remote code
execution against the host.

**Remediation:** Never run with `debug=True` outside local development. Use a
production WSGI server (gunicorn/uwsgi), set `debug=False`, and bind to a
specific interface or front with a reverse proxy.

### 2. Hardcoded token in source — **High**
**File:** `tesr`
```python
    token "sa74io0!"
```
A credential-looking literal is committed in source. (It also sits after a
`return`, so it is dead/unreachable code — but a secret in version control must
be treated as compromised regardless of reachability.)

**Remediation:** Remove the literal, rotate the secret if it was ever real, and
load secrets from environment variables or a secrets manager. Add secret
scanning (e.g. gitleaks/trufflehog) to CI.

### 3. Hardcoded AWS credentials in Terraform — **High**
**File:** `secret.tf`
```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
}
```
The access key `AKIAIOSFODNN7EXAMPLE` is AWS's well-known **documentation
example** key, and the secret is a near-variant of the public example value.
These are almost certainly **not live credentials**, so real exposure is low —
but committing static provider credentials is a critical anti-pattern that
must not reach real code.

**Triage note:** verify these are not a lightly-edited copy of a *real* key
before dismissing. If confirmed as example values, downgrade to policy
violation; if real, rotate immediately.

**Remediation:** Remove static keys from provider blocks. Use IAM roles,
`AWS_PROFILE`, environment variables, or OIDC-federated CI credentials.

### 4. Elasticsearch domain open access policy — **High**
**File:** `echo-elasticsearch (1).yaml`
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: [ "es:*" ]
      Resource: "arn:aws:es:...:domain/${DomainName}/*"
```
A wildcard principal grants full Elasticsearch API access to *any* AWS caller.
Exposure is partially mitigated because the domain is VPC-bound
(`VPCOptions`), so it is not internet-facing — but any principal reaching the
VPC endpoint gets `es:*`. Combined with
`rest.action.multi.allow_explicit_index: "true"`, this widens the blast radius.
Encryption at rest and a customer-managed KMS key are correctly configured;
node-to-node encryption and enforced HTTPS are **not** declared.

**Remediation:** Scope the access policy to specific IAM roles/principals.
Add `NodeToNodeEncryptionOptions: Enabled: true` and
`DomainEndpointOptions: EnforceHTTPS: true`. Reconsider
`rest.action.multi.allow_explicit_index`.

### 5. `spring-boot-devtools` as a runtime dependency — **Medium**
**Files:** `pom (2).xml`, `pom254.xml`
DevTools is a development-only convenience that has historically enabled RCE
paths when exposed (e.g. the LiveReload/restart server). It should never be
present in a production artifact. It is marked `<optional>true</optional>`,
which limits transitive leakage but still packages it in the app's own build.

**Remediation:** Restrict to the `runtime`/`developmentOnly` scope and exclude
from the repackaged jar; confirm it is absent from production images.

### 6. Outdated Spring Boot 2.2.4.RELEASE — **Medium**
**Files:** `pom (2).xml`, `pom254.xml`
2.2.4 (Feb 2020) is end-of-life and carries numerous downstream CVEs across
Spring Framework, Tomcat, Jackson, and Logback (management endpoint exposure,
DoS, deserialization). `<url>` is empty and version strings differ (1.0 vs 2.0)
across the two otherwise-identical POMs.

**Remediation:** Upgrade to a currently-supported Spring Boot line and run
`mvn dependency:tree` + OWASP Dependency-Check / Snyk in CI.

### 7. Known-vulnerable npm dependencies (OWASP Juice Shop) — **Medium (by design)**
**Files:** `package.json`, `package1.json`, `POM` (all identical Juice Shop manifests)
These pin deliberately-insecure/EOL packages, e.g. `jsonwebtoken@0.4.0`,
`express-jwt@0.1.3` (auth-bypass CVE-2020-15084), `sanitize-html@1.4.2`
(XSS-filter bypass), `marsdb` (NoSQL-injection → RCE), `notevil` (sandbox
escape), `libxmljs2` (XXE), and deprecated `request@2.88.2`.

**Triage note:** This is the intentionally-vulnerable OWASP Juice Shop
training app. For a *real* project these would be critical; here they are
**expected**. Do not auto-bump — flag only so they are not mistaken for a
finding in first-party code.

### 8. Container base images — **Medium**
**Files:** `dockerarm` (`FROM node:14`, `node:14-alpine`), `doc` (`FROM Doc`)
`node:14` is end-of-life (no security updates). `doc` uses `FROM Doc`, an
invalid/unresolvable base that also duplicates `http_proxy` for both
`http_proxy` and `https_proxy` env vars. The `Dockerfile (1)` (OpenJDK 17) is
fine.

**Remediation:** Move to a supported, digest-pinned base image; fix the `doc`
base reference and the copy-paste proxy env bug.

### 9. ECS image pinned to `:latest` — **Low**
**File:** `template.yaml`
```
ContainerImage: 063586453409.dkr.ecr.us-east-2.amazonaws.com/q-gen-01:latest
```
`:latest` defeats immutable/reproducible deploys and complicates rollback and
provenance. Pin to an immutable digest or version tag.

### 10. Deprecated GitHub Actions — **Low**
**File:** `.github/workflows/devsec.yml`
Uses `actions/checkout@v2`, `actions/setup-dotnet@v1`,
`github/codeql-action/upload-sarif@v1` (v1 is deprecated/retired), and
`microsoft/security-devops-action@preview` (unpinned preview channel).

**Remediation:** Upgrade to current major versions and pin third-party actions
to a commit SHA rather than a floating `@preview` tag.

### 11. Hardcoded cloud identifiers — **Low / Info**
**Files:** `template.yaml`, `securityaudits3.py`, `echo-elasticsearch (1).yaml`
Real-looking AWS account IDs (`063586453409`, `478226638351`,
`900182000710`, `460510738068`, `070133345649`), subnet IDs, security-group
IDs, role ARNs, and SNS topic ARNs are committed. Not directly exploitable but
they leak environment topology useful for targeting.

**Remediation:** Parameterize via variables/SSM and scrub from source history
where feasible.

---

## Non-security code-quality notes (informational)
`securityaudits3.py` has latent bugs that would break the audit Lambda at
runtime (and thus silently stop security reporting — a detection gap):
- Module docstring is never closed, so all `import` statements are inside the
  string and never execute.
- `today_date` (lowercase) is used but only `Today_date` is defined →
  `NameError`.
- `except` block references undefined `error`/formats an exception with `+`.

These are reliability defects, not vulnerabilities, but a broken security-audit
job is itself a risk (loss of monitoring). Recommend fixing before relying on it.

---

## Escalation & recommended actions

**Escalate now (owner action required):**
1. `tesr` — disable Flask debug mode / remove `0.0.0.0` binding (RCE). Rotate token `sa74io0!`.
2. `secret.tf` — confirm keys are AWS example placeholders; if real, rotate the IAM key immediately and remove from history.
3. `echo-elasticsearch (1).yaml` — scope the `Principal: "*"` access policy before any deployment.

**Fix in normal cycle:**
4. Spring Boot upgrade + remove devtools from prod build (#5, #6).
5. Base image / `:latest` / Actions hygiene (#8, #9, #10).

**Acknowledge / no action (by design):**
6. OWASP Juice Shop dependency manifests (#7) — intentionally vulnerable training material.

**Preventive controls to add:**
- Secret scanning (gitleaks/trufflehog) as a pre-commit hook and CI gate.
- SCA (Dependency-Check / Snyk) and IaC scanning (checkov/tfsec) in the pipeline.
- Pin all third-party GitHub Actions to commit SHAs.
