# Security Vulnerability Triage — hh23

**Scan date:** 2026-08-03
**Scope:** All committed files in `sairaja992/hh23` (branch `main`)
**Method:** Static review of source, IaC (CloudFormation/Terraform), Dockerfiles, CI workflow, and dependency manifests.

> Note: `README.md` states "Used for testing only" and the repo bundles OWASP Juice Shop (an intentionally vulnerable app). Findings below are still reported and triaged so that any pattern reused in real environments is caught. Severities reflect the risk *if this code shipped to a real environment*.

## Summary

| # | Severity | Finding | File |
|---|----------|---------|------|
| 1 | Critical | Hardcoded AWS credentials in Terraform provider | `secret.tf` |
| 2 | Critical | Hardcoded AWS access keys / secret in dependency manifest | `package.json` |
| 3 | Critical | Hardcoded auth token in source | `tesr` |
| 4 | High | Flask app runs with `debug=True` bound to `0.0.0.0` (Werkzeug debugger RCE) | `tesr` |
| 5 | High | Elasticsearch access policy allows `Principal: "*"` with `es:*` | `echo-elasticsearch (1).yaml` |
| 6 | High | Elasticsearch domain missing HTTPS enforcement & node-to-node encryption | `echo-elasticsearch (1).yaml` |
| 7 | Medium | Known-vulnerable / EOL dependencies | `package.json`, `POM`, `package1.json` |
| 8 | Medium | EOL / unpinned container base images | `Dockerfile (1)`, `dockerarm` |
| 9 | Medium | CI actions unpinned / outdated (`@preview`, `@v1`, `@v2`) | `.github/workflows/devsec.yml` |
| 10 | Low | Hardcoded AWS account IDs, subnet/SG/ARN identifiers | `template.yaml`, `ecs-task-definition-xray.yaml`, `securityaudits3.py` |

---

## Details & Remediation

### 1. Hardcoded AWS credentials in Terraform — `secret.tf` (Critical)
```hcl
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
}
```
The values are AWS's *documented example* keys (not live), but committing long-lived credentials in provider blocks is a critical anti-pattern.
**Fix:** Remove static keys; use environment variables, shared config profiles, IAM roles, or OIDC. Add a secret scanner (gitleaks/trufflehog) to CI. If any real key was ever committed here, rotate it and purge from history.

### 2. Hardcoded AWS keys in dependency manifest — `package.json` (Critical)
```json
"accesskey": "AKIASGHPORST",
...
 "access key": "AKIAXYGHKLYPQGRRS"   // <- also invalid JSON: missing comma
```
AWS-key-shaped secrets injected as fake dependencies. The strings are short/placeholder-length (not valid live keys), and the file is also **malformed JSON** (missing comma) so `npm install` would fail.
**Fix:** Remove the secret-shaped entries; never store keys in `package.json`. Fix the JSON. Add secret scanning.

### 3. Hardcoded auth token in source — `tesr` (Critical)
```python
    token "sa74io0!"
```
A credential-looking literal embedded in the Flask module (the line is also syntactically invalid).
**Fix:** Remove; load secrets from environment/secret manager. Rotate the token if it corresponds to anything real.

### 4. Flask debug server exposed on all interfaces — `tesr` (High)
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
`debug=True` enables the Werkzeug interactive debugger, which allows **arbitrary code execution** to anyone who can reach it; `host="0.0.0.0"` binds every interface.
**Fix:** `debug=False` in any non-local context; run behind a production WSGI server (gunicorn/uwsgi); restrict binding.

### 5. Elasticsearch domain open access policy — `echo-elasticsearch (1).yaml` (High)
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: [ "es:*" ]
```
Wildcard principal grants full ES actions to any AWS principal that can reach the domain. Even inside a VPC this is over-broad (all `es:*`).
**Fix:** Scope `Principal` to specific role ARNs and `Action` to least privilege. Rely on VPC + fine-grained access control.

### 6. Elasticsearch missing transport security — `echo-elasticsearch (1).yaml` (High)
The domain sets `EncryptionAtRestOptions` but does **not** set `NodeToNodeEncryptionOptions` or `DomainEndpointOptions.EnforceHTTPS`. `rest.action.multi.allow_explicit_index: "true"` also broadens multi-index request surface.
**Fix:** Add
```yaml
NodeToNodeEncryptionOptions: { Enabled: true }
DomainEndpointOptions: { EnforceHTTPS: true, TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07 }
```
and set `rest.action.multi.allow_explicit_index: "false"` unless explicitly required.

### 7. Known-vulnerable / EOL dependencies — `package.json`, `POM`, `package1.json` (Medium)
- `wmic-service` (`package.json`): `jsonwebtoken ^1.1.1`, `restify ^2.8.1`, `async ^0.8.0` — years-old, multiple CVEs.
- Juice Shop (`POM` / `package1.json`): intentionally vulnerable, includes `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `unzipper 0.9.15`, deprecated `request`.
**Fix:** Upgrade non-intentional projects; run `npm audit` / Dependabot / OWASP Dependency-Check in CI. (Juice Shop deps are expected-vulnerable by design.)

### 8. EOL / unpinned container base images — `Dockerfile (1)`, `dockerarm` (Medium)
- `FROM node:14` / `node:14-alpine` — Node 14 is end-of-life.
- `dockerarm` uses `FROM Doc` (invalid/typo base) and propagates `http_proxy` from build args into `ENV`.
**Fix:** Move to supported, digest-pinned base images; drop proxy env leakage; scan images (Trivy/Grype).

### 9. CI actions unpinned / outdated — `.github/workflows/devsec.yml` (Medium)
Uses `microsoft/security-devops-action@preview` (mutable tag), `actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1`.
**Fix:** Pin actions to full commit SHAs; upgrade to current major versions; avoid mutable `@preview` tags.

### 10. Hardcoded infra identifiers — `template.yaml`, `ecs-task-definition-xray.yaml`, `securityaudits3.py` (Low)
AWS account IDs (e.g. `063586453409`, `478226638351`), ECR ARNs, subnet IDs, and security-group IDs are committed. Information disclosure that aids reconnaissance; not directly exploitable.
**Fix:** Parameterize via SSM/CloudFormation parameters; avoid committing environment-specific identifiers.

---

## Recommended escalation / next steps
1. **Immediate:** Confirm the credentials in items 1–3 are non-production example/placeholder values. If any are real, **rotate now** and purge from git history (`git filter-repo` / BFG).
2. **CI gate:** Add secret scanning (gitleaks) + dependency scanning + IaC scanning (checkov/tfsec) to block regressions.
3. **IaC hardening:** Apply fixes 5 & 6 to the Elasticsearch template before any real deployment.
4. **App hardening:** Never ship `debug=True` (item 4).
