# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-17 (automated scheduled review)
**Scope:** All files at HEAD (`be86016`) plus git history check

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 4 |
| Medium   | 4 |
| Low      | 3 |

The two critical findings are hardcoded credentials committed to the repository. Because this repo's history is public-facing (GitHub), any real credential that ever appeared in a commit must be treated as compromised and rotated — deleting the file is not sufficient.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."
}
```
The values resemble AWS's documentation example key (`AKIAIOSFODNN7EXAMPLE`), which lowers the likelihood they are live — but they follow the exact hardcoded-credential anti-pattern and are flagged by every secret scanner (CWE-798).
**Triage:** Verify these were never real. If real: rotate immediately in IAM, audit CloudTrail for use. Either way, remove the file and use an IAM role, AWS SSO, or environment-based credential chain. Note: the credentials are in git history since commit `8b9f5c9`, so history rewriting (or credential rotation) is required, not just deletion.

### C2. AWS access key IDs embedded in `package.json:10,28`
```json
"accesskey": "AKIASGHPORST",
"access key": "AKIAXYGHKLYPQGRRS"
```
Access key IDs placed inside the `dependencies`/`devDependencies` maps. These are malformed (AKIA IDs are normally 20 chars) and the file itself is invalid JSON (missing comma after line 28), so this looks like planted/test data — but it will trip secret scanners and normalizes a dangerous pattern.
**Triage:** Confirm not real; remove from the manifest. If any matching key exists in IAM, rotate and audit.

---

## High

### H1. Flask app runs with debug mode exposed on all interfaces — `tesr:21`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
Werkzeug's debug console permits **remote code execution** if reachable (the PIN is bypassable and often disabled). Binding to `0.0.0.0` exposes it beyond localhost. Also: a stray hardcoded token `"sa74io0!"` at `tesr:14` (which is additionally a Python syntax error).
**Triage:** Set `debug=False` in anything deployable, bind to localhost or put behind a reverse proxy, remove the token line.

### H2. Elasticsearch domain access policy open to any AWS principal — `echo-elasticsearch (1).yaml:272-280`
```yaml
Principal:
  AWS: "*"
Action: ["es:*"]
```
Wildcard principal with full `es:*` on the domain. VPC placement reduces exposure, but any principal/workload with network reach to those subnets gets full admin on the domain (including delete). Additionally, node-to-node encryption and enforced HTTPS are not configured, and ES 7.4 is end-of-life.
**Triage:** Scope the policy to specific IAM roles, add `NodeToNodeEncryptionOptions: Enabled: true` and `DomainEndpointOptions: EnforceHTTPS: true`, plan an upgrade to a supported OpenSearch version.

### H3. Critically outdated JWT/auth dependencies — `package.json:9`, `POM`/`package1.json:129,154`
- `jsonwebtoken ^1.1.1` (package.json) and `0.4.0` (package1.json/POM): vulnerable to algorithm-confusion signature bypass (CVE-2015-9235 class) — forged tokens verify successfully.
- `express-jwt 0.1.3`, `sanitize-html 1.4.2` (XSS bypass), `unzipper 0.9.15` (zip-slip), `express-rate-limit`, `request` (deprecated) — all with known CVEs.

**Note:** `POM` and `package1.json` are copies of the OWASP Juice Shop v14.1.1 manifest — an *intentionally vulnerable* training app. If these files are here as test fixtures for scanners, mark them as such (e.g. move under `test-fixtures/`); if any are used for a real service (`wmic-service` in `package.json` appears real), upgrade jsonwebtoken to ^9.x and audit token verification.

### H4. EOL runtime bases and Spring Boot with known RCE exposure — `Dockerfile (1)`, `dockerarm`, `pom (2).xml`/`pom254.xml:15`
- Spring Boot parent `2.2.4.RELEASE` (Spring Framework 5.2.3): end-of-life; in scope for Spring4Shell (CVE-2022-22965) when run on JDK9+ — and the Dockerfile runs it on JDK 17 — plus CVE-2020-5398 and others.
- `Dockerfile (1)` has no `USER` directive → container runs as root.
- `dockerarm` uses `node:14` (EOL April 2023) and `npm install --unsafe-perm`.

**Triage:** Upgrade to a supported Spring Boot 3.x line, add a non-root `USER`, move to `node:20`+ base images.

---

## Medium

### M1. Unpinned / deprecated GitHub Actions — `.github/workflows/devsec.yml`
`actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1` are deprecated (v1/v2 runners are shut off — the workflow likely fails), and `microsoft/security-devops-action@preview` is a **mutable tag**, a supply-chain risk (the referenced code can change silently).
**Triage:** Bump to current majors and pin third-party actions to a full commit SHA.

### M2. Internal infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
AWS account IDs (063586453409, 900182000710, 460510738068, 070133345649, 478226638351), subnet/security-group IDs, IAM role ARNs, and SNS topic ARNs. Not credentials, but useful reconnaissance material in a public repo and they enable confused-deputy attempts against the SNS topic/roles.
**Triage:** Parameterize per environment; keep real IDs in private parameter stores.

### M3. Proxy ENV vars baked into image layers — `doc:7-9`
`ENV http_proxy=$HTTP_PROXY_ARG` persists build-arg values into the final image metadata (visible via `docker inspect`/history). If proxy URLs ever carry credentials (`http://user:pass@proxy`), they leak with the image. Also `https_proxy` is incorrectly set from `HTTP_PROXY_ARG` (copy-paste bug).
**Triage:** Use build-time-only args (`ARG` used directly in `RUN`) or multi-stage builds; fix the https_proxy assignment.

### M4. Broken error handling masks failures in security tooling — `securityaudits3.py`
The audit lambda itself has defects that silently break security reporting: `Today_date` assigned but `today_date` used (`NameError` at import, lines 33-34), the module docstring is never closed so the imports are inside the string, bare `except:` clauses (lines 45, 237), and `publish_msg_security_team` prints an undefined `error` variable on failure (line 212) — meaning SNS alert failures are themselves swallowed. A broken security-alerting pipeline is a security gap.
**Triage:** Fix the syntax/name errors, catch specific exceptions, and add a dead-man's-switch alarm on the lambda.

---

## Low

- **L1.** `Dockerfile (1)` commented guidance suggests `openjdk:9-jdk-alpine` for "Java 8" (wrong and EOL); comments encourage running docker with sudo/port 80.
- **L2.** `package.json` has an empty `"license"` field and points at an internal git remote (`git://git.fpd.cat.com/...`) over the unauthenticated, unencrypted `git://` protocol.
- **L3.** `echo-elasticsearch (1).yaml` allows `t2` instance types which do not support encryption at rest (noted in the template's own comments); `rest.action.multi.allow_explicit_index: "true"` broadens multi-index request surface.

---

## Escalation & recommended immediate actions

1. **Now:** Confirm C1/C2 key material is fictitious; if any doubt, rotate in IAM and review CloudTrail (keys have been public in git history since the initial upload).
2. **This week:** Fix H1 (Flask debug), H2 (ES access policy), and repair the CI workflow (M1) so scanning actually runs.
3. **Planned:** Dependency/base-image upgrades (H3/H4); if Juice Shop manifests are intentional fixtures, isolate and label them to avoid alert noise.
4. Enable GitHub secret scanning + push protection and Dependabot alerts on this repository.
