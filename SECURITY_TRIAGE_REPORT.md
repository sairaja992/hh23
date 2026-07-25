# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-07-25 (automated scheduled scan)
**Scope:** All 14 tracked files (IaC, Dockerfiles, dependency manifests, Python/Flask code, CI workflow)

## Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High     | 6 |
| Medium   | 5 |
| Low      | 4 |

The highest-risk items are hardcoded AWS credentials in Terraform, an Elasticsearch domain policy that grants `es:*` to any AWS principal, and a Flask service running with the Werkzeug debugger enabled on all interfaces (remote code execution).

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
Credentials are committed directly in the provider block. **Triage note:** the access key is AWS's documentation example key and the secret is a near-copy of the docs example, so these are almost certainly placeholders — but the pattern is live in git history and will trip every secret scanner. If these were ever real, rotate immediately.
**Remediation:** Remove the keys; use environment variables, shared credential files, or (preferably) IAM roles/OIDC. Purge from git history if a real key was ever committed.

### C2. Elasticsearch domain open to any AWS principal — `echo-elasticsearch (1).yaml:272-280`
The domain access policy grants `Principal: AWS: "*"` with `Action: es:*` on the whole domain. Partial mitigation: the domain is VPC-attached, so exposure is limited to the VPC/security group — but any principal that can reach the endpoint gets full admin (delete indices, read all data).
**Remediation:** Scope the principal to specific IAM roles; restrict actions to the minimum needed (`es:ESHttpGet`, etc.). Also note allowed ES versions (6.0–7.4) are all end-of-life.

### C3. Flask debug mode bound to all interfaces — `tesr:21`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
`debug=True` enables the Werkzeug interactive debugger, which allows arbitrary code execution to anyone who reaches the port; binding to `0.0.0.0` exposes it beyond localhost. This is the file the `doc` Dockerfile appears to deploy (`ENTRYPOINT ["python3", "app.py"]`).
**Remediation:** `debug=False` (or drive via `FLASK_DEBUG` only in local dev), bind to localhost or rely on the container port mapping, and run behind a production WSGI server (gunicorn/uwsgi).

---

## High

### H1. Hardcoded token in application code — `tesr:14`
`token "sa74io0!"` is committed in source (the line is also a Python syntax error, as is the unterminated module docstring in `securityaudits3.py:2`). Rotate the token if it was ever real; load secrets from environment/secret manager.

### H2. AWS access-key-pattern strings in npm manifest — `package.json:10,28`
`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` sit inside `dependencies`/`devDependencies`. **Triage note:** both are shorter than a real AKIA key (20 chars), so they look like planted/test values — but they will trigger secret scanners, and the file is invalid JSON (missing comma after line 28), so the manifest is broken anyway.

### H3. Critically vulnerable JWT libraries — `package.json:9`, `package1.json:129,154`, `POM:129,154`
- `jsonwebtoken 0.4.0` and `^1.1.1` — vulnerable to algorithm-confusion / `alg:none` signature bypass (CVE-2015-9235 class): forged tokens verify successfully.
- `express-jwt 0.1.3` — same bypass class, plus years of unpatched issues.
**Remediation:** jsonwebtoken ≥ 9.0.0, express-jwt ≥ 8.x, and pin `algorithms` explicitly on verify. (Note: `package1.json`/`POM` are OWASP Juice Shop v14.1.1 manifests — intentionally vulnerable; if this repo is a scanner test-bed, mark them as such so they aren't mistaken for production.)

### H4. Multiple known-vulnerable npm dependencies — `package1.json` / `POM`
Highlights: `sanitize-html 1.4.2` (multiple XSS bypasses), `unzipper 0.9.15` (zip-slip path traversal), `request 2.88.2` (deprecated, SSRF issues), `express-jwt 0.1.3`, `node-pre-gyp 0.15.0`. Engines pinned to Node 14–18 (Node 14/16 are EOL).

### H5. End-of-life base images and EOL framework — `dockerarm:1,9`, `POM`/`pom (2).xml`/`pom254.xml`
- `node:14` and `node:14-alpine` — Node 14 is EOL (April 2023); no security patches.
- Spring Boot `2.2.4.RELEASE` (spring-core 5.2.x) — EOL since 2020; affected by later Spring CVEs including the Spring4Shell class (CVE-2022-22965) on JDK9+ deployments. `spring-boot-devtools` is also declared as a runtime dependency (remote-restart/devtools should never ship to prod).
**Remediation:** Move to a supported Node LTS (20/22) and Spring Boot 3.x; drop devtools from non-dev scopes.

### H6. Unpinned / deprecated GitHub Actions — `.github/workflows/devsec.yml:17,27,32`
`actions/checkout@v2` and `codeql-action/upload-sarif@v1` are deprecated (run on retired Node runtimes), and `microsoft/security-devops-action@preview` is a mutable tag — a supply-chain risk since the tag can be repointed. Pin actions to full commit SHAs and upgrade to `checkout@v4` / `upload-sarif@v3`.

---

## Medium

### M1. Java container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root inside the container. Add a non-root user (the `dockerarm` Juice Shop Dockerfile does this correctly with `USER 1001`).

### M2. Proxy settings baked into image layers — `doc:7-9`
`ENV http_proxy/https_proxy` from build args persist in the final image and leak internal proxy endpoints (and credentials if ever embedded in the URL). Use `--build-arg` with per-`RUN` scoping or BuildKit secrets. Also `FROM Doc` is not a valid base image reference, and `https_proxy` is set from `HTTP_PROXY_ARG` (copy-paste bug).

### M3. Elasticsearch risky advanced option and EOL versions — `echo-elasticsearch (1).yaml:15-27,307-308`
`rest.action.multi.allow_explicit_index: "true"` permits cross-index access in multi-document APIs, weakening index-level access control; all selectable ES versions are EOL.

### M4. Plaintext environment variables in ECS task definition — `ecs-task-definition-xray.yaml:165-167`
Generic `Environment` name/value parameters invite passing secrets as plaintext env vars (visible in console/DescribeTaskDefinition). Registry credentials are correctly in Secrets Manager; extend the same pattern using `Secrets`/`ValueFrom` for app secrets.

### M5. Error-handling and code defects in audit Lambda — `securityaudits3.py`
Unterminated module docstring (file cannot import), `Today_date` assigned but `today_date` used (NameError at runtime), bare `except:` clauses that swallow all errors including credential failures, and `raise e` before the alert-append (dead code). The audit job will fail silently or not run at all — an availability issue for a security control.

---

## Low

### L1. Internal infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
AWS account IDs (063586453409, 900182000710, 460510738068, 070133345649, 478226638351), subnet/SG IDs, role ARNs, and SNS topic ARNs are hardcoded. Not directly exploitable, but useful reconnaissance; parameterize where practical.

### L2. Invalid JSON manifest — `package.json:28`
Missing comma renders the file unparseable; any tooling consuming it fails.

### L3. Outdated Java image comment / JDK 9 suggestion — `Dockerfile (1):2`
Commented `openjdk:9-jdk-alpine` (long EOL) should not be suggested as an alternative.

### L4. Repo hygiene
Duplicate/oddly named files (`POM` vs `package1.json` identical, `pom (2).xml` vs `pom254.xml` near-identical, `Dockerfile (1)`) make it easy to patch one copy and miss the other.

---

## Escalation & recommended order of work

1. **Now:** Confirm the `secret.tf` keys and `tesr` token were never real; rotate if any doubt. Remove them and purge history.
2. **Now:** Disable Flask debug mode in `tesr` before any deployment of the `doc` image.
3. **This week:** Lock down the Elasticsearch access policy; upgrade JWT libraries if any of these manifests feed a real build.
4. **This sprint:** Base image / framework upgrades (Node 14 → 20+, Spring Boot 2.2 → 3.x), pin GitHub Actions, add non-root users to Dockerfiles.
5. **Housekeeping:** Fix broken JSON/Python files, de-duplicate manifests, and if the Juice Shop files are intentional scanner fixtures, label them in the README.
