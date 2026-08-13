# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-13 (automated scheduled review)
**Scope:** All 15 tracked files (IaC templates, Dockerfiles, package manifests, Python source, CI workflow)

---

## Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 3 | Hardcoded credentials, debug-mode RCE exposure |
| High | 4 | Open resource policy, EOL/vulnerable dependencies |
| Medium | 4 | Container hardening, EOL base images, deprecated CI actions |
| Low / Informational | 3 | Infrastructure detail disclosure, code-quality defects |

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
The AWS provider block embeds an access key and secret key directly in source:
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
**Triage:** The access key is AWS's canonical documentation example key, and the secret key is a near-copy of the docs example, so these are almost certainly not live credentials. However, the pattern itself is the vulnerability: any real credentials placed here would be committed to git history permanently.
**Remediation:** Delete the static credentials; use an IAM role, AWS SSO, or environment-based credential chain. If any real credentials were ever committed in this file's history, rotate them immediately.

### C2. AWS access-key-shaped strings in `package.json:10,28`
`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` appear inside the dependencies/devDependencies maps.
**Triage:** Both strings are shorter than a real 20-character AKIA key, so they will not authenticate — but they trip secret scanners and indicate credentials were being stashed in a manifest. The file is also malformed JSON (missing comma after line 28), so `npm install` fails outright.
**Remediation:** Remove both entries; never store credentials in `package.json`. Fix the JSON syntax.

### C3. Flask debug mode on all interfaces + hardcoded token — `tesr:14,21`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
Running Flask with `debug=True` exposes the Werkzeug interactive debugger, which allows **remote code execution** on anyone who reaches the port; binding to `0.0.0.0` exposes it on every interface. Line 14 also embeds a hardcoded token (`"sa74io0!"`) — it is syntactically invalid Python where it sits, but it is a committed secret regardless.
**Remediation:** Set `debug=False` (or drive it from an environment variable), bind to localhost or rely on the container port mapping, and remove the token from source.

---

## High

### H1. Elasticsearch domain access policy open to any principal — `echo-elasticsearch (1).yaml:272-280`
The domain access policy grants `es:*` to `Principal: AWS: "*"` on the whole domain. Placement in a VPC with a security group limits network reachability, but any principal that can reach the endpoint gets full data-plane **and admin** access with no IAM authentication.
**Remediation:** Restrict the principal to the specific roles/accounts that need access, or enable fine-grained access control.

### H2. Known-vulnerable JWT/auth dependencies — `package.json:9`, `POM` / `package1.json:129,154`
- `jsonwebtoken ^1.1.1` and `0.4.0` — vulnerable to algorithm-confusion / signature-verification bypass (CVE-2015-9235 class): forged tokens can be accepted as valid.
- `express-jwt 0.1.3` — same era, inherits the bypass.
Note: `POM` and `package1.json` are identical copies of OWASP Juice Shop's manifest — an *intentionally* vulnerable application. If this is deliberate lab material, mark it as such; it should never be deployed to a reachable environment.

### H3. Multiple EOL / CVE-bearing dependencies in the Juice Shop manifests — `POM`, `package1.json`
Highlights: `sanitize-html 1.4.2` (multiple XSS bypasses), `unzipper 0.9.15` (zip-slip), `request 2.88.2` (deprecated; SSRF CVE-2023-28155), `node-fetch 2.6.1` (CVE-2022-0235), `express-jwt 0.1.3`, Node 14 engine (EOL). Same caveat as H2 regarding intentional lab content.

### H4. EOL Spring Boot parent — `pom (2).xml:15`, `pom254.xml:15`
Spring Boot `2.2.4.RELEASE` (Feb 2020) is long end-of-life and pulls Spring Framework 5.2.3, which is in the affected range for later critical advisories (including the CVE-2022-22965 "Spring4Shell" class when deployed as WAR on JDK9+). `spring-boot-devtools` is also declared as a runtime-adjacent dependency and must not ship in production images.
**Remediation:** Upgrade to a supported Spring Boot 3.x line; scope devtools out of production builds.

---

## Medium

### M1. Container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root inside the container. Add a non-root user (compare `dockerarm`, which does this correctly with `USER 1001`).

### M2. EOL base images — `dockerarm:1,9` (node:14, EOL since April 2023) and `Dockerfile (1)` comment suggesting `openjdk:9-jdk-alpine` (EOL). Unpatched base images accumulate OS-level CVEs.

### M3. Proxy settings baked into image env — `doc:7-9`
`ENV http_proxy/https_proxy` persist build-time proxy endpoints (potentially internal hostnames) into every layer and into the runtime environment of the shipped image. Use build-time-only args or `--mount=type=secret`. Also: `FROM Doc` is not a valid base image reference, and `https_proxy` is incorrectly set from `$HTTP_PROXY_ARG`.

### M4. Deprecated CI actions — `.github/workflows/devsec.yml:17,32`
`actions/checkout@v2` and `github/codeql-action/upload-sarif@v1` are deprecated; the v1 CodeQL action has been turned off by GitHub, so SARIF upload silently fails — meaning the security scanning this workflow exists for is likely **not reporting results at all**. Upgrade to `checkout@v4` and `codeql-action/upload-sarif@v3`.

---

## Low / Informational

### L1. Internal infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
AWS account IDs (063586453409, 478226638351, 900182000710, 460510738068, 070133345649), subnet IDs, security-group IDs, role ARNs, SNS topic ARNs, and internal bucket names are hardcoded. Not directly exploitable, but useful reconnaissance material; parameterize where practical.

### L2. `securityaudits3.py` is non-functional as committed
The module docstring starting at line 2 is never closed, so every import and the entire body is inside a string — the Lambda cannot run. Additional latent defects once fixed: `Today_date` vs `today_date` name mismatch (line 33/34), bare `except:` clauses swallowing errors, `print(error)` on an undefined name in `publish_msg_security_team` (line 212), and unreachable `alrt` update after `raise e` (line 305-306). If this powers the security-audit pipeline it is silently dead.

### L3. Elasticsearch `rest.action.multi.allow_explicit_index: "true"` — `echo-elasticsearch (1).yaml:308` combined with the open access policy (H1) broadens multi-index request abuse potential; also ES 7.4/6.x versions offered are all EOL.

---

## Recommended escalation order

1. **Rotate/remove all committed credentials** (C1, C2, `tesr` token) and scrub git history if any were real.
2. **Fix the dead security-scanning pipeline** (M4) and the dead audit Lambda (L2) — both are silent failures in the security monitoring itself.
3. Lock down the Elasticsearch access policy (H1).
4. Dependency and base-image upgrades (H2-H4, M1-M3).
5. If Juice Shop files are intentional lab material, isolate them in a clearly labeled directory so scanners and reviewers can triage them separately.
