# Security Vulnerability Triage Report

**Repository:** `sairaja992/hh23`
**Scan date:** 2026-07-09
**Scope:** Static review of all tracked files (IaC, Dockerfiles, dependency manifests, application source).
**Method:** Manual secret & misconfiguration triage across the working tree.

> This repo's README states "Used for testing only." Several files are copied from OWASP Juice Shop
> and AWS documentation examples, so some secrets are known non-live placeholders. They are still
> triaged and reported because the *patterns* are exactly what must never reach a real repository.

---

## Severity summary

| Severity | Count | Category |
|----------|-------|----------|
| Critical | 3 | Hardcoded credentials / secrets committed to source |
| High     | 4 | Dangerous runtime config (debug RCE, root containers, outdated framework) |
| Medium   | 4 | Supply-chain / CI hygiene, information disclosure |
| Low      | 2 | Broken/dead code that masks security logic |

---

## CRITICAL findings — hardcoded secrets (escalate immediately)

### C1 — AWS credentials hardcoded in Terraform provider — `secret.tf:2-3`
```
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
Static AWS keys embedded directly in the `aws` provider block. This is the AWS docs example key
(non-live), but the pattern hardcodes long-lived IAM credentials into version control.
**Fix:** remove the block; source credentials from environment / IAM roles / a secrets backend.
If this pattern is ever used with a real key, rotate and purge from git history.

### C2 — AWS access key IDs embedded in npm manifest — `package.json:10,28`
```
"accesskey": "AKIASGHPORST",
...
"access key": "AKIAXYGHKLYPQGRRS"
```
AWS `AKIA…` access-key IDs planted inside the `dependencies`/`devDependencies` maps. These are not
valid package specs and would leak on any `npm publish` or repo clone. (They are malformed/short,
so likely test fixtures — but must be treated as leaked until proven otherwise.)
**Fix:** delete both keys; if the corresponding secret keys exist anywhere, rotate.

### C3 — Hardcoded auth token in Flask app — `tesr:14`
```
token "sa74io0!"
```
A bearer/secret token literal committed in source (also syntactically dead — see L1).
**Fix:** remove; load tokens from environment/secret store.

---

## HIGH findings — dangerous runtime configuration

### H1 — Flask debug server exposed on all interfaces — `tesr:21`
```
app.run(debug=True, host="0.0.0.0", port=8080)
```
`debug=True` enables the Werkzeug interactive debugger, which allows **remote code execution** via
the debugger console; binding to `0.0.0.0` exposes it on every interface. Never run this in
anything reachable.
**Fix:** `debug=False`, bind to `127.0.0.1` behind a real WSGI server (gunicorn/uwsgi).

### H2 — Container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot jar runs as UID 0. A container breakout or app RCE inherits root.
**Fix:** add a non-root `USER` (as `dockerarm` correctly does with `USER 1001`).

### H3 — End-of-life base image + install flags — `dockerarm:1,6`
`FROM node:14` (and `node:14-alpine`) is past end-of-life (no security patches); `npm install
--unsafe-perm` runs lifecycle scripts as root.
**Fix:** move to a supported LTS Node image; drop `--unsafe-perm` unless strictly required.

### H4 — Outdated Spring Boot with known CVEs — `pom (2).xml:17`, `pom254.xml`
`spring-boot-starter-parent 2.2.4.RELEASE` (2020) pulls transitive dependencies affected by multiple
CVEs (e.g. Spring4Shell-class, Tomcat, Jackson, Logback). `spring-boot-devtools` is also included,
which should never ship to production.
**Fix:** upgrade to a supported Spring Boot line; scope devtools out of production builds.

---

## MEDIUM findings — supply chain & information disclosure

- **M1 — CI actions pinned to mutable/old tags** (`.github/workflows/devsec.yml`):
  `actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1`,
  and `microsoft/security-devops-action@preview`. Mutable tags/`@preview` are a supply-chain risk.
  **Fix:** pin third-party actions to a full commit SHA; upgrade to current major versions.
- **M2 — HTTPS proxy set from HTTP arg** (`doc:11`): `ENV https_proxy=$HTTP_PROXY_ARG` uses the
  *HTTP* proxy value for HTTPS traffic — can silently downgrade/misroute TLS traffic. Also base
  image `FROM Doc` is invalid.
- **M3 — Cloud identifiers disclosed in IaC** (`template.yaml`, `ecs-task-definition-xray.yaml`,
  `echo-elasticsearch (1).yaml`): AWS account IDs, ECR image URIs, subnet IDs, security-group IDs,
  and IAM role ARNs are hardcoded. Not secrets on their own, but they aid targeting/recon.
  **Fix:** parameterize via variables/SSM; avoid committing environment-specific IDs.
- **M4 — OWASP Juice Shop manifest committed** (`POM`, `package1.json`): the full intentionally
  vulnerable Juice Shop `package.json` with many pinned old dependencies. Fine as a test fixture,
  dangerous if any build actually installs from it.

## LOW findings — broken code masking security logic

- **L1 — `tesr` is not valid Python**: line 14 `token "sa74io0!"` sits after a `return` (dead/invalid).
  The hardcoded secret is real (C3) even though the statement never executes.
- **L2 — `securityaudits3.py` module docstring never closes** (opens `"""` line 2, imports fall
  inside it): the file would `SyntaxError` on import, so the S3 audit Lambda cannot run. Also
  `except: print(error)` references an undefined name. This is a **security-monitoring outage** risk —
  the tool meant to detect misconfig is itself broken.

---

## Recommended actions (priority order)

1. **Rotate & purge** any credential in C1–C3 that maps to a live account; scrub git history.
2. Remove all hardcoded secrets; move to environment variables / a secrets manager.
3. Disable Flask debug (H1) and add non-root container users (H2).
4. Patch/upgrade Spring Boot (H4) and Node base images (H3).
5. Pin CI actions to SHAs (M1); parameterize IaC identifiers (M3).
6. Fix the broken audit script (L2) so security monitoring actually runs.
