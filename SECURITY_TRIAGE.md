# Security Vulnerability Triage Report

**Repository:** `sairaja992/hh23`
**Scan date:** 2026-07-08
**Scope:** All files on branch `claude/loving-wright-zt1jh0`
**Triage method:** Static review of source, IaC, container, and dependency manifests.

---

## Summary

| # | Finding | Severity | File | Status |
|---|---------|----------|------|--------|
| 1 | Hardcoded AWS credentials in Terraform provider | High | `secret.tf` | Open |
| 2 | Hardcoded AWS access keys in npm manifest | High | `package.json` | Open |
| 3 | Flask app served with `debug=True` (Werkzeug RCE) | Critical | `tesr` | Open |
| 4 | ElasticSearch domain access policy allows `Principal: *` with `es:*` | High | `echo-elasticsearch (1).yaml` | Open |
| 5 | Known-vulnerable/outdated dependencies (Juice Shop manifest) | High | `POM`, `package1.json` | Open |
| 6 | Outdated Spring Boot + `spring-boot-devtools` shipped | Medium | `pom (2).xml`, `pom254.xml` | Open |
| 7 | Container image runs as root (no `USER`) | Medium | `Dockerfile (1)` | Open |
| 8 | Hardcoded plaintext token in source | Medium | `tesr` | Open |
| 9 | Cloud resource identifiers committed (account IDs, subnets, SGs) | Low | `template.yaml`, `echo-elasticsearch (1).yaml` | Info |
| 10 | `rest.action.multi.allow_explicit_index: true` on ES domain | Low | `echo-elasticsearch (1).yaml` | Open |
| 11 | Proxy env var mis-assignment; broken docstring/undefined vars | Low | `doc`, `securityaudits3.py` | Open |

---

## Detailed Findings

### 1. Hardcoded AWS credentials — `secret.tf` — **High**
```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
}
```
Credentials are embedded directly in the Terraform provider block. The specific values are AWS's published *example* keys (not live), so there is no active exposure — but the **pattern is the vulnerability**: committing static IAM keys instead of using environment variables, an assumed role, or an instance/OIDC profile. If this file is ever copy-pasted with real keys, they leak into git history permanently.
- **Remediation:** Remove keys; use `AWS_PROFILE`/`AWS_ACCESS_KEY_ID` env vars, `assume_role`, or OIDC. Add `*.tf` secret scanning to CI. Never store live keys in VCS.

### 2. Hardcoded AWS access keys in npm manifest — `package.json` — **High**
```json
"dependencies": {
    "accesskey": "AKIASGHPORST",
    ...
    "access key": "AKIAXYGHKLYPQGRRS"
}
```
Two AWS-style access-key IDs are wedged into the dependency map. The values are malformed (too short to be live keys), but they are secret-shaped strings committed to source and will trip secret scanners. The file is also **invalid JSON** (missing comma after the `"access key"` line), so `npm install` would fail — a reliability issue on top of the secret smell. Also pins `jsonwebtoken@^1.1.1`, a very old release with known JWT verification weaknesses.
- **Remediation:** Delete the bogus `accesskey`/`access key` entries, fix the JSON, and upgrade `jsonwebtoken` to a current major (>=9).

### 3. Flask `debug=True` in production entrypoint — `tesr` — **Critical**
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
Running Flask with `debug=True` enables the Werkzeug interactive debugger. On an unhandled exception it exposes an in-browser Python console; combined with `host="0.0.0.0"` (bound to all interfaces) this is **remote code execution** for anyone who can reach the port. The debugger PIN offers only weak protection and has historically been bypassable.
- **Remediation:** Set `debug=False` for any non-local deployment, run behind a WSGI server (gunicorn/uwsgi), and do not bind `0.0.0.0` without an explicit reason and network controls.

### 4. ElasticSearch access policy allows anonymous principal — `echo-elasticsearch (1).yaml` — **High**
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: [ "es:*" ]
      Resource: "arn:aws:es:...:domain/${DomainName}/*"
```
The domain access policy grants **all ES actions to any AWS principal (`*`)**. The domain is placed in a VPC (which limits the blast radius to the VPC/peered networks), but a wildcard principal + `es:*` means anything with network reachability gets full read/write/admin on the cluster. Data-plane authZ should not rely on network position alone.
- **Remediation:** Scope `Principal` to specific role/account ARNs and `Action` to the minimum required. Enable fine-grained access control.

### 5. Known-vulnerable dependency set — `POM`, `package1.json` — **High**
Both files are the OWASP Juice Shop `package.json` (v14.1.1), which intentionally pins outdated, CVE-bearing packages, e.g.:
- `jsonwebtoken@0.4.0`, `express-jwt@0.1.3` — ancient JWT libs with auth-bypass classes of bugs.
- `sanitize-html@1.4.2` — XSS-bypass CVEs fixed in later versions.
- `request@2.88.2` — deprecated/unmaintained; SSRF & proxy issues.
- `marsdb`, `notevil` — sandbox-escape / prototype-pollution history.

If these manifests represent anything intended to run (not just a test fixture), they carry dozens of transitive CVEs.
- **Remediation:** Confirm whether this is a deliberate vulnerable fixture. If it must run, run `npm audit`, upgrade, and pin resolutions. If it is only a fixture, mark it clearly and exclude it from deploy paths.

### 6. Outdated Spring Boot + devtools — `pom (2).xml`, `pom254.xml` — **Medium**
Parent `spring-boot-starter-parent:2.2.4.RELEASE` (Feb 2020) pulls transitive Spring/Tomcat/Jackson versions with numerous published CVEs. Both POMs also include `spring-boot-devtools`. Devtools must never ship to production — its LiveReload/remote features and relaxed behavior expand attack surface.
- **Remediation:** Upgrade to a supported Spring Boot line; keep `devtools` as `optional`/`provided` and ensure it is stripped from production images.

### 7. Container runs as root — `Dockerfile (1)` — **Medium**
The Java image sets `WORKDIR`/`COPY`/`ENTRYPOINT` but never drops privileges with a `USER` directive, so the process runs as UID 0. (Contrast with `dockerarm`, which correctly creates and switches to `USER 1001`.) A container breakout or app RCE then executes as root.
- **Remediation:** Add a non-root user and `USER` directive, matching the `dockerarm` pattern.

### 8. Hardcoded token in source — `tesr` — **Medium**
```python
    token "sa74io0!"
```
A plaintext credential-looking literal is embedded in `elapsed()`. It is syntactically dead (unreachable after `return`), so it does not function as auth today, but it is a committed secret string and a bad pattern.
- **Remediation:** Remove it; load any real token from env/secret store.

### 9. Cloud identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml` — **Low / Info**
Hardcoded AWS account IDs (`063586453409`, `900182000710`, `460510738068`, `070133345649`, `478226638351`), subnet IDs, security-group IDs, and role ARNs are checked in. Not directly exploitable but useful reconnaissance for an attacker and hard to rotate.
- **Remediation:** Parameterize via SSM/CFN parameters or a private config source.

### 10. `rest.action.multi.allow_explicit_index: true` — `echo-elasticsearch (1).yaml` — **Low**
Allows clients to specify explicit indices in multi-search/bulk request bodies, weakening index-level access separation. Combined with finding #4 this compounds exposure.
- **Remediation:** Set to `false` unless a specific consumer requires it.

### 11. Non-security defects worth fixing — `doc`, `securityaudits3.py` — **Low**
- `doc` (Dockerfile): `ENV https_proxy=$HTTP_PROXY_ARG` assigns the **HTTP** proxy arg to `https_proxy` — likely a copy-paste bug that can route HTTPS traffic through the wrong proxy.
- `securityaudits3.py`: the module docstring opened on line 2 is never closed, so all `import` statements are swallowed into the string and the script cannot run; `except: print(error)` references an undefined `error`; `today_date` vs `Today_date` casing mismatch. These are correctness bugs, not vulns, but they mean the security-audit job itself is broken.

---

## Escalation

**Escalated now (owner should action promptly):**
- **#3 Flask `debug=True` on `0.0.0.0`** — treat as Critical; potential unauthenticated RCE if this entrypoint is ever exposed.
- **#1 / #2 hardcoded AWS keys** — rotate immediately *if any real key was ever committed here or derived from this pattern*; the committed values appear to be examples/placeholders, but verify and purge from history.
- **#4 wildcard ES access policy** — confirm the domain is not reachable beyond intended VPC consumers.

**Recommended process fixes:**
- Enable secret scanning (GitHub secret scanning / gitleaks) and dependency scanning (Dependabot / `npm audit` / `mvn dependency-check`) in CI. The existing `.github/workflows/devsec.yml` (Microsoft Security DevOps) only runs on `main` for push/PR — extend it to scan this branch and add secret + SCA analyzers.
- Add a `.gitignore`/pre-commit hook to block `*.tf` and manifest files containing key-shaped strings.

*Note: `README.md` states "Used for testing only." Several files (Juice Shop manifests, the Flask stubs) look like intentional vulnerable fixtures. Confirm intent before remediating vs. quarantining — but the hardcoded-secret and `debug=True` patterns should not live in any shared repo regardless.*
