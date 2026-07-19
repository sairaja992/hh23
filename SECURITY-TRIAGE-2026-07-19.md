# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-07-19
**Scanned ref:** branch `claude/loving-wright-c9q7wy` (head `be86016`)
**Scope:** All 15 tracked files (Dockerfiles, CloudFormation/Terraform IaC, Maven POMs, package manifests, Python sources, GitHub Actions workflow)

---

## Executive summary

| Severity | Count | Themes |
|----------|-------|--------|
| Critical | 3 | Hardcoded cloud credentials, remote-code-execution-prone debug config |
| High     | 4 | Wildcard IAM access policy, EOL frameworks with known CVEs, vulnerable JWT library |
| Medium   | 5 | Supply-chain hygiene, container hardening, internal infrastructure disclosure |
| Low/Info | 4 | Duplicate/broken manifests, intentionally vulnerable test app content |

The most urgent items are the committed AWS credentials (`secret.tf`, `package.json`) and the hardcoded token in `tesr`. Even where values look like placeholders, committed-credential patterns must be verified, rotated if live, and purged from history.

---

## Critical

### C1. Hardcoded AWS access key pair in Terraform provider — `secret.tf:2-3`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
- The access key ID matches AWS's documentation example key, and the secret is a variant of the docs example — likely a deliberate test fixture. Treat as a finding regardless: this pattern trains contributors to commit real keys, and secret scanners will (correctly) flag it forever.
- **Action:** Confirm the pair is inert. Remove the file or replace with a provider block that uses an assumed role / environment credentials. If any real key was ever committed here, rotate it immediately and scrub git history (`git filter-repo`).

### C2. Hardcoded credential token in Flask app — `tesr:15`
```python
token "sa74io0!"
```
- A literal secret embedded in source (the line is also a Python syntax error, so the file cannot even run as committed).
- **Action:** Remove the token; source secrets from environment/secrets manager. Rotate if this value is used anywhere real.

### C3. Flask debug server bound to all interfaces — `tesr:22`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
- `debug=True` enables the Werkzeug interactive debugger, which provides **remote code execution** to anyone who can reach the port; binding to `0.0.0.0` exposes it on every interface. This is a well-known RCE foothold if the container/host is network-reachable.
- **Action:** `debug=False` in anything deployable; bind to localhost or serve behind a real WSGI server (gunicorn/uwsgi).

---

## High

### H1. AWS access key IDs embedded in npm manifest — `package.json:10,27`
```json
"accesskey": "AKIASGHPORST",
"access key": "AKIAXYGHKLYPQGRRS"
```
- Two AKIA-prefixed access key IDs committed as fake "dependencies". Key IDs alone don't grant access, but they identify IAM users for targeted attack and violate secret-handling policy. (Note: both entries also make the JSON invalid — missing comma after the devDependencies entry.)
- **Action:** Remove both entries; verify in IAM whether these key IDs exist and disable/rotate if so.

### H2. Elasticsearch domain access policy open to any AWS principal — `echo-elasticsearch (1).yaml` (AccessPolicies)
```yaml
Principal:
  AWS: "*"
Action:
  - "es:*"
```
- Grants **every AWS principal** full `es:*` on the domain. VPC placement reduces exposure, but any principal with network reach inside the VPC gets full admin (delete indices, read all data). Also: Elasticsearch 7.4 is long past end-of-support.
- **Action:** Scope Principal to the specific task/app roles; enforce fine-grained access control; upgrade to a supported OpenSearch version.

### H3. Critically outdated `jsonwebtoken ^1.1.1` — `package.json:9`
- jsonwebtoken < 4.2.2 is vulnerable to algorithm-confusion / signature-verification bypass (CVE-2015-9235 class): attackers can forge tokens (e.g., `alg: none` / RS256→HS256 confusion). Current is 9.x. Companion deps `async ^0.8.0` and `restify ^2.8.1` are also ~10 years old with known advisories.
- **Action:** Upgrade to jsonwebtoken ≥ 9.0.0 and refresh the dependency set.

### H4. End-of-life Spring Boot 2.2.4.RELEASE — `pom (2).xml`, `pom254.xml`
- Spring Boot 2.2.x (Spring Framework 5.2.x) is EOL and in the affected range for Spring4Shell (CVE-2022-22965) on JDK 9+ deployments, plus numerous later framework/Tomcat CVEs. `spring-boot-devtools` is also declared as a dependency, which must never reach production images.
- **Action:** Move to a supported Spring Boot 3.x line; mark devtools `runtime`-only/excluded from packaging.

---

## Medium

### M1. EOL Node.js 14 base images — `dockerarm:1,9`
- `node:14` / `node:14-alpine` are end-of-life (April 2023) and accumulate unpatched OS+runtime CVEs. Build also uses `npm install --unsafe-perm`, which runs lifecycle scripts as root during build.
- **Action:** Rebase to a maintained LTS image (node:20-alpine+); drop `--unsafe-perm`.

### M2. Container runs as root — `Dockerfile (1)`
- No `USER` directive; the Spring Boot app runs as root inside the container, amplifying any app-level compromise. (Contrast: `dockerarm` and `doc` both correctly drop privileges.)
- **Action:** Add a non-root user before `ENTRYPOINT`.

### M3. Unpinned / deprecated GitHub Actions — `.github/workflows/devsec.yml`
- `actions/checkout@v2`, `codeql-action/upload-sarif@v1` (both deprecated, run on retired Node runtimes) and `microsoft/security-devops-action@preview` — a mutable tag that a compromised upstream could repoint (supply-chain risk).
- **Action:** Upgrade to current majors and pin third-party actions to full commit SHAs.

### M4. Internal AWS infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
- Real-looking account IDs (`063586453409`, `478226638351`, `900182000710`, `460510738068`, `070133345649`), role ARNs, subnet IDs, security-group IDs, SNS topic ARNs, and internal bucket names are hardcoded. Not directly exploitable, but valuable reconnaissance and it couples templates to environments.
- **Action:** Parameterize via SSM/parameters; keep environment maps out of public/test repos.

### M5. Proxy settings baked into image env — `doc:6-8`
- `ENV http_proxy=...` persists build-time proxy endpoints (potentially internal hostnames/credentials if ever passed) into the final image metadata. Also note line 7 assigns `https_proxy` from `$HTTP_PROXY_ARG` (copy-paste bug).
- **Action:** Use build-time `ARG` only, or multi-stage builds so proxy config doesn't ship in the final image; fix the https_proxy assignment.

---

## Low / Informational

- **L1.** `POM` and `package1.json` are byte-identical copies of OWASP Juice Shop's `package.json` (an intentionally vulnerable app) — expected content for a security test repo; its dependency list will light up any SCA scanner by design.
- **L2.** `package.json` is syntactically invalid JSON (missing comma at `devDependencies`), so `npm install` fails — masks the vulnerable dependency issue from some scanners.
- **L3.** `securityaudits3.py` has a module-level docstring that is never closed properly around the imports and uses `Today_date` vs `today_date` (NameError at runtime); over-broad `except:` clauses swallow credential/permission errors.
- **L4.** `tesr` and `securityaudits3.py` will not run as committed (syntax errors) — if these are meant as live services/lambdas, they are silently broken.

---

## Escalation & remediation priority

1. **Now:** Verify/rotate anything matching C1, C2, H1 in IAM & secrets tooling; enable GitHub secret scanning + push protection on this repo.
2. **This week:** Fix C3 (debug server), H2 (ES access policy), pin workflow actions (M3).
3. **This sprint:** Dependency/base-image upgrades (H3, H4, M1), container hardening (M2), parameterize IaC identifiers (M4, M5).

*Generated by the scheduled vulnerability-triage routine.*
