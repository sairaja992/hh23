# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-05 (automated scheduled review)
**Scope:** All 15 tracked files at commit `be86016`, full manual review (secrets, dependencies, IaC, Dockerfiles, CI workflow, application code)

---

## Summary

| Severity | Count | Highlights |
|----------|-------|-----------|
| Critical | 3 | Hardcoded AWS credentials, JWT auth-bypass dependency, Flask debug RCE exposure |
| High     | 3 | AKIA key IDs in package.json, anonymous `es:*` access policy, intentionally vulnerable Juice Shop artifacts |
| Medium   | 4 | EOL Spring Boot, root containers, broken/deprecated CI security workflow, proxy ENV leakage |
| Low/Info | 3 | Internal infrastructure identifiers, non-functional audit script, EOL Elasticsearch versions |

---

## Critical

### C1. Hardcoded AWS credentials committed — `secret.tf`
```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."
}
```
- **Triage:** The access key ID matches AWS's public documentation example (`AKIAIOSFODNN7EXAMPLE`) and the secret is a near-copy of the docs example, so these are almost certainly placeholder values rather than live credentials. However, the file establishes the anti-pattern and every secret scanner will (correctly) flag it.
- **Action:** Delete the file or replace with a provider block using environment variables / an AWS profile. If there is any chance a real key was ever committed in this file's history, rotate it and audit CloudTrail.

### C2. `jsonwebtoken ^1.1.1` — authentication bypass — `package.json`
- Versions before 4.2.2 accept forged tokens via the `alg=none` / key-confusion flaw (**CVE-2015-9235**). Any service verifying JWTs with this version can be trivially bypassed. The sibling deps are similarly ancient (`async ^0.8.0`, `restify ^2.8.1`, `mocha ^1.21.4`), each with multiple known CVEs (e.g. restify path traversal, ReDoS in old async/qs chains).
- **Action:** Upgrade `jsonwebtoken` to `^9.0.x` and refresh the remaining dependencies; run `npm audit` after the file is made parseable (see H1 — it is currently invalid JSON).

### C3. Flask app runs debugger exposed on all interfaces — `tesr`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
- `debug=True` enables the Werkzeug interactive debugger; anyone who reaches port 8080 and triggers an exception gets an in-browser Python shell → **remote code execution**. Binding `0.0.0.0` maximizes exposure. The file also contains a hardcoded credential fragment (`token "sa74io0!"`) — a secret in source, on a line that is also a syntax error.
- **Action:** Set `debug=False` (or gate on an env var), bind to localhost or rely on a fronting proxy, remove the hardcoded token.

## High

### H1. AWS access key IDs embedded in `package.json`
- `"accesskey": "AKIASGHPORST"` (dependencies) and `"access key": "AKIAXYGHKLYPQGRRS"` (devDependencies). Neither is a valid 20-character AKIA key ID, so likely test/seed data — but they trip secret scanners and don't belong in a manifest. The `"access key"` entry is also missing a trailing comma, making the whole file **invalid JSON** (npm install fails, and audit tooling silently skips it).
- **Action:** Remove both entries; fix the JSON.

### H2. Elasticsearch domain open to any AWS principal — `echo-elasticsearch (1).yaml:272-280`
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: ["es:*"]
```
- `Principal: "*"` with `es:*` grants every AWS principal full domain access. Partially mitigated by VPC-only deployment (subnet/SG restrictions apply), but any workload inside those subnets — or any future misconfiguration exposing the endpoint — gets unrestricted read/write/admin. Data classification tag is "Yellow" and the stack references prod account `070133345649`.
- **Action:** Scope the principal to the specific IAM roles that need access, or enable fine-grained access control.

### H3. OWASP Juice Shop artifacts — `dockerarm`, `package1.json`, `POM`
- These build/ship **Juice Shop 14.1.1**, an intentionally vulnerable application, on the EOL `node:14` base image. Fine for training/CTF use, dangerous if any pipeline deploys it to a reachable environment.
- **Action:** Confirm these are training material only; keep them out of any deploy pipeline (README says "Used for testing only" — recommend stating this per-file or isolating them in a `training/` directory).

## Medium

### M1. EOL Spring Boot parent + devtools in build — `pom (2).xml`, `pom254.xml`
- `spring-boot-starter-parent 2.2.4.RELEASE` (Spring Framework 5.2.3) is long past EOL and in the vulnerable range for multiple CVEs including CVE-2022-22965 (Spring4Shell — exploitability depends on deployment shape, and the paired Dockerfile uses JDK 17, which is a precondition). `spring-boot-devtools` is included as a dependency.
- **Action:** Move to a supported Spring Boot 3.x line; drop devtools from anything that ships.

### M2. Spring Boot container runs as root — `Dockerfile (1)`
- No `USER` directive; the app runs as root in the container. (Contrast: `dockerarm` correctly drops to UID 1001.)
- **Action:** Add a non-root user before `ENTRYPOINT`.

### M3. Security scanning workflow is broken and uses deprecated actions — `.github/workflows/devsec.yml`
- `github/codeql-action/upload-sarif@v1` was **turned off by GitHub in Jan 2024** — SARIF upload fails, so the MSDO findings never reach the Security tab: the repo's only automated security gate is silently dead. Also `actions/checkout@v2`, `setup-dotnet@v1` (deprecated Node 12/16 runtimes) and `microsoft/security-devops-action@preview` (mutable tag → supply-chain drift).
- **Action:** Bump to `codeql-action/upload-sarif@v3`, `checkout@v4`, `setup-dotnet@v4`, and pin MSDO to a released version.

### M4. Proxy settings baked into image as ENV — `doc`
- `ENV http_proxy/https_proxy` persist into the final image and every derived container, leaking internal proxy hostnames and potentially routing production traffic through a build proxy. Also `FROM Doc` is not a valid base image (file doesn't build), and `https_proxy` is set from `$HTTP_PROXY_ARG` (copy-paste bug).
- **Action:** Use build-time `--build-arg`/`ARG` only, or unset the ENVs in the final stage.

## Low / Informational

- **L1. Internal infrastructure identifiers committed:** AWS account IDs (`063586453409`, `478226638351`, `900182000710`, `460510738068`, `070133345649`), subnet/security-group IDs, IAM role ARNs, SNS topic ARNs, internal hostnames (`git.fpd.cat.com`, `azdo-q-gen-dev-*` S3 buckets) across `template.yaml`, `ecs-task-definition-xray.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`, `package.json`. Not secrets, but useful recon for targeting those accounts. Prefer parameterizing them in a public/personal repo.
- **L2. `securityaudits3.py` is non-functional:** the module docstring is never closed (the entire import block is inside the string), and `Today_date` vs `today_date` would be a NameError regardless. Also bare `except:` clauses swallow errors and `publish_msg_security_team` references an undefined `error` variable in its handler. If this is meant to be the S3-findings reporting Lambda, it cannot run as committed.
- **L3. EOL Elasticsearch versions:** the template only allows ES 6.0–7.4, all past end-of-support. `rest.action.multi.allow_explicit_index: "true"` combined with the broad access policy widens multi-index request abuse.

---

## Escalation & recommended order of work

1. **Now:** Remove `secret.tf` credentials pattern; strip AKIA strings from `package.json` (C1, H1). Enable GitHub secret scanning + push protection on the repo.
2. **Now:** Fix `tesr` debug/binding and remove the hardcoded token (C3).
3. **This week:** Upgrade `jsonwebtoken` and repair `package.json` (C2/H1); fix the dead CI security workflow (M3) so scanning actually reports again.
4. **This week:** Scope the Elasticsearch access policy (H2).
5. **Backlog:** Spring Boot upgrade, non-root containers, proxy ENV cleanup, parameterize account/network IDs, fix or retire `securityaudits3.py`.
