# Security Triage Report — hh23

**Scan date:** 2026-08-10 (automated scheduled run)
**Scope:** All files on `main` / `claude/loving-wright-c975r6` (commit `be86016`), plus git history.

## Summary

| Severity | Count | Themes |
|----------|-------|--------|
| Critical | 3 | Hardcoded cloud credentials / tokens committed to the repo (and its history) |
| High | 4 | Wide-open Elasticsearch access policy, RCE-prone Flask debug config, EOL/vulnerable dependency baselines, unpinned CI supply chain |
| Medium | 4 | Cloud account/network metadata disclosure, runtime devtools, broken/buggy audit script, invalid manifests masking issues |

**Immediate actions needed:** rotate/revoke any real credentials matching the strings below, purge them from git history, and lock down the Elasticsearch access policy before any deployment of these templates.

---

## Critical

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
The AWS provider block embeds an `access_key`/`secret_key` pair directly in source. The access key ID matches the AWS documentation example key (`AKIAIOSFODNN7EXAMPLE`), and the secret is a near-copy of the docs example, so this is very likely a planted/test secret — but the pattern is critical and the file is named `secret.tf`, which will trip every scanner and normalizes committing real keys.
**Action:** Remove the block; use environment variables, an AWS profile, or an assumed role. If any real key ever used this pattern, rotate it. Purge from history (`git filter-repo`), since the file exists in prior commits.

### C2. AWS access key IDs embedded in `package.json:10,28`
`"accesskey": "AKIASGHPORST"` (in `dependencies`) and `"access key": "AKIAXYGHKLYPQGRRS"` (in `devDependencies`). `AKIA…` prefixes are AWS access key ID format (these are truncated at 12/17 chars, so likely seeded test data, but must be treated as leaked until confirmed). Bonus: the missing comma after line 28 makes the JSON invalid, so `npm install` fails — which may be hiding this file from dependency scanners.
**Action:** Delete both entries, validate the JSON, confirm in IAM that no matching keys exist; rotate if they do.

### C3. Hardcoded token in `tesr:14`
`token "sa74io0!"` sits inside the Flask app (it's also a Python syntax error — the file cannot actually run as committed). Credential material in source, in history since commit `498c511`.
**Action:** Remove; store tokens in a secret manager.

## High

### H1. Elasticsearch domain open to any AWS principal — `echo-elasticsearch (1).yaml` (AccessPolicies)
The `AWS::Elasticsearch::Domain` access policy grants `Principal: AWS: "*"` the full `es:*` action set on the domain. VPC placement reduces exposure, but any principal/workload that can reach the VPC endpoints gets full admin (including delete) on the domain. Template also targets EOL Elasticsearch versions (6.x/7.4).
**Action:** Scope the principal to specific IAM roles and restrict actions (e.g., `es:ESHttp*`); enforce node-to-node encryption + HTTPS; move to a supported OpenSearch version.

### H2. Flask debug server exposed — `tesr:21`
`app.run(debug=True, host="0.0.0.0", port=8080)` enables the Werkzeug interactive debugger on all interfaces — the debugger console gives remote code execution to anyone who reaches the port.
**Action:** `debug=False` (or env-driven), bind to localhost or run behind a real WSGI server.

### H3. EOL / known-vulnerable dependency baselines
- `package.json`: `jsonwebtoken ^1.1.1` (pre-4.2.2 — algorithm-confusion / `none` verification bypass, CVE-2015-9235 class), `restify ^2.8.1`, `async ^0.8.0` — all ancient.
- `POM` (Juice Shop `package.json`): `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `unzipper 0.9.15` — this is OWASP Juice Shop, intentionally vulnerable; keep it clearly quarantined/labelled so it's never deployed as a real service.
- `pom (2).xml` / `pom254.xml`: Spring Boot `2.2.4.RELEASE` (EOL since 2020, multiple CVEs in transitive Spring/Tomcat versions) and `spring-boot-devtools` as a runtime dependency.
- `dockerarm`: `node:14` base images (EOL April 2023, unpatched CVEs).
**Action:** Upgrade Spring Boot to a supported 3.x line, jsonwebtoken to ≥9.x, node base images to a current LTS; drop devtools from production builds.

### H4. CI workflow supply-chain hygiene — `.github/workflows/devsec.yml`
Actions are referenced by mutable tags, including `microsoft/security-devops-action@preview` (a floating pre-release tag) and deprecated `actions/checkout@v2` / `codeql-action/upload-sarif@v1` (v1 uploads no longer accepted by GitHub).
**Action:** Pin actions to commit SHAs, move to `checkout@v4` and `codeql-action@v3`.

## Medium

- **M1. Cloud environment metadata disclosure** — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py` expose AWS account IDs (`063586453409`, `478226638351`, `900182000710`, `460510738068`, `070133345649`), subnet/SG IDs, role ARNs, bucket names, and SNS topic ARNs. Not credentials, but useful recon material for targeting those accounts.
- **M2. `securityaudits3.py` is broken and unsafe as written** — the module docstring on line 2 is never closed (imports are swallowed), `Today_date` vs `today_date` NameError, `raise e` before the error-alert line makes the SNS alert unreachable, and bare `except:` clauses hide failures. As deployed, the audit Lambda this represents would silently not run — a monitoring gap, itself a security issue.
- **M3. `doc` Dockerfile issues** — `FROM Doc` is not a valid base image, proxy values baked into ENV (leak into image layers/history), unpinned `pip install`. Positive: it does drop to `USER www-data`.
- **M4. Duplicate/orphan manifests** — `package1.json`/`POM`, `pom (2).xml`/`pom254.xml`, `Dockerfile (1)` suggest copy-paste sprawl; scanners and humans can't tell which file is authoritative, so fixes land in the wrong copy.

## Notes

- The credential strings above appear in git **history** (commits `8b9f5c9`, `cc8b7f9`, `498c511`), not just the tip — removing them from the working tree is not sufficient; history rewrite + rotation is required for any real secret.
- `Dockerfile (1)` and `dockerarm` (Juice Shop) are otherwise reasonably built (multi-stage, non-root user in dockerarm).
