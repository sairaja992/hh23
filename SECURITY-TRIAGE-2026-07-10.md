# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-07-10
**Scope:** Full repository (17 tracked files) — manifests, Dockerfiles, IaC templates, scripts, CI workflow.
**Context:** README states "Used for testing only". Several artifacts are copies of intentionally vulnerable projects (OWASP Juice Shop). Severity below reflects risk *if these artifacts are ever deployed or the patterns are copied into real projects*.

---

## Summary

| Severity | Count | Themes |
|----------|-------|--------|
| Critical | 3 | Hardcoded cloud credentials, remote-code-execution debug config |
| High | 4 | Known-vulnerable auth libraries, end-of-life runtimes |
| Medium | 4 | Container hardening gaps, internal infrastructure disclosure |
| Low | 3 | Deprecated CI actions, broken/unparseable files |

---

## Critical

### C1. Hardcoded AWS credentials in Terraform — `secret.tf:2-3`
```
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
**Triage:** The access key ID is AWS's canonical documentation example, and the secret key is a near-copy of the docs example, so these are almost certainly inert placeholders. However, the *pattern* (provider credentials inline in `.tf`) is critical if reused with real keys, and the strings will trip every secret scanner.
**Action:** Confirm the keys are inactive in the AWS console; delete the file or replace with an assumed-role / environment-variable provider block. If any real key was ever committed here, rotate it and purge git history (`git filter-repo`).

### C2. AWS access key IDs embedded in npm manifest — `package.json:10,28`
`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` sit inside `dependencies`/`devDependencies`.
**Triage:** Both are shorter than a valid 20-character AKIA key ID, so likely fabricated test values — but they follow the live-key prefix format and must be treated as potential leaks until verified. (The file is also invalid JSON — missing comma at line 28 — so npm cannot parse it.)
**Action:** Verify against IAM, remove the entries, and rotate if any match a real key.

### C3. Flask app runs with debug mode on all interfaces — `tesr:22` (plus hardcoded token at line 14)
`app.run(debug=True, host="0.0.0.0", port=8080)` exposes the Werkzeug interactive debugger to the network; anyone who triggers an exception (or guesses the debugger PIN) gets **arbitrary code execution** on the host. Line 14 also embeds a hardcoded token `"sa74io0!"` (and is a Python syntax error as written).
**Action:** Never ship `debug=True`; bind to localhost or run behind a WSGI server; move the token to a secret store and rotate it.

---

## High

### H1. Known-vulnerable JWT libraries — `package.json:9`, `POM:129,154`, `package1.json:129,154`
- `jsonwebtoken ^1.1.1` and `0.4.0` — vulnerable to algorithm-confusion / signature-verification bypass (CVE-2015-9235 class); attacker can forge tokens.
- `express-jwt 0.1.3` — authorization bypass (CVE-2020-15084 class).
**Triage:** `POM` and `package1.json` are verbatim copies of **OWASP Juice Shop 14.1.1** (deliberately vulnerable app) — expected for a test repo, but they will keep firing Dependabot/audit alerts and must never be deployed.
**Action:** If these manifests are only fixtures, move them under a clearly named `test-fixtures/` directory with a README; otherwise upgrade `jsonwebtoken` ≥ 9.x and `express-jwt` ≥ 6.x.

### H2. Additional vulnerable dependencies in Juice Shop manifests — `POM` / `package1.json`
`sanitize-html 1.4.2` (multiple XSS filter bypasses), `marsdb 0.6.11` (command injection advisory GHSA-5mrr-rgp6-x4gr), `node-pre-gyp 0.15` (deprecated). Same disposition as H1.

### H3. End-of-life Spring Boot parent — `pom (2).xml:17`, `pom254.xml:17`
`spring-boot-starter-parent 2.2.4.RELEASE` (Feb 2020) is years past end-of-support and pulls Spring Framework 5.2.x with numerous known CVEs. `spring-boot-devtools` is also declared, which must not reach production images.
**Action:** Upgrade to a supported Spring Boot 3.x line; mark devtools `runtime`-excluded for packaging.

### H4. End-of-life Node.js base image — `dockerarm:1,9`
`FROM node:14` / `node:14-alpine` — Node 14 reached end-of-life April 2023; the image accumulates unpatched OS and runtime CVEs. `npm install --unsafe-perm` (line 5) additionally runs lifecycle scripts as root during build.
**Action:** Rebase to `node:20-alpine` or newer; drop `--unsafe-perm`.

---

## Medium

### M1. Container runs as root — `Dockerfile (1)`
No `USER` directive; the Spring Boot app runs as root at runtime. Add a non-root user (compare `doc` and `dockerarm`, which do this correctly).

### M2. Internal AWS topology disclosed in IaC — `template.yaml`, `echo-elasticsearch (1).yaml`, `ecs-task-definition-xray.yaml`
Real-looking AWS account IDs (063586453409, 900182000710, 460510738068, 070133345649), IAM role ARNs, subnet IDs, and security-group IDs are committed to a public-facing repo. This is reconnaissance material for targeted attacks even without credentials.
**Action:** Parameterize account-specific values (SSM/Parameter Store, stack parameters) and scrub history if these map to live accounts.

### M3. Legacy Elasticsearch versions permitted — `echo-elasticsearch (1).yaml`
`ESVersion` allows 6.0–7.4 (all end-of-life), and the instance-type comment concedes t2 instances run **without encryption**. Restrict to supported OpenSearch versions and enforce `EncryptionAtRestOptions`.

### M4. Unpinned pip/apt installs in image build — `doc`
`pip install -r requirements.txt` with no version pinning/hashes and `apt-get install` without version pins makes builds non-reproducible and open to dependency-substitution drift. (Credit: this Dockerfile does drop privileges via `USER www-data`.) Note `FROM Doc` is not a valid base image, so this file cannot currently build.

---

## Low

### L1. Deprecated / unpinned GitHub Actions — `.github/workflows/devsec.yml`
`actions/checkout@v2` and `github/codeql-action/upload-sarif@v1` are deprecated (v1 SARIF upload has been shut off by GitHub, so the upload step fails), and `microsoft/security-devops-action@preview` is a mutable tag — a supply-chain risk. Pin actions to current majors or full commit SHAs.

### L2. Broken audit script — `securityaudits3.py`
The opening docstring is never closed, so the entire file is syntactically dead; it also references `today_date` before defining it (`Today_date` at line 34) and hardcodes bucket name `ue2`. If this Lambda is expected to feed the `security-audit-S3` DynamoDB table, **it is not running**, which is itself a monitoring gap.

### L3. Invalid manifest JSON — `package.json:28`
Missing comma renders the file unparseable, which masks the H1 dependency issues from `npm audit`/Dependabot.

---

## Escalation & recommended next steps (priority order)

1. **Verify and neutralize secrets (C1–C3):** confirm the AKIA keys and the `sa74io0!` token are not live; rotate anything real; purge from git history; enable GitHub secret-scanning push protection on the repo.
2. **Quarantine intentional fixtures:** move Juice Shop manifests (`POM`, `package1.json`, `dockerarm`) into a labeled fixtures directory so scanners can be scoped and no one deploys them.
3. **Fix the deployable patterns:** Flask debug flag, root containers, EOL bases (Node 14, Spring Boot 2.2, ES 6.x/7.4).
4. **Scrub infrastructure identifiers** from IaC templates if the accounts are live.
5. **Repair the CI security pipeline** (`devsec.yml`) — as written, the SARIF upload step fails, so no findings reach the GitHub Security tab.
