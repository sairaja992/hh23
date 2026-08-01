# Security Vulnerability Triage Report — `hh23`

**Scan date:** 2026-08-01 (automated scheduled review)
**Scope:** All 15 tracked files on branch `claude/loving-wright-3rxrgf` (head `be86016`)
**Method:** Full manual review of every file (source, IaC, Dockerfiles, dependency manifests, CI workflow)

---

## Summary

| Severity | Count | Themes |
|----------|-------|--------|
| Critical | 4 | Hardcoded cloud credentials, debug-mode RCE exposure |
| High     | 6 | Wildcard IAM access, known-vulnerable dependencies, EOL runtimes |
| Medium   | 5 | Container hardening, CI supply chain, broken/deprecated tooling |
| Low      | 3 | Internal infrastructure disclosure, broken files |

**Escalated (act immediately):** C-1 through C-4.

---

## Critical

### C-1. Hardcoded AWS credentials in Terraform — `secret.tf:2-3`
A Terraform AWS provider block embeds an access key ID and secret access key directly in source control.
The access key ID matches AWS's documentation example (`AKIAIOSFODNN7EXAMPLE`) and the secret is a near-copy of the docs example, so this is *probably* a placeholder — but it is a textbook secret-scanning hit and normalizes the pattern.
**Action:** Confirm the pair is inert; if there is any chance a real value was ever committed here, rotate immediately. Remove the block and use environment variables, shared credentials file, or (best) an assumed role / OIDC. Add pre-commit secret scanning (gitleaks/trufflehog) and enable GitHub secret scanning + push protection.

### C-2. AWS access key IDs committed in `package.json:10,28`
`"accesskey": "AKIASGHPORST"` (in `dependencies`) and `"access key": "AKIAXYGHKLYPQGRRS"` (in `devDependencies`). Both carry the AWS `AKIA` prefix. They are malformed lengths (real key IDs are 20 chars), so likely test data — but they sit where no credential should ever appear.
Also note: the file is **invalid JSON** (missing comma after line 28), so `npm install` fails outright.
**Action:** Delete both keys, verify nothing real was derived from them, fix the JSON.

### C-3. Hardcoded token in `tesr:14`
`token "sa74io0!"` — a hardcoded secret embedded in the Flask app (the line is also a Python syntax error, so the file cannot currently run).
**Action:** Remove; if this token is used anywhere real, rotate it.

### C-4. Flask debug mode bound to all interfaces — `tesr:21`
`app.run(debug=True, host="0.0.0.0", port=8080)`. Werkzeug's debug console allows **remote code execution** if the port is reachable; binding to `0.0.0.0` maximizes exposure (and the container in `doc` EXPOSEs 8080).
**Action:** `debug=False` (or drive from an env var defaulting to off), bind to localhost or run behind a proper WSGI server (gunicorn/uwsgi).

---

## High

### H-1. Elasticsearch domain access policy allows any principal — `echo-elasticsearch (1).yaml:272-280`
`Principal: AWS: "*"` with `Action: es:*` on the domain. VPC placement reduces reach, but any principal inside the VPC (or via a peering/VPN path) gets full admin on the domain — no IAM authentication boundary at all. `rest.action.multi.allow_explicit_index: "true"` (line 308) additionally permits cross-index access in multi-document APIs.
**Action:** Scope the principal to the specific task/service roles; set `rest.action.multi.allow_explicit_index` to `false` unless required.

### H-2. End-of-life Elasticsearch versions — `echo-elasticsearch (1).yaml:12-27`
Template defaults to ES 7.4 and allows 6.0–6.8 — all long past end of support, no security patches.
**Action:** Move to a supported OpenSearch version; prune the `AllowedValues` list.

### H-3. Known-vulnerable JWT stack — `package.json:9` and `package1.json`/`POM`
- `jsonwebtoken ^1.1.1` (wmic-service) and `0.4.0` (juice-shop): subject to algorithm-confusion / `alg:none` verification bypass (CVE-2015-9235 class) — forged tokens verify.
- `express-jwt 0.1.3`: same era, same bypass exposure.
**Action:** Upgrade to `jsonwebtoken >= 9.x` and current `express-jwt`; pin algorithms explicitly on verify.

### H-4. Intentionally vulnerable app manifest checked in — `package1.json` / `POM` (OWASP Juice Shop 14.1.1)
Duplicate copies of Juice Shop's manifest: `sanitize-html 1.4.2` (multiple XSS bypasses), `unzipper 0.9.15` (zip-slip, CVE-2018-1002203 class), deprecated `request`, `notevil` (sandbox escapes), `express-jwt 0.1.3`, etc. Fine **if** this repo is deliberately a vulnerable-app lab; a real deployment of these versions would be severely exposed.
**Triage:** Confirm intent. If this is lab material, label the files clearly (README) so scanners/auditors can suppress; if not, remove.

### H-5. EOL Node.js 14 base images — `dockerarm:1,9`
`node:14` / `node:14-alpine` reached end of life April 2023 — unpatched OpenSSL/V8 CVEs. `npm install --unsafe-perm` (line 5) also runs lifecycle scripts as root during build.
**Action:** Move to a current LTS (`node:20-alpine`+) and drop `--unsafe-perm`.

### H-6. Ancient HTTP stack in wmic-service — `package.json:8-11`
`async ^0.8.0` (2014), `restify ^2.8.1` (known ReDoS/DoS advisories in the 2.x–4.x line). Combined with H-3 this service's dependency tree is ~a decade unpatched.
**Action:** Full dependency refresh or retire the service.

---

## Medium

### M-1. Spring Boot container runs as root — `Dockerfile (1)`
No `USER` directive; the app runs as root in the container. Base image tag `jdk:17-ubuntu` is mutable/unpinned. Spring Boot parent `2.2.4.RELEASE` (`pom (2).xml`, `pom254.xml`) is EOL (pre-dates fixes such as Spring4Shell-adjacent hardening in supported lines).
**Action:** Add a non-root user, pin the base image by digest, upgrade Spring Boot to a supported 3.x line.

### M-2. Proxy credentials baked into image — `doc:3-9`
`HTTP_PROXY_ARG` build args are copied into persistent `ENV` vars; if the proxy URL carries credentials they ship in every image layer and are visible via `docker inspect`. Bug as well: `https_proxy` is set from `$HTTP_PROXY_ARG` (line 8). Base image `FROM Doc` is not a valid public reference. `pip install -r requirements.txt` is unhashed/unpinned.
**Action:** Use `--build-arg` only at build time (no ENV persistence) or BuildKit secrets; fix the https_proxy typo; pin requirements with hashes.

### M-3. CI workflow supply chain and deprecation — `.github/workflows/devsec.yml`
- `github/codeql-action/upload-sarif@v1` is **shut off** by GitHub — the upload step fails, so findings never reach the Security tab (silent loss of security signal).
- `microsoft/security-devops-action@preview` and `actions/checkout@v2` are mutable tags — no commit pinning, supply-chain risk; checkout@v2 is deprecated (Node 12).
**Action:** Bump to `codeql-action/upload-sarif@v3`, `actions/checkout@v4`, and pin third-party actions by full commit SHA. Add `permissions:` block (least privilege: `security-events: write`, `contents: read`).

### M-4. `securityaudits3.py` cannot run — file-wide
The opening docstring (line 2) is never closed, making the whole file a `SyntaxError`; additionally `Today_date` is defined but `today_date` is referenced (lines 33-34), and `f.close()` at line 167 references an out-of-scope handle. A security-audit lambda that cannot execute is a silent gap in monitoring coverage.
**Action:** Close the docstring, fix the variable case, verify the lambda actually deploys and runs.

### M-5. ECS task passes config via plaintext CFN parameters — `ecs-task-definition-xray.yaml:57-64,165-167`
`EnvironmentVariableValue1` is a plain String parameter injected into the container environment — if ever used for a secret it lands in CloudFormation console/API and task definition JSON in cleartext. (Repository credentials via Secrets Manager, line 158-159, are done correctly.)
**Action:** Use `Secrets` (valueFrom SSM/Secrets Manager) for anything sensitive; add `NoEcho: true` to the parameter as a minimum.

---

## Low

### L-1. Internal infrastructure disclosure
AWS account IDs (`478226638351`, `063586453409`, `900182000710`, `460510738068`, `070133345649`), subnet IDs, security-group IDs, role ARNs, SNS topic ARNs, internal hostname `git.fpd.cat.com`, and bucket names are spread across `securityaudits3.py`, `template.yaml`, `echo-elasticsearch (1).yaml`, `ecs-task-definition-xray.yaml`, `package.json`. Not directly exploitable, but useful recon for a targeted attacker and inappropriate in a public repo.
**Action:** Parameterize; keep environment maps in private config.

### L-2. KMS key policy breadth — `echo-elasticsearch (1).yaml:193-198`
Root-account `kms:*` is the AWS default pattern, but the management-role statement also grants `ScheduleKeyDeletion`/`Delete*` to a CI role — broader than a deploy pipeline needs.

### L-3. Repo hygiene
Duplicate manifests (`POM` ≡ `package1.json`, `pom (2).xml` ≈ `pom254.xml`), files with spaces/parentheses in names, `README.md` empty of context. Makes automated scanning and ownership triage harder.

---

## Recommended escalation order

1. **Today:** C-1/C-2/C-3 — sweep git history for real secrets (gitleaks over full history), rotate anything genuine, enable GitHub secret scanning + push protection.
2. **Today:** C-4 — kill `debug=True` anywhere this app is deployed.
3. **This week:** H-1 (ES access policy), M-3 (CI workflow is silently failing to upload results).
4. **This sprint:** dependency/base-image upgrades (H-3, H-5, H-6, M-1), lambda fix (M-4).
5. **Backlog:** parameterize internal identifiers (L-1), repo cleanup (L-3), confirm Juice Shop files are intentional lab material (H-4).
