# Security Findings — Triage Report

**Repository:** `sairaja992/hh23`
**Branch:** `claude/loving-wright-fpkahw`
**Scan date:** 2026-07-05
**Scope:** Static review of all committed files (IaC, Dockerfiles, CI workflow, app code, dependency manifests, secrets)

> This repository is labeled "Used for testing only" and contains material derived from
> intentionally vulnerable projects (e.g. OWASP Juice Shop). Findings below are triaged as if
> for a real environment so the exercise mirrors production incident handling.

## Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 3 | Hardcoded credentials / secrets |
| High     | 3 | Public IAM/service policy, debug RCE surface, outdated CI action (deprecated) |
| Medium   | 4 | Vulnerable dependencies, EOL runtimes, Dockerfile bugs, info disclosure |
| Low      | 2 | Invalid manifest, code-quality defects that break the script |

Escalation path: **Critical → notify security on-call immediately + rotate keys**. High → same-day ticket. Medium/Low → backlog with owner.

---

## CRITICAL

### C-1 — Hardcoded AWS credentials in Terraform
- **File:** `secret.tf:2-3`
- **Detail:** Provider block hardcodes `access_key` / `secret_key`. The values are AWS's published documentation example keys (`AKIAIOSFODNN7EXAMPLE`), so they are almost certainly *not* live — but committing credentials in this shape is the exact pattern that leaks real keys, and it trips every secret scanner.
- **Impact:** If ever swapped for real values, full account compromise. As-is: bad-practice / false-positive noise on scanners.
- **Remediation:** Remove keys from source. Use environment variables, AWS profiles, `assume_role`, or OIDC. Add `secret.tf` patterns to secret-scanning allow/deny and pre-commit hooks (`gitleaks`, `trufflehog`).

### C-2 — Hardcoded AWS access keys in `package.json`
- **File:** `package.json:10` (`"accesskey": "AKIASGHPORST"`) and `package.json:28` (`"access key": "AKIAXYGHKLYPQGRRS"`)
- **Detail:** AWS key IDs embedded inside an npm dependency manifest — a place credentials never belong. The values are malformed/truncated (not valid 20-char AKIA IDs), so they read as placeholders, but they will still flag on GitHub secret scanning.
- **Impact:** Credential-leak pattern; if real, account access.
- **Remediation:** Delete both entries. Never store secrets in `package.json`. Rotate if these ever mapped to real IAM users.

### C-3 — Hardcoded application token in Flask app
- **File:** `tesr:14`
- **Detail:** `token "sa74io0!"` — a bare secret literal embedded in `elapsed()`. (It is also a syntax error — an expression statement with no assignment — so this file does not run.)
- **Impact:** Secret disclosure; anyone with repo read access sees the token.
- **Remediation:** Remove the literal; load secrets from env/secret manager. Rotate the token.

---

## HIGH

### H-1 — Elasticsearch domain access policy allows any AWS principal
- **File:** `echo-elasticsearch (1).yaml:272-280`
- **Detail:** `AccessPolicies` grants `Effect: Allow`, `Principal: AWS: "*"`, `Action: es:*` on the domain. Although the domain is VPC-scoped (which limits network reach), a `"*"` principal with `es:*` is an overly-permissive resource policy — any principal that can reach the endpoint gets full Elasticsearch admin.
- **Impact:** Potential full read/write/delete of indexed data if network controls are ever loosened. Combined with `rest.action.multi.allow_explicit_index: "true"` (line 308), raises injection surface.
- **Remediation:** Scope `Principal` to specific role ARNs; restrict `Action` to least privilege; enable fine-grained access control.

### H-2 — Flask debug server exposed on all interfaces
- **File:** `tesr:21`
- **Detail:** `app.run(debug=True, host="0.0.0.0", port=8080)`. Werkzeug's debugger allows arbitrary code execution via the interactive traceback console; binding `0.0.0.0` exposes it on every interface.
- **Impact:** Remote code execution if reachable.
- **Remediation:** `debug=False` in any non-local context; put behind a WSGI server (gunicorn/uwsgi); never expose the debugger.

### H-3 — Deprecated / mutable GitHub Actions in security workflow
- **File:** `.github/workflows/devsec.yml:17,19,27,32`
- **Detail:** Uses `actions/checkout@v2`, `actions/setup-dotnet@v1`, and `github/codeql-action/upload-sarif@v1` — v1 of codeql-action is **deprecated and no longer runs**, so SARIF upload (the security-reporting step) silently breaks. `microsoft/security-devops-action@preview` is pinned to a mutable `preview` tag, a supply-chain risk.
- **Impact:** The DevSecOps pipeline that is supposed to *find* these issues is itself broken and unpinned.
- **Remediation:** Bump to `checkout@v4`, `setup-dotnet@v4`, `codeql-action/upload-sarif@v3`; pin the security-devops action to a released version or commit SHA.

---

## MEDIUM

### M-1 — Vulnerable / abandoned dependencies (Juice Shop manifest)
- **File:** `package.json` / `POM` (identical juice-shop manifests), `dependencies` block
- **Detail (highlights):**
  - `express-jwt@0.1.3` — CVE-2020-15084 authorization bypass.
  - `jsonwebtoken@0.4.0` — pre-CVE-2015-9235 / algorithm-confusion era; forge-able tokens.
  - `sanitize-html@1.4.2` — multiple XSS-filter-bypass CVEs.
  - `marsdb@0.6.11` — NoSQL/`vm` injection leading to RCE.
  - `request@2.88.2` — deprecated, SSRF-prone.
  - `notevil` / `vm2`-style sandboxes — known sandbox escapes.
- **Impact:** Auth bypass, XSS, RCE depending on reachable routes.
- **Remediation:** Run `npm audit` / Dependabot; upgrade or replace unmaintained packages. (Expected: this is the intentionally vulnerable Juice Shop set.)

### M-2 — Legacy dependencies in `package1.json` (wmic-service)
- **File:** `package1.json:8-11,26-29`
- **Detail:** `async@^0.8.0`, `jsonwebtoken@^1.1.1`, `restify@^2.8.1`, `mocha@^1.21.4` — all many major versions behind with known advisories.
- **Remediation:** Upgrade to current majors; re-run `npm audit`.

### M-3 — EOL runtimes & Dockerfile defects
- **Files:** `Dockerfile (1)`, `dockerarm`
- **Detail:**
  - Juice Shop Dockerfile (in git history) and toolchain target Node 14 (EOL).
  - `dockerarm:1` — `FROM Doc` is not a valid/base image reference (build will fail or pull an unexpected image).
  - `dockerarm:8` — `ENV https_proxy=$HTTP_PROXY_ARG` assigns the **HTTP** proxy arg to the **HTTPS** proxy var (copy-paste bug; can route TLS traffic wrong).
- **Remediation:** Pin a supported base image by digest; fix the `FROM` reference; set `https_proxy=$HTTPS_PROXY_ARG`.

### M-4 — Sensitive infrastructure identifiers committed
- **Files:** `template.yaml:17-32`, `ecs-task-definition-xray.yaml`, `echo-elasticsearch (1).yaml:157-177`, `securityaudits3.py` (account IDs / ARNs, e.g. `478226638351`, `063586453409`)
- **Detail:** Hardcoded AWS account IDs, subnet IDs, security-group IDs, ECR image URIs, and role ARNs. Not secrets, but useful reconnaissance for an attacker and coupling that should live in parameters/SSM.
- **Remediation:** Parameterize environment-specific values; source from SSM/Parameter Store or stack parameters.

---

## LOW

### L-1 — `package1.json` is invalid JSON
- **File:** `package1.json:28`
- **Detail:** Missing comma after `"access key": "AKIAXYGHKLYPQGRRS"` — the manifest will not parse, breaking any tooling that reads it (including `npm audit`).
- **Remediation:** Fix JSON (and, per C-2, remove the key entirely).

### L-2 — `securityaudits3.py` does not run (unterminated docstring + undefined names)
- **File:** `securityaudits3.py:2-34`
- **Detail:** The module docstring opened at line 2 is never closed, so the `import` block (lines 12-22) is swallowed into the string and the file fails to execute. Also references `today_date` (defined as `Today_date`, line 33) and `print(error)` on an undefined `error` in `publish_msg_security_team`.
- **Impact:** The S3-findings reporting Lambda is non-functional as written — the security *reporting* automation itself is broken.
- **Remediation:** Close the docstring before the imports; fix `Today_date`/`today_date` casing; reference the caught exception variable.

---

## Recommended immediate actions (escalation)

1. **Rotate & remove** every hardcoded credential (C-1, C-2, C-3) — treat as compromised even if they look like placeholders.
2. **Enable GitHub secret scanning + push protection** and a pre-commit secret scanner so credentials cannot be committed again.
3. **Fix the CI pipeline** (H-3) so security scanning/SARIF upload actually runs — right now the guardrail is broken.
4. **Tighten the Elasticsearch access policy** (H-1) and disable the Flask debug surface (H-2).
5. Triage dependency CVEs (M-1/M-2) via Dependabot; fix the broken manifest and script (L-1/L-2).
