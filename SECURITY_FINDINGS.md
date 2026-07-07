# Security Vulnerability Report — hh23

**Scan date:** 2026-07-07
**Scope:** Full repository (all 16 tracked files) + full git history (8 commits)
**Method:** Manual code/IaC review, secret-pattern scan across all commits

---

## Summary

| # | Finding | File | Severity | Triage status |
|---|---------|------|----------|---------------|
| 1 | Hardcoded AWS credentials in Terraform provider | `secret.tf` | **Critical** | Escalate — verify & rotate |
| 2 | AWS access-key-style strings in npm manifest | `package.json` | **High** | Escalate — verify & rotate |
| 3 | Hardcoded token + Flask debug mode on 0.0.0.0 | `tesr` | **High** | Escalate if deployed |
| 4 | Elasticsearch domain policy allows `Principal: "*"` with `es:*` | `echo-elasticsearch (1).yaml` | **High** | Fix before next deploy |
| 5 | Known-vulnerable dependencies (jsonwebtoken 0.4.0 / ^1.1.1, sanitize-html 1.4.2, express-jwt 0.1.3, unzipper 0.9.15, async ^0.8.0) | `POM`, `package1.json`, `package.json` | **High** | Fix — upgrade or remove |
| 6 | Broken alerting path in security audit Lambda (exceptions swallowed, NameError in SNS publisher) | `securityaudits3.py` | **Medium** | Fix — audit pipeline is silently failing |
| 7 | Deprecated/unpinned GitHub Actions (`codeql-action/upload-sarif@v1`, `security-devops-action@preview`, `checkout@v2`) | `.github/workflows/devsec.yml` | **Medium** | Fix — DevSec pipeline likely non-functional |
| 8 | Container hardening gaps (root user, EOL base images, `--unsafe-perm`, proxy values baked into image ENV) | `Dockerfile (1)`, `dockerarm`, `doc` | **Medium** | Fix opportunistically |
| 9 | Internal infrastructure disclosure (account IDs, subnet/SG IDs, role ARNs, internal hostnames/emails) | multiple | **Low/Medium** | Accept or scrub depending on repo visibility |
| 10 | Mutable `:latest` image tag in ECS task definition | `template.yaml` | **Low** | Fix opportunistically |

Git history scan: no additional secrets found in prior commits beyond those still present in the working tree.

> **Repo context:** `README.md` says "Used for testing only" and several artifacts (OWASP Juice Shop manifest, AWS doc-example access key) indicate this repo is at least partly a scanner test fixture. That lowers real-world exploitability for some items, but every credential-shaped value must still be treated as live until verified — see triage notes per finding.

---

## Findings detail

### 1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3` — CRITICAL

```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
}
```

- **Triage:** The access key is AWS's official documentation example key, and the secret key is a near-copy of the doc example — very likely planted test data, **not live**. However, the pattern (static credentials in a provider block, committed to git) is critical if this file is ever copied with real values.
- **Action:** Confirm via IAM/secret scanning that no key with this prefix exists in your accounts. Delete the file or replace with an assume-role / environment-based provider config. Never pass `access_key`/`secret_key` literals in Terraform.

### 2. AWS access-key-style strings in npm manifest — `package.json:10,28` — HIGH

`"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` are embedded in `dependencies`/`devDependencies`.

- **Triage:** Both are shorter than a real 20-character AKIA key ID and no secret key accompanies them — likely synthetic test data for secret scanners. The file is also **invalid JSON** (missing comma after line 28), so it cannot be installed as-is.
- **Action:** Verify the strings against IAM, then remove them. Fix or delete the manifest. Note `jsonwebtoken ^1.1.1` here is vulnerable to algorithm-confusion/signature-bypass (CVE-2015-9235 class) and `async ^0.8.0` predates prototype-pollution fixes.

### 3. Hardcoded token + Flask debug on all interfaces — `tesr:14,21` — HIGH

- Line 14 embeds `token "sa74io0!"` (a credential-shaped literal; also makes the file syntactically invalid Python).
- Line 21: `app.run(debug=True, host="0.0.0.0", port=8080)` — the Werkzeug debug console gives **remote code execution** to anyone who can reach the port if this ever runs outside a sandbox. The `doc` Dockerfile appears to package a Flask app on port 8080, so this pattern could reach a container image.
- **Action:** Rotate/retire the token if it is real. Never ship `debug=True`; bind to localhost or gate behind an env var.

### 4. Elasticsearch domain open access policy — `echo-elasticsearch (1).yaml:272-280` — HIGH

The domain access policy grants `es:*` to `Principal: AWS: "*"`. Mitigating factor: the domain is VPC-attached (`VPCOptions`), so exposure is limited to the VPC/security group — this downgrades practical risk from critical, but any principal inside the network path gets full admin (including delete) on the domain with no IAM authentication.

- **Action:** Restrict the principal to the specific task/app roles, or add IAM condition keys. Also note `rest.action.multi.allow_explicit_index: "true"` weakens index-level isolation, and the allowed ES versions (6.x–7.4) are all past end-of-support.

### 5. Known-vulnerable dependency manifests — `POM` / `package1.json` / `package.json` — HIGH

`POM` and `package1.json` are identical copies of the **OWASP Juice Shop** manifest — an intentionally vulnerable application. Notable pinned-vulnerable packages: `jsonwebtoken 0.4.0` (signature bypass), `sanitize-html 1.4.2` (multiple XSS bypasses), `express-jwt 0.1.3`, `unzipper 0.9.15` (zip-slip), deprecated `request`.

- **Triage:** Expected if these files exist purely as scanner fixtures. Dangerous if any CI job or developer ever runs `npm install` against them, or if the repo is used as a template.
- **Action:** Confirm they are fixtures; if so, label them clearly (e.g., move to a `fixtures/` directory with a README) so they're never mistaken for real manifests.

### 6. Security-audit Lambda's alerting path is broken — `securityaudits3.py` — MEDIUM

This is the component that *reports* findings to the security team, and it cannot do its job:

- `publish_msg_security_team()` (line 206-212): the `except` block prints undefined variable `error` → a `NameError` masks any SNS publish failure, so **missed-report alerts silently disappear**.
- Line 33-34: `Today_date` is assigned but `today_date` is referenced → `NameError` at import time; the module-level docstring starting at line 2 is also never closed, so the file as committed cannot even parse.
- Bare `except:` at line 45 hides real SSM errors; `raise e` at line 305 makes the subsequent error-handling lines unreachable.
- Hardcoded account ID, bucket names, SNS topic ARNs.
- **Action:** If this Lambda is deployed anywhere from a working copy of this code, verify it is actually running and alerting — the failure mode here is silent. Fix the NameErrors and replace bare excepts with scoped handlers.

### 7. DevSec CI pipeline uses dead/unpinned actions — `.github/workflows/devsec.yml` — MEDIUM

- `github/codeql-action/upload-sarif@v1` was deprecated and turned off by GitHub (Jan 2023) — SARIF uploads to the Security tab will fail, meaning **scanner results are not reaching the Security tab**.
- `microsoft/security-devops-action@preview` and `actions/checkout@v2` are mutable/stale tags — supply-chain risk and deprecation warnings.
- **Action:** Bump to `codeql-action/upload-sarif@v3`, `checkout@v4`, and pin the MSDO action to a release tag or commit SHA.

### 8. Container hardening gaps — `Dockerfile (1)`, `dockerarm`, `doc` — MEDIUM

- `Dockerfile (1)`: no `USER` directive — Spring Boot app runs as root.
- `dockerarm`: `node:14` base is end-of-life (no security patches since 2023); `npm install --unsafe-perm` runs lifecycle scripts as root during build. (Runs as non-root at runtime — good.)
- `doc`: `FROM Doc` is not a resolvable base image (file is broken as committed); proxy URLs are baked into `ENV` so they persist in image layers; `apt-get` lists not cleaned. (Has `USER www-data` — good.)
- **Action:** Add non-root users, move to supported base images, use `--mount=type=secret`/build-args-only for proxies.

### 9. Internal infrastructure disclosure — multiple files — LOW/MEDIUM

AWS account IDs (`478226638351`, `063586453409`, `900182000710`, `460510738068`, `070133345649`), subnet/SG IDs, IAM role ARNs, SNS topic ARNs, internal git host (`git.fpd.cat.com`) and internal email conventions are committed in plain text. Not directly exploitable, but valuable reconnaissance if the repo is or becomes public.

- **Action:** Confirm repo visibility is private; parameterize identifiers where practical.

### 10. Mutable `:latest` image tag — `template.yaml:17` — LOW

`ContainerImage: ...q-gen-01:latest` — deploys are not reproducible and a poisoned/regressed image ships automatically.

- **Action:** Pin to an immutable tag or digest.

---

## Escalation

Items **1–3** are credential-class findings and follow the standard leaked-secret playbook even though triage suggests they are synthetic: (a) verify against IAM / secret stores, (b) rotate anything real, (c) purge from history if rotated. Item **6** deserves attention because it's the alerting pipeline itself failing silently, and item **7** means scanner results are currently not landing in the GitHub Security tab.
