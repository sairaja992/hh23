# Security Triage Report — 2026-08-08

Automated vulnerability identification and triage across all files in `sairaja992/hh23`
(branch `main` @ `be86016`). Findings are ordered by severity. Each finding lists the
affected file, the issue, why it matters, and the recommended remediation.

---

## Summary

| # | Severity | File | Finding |
|---|----------|------|---------|
| 1 | Critical | `secret.tf` | Hardcoded AWS access key + secret key in Terraform provider block |
| 2 | Critical | `package.json` | AWS access-key-style credentials embedded in dependency lists |
| 3 | Critical | `tesr` | Flask app runs with `debug=True` on `0.0.0.0` (Werkzeug debugger RCE) + hardcoded token |
| 4 | High | `echo-elasticsearch (1).yaml` | Elasticsearch domain access policy allows `Principal: "*"` with `es:*` |
| 5 | High | `package.json` | Severely outdated deps with known CVEs (`jsonwebtoken ^1.1.1`, `async ^0.8.0`, `restify ^2.8.1`) |
| 6 | High | `POM`, `dockerarm` | OWASP Juice Shop (intentionally vulnerable app) + EOL `node:14` base image |
| 7 | Medium | `.github/workflows/devsec.yml` | Unpinned mutable action tag (`@preview`) and deprecated action versions |
| 8 | Medium | `Dockerfile (1)` | Container runs as root; no `USER` directive |
| 9 | Medium | `pom (2).xml`, `pom254.xml` | EOL Spring Boot 2.2.4.RELEASE parent (multiple known CVEs in that line) |
| 10 | Low | `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py` | Internal AWS account IDs, subnet/SG IDs, role ARNs, internal hostnames disclosed |
| 11 | Low | `doc` | Unpinned `pip install`, invalid base image reference, no dependency hashes |
| 12 | Info | `securityaudits3.py` | Broken code (unclosed docstring, `Today_date`/`today_date` mismatch); bare `except`; error paths swallow failures |

---

## Detailed findings

### 1. Hardcoded AWS credentials in Terraform — `secret.tf` (Critical)

```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."
}
```

- The access key matches AWS's documentation example key, so this is likely planted/test
  data — but it sits in a file named `secret.tf` in a public-style repo and will trip every
  secret scanner. If any real key was ever committed in this pattern, it must be treated as
  compromised.
- **Triage:** Confirm the key pair is inert (it appears to be the AWS docs example).
  If there is any doubt: rotate immediately in IAM and audit CloudTrail for use.
- **Remediation:** Never put credentials in provider blocks. Use IAM roles, AWS SSO, or
  environment variables; add `git-secrets`/`trufflehog` pre-commit hooks; purge history
  with `git filter-repo` if a real key was exposed.

### 2. AWS access keys embedded in `package.json` (Critical)

Lines 10 and 28 embed AWS access-key-style strings as fake "dependencies":

```json
"accesskey": "AKIASGHPORST",
"access key": "AKIAXYGHKLYPQGRRS"
```

- Both are malformed (real `AKIA` key IDs are 20 characters), so these look like seeded
  test data for scanner validation — but they should be triaged the same way: verify
  they map to no live IAM user, then remove.
- The file is also invalid JSON (missing comma after line 28's entry), so `npm install`
  fails — the credentials are the only "functional" content the file leaks.
- **Remediation:** Remove both keys; fix or delete the file.

### 3. Flask debug server exposed on all interfaces — `tesr` (Critical)

```python
app.run(debug=True, host="0.0.0.0", port=8080)
```

- `debug=True` enables the Werkzeug interactive debugger. If the PIN is bypassed (a
  well-documented weakness) or disabled, this is **remote code execution** on any
  reachable interface, and `0.0.0.0` binds it to all of them.
- Line 14 also contains a hardcoded credential: `token "sa74io0!"` (syntactically invalid
  Python, but a secret in source regardless).
- **Remediation:** `debug=False` in anything deployable; bind to `127.0.0.1` unless
  fronted by a proper server (gunicorn/uwsgi behind a reverse proxy); move the token to a
  secrets manager and rotate it.

### 4. Wide-open Elasticsearch access policy — `echo-elasticsearch (1).yaml` (High)

```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: ["es:*"]
```

- Any AWS principal is granted full `es:*` on the domain. VPC placement
  (`VPCOptions`) limits network reachability, but the resource policy itself provides no
  authentication boundary — anyone with network access to the VPC endpoint has full
  admin (read, write, delete indices, change settings).
- Also: the allowed `ESVersion` values (6.0–7.4) are all long past end-of-life.
- **Remediation:** Scope `Principal` to specific IAM roles, enable fine-grained access
  control, require signed requests, and move to a supported OpenSearch version.

### 5. Known-vulnerable Node dependencies — `package.json` (High)

- `jsonwebtoken ^1.1.1` — pre-4.2.2 versions are vulnerable to algorithm-confusion
  signature bypass (CVE-2015-9235 class): an attacker can forge tokens by switching
  RS256→HS256 or `alg:none`.
- `async ^0.8.0` — years of unpatched prototype-pollution fixes missing.
- `restify ^2.8.1` — multiple known vulnerabilities in the 2.x line.
- **Remediation:** Upgrade all three to current major versions; add `npm audit` /
  Dependabot to CI.

### 6. OWASP Juice Shop + EOL base images — `POM`, `dockerarm` (High, likely intentional)

- `POM` is the package manifest of OWASP Juice Shop 14.1.1 — an *intentionally
  vulnerable* application (`jsonwebtoken 0.4.0`, `sanitize-html 1.4.2`, `express-jwt 0.1.3`,
  `unzipper 0.9.15`, etc.). `dockerarm` builds it on `node:14` / `node:14-alpine`, which are
  end-of-life (no security patches since April 2023).
- **Triage:** If this repo is a scanner test-bed (which its contents strongly suggest),
  this is expected content — but it must never be deployed to any shared or
  internet-reachable environment.
- **Remediation:** Isolate to lab environments only; if the image is actually built
  anywhere, move to a supported Node LTS base.

### 7. CI workflow supply-chain hygiene — `.github/workflows/devsec.yml` (Medium)

- `microsoft/security-devops-action@preview` — a mutable, floating tag. Whoever controls
  that tag controls code executing in your CI with repo access. Pin to a full commit SHA.
- `actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1`
  are deprecated; `upload-sarif@v1` has been shut off by GitHub, so the upload step
  fails — meaning findings never reach the Security tab (silent loss of security signal).
- **Remediation:** Bump to `checkout@v4`, `setup-dotnet@v4`, `codeql-action/upload-sarif@v3`,
  and pin third-party actions by SHA. Add `permissions:` block with least privilege
  (`security-events: write`, `contents: read`).

### 8. Container runs as root — `Dockerfile (1)` (Medium)

- No `USER` directive: the Spring Boot app runs as root inside the container, amplifying
  any app-level compromise. (Contrast with `dockerarm`, which correctly drops to UID 1001.)
- **Remediation:** Add a non-root user and `USER` directive before `ENTRYPOINT`.

### 9. EOL Spring Boot parent — `pom (2).xml`, `pom254.xml` (Medium)

- `spring-boot-starter-parent 2.2.4.RELEASE` (Jan 2020) is end-of-life and pulls
  dependency versions affected by many subsequent CVEs (including the Spring Framework
  RCE class fixed in 2022). `spring-boot-devtools` is also included as a non-test
  dependency — it must never ship in production images.
- **Remediation:** Move to a supported Spring Boot 3.x line; mark devtools
  `<scope>runtime</scope>` + `<optional>true</optional>` and exclude from packaging.

### 10. Internal infrastructure disclosure (Low)

Across `template.yaml`, `echo-elasticsearch (1).yaml`, `ecs-task-definition-xray.yaml`,
and `securityaudits3.py`: AWS account IDs (`063586453409`, `478226638351`, `900182000710`,
`460510738068`, `070133345649`), subnet and security-group IDs, IAM role ARNs, SNS topic
ARNs, S3 bucket names, and an internal git host (`git.fpd.cat.com`).

- None of these are credentials, but together they map internal environments and aid
  targeted attacks (e.g. confused-deputy attempts against named roles).
- **Remediation:** Parameterize account-specific values; keep real IDs out of public repos.

### 11. Unpinned Python dependencies — `doc` (Low)

- `RUN pip install -r requirements.txt` with no version pins/hashes referenced in the
  repo; `FROM Doc` is not a valid base image, so the file cannot build as-is.
- **Remediation:** Pin with `pip install --require-hashes`; use a real, digest-pinned base.

### 12. Code quality issues in the audit lambda — `securityaudits3.py` (Info)

- The module docstring opened on line 2 is never closed, and `Today_date` is defined but
  `today_date` is referenced — the script cannot run in its current form.
- `except:` without exception type (line 45) and a `raise` before the alert-append in
  `writedatatodynamodb` (dead code, lines 305-307) mean failures are partially swallowed
  or mis-reported.
- Not directly exploitable, but a broken security-audit pipeline is itself a security
  monitoring gap.

---

## Escalation guidance

1. **Immediate (today):** Verify findings 1–3 involve no live credentials (rotate if any
   doubt); confirm nothing in this repo is deployed anywhere reachable.
2. **This week:** Fix the CI workflow (finding 7) so security scanning results actually
   land in the Security tab again; that pipeline is the repo's own detection control and
   is currently failing silently.
3. **Backlog:** Dependency and base-image upgrades (findings 5, 6, 8, 9), IaC hardening
   (finding 4), and information-disclosure cleanup (finding 10).

*If this repository is intentionally a security-scanner test-bed, mark it clearly in the
README and keep it private, so seeded secrets and vulnerable manifests are never mistaken
for production configuration — and so real secrets are never added alongside fake ones.*
