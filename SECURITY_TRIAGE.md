# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Branch:** claude/loving-wright-hudhyx
**Date:** 2026-07-04
**Scope:** All files on the branch plus full git history scan for leaked secrets.

This repository is a collection of infrastructure, container, and dependency
manifest files used for security testing/demonstration. The triage below ranks
findings by severity, states the concrete impact, and gives a recommended
remediation and escalation path for each.

---

## Severity summary

| # | Severity | Finding | File |
|---|----------|---------|------|
| 1 | **Critical** | Hardcoded AWS access keys committed to source (and git history) | `package.json`, `secret.tf` |
| 2 | **High** | Hardcoded auth token in Flask app | `tesr` |
| 3 | **High** | Elasticsearch domain access policy allows `Principal: "*"` with `es:*` | `echo-elasticsearch (1).yaml` |
| 4 | **High** | Flask app runs with `debug=True` bound to `0.0.0.0` | `tesr` |
| 5 | **High** | Severely outdated / known-vulnerable JS dependencies | `POM`, `package1.json`, `package.json` |
| 6 | **Medium** | `package.json` is malformed JSON (parser/tooling risk) | `package.json` |
| 7 | **Medium** | Spring Boot 2.2.4 + `spring-boot-devtools` shipped to build | `pom (2).xml`, `pom254.xml` |
| 8 | **Medium** | Deprecated/pinned CI actions and preview action in workflow | `.github/workflows/devsec.yml` |
| 9 | **Low** | Broad KMS key-policy statements / no least-privilege | `echo-elasticsearch (1).yaml` |
| 10| **Low** | Unpinned `:latest` container image in ECS task | `template.yaml` |

---

## 1. Hardcoded AWS credentials in source and git history — CRITICAL

**Files:** `secret.tf`, `package.json`

```
secret.tf:   access_key = "AKIAIOSFODNN7EXAMPLE"
secret.tf:   secret_key = "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"
package.json: "accesskey": "AKIASGHPORST",
package.json: "access key": "AKIAXYGHKLYPQGRRS"
```

**Impact:** Static AWS credentials embedded in a Terraform provider block and in
a Node manifest. The `secret.tf` pair is AWS's well-known *documentation example*
key (`AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFE...`), so it is not a live secret — but
committing it trains a dangerous pattern and will trip secret scanners. The
`AKIASGHPORST` / `AKIAXYGHKLYPQGRRS` values in `package.json` are non-standard
lengths (real AKIA IDs are 20 chars) and are most likely placeholders, but they
must be treated as live until proven otherwise. **All four are present across the
entire git history** (commits `cc8b7f9`, `fdf7080`, `4f6a522`, `be86016`), so
deleting them from `HEAD` alone does not remediate.

**Remediation:**
- Remove all keys from source. Use a Terraform backend/provider that relies on
  environment credentials, an IAM role, or AWS SSO — never inline `access_key`/`secret_key`.
- If any key is real, **rotate/deactivate it immediately** in IAM before anything else.
- Purge from history (`git filter-repo` or BFG) and force-push, then invalidate
  any clones. Enable GitHub push protection / secret scanning to prevent recurrence.

**Escalation:** Treat as an active credential-exposure incident. Owner: repo owner +
cloud/security team. Verify in CloudTrail whether the `AKIASGHPORST`/`AKIAXYGHKLYPQGRRS`
IDs ever existed in the account; if so, rotate and review usage.

---

## 2. Hardcoded auth token in Flask app — HIGH

**File:** `tesr`

```python
    return "%d:%02d:%02d" % (hours, minutes, seconds)
    token "sa74io0!"
```

**Impact:** A literal secret `"sa74io0!"` is committed. (The line is also
syntactically invalid Python — `token "sa74io0!"` is not a statement — so it is
dead/broken code, but the string is still an exposed secret in history.) Any real
token committed this way is compromised.

**Remediation:** Remove the line; load secrets from environment variables or a
secrets manager. Rotate the token if it is real. Purge from history.

**Escalation:** Same incident channel as finding #1 if the token grants access to
any live system.

---

## 3. Elasticsearch access policy open to all principals — HIGH

**File:** `echo-elasticsearch (1).yaml` (`ElasticsearchDomain.AccessPolicies`)

```yaml
Principal:
  AWS: "*"
Action:
  - "es:*"
Resource: "arn:aws:es:...:domain/${DomainName}/*"
```

**Impact:** The domain access policy grants **every AWS principal** full
Elasticsearch actions on the domain. The domain is VPC-attached (which limits
reachability) and `rest.action.multi.allow_explicit_index: "true"` is enabled,
but the `Principal: "*"` + `es:*` combination is a textbook over-permissive
policy: any principal that can reach the endpoint gets full read/write/admin.

**Remediation:** Scope `Principal` to specific IAM roles/ARNs that need access and
reduce `es:*` to the minimum actions (e.g., `es:ESHttpGet`, `es:ESHttpPost`).
Consider fine-grained access control. Set
`rest.action.multi.allow_explicit_index` to `false` unless explicitly required.

**Escalation:** Cloud/platform team; block deployment of this template until the
policy is scoped.

---

## 4. Flask debug mode exposed on all interfaces — HIGH

**File:** `tesr`

```python
app.run(debug=True, host="0.0.0.0", port=8080)
```

**Impact:** `debug=True` enables the Werkzeug interactive debugger, which allows
**arbitrary code execution** via the debugger console on unhandled exceptions.
Bound to `0.0.0.0`, it listens on all interfaces. In any non-local deployment this
is remote code execution.

**Remediation:** Never run with `debug=True` outside local dev. Drive it from an
env flag defaulting to off, and serve behind a production WSGI server (gunicorn/uwsgi).

**Escalation:** App owner; if this file is ever deployed, treat as RCE risk.

---

## 5. Outdated / known-vulnerable JS dependencies — HIGH

**Files:** `POM` / `package1.json` (identical, OWASP Juice Shop manifest), `package.json`

**Impact:** These manifests pin numerous dependencies with known CVEs, e.g.:
- `jsonwebtoken` **0.4.0** (POM) and `^1.1.1` (package.json) — pre-CVE-2015-9235
  (signature/`alg:none` bypass) and later JWT verification flaws.
- `express-jwt` **0.1.3** — very old, known auth-bypass issues.
- `request ^2.88.2` — deprecated/unmaintained, SSRF-adjacent risks.
- `sanitize-html` **1.4.2** — multiple XSS-bypass CVEs fixed in later majors.
- `marsdb`, `notevil` — known to enable sandbox-escape/NoSQL-injection style
  issues (notevil is a deliberately-exploitable eval sandbox).
- `async ^0.8.0` (package.json) — years out of date.

Note the OWASP Juice Shop manifest is *intentionally vulnerable by design*; flag
it so it is not mistaken for a production dependency set.

**Remediation:** Run `npm audit` / Dependabot / Snyk against each manifest.
Upgrade `jsonwebtoken`, `express-jwt`, `sanitize-html`, and replace `request`
with a maintained client. Remove intentionally-insecure packages (`notevil`,
`marsdb`) from anything real.

**Escalation:** Dev team; enable Dependabot alerts on the repo.

---

## 6. `package.json` is malformed JSON — MEDIUM

**File:** `package.json`

```json
    "supertest": "^0.14.0",
     "access key": "AKIAXYGHKLYPQGRRS"     <-- missing trailing comma
    "mocha-jenkins-reporter": "^0.1.2"
```

**Impact:** The file is not valid JSON (missing comma; secrets stashed under bogus
`accesskey` / `access key` keys inside `dependencies`/`devDependencies`). Any tool
that parses it will fail, and the injected keys are both a secret leak (#1) and a
sign the file was hand-edited to smuggle credentials.

**Remediation:** Fix JSON validity and delete the credential keys entirely.

---

## 7. Spring Boot 2.2.4 + devtools in build — MEDIUM

**Files:** `pom (2).xml`, `pom254.xml` (near-identical, versions 1.0 / 2.0)

**Impact:** `spring-boot-starter-parent` **2.2.4.RELEASE** (Feb 2020) is far out of
support and pulls transitive dependencies with known CVEs (Spring, Tomcat,
Jackson, etc.). `spring-boot-devtools` is included; if it reaches a running
artifact it enables extra endpoints/auto-restart not meant for production.

**Remediation:** Upgrade to a current supported Spring Boot line. Keep devtools
`<scope>` appropriate and ensure it is excluded from production jars.

---

## 8. CI workflow uses deprecated/preview actions — MEDIUM

**File:** `.github/workflows/devsec.yml`

**Impact:**
- `actions/checkout@v2` and `actions/setup-dotnet@v1` are deprecated (Node 12
  runners, EOL).
- `github/codeql-action/upload-sarif@v1` is **retired** — v1 stopped working; SARIF
  uploads will fail, silently disabling the security-tab reporting this workflow exists for.
- `microsoft/security-devops-action@preview` pins an unstable `preview` ref rather
  than a released, immutable version.

**Remediation:** Bump to `actions/checkout@v4`, `setup-dotnet@v4`,
`codeql-action/upload-sarif@v3`, and pin the MSDO action to a released tag (ideally
a commit SHA). A retired upload action means this repo's own scanning is currently broken.

---

## 9. Broad KMS key-policy statements — LOW

**File:** `echo-elasticsearch (1).yaml` (`KMSKey.KeyPolicy`)

**Impact:** Management statement grants a wide `kms:*`-style set (Create/Delete/
Disable/ScheduleKeyDeletion, etc.) to `SystemAdmin` and the CFN role with
`Resource: "*"`. Encryption-at-rest and key rotation are correctly enabled (good),
but the admin surface is broad.

**Remediation:** Split duties — keep destructive actions
(`ScheduleKeyDeletion`, `DisableKey`) to a minimal break-glass role and scope the
day-to-day role to what it needs.

---

## 10. Unpinned `:latest` container image — LOW

**File:** `template.yaml`

```
ContainerImage: 063586453409.dkr.ecr.us-east-2.amazonaws.com/q-gen-01:latest
```

**Impact:** `:latest` gives non-reproducible deploys and no way to know what code
is actually running; a compromised/rebuilt tag is pulled without notice. The
template also hardcodes account ID, subnet IDs, and a security-group ID (info
disclosure, low risk on their own).

**Remediation:** Pin to an immutable image digest (`@sha256:...`) or a versioned
tag. Move environment-specific IDs to parameters.

---

## Recommended escalation order

1. **Immediately** — confirm whether any AWS key (#1) or token (#2) is live;
   rotate/deactivate before anything else. Owner: security/cloud incident channel.
2. **Same day** — remove all secrets from `HEAD`, purge git history, enable GitHub
   secret scanning + push protection.
3. **This sprint** — scope the Elasticsearch `Principal: "*"` policy (#3), disable
   Flask debug (#4), fix the retired CI upload action (#8) so scanning works again.
4. **Backlog** — dependency upgrades (#5, #7), JSON fix (#6), KMS least-privilege
   (#9), image pinning (#10).

*Note: `README.md` states this repo is "Used for testing only," and several files
(OWASP Juice Shop manifest, AWS example keys) appear to be deliberately insecure
samples. Findings are reported as-is; confirm intent before spending remediation
effort on the intentionally-vulnerable demo artifacts.*
