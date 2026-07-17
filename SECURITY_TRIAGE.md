# Security Vulnerability Triage Report

**Repository:** `sairaja992/hh23`
**Scan date:** 2026-07-17
**Scope:** Full repository (IaC, Dockerfiles, app source, CI workflow, dependency manifests)
**Method:** Manual static review of every tracked file.

---

## Summary

| Severity | Count | Category |
|----------|-------|----------|
| Critical | 2 | Exposed credentials / RCE-prone runtime config |
| High     | 2 | Over-permissive cloud access policy, broken security-relevant files |
| Medium   | 3 | Vulnerable/outdated dependencies, deprecated CI actions, container hardening |
| Low/Info | 3 | Example keys, exposed infra identifiers, image hygiene |

The repository is a grab-bag of infrastructure and demo files (including a copy of OWASP
Juice Shop's manifest, which is *intentionally* vulnerable). Findings below separate the
**genuinely actionable** issues from the intentional/demo noise.

---

## CRITICAL

### C1 — Hardcoded secret pattern in Flask app + debug server exposed on all interfaces
**File:** `tesr` (lines 14, 21)

- Line 14: `token "sa74io0!"` — a hardcoded credential string embedded in the source. (It
  sits as dead code after a `return`, so it never executes, but it is committed in clear
  text and will trip secret scanners; treat the value as compromised.)
- Line 21: `app.run(debug=True, host="0.0.0.0", port=8080)` — Flask/Werkzeug **debug mode
  bound to all interfaces**. The Werkzeug interactive debugger allows **arbitrary code
  execution** on any unhandled exception for anyone who can reach the port. This is a
  textbook remote-code-execution exposure.

**Action:** Remove the hardcoded token; rotate it if ever real. Set `debug=False` (or gate
on an env var) and never bind the debugger to `0.0.0.0` in any shared/prod environment.

### C2 — AWS access-key IDs committed in source
**Files:** `secret.tf` (lines 2–3), `package.json` (lines 10, 28)

- `secret.tf`: `access_key`/`secret_key` hardcoded in the Terraform `aws` provider block.
  The values are AWS's *documented example* keys (`AKIAIOSFODNN7EXAMPLE` + the canonical
  example secret), so they are **not live credentials** — but hardcoding provider creds in
  IaC is the exact pattern that leaks real keys, and secret scanners will alert on it.
- `package.json`: `"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"`
  embedded as fake dependencies. These are malformed (too short to be valid AWS key IDs)
  and appear to be planted test data, but they mimic AWS key IDs and pollute the manifest.

**Action:** Remove all key material from `secret.tf` and `package.json`. Source AWS
credentials from environment/instance roles or a secrets manager, never from committed
files. If any of these were ever copied from a real key, rotate immediately.

---

## HIGH

### H1 — Elasticsearch access policy allows any AWS principal
**File:** `echo-elasticsearch (1).yaml` (lines 272–280)

```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal:
        AWS: "*"          # <-- any principal
      Action:
        - "es:*"          # <-- all ES actions
```

Wildcard principal combined with `es:*`. The domain is VPC-scoped (which limits blast
radius to the VPC), but this is still an over-permissive policy: anything that can reach
the domain in-VPC gets full admin over the cluster. `rest.action.multi.allow_explicit_index:
"true"` further widens what a request can target.

**Action:** Scope `Principal` to specific role ARNs and restrict `Action` to the minimum
required set.

### H2 — Security-relevant files are syntactically broken (won't run / breaks install)
**Files:** `package.json`, `securityaudits3.py`

- `package.json` is **invalid JSON** — missing comma at line 29 (after the injected
  `"access key"` entry). Any `npm install`/CI step reading it fails. Verified:
  `Expecting ',' delimiter: line 29 column 5`.
- `securityaudits3.py` has an **unterminated triple-quoted docstring** (opens line 2, never
  closed) — the entire file is swallowed into a string literal, `SyntaxError` on import.
  This is the AWS ScoutSuite/S3 findings-collection Lambda; in its current state it cannot
  run, so the security-audit pipeline it belongs to is silently dead.

**Action:** Fix the JSON delimiter (and remove the planted key entries), and close the
docstring in `securityaudits3.py` so the audit Lambda executes.

---

## MEDIUM

### M1 — Outdated / known-vulnerable dependency manifest
**Files:** `package1.json`, `POM` (both are OWASP Juice Shop v14.1.1's `package.json`)

These are a verbatim copy of OWASP Juice Shop — an **intentionally vulnerable** app.
Notable pinned-old libraries with known CVEs: `jsonwebtoken@0.4.0`, `express-jwt@0.1.3`,
`sanitize-html@1.4.2`, `request@2.88.2` (deprecated), `marsdb`, `vm2`-style eval helpers
(`notevil`). **Informational** if these files are only demo artifacts; **do not deploy**
this manifest to anything real. If the copy is unintentional, remove it.

### M2 — Deprecated / mutable GitHub Actions in CI
**File:** `.github/workflows/devsec.yml`

- `github/codeql-action/upload-sarif@v1` — **CodeQL Action v1 is retired**; SARIF upload
  will stop working.
- `actions/checkout@v2`, `actions/setup-dotnet@v1` — old major versions (node12-era).
- `microsoft/security-devops-action@preview` — pinned to a **mutable `@preview` tag**;
  supply-chain risk (the action can change under you). Pin to a commit SHA or release tag.

**Action:** Upgrade to `checkout@v4`, `setup-dotnet@v4`, `codeql-action/upload-sarif@v3`,
and pin the MSDO action to an immutable ref.

### M3 — Container images run without hardening
**Files:** `Dockerfile (1)`, `dockerarm`

- `Dockerfile (1)` defines **no `USER`** — the Spring Boot app runs as **root**. Also uses
  `mcr.microsoft.com/openjdk/jdk:17-ubuntu` (Microsoft has deprecated its OpenJDK images).
- `dockerarm`: `FROM Doc` is not a valid base image (build will fail), and
  `ENV https_proxy=$HTTP_PROXY_ARG` sets the **HTTPS** proxy from the **HTTP** proxy arg —
  a copy-paste bug that can route TLS traffic through the wrong proxy. (It does correctly
  drop to `USER www-data`.)

**Action:** Add a non-root `USER` to `Dockerfile (1)`; move to a maintained JDK base; fix
the `FROM` and the `https_proxy` assignment in `dockerarm`.

---

## LOW / INFORMATIONAL

- **L1 — Exposed infrastructure identifiers.** `template.yaml`, `echo-elasticsearch (1).yaml`,
  `ecs-task-definition-xray.yaml` and `securityaudits3.py` embed real-looking AWS account IDs
  (`063586453409`, `478226638351`, `900182000710`, …), subnet/SG IDs, ARNs and ECR image
  URIs. Not secrets, but they aid reconnaissance; prefer parameters/SSM over hardcoding.
- **L2 — Example AWS keys.** The `secret.tf` values are AWS's public documentation examples
  (not live) — flagged under C2 for the *pattern*, downgraded here for actual exploitability.
- **L3 — `securityaudits3.py` runtime bugs.** Beyond the syntax break: `except: print(error)`
  references an undefined `error`; `today_date`/`Today_date` casing mismatch would `NameError`.
  Reliability issues in the audit tooling itself.

---

## Escalation

**Escalate now (owner action required):**
1. **C1** — disable the Werkzeug debug server on `0.0.0.0` before any deployment; treat the
   embedded token as compromised and rotate.
2. **C2** — purge credential material from `secret.tf` and `package.json`; rotate anything
   that was ever real. Add secret-scanning (the repo already has an MSDO workflow — see M2)
   and a pre-commit secret hook.
3. **H1** — tighten the Elasticsearch access policy off `Principal: "*"` / `es:*`.

**Verify intent:** Confirm whether the Juice Shop manifests (`POM`, `package1.json`) and the
demo files are deliberate test fixtures. If so, isolate/label them so scanners and reviewers
don't treat them as production. If not, remove them.
