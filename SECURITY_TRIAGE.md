# Security Vulnerability Triage

_Automated triage of committed configuration, IaC, container, and application files._
_Date: 2026-07-30 · Branch: `claude/loving-wright-g9oge1`_

Severity scale: **Critical** (exploitable / secret exposure) → **High** → **Medium** → **Low / Informational**.

---

## Critical

### C1 — Hardcoded AWS credentials in Terraform (`secret.tf`)
```
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
Static AWS credentials committed in the provider block. These particular values are AWS's
well-known **documentation example** keys (not live), but committing credentials in a provider
block is a critical anti-pattern: the next edit puts a real key in git history.
**Fix:** remove the block; use environment variables, shared config profiles, or IAM roles.
Never store static keys in `.tf`.

### C2 — AWS access-key-shaped secrets in `package.json`
```
"accesskey": "AKIASGHPORST",
...
"access key": "AKIAXYGHKLYPQGRRS"
```
Two `AKIA…`-prefixed strings embedded in the dependency manifest of the `wmic-service` package.
They are not valid dependencies and read as leaked AWS Access Key IDs.
**Also breaks the build:** the `"access key"` line is missing a trailing comma, so this JSON is
invalid and `npm install` will fail.
**Fix:** delete both keys, rotate them if they were ever real, restore valid JSON.

### C3 — Flask running with the interactive debugger exposed (`tesr`)
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
`debug=True` enables the Werkzeug interactive debugger; bound to `0.0.0.0` it is reachable from
the network. Any unhandled exception exposes a Python console → **remote code execution**.
The file also contains a stray hardcoded secret literal `token "sa74io0!"` (dead code after a
`return`, but a committed secret nonetheless).
**Fix:** `debug=False` in any non-local deployment; bind to a specific interface; remove the token.

---

## High

### H1 — Elasticsearch domain open to any principal (`echo-elasticsearch (1).yaml`)
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: [ "es:*" ]
      Resource: arn:aws:es:...:domain/${DomainName}/*
```
`Principal: "*"` combined with `es:*` grants **every** Elasticsearch action to **anyone** whose
requests reach the endpoint. The domain is VPC-scoped (mitigating), but the wildcard policy is
still a serious misconfiguration; paired with `rest.action.multi.allow_explicit_index: "true"`,
a client can target arbitrary indices.
**Fix:** scope `Principal` to specific IAM roles/ARNs and `Action` to the minimum required.

### H2 — Unpinned / deprecated GitHub Actions (`.github/workflows/devsec.yml`)
- `microsoft/security-devops-action@preview` — pinned to a **mutable tag**; supply-chain risk
  (upstream can change what runs in CI). Pin to a commit SHA.
- `actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1` are
  **deprecated** (Node 12 / v1 runtimes). Upgrade to current major versions.

### H3 — End-of-life & intentionally-vulnerable app stack (`dockerarm`, `package.json`)
The `dockerarm` Dockerfile builds **OWASP Juice Shop** (`node:14`, itself EOL) — an intentionally
vulnerable application — and the accompanying `package.json` pins dozens of known-vulnerable
versions (e.g. `express-jwt@0.1.3`, `jsonwebtoken@0.4.0`, `sanitize-html@1.4.2`, `request@2.88.2`).
Fine as a security **training target**; must never be deployed as a real service.

---

## Medium

### M1 — Outdated Spring Boot + devtools shipped (`POM`/`package1.json` are copies of Juice Shop's package.json; `pom (2).xml`, `pom254.xml`)
The Maven POMs use `spring-boot-starter-parent` **2.2.4.RELEASE** (long EOL, numerous CVEs) and
include `spring-boot-devtools` without restricting it to a dev profile. If devtools reaches a
running instance it can expose remote restart/reload behavior.
**Fix:** upgrade Spring Boot to a supported line; keep devtools `runtime`/`optional` and out of
production images. Note `POM` and `package1.json` are byte-identical copies of the Juice Shop
`package.json` — misnamed files, worth removing to avoid confusion.

### M2 — Infrastructure identifiers hardcoded (`template.yaml`, `ecs-task-definition-xray.yaml`, `echo-elasticsearch (1).yaml`)
AWS account IDs (`063586453409`, `478226638351`, `900182000710`, `460510738068`, `070133345649`),
subnet IDs, security-group IDs, and role ARNs are committed in plaintext. Not secrets on their own,
but they aid reconnaissance and should live in parameters/SSM, not source.

---

## Low / Informational

### L1 — `securityaudits3.py` will not execute
- The module docstring opened on line 2 (`"""`) is **never closed**, so the entire file is one
  unterminated string literal → `SyntaxError`; the Lambda cannot run.
- Even if parsed: `Today_date` is defined (line 33) but `today_date` is used (lines 34, 37) →
  `NameError`; `print(error)` references an undefined `error` in an `except` block.
- Bare `except:` clauses swallow all errors.
The net effect is operational, not directly exploitable, but a **security-audit job that silently
fails to run** is a real blind spot.
**Fix:** close the docstring, correct the variable name, name caught exceptions.

### L2 — Base Dockerfiles pull mutable/old tags (`Dockerfile (1)`, `dockerarm`)
`FROM mcr.microsoft.com/openjdk/jdk:17-ubuntu` and `FROM node:14…` use floating tags. Pin to
digests for reproducible, auditable builds and to pick up patched bases.

---

## Recommended remediation order
1. **C1, C2, C3** — purge committed secrets, rotate anything that was ever real, scrub git history,
   and add a secrets scanner (gitleaks / GitHub secret scanning) as a pre-commit + CI gate.
2. **H1** — lock down the Elasticsearch access policy.
3. **H2** — pin CI actions to SHAs and upgrade deprecated ones.
4. **M1/M2, H3, L1, L2** — dependency upgrades, parameterize identifiers, fix the audit script.
