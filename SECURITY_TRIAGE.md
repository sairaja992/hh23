# Security Vulnerability Triage Report

**Repository:** `sairaja992/hh23`
**Date:** 2026-07-02
**Scope:** Static review of all committed files (IaC, Dockerfiles, dependency manifests, application code, CI workflow)
**Note:** The repository README states "Used for testing only." Several artifacts are copies of the intentionally-vulnerable OWASP Juice Shop project. Findings are triaged as if this were production to give an accurate risk picture.

---

## Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 3 | Hardcoded credentials, Remote Code Execution |
| High | 4 | Vulnerable dependencies, over-permissive IAM/access policy |
| Medium | 5 | Outdated base images/frameworks, unpinned CI actions, container hardening |
| Low / Info | 3 | Code-quality bugs, mutable image tags, missing transport encryption |

---

## CRITICAL

### C1 — Hardcoded AWS credentials in Terraform (`secret.tf`)
```hcl
provider "aws" {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "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"
}
```
- **Issue:** Static AWS access/secret key embedded in a provider block (CWE-798). These specific values are AWS's *published documentation example* keys, so they are not live — but the pattern is a critical anti-pattern and would leak real keys if copied.
- **Triage:** Not currently exploitable (example keys), but must not ship. Treat any real analogue as an active credential-leak incident.
- **Fix:** Remove hardcoded keys. Use environment variables, AWS SSO/IAM roles, or a shared credentials profile. Add `*.tf` secret scanning to CI and rotate anything that was ever real.

### C2 — Hardcoded secrets embedded in `package.json`
```json
"accesskey": "AKIASGHPORST",        // dependencies
"access key": "AKIAXYGHKLYPQGRRS"   // devDependencies
```
- **Issue:** AWS-access-key-style secrets planted as fake dependency names (CWE-798). Both values are malformed/not live, but this is a secret-in-source finding. The file is **also invalid JSON** (missing comma after the `"access key"` line), so `npm install` would fail.
- **Fix:** Remove the credential entries, fix the JSON, run a secret scanner (gitleaks/trufflehog) over history, and rotate any real keys.

### C3 — Flask app with debugger enabled bound to all interfaces (`tesr`)
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
- **Issue:** `debug=True` enables the Werkzeug interactive debugger. Bound to `0.0.0.0`, any unhandled exception exposes an in-browser Python console → **unauthenticated Remote Code Execution** (CWE-489). The file also contains a hardcoded secret `token "sa74io0!"` (dead code after `return`, but a leaked secret).
- **Fix:** Never run with `debug=True` in a reachable environment. Bind to localhost for local dev, gate debug behind an env flag defaulting off, and remove the hardcoded token.

---

## HIGH

### H1 — OWASP Juice Shop dependency set (`package1.json`, `POM`)
Both files are Juice Shop 14.1.1 manifests pinning known-vulnerable versions, e.g.:
- `express-jwt@0.1.3` — authorization bypass, algorithm not enforced (CVE-2020-15084).
- `jsonwebtoken@0.4.0` — ancient JWT lib; signature/`alg=none` weaknesses.
- `sanitize-html@1.4.2` — multiple XSS-filter bypass CVEs.
- `marsdb@0.6.11` — NoSQL injection leading to RCE.
- `notevil` / `vm`-style sandbox — sandbox escape.
- `request@2.88.2` (deprecated, SSRF-prone), `unzipper@0.9.15` (path traversal / zip-slip).
- **Fix:** These are intentional in Juice Shop. If any of this dependency tree is reused elsewhere, upgrade to maintained versions and run `npm audit` / Dependabot.

### H2 — `package.json` uses obsolete auth/JWT libraries
`jsonwebtoken@^1.1.1` and `express-jwt@…` (via the Juice files) are years out of date and carry JWT verification CVEs. `async@^0.8.0` and `restify@^2.8.1` are also EOL.
- **Fix:** Upgrade `jsonwebtoken` to a current major, pin and audit the rest.

### H3 — Elasticsearch domain access policy allows wildcard principal (`echo-elasticsearch (1).yaml`)
```yaml
AccessPolicies:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: [ "es:*" ]
      Resource: "arn:aws:es:...:domain/${DomainName}/*"
```
- **Issue:** `Principal: "*"` with `es:*` grants every action to any principal (CWE-284). Risk is reduced because the domain is VPC-scoped (`VPCOptions`), but combined with `rest.action.multi.allow_explicit_index: true` an in-VPC caller has unrestricted read/write/admin.
- **Fix:** Scope the principal to specific IAM roles and the actions to least privilege. Consider fine-grained access control.

### H4 — Spring Boot 2.2.4.RELEASE with devtools shipped (`pom (2).xml`, `pom254.xml`)
- **Issue:** Spring Boot 2.2.4 (Feb 2020) predates the Spring4Shell fix (CVE-2022-22965 patched in 2.5.12 / 2.6.6) and many spring-web/tomcat CVEs. `spring-boot-devtools` is declared and can enable a remote restart/debug surface if it leaks into a runnable artifact.
- **Fix:** Upgrade Spring Boot to a supported 2.7.x/3.x line; ensure devtools is `optional` and excluded from production images.

---

## MEDIUM

### M1 — CI actions unpinned / deprecated (`.github/workflows/devsec.yml`)
`actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1` (deprecated Node 12), and `microsoft/security-devops-action@preview` (mutable `@preview` tag). Mutable tags allow a supply-chain swap.
- **Fix:** Pin actions to full commit SHAs; move off deprecated `@v1`/`@v2`.

### M2 — Java container runs as root (`Dockerfile (1)`)
No `USER` directive; the Spring Boot app runs as root inside the container.
- **Fix:** Add a non-root user and `USER` before `ENTRYPOINT`.

### M3 — `dockerarm` / `doc` image hygiene
`dockerarm` builds on EOL `node:14` and installs with `--unsafe-perm`. `doc` uses an invalid base (`FROM Doc`), bakes proxy env vars into the image, and copies `HTTP_PROXY_ARG` into `https_proxy` (typo). (`dockerarm` does correctly drop to `USER 1001`.)
- **Fix:** Use a supported Node LTS base, drop `--unsafe-perm`, fix the base image and proxy wiring; don't bake proxy creds into layers.

### M4 — Elasticsearch: no HTTPS enforcement / node-to-node encryption (`echo-elasticsearch (1).yaml`)
Encryption-at-rest and KMS are configured (good), but `DomainEndpointOptions.EnforceHTTPS` and `NodeToNodeEncryptionOptions` are absent — in-transit traffic is not required to be encrypted.
- **Fix:** Add `EnforceHTTPS: true` and enable node-to-node encryption.

### M5 — `securityaudits3.py` reliability/robustness bugs
Runtime bugs that break the audit job or hide failures: `today_date` referenced but only `Today_date` is defined (NameError); bare `except:` handlers that `print(error)` where `error` is undefined; the module docstring is unterminated so all `import`s are inside the string and never execute. A security-audit job that silently fails is itself a risk (missed findings).
- **Fix:** Correct the variable casing, terminate the docstring, and log real exception objects.

---

## LOW / INFORMATIONAL

- **L1 — Mutable image tag (`template.yaml`):** ECS task uses `q-gen-01:latest`. Pin to an immutable digest for reproducible, tamper-evident deploys.
- **L2 — Hardcoded infra identifiers:** Account IDs, subnet/SG IDs, and ARNs are committed across `template.yaml`, `ecs-task-definition-xray.yaml`, `echo-elasticsearch (1).yaml`, and `securityaudits3.py`. Not secret, but aids reconnaissance; prefer parameters/SSM.
- **L3 — Good patterns to keep:** `ecs-task-definition-xray.yaml` uses Secrets Manager for repo credentials and KMS-encrypted logs; the ES template uses a customer-managed KMS key with rotation. Preserve these.

---

## Recommended remediation order
1. **C1–C3** immediately — remove secrets from source, disable Flask debug/RCE, rotate any real keys and scan git history.
2. **H1–H4** — patch/upgrade vulnerable dependencies and frameworks; tighten the ES access policy.
3. **M1–M5** — pin CI actions, harden containers, enable ES transport encryption, fix the audit script.
4. **L1–L2** — pin image digests and externalize infra identifiers.
