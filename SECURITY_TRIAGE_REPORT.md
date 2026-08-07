# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-07 (automated scheduled triage)
**Scope:** All 15 tracked files at commit `be86016`

---

## Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 3 | Hardcoded credentials / secrets |
| High | 4 | Open resource policy, RCE-prone debug config, vulnerable dependencies |
| Medium | 5 | Container hardening, CI/CD supply chain, EOL software |
| Low / Informational | 4 | Infrastructure detail exposure, broken/non-functional files |

**Escalation required:** Yes — hardcoded AWS credentials and tokens are committed to the repository history and must be treated as compromised until rotated/confirmed inert.

---

## Critical Findings — Hardcoded Secrets

### C1. AWS access key pair in Terraform provider block
- **File:** `secret.tf:2-3`
- **Detail:** `access_key = "AKIAIOSFODNN7EXAMPLE"` and a `secret_key` are hardcoded in the `aws` provider. The access key ID matches AWS's documentation example key, but the secret key value does **not** match the documented example — treat it as a real secret until proven otherwise.
- **Risk:** Anyone with repo read access (and anyone who ever cloned it) obtains AWS API credentials. Secrets in git history persist even after file deletion.
- **Remediation:** Rotate/deactivate the key in IAM immediately; remove the file; purge history (`git filter-repo`/BFG); use environment variables, AWS SSO, or instance profiles for provider auth. Enable GitHub secret scanning + push protection.

### C2. AWS access key IDs embedded in `package.json`
- **File:** `package.json:10` (`"accesskey": "AKIASGHPORST"`) and `package.json:28` (`"access key": "AKIAXYGHKLYPQGRRS"`)
- **Detail:** AKIA-prefixed key IDs planted inside the dependencies/devDependencies maps. (The file is also invalid JSON — missing comma after line 28 — so `npm install` would fail.)
- **Risk:** Credential exposure pattern; key IDs alone aid enumeration and often accompany a leaked secret elsewhere.
- **Remediation:** Verify these IDs against IAM; deactivate if real; remove from the manifest and history.

### C3. Hardcoded token in Flask app
- **File:** `tesr:14` — `token "sa74io0!"`
- **Detail:** A plaintext token/password committed in source (line is also a syntax error, see L4).
- **Remediation:** Rotate wherever this token is valid; load secrets from a secret manager or environment at runtime.

---

## High Findings

### H1. Elasticsearch domain access policy allows `es:*` to any principal
- **File:** `echo-elasticsearch (1).yaml:272-280`
- **Detail:** `AccessPolicies` grants `Principal: AWS: "*"` the full `es:*` action set on the domain. VPC placement reduces exposure, but any principal that can reach the endpoint inside the VPC gets full admin (including delete) with no IAM identity check. `rest.action.multi.allow_explicit_index: "true"` further broadens multi-index request abuse.
- **Remediation:** Scope `Principal` to specific IAM roles; restrict actions to `es:ESHttp*` for data-plane clients; enable fine-grained access control.

### H2. Flask app runs with `debug=True` bound to `0.0.0.0`
- **File:** `tesr:21`
- **Detail:** The Werkzeug interactive debugger is exposed on all interfaces. The debugger console permits arbitrary Python execution (PIN is brute-forceable / bypassable in containers) — effectively remote code execution if the port is reachable.
- **Remediation:** `debug=False` in anything deployed; bind to localhost or gate behind a reverse proxy.

### H3. Critically vulnerable JavaScript dependencies pinned
- **Files:** `package.json`, `package1.json`, `POM` (the latter two are copies of OWASP Juice Shop 14.1.1's manifest — an intentionally vulnerable app)
- **Detail (highlights):**
  - `jsonwebtoken ^1.1.1` / `0.4.0` — pre-4.2.2 versions subject to algorithm-confusion signature verification bypass (CVE-2015-9235 class).
  - `express-jwt 0.1.3` — ancient, inherits JWT bypass issues.
  - `sanitize-html 1.4.2` — multiple XSS bypass CVEs fixed in later versions.
  - `unzipper 0.9.15` — zip-slip path traversal exposure.
  - `request ^2.88.2` — deprecated, unpatched.
  - `notevil`, `marsdb`, vintage `mocha`/`supertest` — known-vulnerable or unmaintained.
- **Note:** If the Juice Shop manifests are deliberately present as scanner test fixtures, mark them as such (e.g., a `fixtures/` directory and README note) so scanners and reviewers can suppress with justification. `package.json` ("wmic-service") appears to be a distinct app manifest and should be genuinely remediated.

### H4. ECS service references container with mutable `:latest` tag and shared task/execution role
- **File:** `template.yaml:17-20`
- **Detail:** `ContainerImage: ...q-gen-01:latest` (mutable tag → non-reproducible deploys, tag-poisoning risk) and the same IAM role is used for both `ExecutionRoleArn` and `TaskRoleArn`, over-privileging the task with pull/log permissions and vice versa.
- **Remediation:** Pin images by digest or immutable tag; use separate least-privilege task and execution roles.

---

## Medium Findings

### M1. Spring Boot container runs as root
- **File:** `Dockerfile (1)`
- **Detail:** No `USER` directive — the JVM runs as root. Also uses a full JDK base for a runtime image and pins Spring Boot parent `2.2.4.RELEASE` (`pom (2).xml`, `pom254.xml`), an EOL release line with many published CVEs in transitive dependencies (Tomcat, Jackson, Spring Framework — including the SpringShell-era fixes it predates).
- **Remediation:** Add a non-root `USER`; switch to a JRE/distroless base; move to a supported Spring Boot 3.x line.

### M2. EOL Node.js 14 base images
- **File:** `dockerarm` (`FROM node:14`, `node:14-alpine`)
- **Detail:** Node 14 is end-of-life (April 2023) — no security patches for runtime or base OS layers. `--unsafe-perm` install also runs lifecycle scripts as root in the build stage. (This is the Juice Shop image — intentionally insecure, but still flag if it's ever deployed.)

### M3. CI workflow uses deprecated/mutable actions and lacks a permissions block
- **File:** `.github/workflows/devsec.yml`
- **Detail:** `actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1` are deprecated majors (upload-sarif@v1 is shut off and will fail); `microsoft/security-devops-action@preview` is a mutable tag — a moving supply-chain reference. No top-level `permissions:` stanza, so the workflow token gets the repo default (potentially write-all).
- **Remediation:** Bump to current majors or pin by commit SHA; add `permissions: { contents: read, security-events: write }`.

### M4. Build-time proxy credentials baked into image environment
- **File:** `doc:7-9`
- **Detail:** `HTTP_PROXY_ARG` is persisted via `ENV http_proxy=...` into the final image. If the proxy URL carries credentials, they are readable from image metadata by anyone who can pull the image. Also `FROM Doc` is not a valid base image reference, and `https_proxy` is incorrectly set from `HTTP_PROXY_ARG`.
- **Remediation:** Use build-time-only args (or `--mount=type=secret`); don't persist proxies with `ENV`.

### M5. EOL Elasticsearch versions permitted
- **File:** `echo-elasticsearch (1).yaml:12-27`
- **Detail:** Allowed versions 6.0–7.4 are all end-of-life with known CVEs; no `NodeToNodeEncryptionOptions` or `DomainEndpointOptions` (enforce HTTPS/TLS policy) configured, so transport and node-to-node encryption are not guaranteed despite at-rest KMS encryption being enabled.

---

## Low / Informational

- **L1. Internal infrastructure identifiers committed:** AWS account IDs (`063586453409`, `478226638351`, `900182000710`, `460510738068`, `070133345649`), subnet IDs, security group IDs, role ARNs, SNS topic ARNs, internal bucket names across `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`. Useful reconnaissance material if the repo is or becomes public.
- **L2. `securityaudits3.py` does not parse:** the module docstring opened at line 2 is never closed before the imports, so the whole top of the file is swallowed by the string and the file is a `SyntaxError` at the next `"""`. Also `Today_date` vs `today_date` case mismatch (line 33-34), bare `except:` clauses swallowing errors, and `print(error)` referencing an undefined name in `publish_msg_security_team`.
- **L3. `tesr` does not parse** (`token "sa74io0!"` at line 14 is invalid syntax) — the RCE-prone debug config in H2 only matters if the stray line is removed and the app deployed.
- **L4. Invalid JSON in `package.json`** (missing comma, and `accesskey`/`access key` are not real dependency specifiers) — install would fail before any of its vulnerable pins even resolve.

---

## Recommended Actions (priority order)

1. **Now:** Rotate/deactivate all AWS keys and the `sa74io0!` token (C1–C3); confirm in IAM/CloudTrail whether the keys were ever active or used.
2. **Now:** Enable GitHub secret scanning + push protection on the repo; purge secrets from git history.
3. **This week:** Lock down the Elasticsearch access policy (H1), remove `debug=True` (H2), pin the ECS image and split IAM roles (H4).
4. **This week:** Fix the CI workflow's deprecated actions and add a least-privilege `permissions` block (M3) — as-is, the SARIF upload step will fail anyway.
5. **Backlog:** Container hardening (M1, M2, M4), Spring Boot / ES version upgrades (M1, M5), quarantine or clearly label the Juice Shop fixture files, and repair the broken files (L2–L4).

---

*This report was generated by an automated scheduled security triage run.*
