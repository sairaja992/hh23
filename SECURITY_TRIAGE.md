# Security Vulnerability Triage — sairaja992/hh23

**Scan date:** 2026-08-16 (automated scheduled scan)
**Scope:** All files at HEAD (`be86016`) of `main`
**Context note:** The README states this repository is "Used for testing only" and several artifacts (OWASP Juice Shop package/Dockerfile) are intentionally vulnerable test content. Severity below is assessed as if these files were used in a real deployment; items confirmed as planted/example values are marked accordingly.

---

## Critical

### C1. Hardcoded AWS credentials in `secret.tf`
`secret.tf:2-3` embeds an AWS `access_key` and `secret_key` directly in the Terraform provider block.

- The access key `AKIAIOSFODNN7EXAMPLE` is AWS's published documentation example key, and the secret key is a variant of the documentation example — so these specific values are almost certainly not live credentials.
- **Risk if pattern is copied:** committing real provider credentials grants full account access to anyone with repo read access, and git history retains them after removal.
- **Remediation:** never put credentials in provider blocks. Use environment variables, shared credentials files, or (preferred) IAM roles / OIDC. Delete the file; if a real key was ever committed here, rotate it and audit CloudTrail.

### C2. Flask app runs with `debug=True` bound to all interfaces (`tesr`)
`tesr:21` — `app.run(debug=True, host="0.0.0.0", port=8080)`.

- The Werkzeug interactive debugger gives **remote code execution** to anyone who can reach the port and trigger an exception (the debugger PIN is routinely bypassable/brute-forceable).
- Also exposes `sys.version` in the response (information disclosure) and contains a hardcoded token string `"sa74io0!"` at `tesr:14` (which is also a Python syntax error — the file does not run as-is).
- **Remediation:** `debug=False` (or drive via `FLASK_DEBUG` only in local dev), bind to localhost or put behind a proper WSGI server, remove the hardcoded token.

## High

### H1. Hardcoded access-key-like strings in `package.json`
`package.json:11` — `"accesskey": "AKIASGHPORST"` and `package.json:28` — `"access key": "AKIAXYGHKLYPQGRRS"` planted inside `dependencies`/`devDependencies`.

- Both use the AWS `AKIA` prefix but are 12/17 characters (real AWS access key IDs are 20), so they appear to be planted test values, not valid keys. They will still trip secret scanners, and the pattern normalizes secrets-in-manifest.
- The file is also **invalid JSON** (missing comma after the `supertest` entry), so `npm install` fails.

### H2. Severely outdated dependencies with known CVEs (`package.json`)
- `jsonwebtoken ^1.1.1` — pre-4.2.2 versions accept forged tokens via the `alg=none` / algorithm-confusion signature-verification bypass (CVE-2015-9235 class). Current is 9.x.
- `async ^0.8.0` — prototype-pollution fix landed in 2.6.4/3.2.2 (CVE-2021-43138).
- `restify ^2.8.1` — years EOL with multiple known advisories.
- **Remediation:** upgrade all to current majors; run `npm audit` in CI.

### H3. End-of-life Spring Boot parent (`pom (2).xml`, `pom254.xml`, both 2.2.4.RELEASE)
- Spring Boot 2.2.x is EOL (Oct 2020). With `spring-boot-starter-web` on JDK 9+ — and `Dockerfile (1)` runs this exact jar on **JDK 17** — the stack is in the vulnerable configuration for **Spring4Shell (CVE-2022-22965, RCE)**, plus numerous other framework CVEs fixed in later trains.
- `spring-boot-devtools` is declared as a runtime (non-test) dependency; if packaged/enabled in a deployed image it widens the attack surface.
- **Remediation:** move to a supported Spring Boot 3.x line; drop devtools from production builds.

### H4. Intentionally vulnerable OWASP Juice Shop artifacts (`package1.json`, `POM`, `dockerarm`)
- These are the manifest/Dockerfile of OWASP Juice Shop 14.1.1 — a deliberately insecure application (includes e.g. `jsonwebtoken 0.4.0`, `sanitize-html 1.4.2`, vulnerable `express-jwt`).
- `dockerarm` builds on **Node 14**, EOL since April 2023 (unpatched runtime CVEs), and uses `npm install --unsafe-perm`.
- **Triage:** acceptable only as training/scanner-test material; must never be deployed to shared infrastructure or reachable networks.

## Medium

### M1. Spring Boot container runs as root (`Dockerfile (1)`)
No `USER` directive — the Java process runs as root in the container, so any app-level RCE (see H3) is immediately root-in-container. Add a non-root user (compare `dockerarm`, which does this correctly).

### M2. Unpinned/deprecated GitHub Actions in `.github/workflows/devsec.yml`
- `microsoft/security-devops-action@preview` — mutable tag; a compromised or changed tag executes arbitrary code in CI (supply-chain risk). Pin to a version or commit SHA.
- `actions/checkout@v2`, `actions/setup-dotnet@v1`, `github/codeql-action/upload-sarif@v1` — deprecated; `codeql-action@v1` is shut off, so the SARIF upload step will fail. Upgrade to current majors.

### M3. Infrastructure detail exposure in `template.yaml`
Hardcoded AWS account ID (`063586453409`), IAM role ARNs, subnet IDs, and security-group IDs in a public-facing repo; container image pinned to `:latest` (non-reproducible deploys). Parameterize these and pin image digests/tags.

### M4. `doc` Dockerfile hygiene
Unpinned `pip install -r requirements.txt` and `apt-get install` without version pins or cache cleanup; proxy values passed as build `ARG`s become `ENV` in the final image (can leak internal proxy hostnames). Positive: it does drop to `USER www-data`.

## Low / Code quality

- `securityaudits3.py` is broken as shipped: the entire import block and code sit inside an unterminated module docstring; `Today_date` is defined but `today_date` is referenced (NameError); `publish_msg_security_team` prints undefined `error`; bare `except:` clauses swallow failures; internal account IDs/SNS ARNs hardcoded.
- `package.json` license field empty; `tesr` unreachable code after `return`.

---

## Escalation summary

| # | Finding | Severity | Live risk |
|---|---------|----------|-----------|
| C1 | AWS creds in `secret.tf` | Critical pattern | Values are AWS doc examples — no rotation needed, but confirm no real keys elsewhere in history |
| C2 | Flask `debug=True` on 0.0.0.0 | Critical if deployed | RCE via Werkzeug debugger |
| H1 | AKIA-style strings in `package.json` | High pattern | Wrong length for real AWS keys — planted values |
| H2/H3 | EOL deps: jsonwebtoken 1.x, Spring Boot 2.2.4 on JDK 17 | High | Auth bypass / Spring4Shell RCE if deployed |
| H4 | Juice Shop artifacts | High by design | Keep isolated; training use only |
| M1–M4 | Container root user, unpinned CI actions, infra ID exposure | Medium | Fix opportunistically |

**Recommended actions, in order:**
1. Verify no *real* credentials exist anywhere in git history (`git log -p`, GitHub secret scanning); rotate anything genuine.
2. If any of these manifests feed a real deployment, patch H2/H3 immediately (Spring4Shell-eligible stack).
3. Fix M2 so the security scanning workflow actually runs (codeql-action@v1 uploads now fail).
4. Keep Juice Shop material clearly segregated and never deployed.

*Report generated by an automated scheduled security triage.*
