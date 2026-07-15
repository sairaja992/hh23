# Security Vulnerability Triage Report

- **Repository:** sairaja992/hh23
- **Scan date:** 2026-07-15 (scheduled automated review)
- **Scope:** Full repository (16 files: Terraform, CloudFormation, Dockerfiles, npm/Maven manifests, Python, GitHub Actions)
- **Note:** README states "Used for testing only". Several findings appear to be intentionally planted test secrets; they are still triaged below because the patterns are what secret/vuln scanners must catch, and any real value in these positions would be a critical exposure.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High     | 5 |
| Medium   | 5 |
| Low      | 4 |

---

## CRITICAL

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
`access_key` and `secret_key` are committed directly in the provider block.
- The values match the AWS **documentation example key** (`AKIAIOSFODNN7EXAMPLE` / a variant of the example secret), so they are almost certainly not live — but the pattern is exactly what leaks real keys.
- **Action:** Remove credentials from source. Use environment variables, shared credentials file, or (preferred) IAM roles/OIDC. If real keys were ever committed in history, rotate them immediately and scrub history.

### C2. AWS access-key-style secrets embedded in `package.json:10,28`
`"accesskey": "AKIASGHPORST"` in `dependencies` and `"access key": "AKIAXYGHKLYPQGRRS"` in `devDependencies`.
- These are 12/17 chars (real AKIA IDs are 20), so they look like planted test values — but they trip secret scanners for good reason.
- The file is also **invalid JSON** (missing comma after line 28), so `npm install` fails outright.
- **Action:** Remove both keys; secrets never belong in a package manifest. Fix the JSON.

### C3. Flask app runs with `debug=True` bound to `0.0.0.0` — `tesr:21`
`app.run(debug=True, host="0.0.0.0", port=8080)` exposes the Werkzeug interactive debugger on all interfaces. The debugger console permits **remote code execution** on anyone who can reach the port.
- Also contains a hardcoded token on line 14 (`token "sa74io0!"`), which additionally makes the file a Python **syntax error** — it cannot run as committed.
- **Action:** `debug=False` (or gate via env var), bind to localhost or run behind a WSGI server, move the token to a secret store.

### C4. Wide-open Elasticsearch domain access policy — `echo-elasticsearch (1).yaml:272-280`
The domain access policy grants `es:*` to `Principal: AWS: "*"` (anyone). Deployment inside a VPC reduces exposure, but any principal/workload with network reach to the VPC endpoints gets full admin on the domain (read, write, delete indices, change settings).
- **Action:** Scope the principal to specific IAM roles, restrict actions to `es:ESHttp*` as needed, and enable fine-grained access control.

---

## HIGH

### H1. Severely outdated, known-vulnerable npm dependencies — `package.json`
- `jsonwebtoken ^1.1.1` — pre-dates fixes for algorithm-confusion / auth-bypass issues (CVE-2015-9235 class); current is 9.x.
- `async ^0.8.0` — prototype pollution (CVE-2021-43138 fixed in 2.6.4/3.2.2).
- `restify ^2.8.1` — years past EOL, multiple known issues.
- **Action:** Upgrade all three; add `npm audit`/Dependabot to CI.

### H2. Intentionally vulnerable app manifest (OWASP Juice Shop) — `POM` and `package1.json` (identical copies)
This is the Juice Shop v14.1.1 manifest: `jsonwebtoken 0.4.0`, `express-jwt 0.1.3`, `sanitize-html 1.4.2`, `unzipper 0.9.15`, `request 2.88.2` (deprecated), etc. Fine as a deliberate test target, but it must never be deployed to shared infrastructure or mistaken for a production manifest.
- **Action:** If these are test fixtures, move them under a clearly named `test-fixtures/` directory; delete the duplicate (`package1.json` is byte-identical to `POM`).

### H3. EOL base images and runtimes
- `dockerarm:1,9` — `node:14` / `node:14-alpine`: Node 14 EOL April 2023, no security patches.
- `pom (2).xml` / `pom254.xml:15` — Spring Boot **2.2.4.RELEASE** (Spring Framework 5.2.3): EOL, in the vulnerable range for Spring4Shell (CVE-2022-22965, exploitable on JDK 9+ — these builds target Java 11/17) and numerous later CVEs.
- **Action:** Move to Node 20/22 LTS and Spring Boot 3.x.

### H4. Spring Boot container runs as root — `Dockerfile (1)`
No `USER` directive; the JVM runs as root inside the container (compare `dockerarm`, which correctly drops to UID 1001). Also `spring-boot-devtools` is included in the runtime dependency set (`pom (2).xml:42-46`) — devtools in a deployed jar enables remote-restart attack surface.
- **Action:** Add a non-root `USER`; mark devtools `runtime`-excluded or rely on repackaging to strip it.

### H5. Internal infrastructure identifiers committed to a public-facing repo
AWS account IDs (`063586453409`, `478226638351`, `900182000710`, `460510738068`, `070133345649`), subnet IDs, security-group IDs, IAM role ARNs, SNS topic ARNs, and internal hostnames (`git.fpd.cat.com`) across `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`, `package.json`.
- Not credentials, but valuable reconnaissance for targeted attacks (confused-deputy attempts, role-trust probing).
- **Action:** Parameterize per environment; keep real account/network identifiers out of source where feasible.

---

## MEDIUM

### M1. GitHub Actions workflow issues — `.github/workflows/devsec.yml`
- No `permissions:` block — the job runs with the default (potentially write-all) `GITHUB_TOKEN`.
- `actions/checkout@v2`, `actions/setup-dotnet@v1`, `codeql-action/upload-sarif@v1` — v1/v2 tags are deprecated; `codeql-action@v1` has been turned off by GitHub, so the SARIF upload step likely fails.
- `microsoft/security-devops-action@preview` — mutable tag; pin to a version/SHA.
- **Action:** Add `permissions: { contents: read, security-events: write }`, bump actions to current majors, pin by SHA.

### M2. Elasticsearch hardening gaps — `echo-elasticsearch (1).yaml`
`NodeToNodeEncryptionOptions` and `DomainEndpointOptions.EnforceHTTPS` are absent; Elasticsearch 7.4 (and every `AllowedValues` option) is EOL. Encryption at rest with CMK **is** correctly enabled.
- **Action:** Enable node-to-node encryption and EnforceHTTPS (TLS 1.2 policy); move to a supported OpenSearch version.

### M3. Mutable `:latest` image tag in ECS task — `template.yaml:17`
`q-gen-01:latest` means deploys are non-reproducible and a poisoned/retagged image is silently picked up. Same task+execution role (`q-gen-ECSServiceRole`) is used for both roles — broader permissions than the task needs.
- **Action:** Pin image by digest or immutable tag; split task vs execution roles.

### M4. Broken security-audit Lambda — `securityaudits3.py`
The module docstring at line 2 is never closed, so the entire file is a **SyntaxError** (imports are swallowed by the string; confirmed with `py_compile`). Also `Today_date` is defined but `today_date` is referenced (line 34) — a NameError even after fixing the docstring. A security-monitoring function that cannot run is a silent monitoring gap.
- **Action:** Close the docstring, fix the variable name, add a smoke test / deploy-time syntax check.

### M5. `npm install --unsafe-perm` in image build — `dockerarm:5`
Allows package lifecycle scripts to run as root during build. Acceptable only because this is the upstream Juice Shop Dockerfile (deliberately vulnerable app); avoid in any first-party image.

---

## LOW

- **L1.** `Dockerfile (1)` — commented guidance suggests `openjdk:9-jdk-alpine` for Java 8 (wrong and EOL); comments advertise running with `sudo docker` mapping privileged ports.
- **L2.** `doc` — Dockerfile `FROM Doc` is not a valid base image (build breaks); proxy args copied into ENV persist in image layers (`https_proxy` is set from `HTTP_PROXY_ARG` — also a bug). Does correctly use `USER www-data`.
- **L3.** `package.json` — `"license": ""` and `git://` (unauthenticated, unencrypted) protocol in repository URL.
- **L4.** Housekeeping: files named `POM` (actually a package.json), `pom (2).xml`, `package1.json` (duplicate), `tesr` — misleading names/duplicates increase the odds a scanner or human misses the real manifest.

---

## Escalation & recommended next steps (priority order)

1. **Rotate/remove all committed secrets** (C1, C2, C3-token) and scrub git history if any value was ever real; enable GitHub secret scanning + push protection.
2. **Lock down the Elasticsearch access policy** (C4) — one-line change, large blast-radius reduction.
3. **Disable Flask debug mode** (C3) anywhere this pattern is copied from.
4. Patch the dependency set (H1, H3) and add Dependabot + `npm audit` to CI.
5. Fix the broken security tooling itself (M1 workflow, M4 Lambda) — both currently fail silently, which is a monitoring gap, not just tech debt.
