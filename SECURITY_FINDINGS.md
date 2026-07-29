# Security Vulnerability Triage Report — hh23

**Scan date:** 2026-07-29 (automated scheduled scan)
**Scope:** All files on branch `claude/loving-wright-sqokbs` (full working tree)
**Method:** Manual file-by-file review of source, IaC, Dockerfiles, CI workflows, and dependency manifests.

---

## Summary

| Severity | Count |
|----------|-------|
| High     | 5     |
| Medium   | 6     |
| Low      | 4     |

The most urgent items are **hardcoded credentials committed to the repository** (`secret.tf`, `package.json`, `tesr`) and a **Flask app configured with the Werkzeug debugger enabled on all interfaces**, which is a well-known remote-code-execution vector. Because git history preserves secrets even after deletion, any real credentials must be rotated, not just removed.

---

## High severity

### H-1. Hardcoded AWS credentials in Terraform — `secret.tf:2-3`
- **Issue:** AWS `access_key` and `secret_key` are hardcoded in the provider block (CWE-798).
- **Triage note:** The access key ID `AKIAIOSFODNN7EXAMPLE` matches AWS's documentation example key, and the secret is a mutated variant of the docs example — this is *probably* a planted/test secret. However, it still trains contributors to commit credentials and will trip every secret scanner.
- **Action:** Remove the block; use environment variables, an AWS profile, or IAM roles. Confirm the key is not active in any account. Enable GitHub secret scanning + push protection on the repo.

### H-2. AWS access key IDs embedded in `package.json:10,28`
- **Issue:** `"accesskey": "AKIASGHPORST"` and `"access key": "AKIAXYGHKLYPQGRRS"` appear inside the dependency maps of the `wmic-service` manifest. These follow the AKIA access-key-ID format (CWE-798 / CWE-540).
- **Triage note:** No paired secret key is present, and both IDs are shorter than the canonical 20-character format, so they may be planted test data — but they must be treated as potentially real until verified. The file is also invalid JSON (missing comma after line 28), so these entries were clearly hand-inserted, not installed.
- **Action:** Delete both entries; verify neither ID exists in IAM; rotate if found.

### H-3. Flask debug mode exposed on all interfaces — `tesr:21`
- **Issue:** `app.run(debug=True, host="0.0.0.0", port=8080)` (CWE-489 / CWE-605). With `debug=True`, the Werkzeug interactive debugger allows arbitrary Python code execution to anyone who reaches the port and can obtain/guess the PIN; binding to `0.0.0.0` exposes it beyond localhost. The `doc` Dockerfile runs this app (`ENTRYPOINT ["python3", "app.py"]`), so the container would ship this configuration.
- **Additional:** A hardcoded token string `"sa74io0!"` sits at `tesr:14` (syntactically dead code, but a secret-looking literal in source).
- **Action:** Set `debug=False` (or gate on an env var) for anything deployed; remove the token literal.

### H-4. Elasticsearch domain policy allows any principal — `echo-elasticsearch (1).yaml:272-280`
- **Issue:** The domain access policy grants `Principal: AWS: "*"` with `Action: es:*` on the domain (CWE-284). The domain is VPC-attached, which mitigates internet exposure, but any principal with network reach in those subnets gets full admin (`es:*`) on the cluster — no IAM authentication boundary at all.
- **Action:** Restrict the principal to the specific roles/services that need access, and scope actions (e.g., `es:ESHttp*` for clients). Also note `ESVersion: 7.4` is end-of-life (see M-4).

### H-5. Critically vulnerable auth dependencies — `package.json:9`, `package1.json` / `POM`
- **Issue:**
  - `package.json` (wmic-service): `jsonwebtoken ^1.1.1` — affected by the algorithm-confusion auth bypass (CVE-2015-9235, fixed in 4.2.2); `restify ^2.8.1` is years EOL.
  - `package1.json` and `POM` (identical files): `jsonwebtoken 0.4.0`, `express-jwt 0.1.3` (CVE-2020-15084 auth bypass), `sanitize-html 1.4.2` (multiple XSS bypasses), `unzipper 0.9.15` (zip-slip), deprecated `request`, Node 14 (EOL).
- **Triage note:** `package1.json`/`POM` are the manifest of **OWASP Juice Shop v14.1.1**, a deliberately vulnerable training app (as is the `dockerarm` Dockerfile). If this repo is a security-tooling test bed — which its contents suggest — these are *intentional* fixtures: triage as **accepted/expected**, but keep them out of any production build pipeline. The `wmic-service` manifest is **not** Juice Shop and should be fixed if that service is real.
- **Action:** Upgrade `jsonwebtoken` (≥9.x) and `restify` in `wmic-service`; label the Juice Shop fixtures clearly as intentional (e.g., move under a `fixtures/` directory with a README note).

---

## Medium severity

### M-1. CI workflow uses deprecated, unpinned actions and default token permissions — `.github/workflows/devsec.yml`
- `actions/checkout@v2`, `actions/setup-dotnet@v1`, and `github/codeql-action/upload-sarif@v1` are deprecated major versions running on EOL Node runtimes; `microsoft/security-devops-action@preview` is a mutable tag — a supply-chain risk (CWE-829), since the tag can be repointed at any time.
- No top-level `permissions:` block, so the workflow gets the repository's default `GITHUB_TOKEN` scope.
- **Action:** Bump to current majors (checkout@v4, upload-sarif@v3, setup-dotnet@v4), pin third-party actions by commit SHA, and add a least-privilege `permissions:` block (`contents: read`, `security-events: write`).

### M-2. Container runs as root — `Dockerfile (1)`
- No `USER` directive; the Spring Boot app runs as root inside the container (CWE-250). Add a non-root user (the `dockerarm` Juice Shop file does this correctly with `USER 1001`).

### M-3. EOL base images — `dockerarm:1,9` and `Dockerfile (1):5`
- `node:14` / `node:14-alpine` are end-of-life (no security patches since 2023). The commented-out `openjdk:9-jdk-alpine` suggestion is also EOL. Pin currently supported, digest-pinned bases.

### M-4. EOL Elasticsearch version and mutable image tag — `echo-elasticsearch (1).yaml:15`, `template.yaml:17`
- Elasticsearch 7.4 (and every version in the AllowedValues list) is end-of-life. `template.yaml` deploys `q-gen-01:latest` — a mutable tag, so deployments are not reproducible and can silently pull changed images. Pin by digest or immutable version tag.

### M-5. Internal infrastructure identifiers committed — `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`
- AWS account IDs (063586453409, 900182000710, 460510738068, 070133345649, 478226638351), subnet IDs, security-group IDs, role ARNs, and SNS topic ARNs are hardcoded (CWE-200). Individually low-risk, but together they map internal environments for an attacker. Parameterize via SSM/parameters where practical.

### M-6. Build-arg proxy credentials pattern — `doc:3-9`
- Proxy URLs passed as build args are baked into image ENV (visible via `docker history`/`inspect`). If the proxy URL ever carries credentials, they leak with the image. Also `FROM Doc` is not a valid base image (file as committed cannot build), and `pip install -r requirements.txt` is unpinned/unverified.

---

## Low severity

- **L-1.** `securityaudits3.py` — the entire body is inside an unterminated docstring (the `"""` opened at line 2 is never closed before the imports), `today_date`/`Today_date` NameError, bare `except:` clauses swallowing errors, unreachable code after `raise e` (line 305-307), and `error` referenced instead of `err` in `publish_msg_security_team` (line 212). The script as committed cannot run; if it's meant to be a production Lambda, it is silently broken — which for a security-audit pipeline is itself a monitoring gap.
- **L-2.** `package.json` is malformed JSON (missing comma, line 28) — `npm install` would fail; masks the embedded keys from some parsers/scanners.
- **L-3.** `dockerarm` builds Juice Shop with `--unsafe-perm` and copies the full build context (`COPY . /juice-shop`) with no `.dockerignore` — risk of leaking local files into the image. Acceptable for the training fixture, not for a real service.
- **L-4.** Odd/duplicate file naming (`Dockerfile (1)`, `pom (2).xml`, `pom254.xml`, `POM` vs `package1.json` duplicates, `tesr`) makes the repo hard to scan reliably and suggests uploads rather than maintained source. Consolidate and remove dead copies.

---

## Recommended escalation order

1. **Now:** Verify/rotate anything matching the credentials in H-1/H-2; enable GitHub secret scanning + push protection.
2. **This week:** Fix H-3 (Flask debug) and H-4 (ES access policy) anywhere these templates are actually deployed; patch `wmic-service` deps (H-5).
3. **Next sprint:** CI hardening (M-1), container/user and base-image hygiene (M-2/M-3), pin image versions (M-4), parameterize infra identifiers (M-5).
4. **Housekeeping:** Repair or clearly quarantine the broken/fixture files (L-1..L-4).
