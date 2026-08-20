# Security Vulnerability Triage Report

**Repository:** sairaja992/hh23
**Scan date:** 2026-08-20 (automated scheduled scan)
**Scope:** Full repository (all files at HEAD `be86016` on branch `claude/loving-wright-cyxc8c`)

---

## Executive summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High     | 4 |
| Medium   | 5 |
| Low / Informational | 4 |

The highest-risk items are **hardcoded AWS credentials committed to source control** (`secret.tf`, `package.json`), a **Flask app configured with the Werkzeug debugger enabled and bound to 0.0.0.0** (remote code execution via the debug console), and a **`jsonwebtoken` v1.x dependency vulnerable to signature-bypass attacks**. Several of the committed credentials appear to be planted/example values (see triage notes), but they still trip secret scanners and normalize a dangerous pattern — all should be removed and rotated if ever valid.

---

## Critical findings

### C1. Hardcoded AWS access key and secret key — `secret.tf:2-3`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "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"
```
- **Issue:** Long-term AWS credentials embedded directly in a Terraform provider block committed to git.
- **Triage:** `AKIAIOSFODNN7EXAMPLE` is AWS's documentation example key and the secret is a variant of the docs example string, so these are almost certainly **planted/test values, not live credentials**. Treated as critical by pattern because git history preserves secrets forever and this file establishes the pattern.
- **Remediation:** Delete the credentials from the provider block; use environment variables, shared credentials files, or (preferred) IAM roles / OIDC. If any real key was ever committed here, rotate it and purge git history.

### C2. Flask debug mode enabled and bound to all interfaces — `tesr:21`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
- **Issue:** `debug=True` enables the Werkzeug interactive debugger, which allows **arbitrary code execution** on any unhandled exception; `host="0.0.0.0"` exposes it on every network interface. Together this is a remote-RCE configuration if the container/host is reachable.
- **Also:** Hardcoded token literal `token "sa74io0!"` at `tesr:14` (which is additionally a Python syntax error — the file will not run as-is).
- **Remediation:** Set `debug=False` (or drive via env var, never true in deployed images), bind to localhost or rely on the orchestrator's port mapping, remove the hardcoded token, fix the syntax error.

### C3. `jsonwebtoken ^1.1.1` — authentication bypass — `package.json:9`
- **Issue:** jsonwebtoken 1.x predates fixes for the classic JWT verification flaws (algorithm-confusion / `alg: none` acceptance, CVE-2015-9235 class). Any service using it for auth is bypassable. `restify ^2.8.1` and `async ^0.8.0` are similarly ancient with known CVEs (e.g., restify path traversal / ReDoS advisories).
- **Remediation:** Upgrade to `jsonwebtoken` ≥ 9.x, current `restify`/`async`; run `npm audit`.

---

## High findings

### H1. AWS access-key-shaped strings in `package.json` — lines 10 and 28
```json
"accesskey": "AKIASGHPORST",
"access key": "AKIAXYGHKLYPQGRRS"
```
- **Triage:** Both are shorter than a valid 20-character AKIA key, so they appear to be **planted/dummy values** — but they match secret-scanner patterns and don't belong in a manifest under any circumstances. The file is also **malformed JSON** (missing comma after line 28's entry), so `npm install` would fail.
- **Remediation:** Remove both entries; rotate if they correspond to any real key prefix; fix the JSON.

### H2. Elasticsearch domain access policy allows `Principal: "*"` with `es:*` — `echo-elasticsearch (1).yaml:272-280`
- **Issue:** The domain access policy grants every AWS principal full Elasticsearch API access on the domain. VPC placement (`VPCOptions`) limits network reachability, but the resource policy itself is wide open — anything with network line-of-sight inside those subnets (any compromised workload) gets full read/write/admin on the domain.
- **Also:** Allowed ES versions (6.x–7.4) are all end-of-life; `NodeToNodeEncryptionOptions` and `DomainEndpointOptions` (enforce HTTPS/TLS policy) are not set.
- **Remediation:** Scope the principal to specific IAM roles, enable node-to-node encryption and `EnforceHTTPS`, move to a supported OpenSearch version.

### H3. EOL base images and intentionally vulnerable app — `dockerarm`
- **Issue:** `FROM node:14` / `node:14-alpine` (EOL April 2023, no security patches) building **OWASP Juice Shop 14.1.1** — a deliberately insecure application. `npm install --unsafe-perm` disables the uid/gid safety on lifecycle scripts. If this image is ever deployed anywhere reachable, it is exploitable by design.
- **Triage:** Juice Shop is a training target; presence here is likely intentional (hackathon/demo repo). Escalate only if this image is deployed to shared or production infrastructure.

### H4. EOL framework — Spring Boot 2.2.4.RELEASE — `pom (2).xml`, `pom254.xml`, `POM`
- **Issue:** Spring Boot 2.2.x is EOL (since 2021) and transitively pins vulnerable Spring/Tomcat versions (Spring4Shell-era and multiple later CVEs never backported). `spring-boot-devtools` is included as a runtime dependency (line 42-46) — devtools must never ship in production images.
- **Remediation:** Upgrade to a supported Spring Boot 3.x line; keep devtools out of the packaged artifact.

---

## Medium findings

- **M1. Unpinned / deprecated GitHub Actions — `.github/workflows/devsec.yml`**: `microsoft/security-devops-action@preview` is a mutable tag (supply-chain risk — pin to a commit SHA); `actions/checkout@v2`, `setup-dotnet@v1`, and `codeql-action/upload-sarif@v1` are deprecated/archived versions that run on an EOL Node runtime and will stop working. The workflow also lacks a `permissions:` block (defaults may grant write token scope; it only needs `security-events: write`, `contents: read`).
- **M2. Nested-stack template URLs from a name-predictable S3 bucket — `template.yaml:8,14,26`**: `azdo-q-gen-dev-${AWS::Region}` — if this stack is launched in any region where the bucket name is unclaimed, an attacker who registers the bucket controls the CloudFormation templates being executed (template-injection / bucket-takeover pattern). Pin to a single known bucket you own, and consider S3 object versions/checksums.
- **M3. Proxy credentials via build ARG → ENV — `doc:3-9`**: `HTTP_PROXY_ARG` etc. persisted as image ENV; if proxy URLs carry credentials they are baked into image metadata (`docker history`/`inspect`). Also `https_proxy` is incorrectly set from `$HTTP_PROXY_ARG` (copy-paste bug), and `pip install -r requirements.txt` is unpinned/unhashed.
- **M4. KMS key policy breadth — `echo-elasticsearch (1).yaml:193-198`**: root-account `kms:*` plus a management role with `kms:Delete*`/`ScheduleKeyDeletion` — acceptable AWS default pattern, but deletion rights on the encryption key for the data store deserve a second look.
- **M5. `securityaudits3.py` robustness/security hygiene**: bare `except:` clauses swallow errors (lines 45, 76, 237); `Today_date` vs `today_date` **NameError at line 34 means the lambda cannot run at all** — the audit pipeline this feeds is silently broken; unreachable alert code after `raise` (line 305-306); `print(error)` on line 212 references an undefined name inside the SNS failure handler.

---

## Low / informational

- **L1.** Internal AWS account IDs, subnet IDs, security-group IDs, role ARNs, and internal hostnames (`git.fpd.cat.com`) are exposed across `template.yaml`, `echo-elasticsearch (1).yaml`, `securityaudits3.py`, `package.json` — reconnaissance value in a public repo.
- **L2.** `Dockerfile (1)` copies a fat jar and runs as root (no `USER` directive) — add a non-root user (the `dockerarm` file does this correctly).
- **L3.** `package.json` has an empty `"license": ""` and `git://` (unencrypted, integrity-unverified) repository protocol.
- **L4.** `tesr` leaks the full Python version string in the HTTP response — minor fingerprinting aid.

---

## Recommended escalation order

1. **Now:** Remove all credential-shaped strings (C1, H1) and rotate anything that was ever real; enable GitHub secret scanning + push protection on the repo.
2. **Now:** Fix `tesr` debug/bind configuration (C2) if that app is deployed anywhere.
3. **This week:** Dependency upgrades (C3, H4), Elasticsearch access policy scoping (H2), pin GitHub Actions (M1), fix the S3 template-URL takeover pattern (M2).
4. **Backlog:** Hygiene items (M3-M5, L1-L4). Confirm whether the Juice Shop image (H3) is intentional training material and label it as such.
