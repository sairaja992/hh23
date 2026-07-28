# Security Vulnerability Triage — 2026-07-28

Automated scheduled security review of `sairaja992/hh23` (branch `main` @ `be86016`).
Scope: all 15 tracked files. Findings ranked by severity with triage notes and
remediation. Note: the README states this repo is "Used for testing only" — several
findings look like deliberately planted test/canary data, called out where suspected.

---

## CRITICAL — Committed credentials / secrets

### C1. Hardcoded AWS credentials in Terraform provider — `secret.tf:2-3`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY"
```
- **Triage:** The access key is AWS's documented example key and the secret is a
  modified variant of the docs example — almost certainly sample/test data, not a
  live credential. However, the file name (`secret.tf`) and pattern will (correctly)
  trip every secret scanner, and the pattern normalizes committing provider
  credentials.
- **Remediation:** Delete the file or replace with variable references
  (`var.access_key` sourced from env / assumed role). Never define static keys in a
  provider block; use IAM roles or AWS SSO. If any real key was ever used here,
  rotate it and purge history (`git filter-repo`).

### C2. AWS access-key-ID strings embedded in dependency manifest — `package1.json:10,28`
```json
"accesskey": "AKIASGHPORST",
"access key": "AKIAXYGHKLYPQGRRS"
```
- **Triage:** `AKIA…` strings placed inside `dependencies`/`devDependencies`. Both
  are shorter than a valid 20-char AWS key ID, so they are malformed / likely
  planted test data — but they are still secret-scanner hits and must not live in a
  manifest. The file is also **invalid JSON** (missing comma after line 28), so any
  tooling consuming it fails.
- **Remediation:** Remove both entries; fix the JSON. Confirm no matching real keys
  exist in the account (IAM → access keys audit).

### C3. Hardcoded token in source — `tesr:14`
```python
token "sa74io0!"
```
- **Triage:** A literal token/password committed in a Python file (also a syntax
  error — the line is not valid Python, so the app as committed cannot run).
- **Remediation:** Remove; source tokens from environment/secret manager. Rotate if
  this value is used anywhere real.

---

## HIGH

### H1. Flask debug server exposed on all interfaces — `tesr:21`
```python
app.run(debug=True, host="0.0.0.0", port=8080)
```
`debug=True` enables the Werkzeug interactive debugger → **remote code execution**
for anyone who can reach port 8080; binding to `0.0.0.0` maximizes exposure. This is
the app the `doc` Dockerfile ships (`ENTRYPOINT ["python3", "app.py"]`, `EXPOSE 8080`).
**Fix:** `debug=False` (or gate on env var), run behind a WSGI server (gunicorn).

### H2. Elasticsearch domain access policy open to any principal — `echo-elasticsearch (1).yaml:272-280`
```yaml
Principal: { AWS: "*" }
Action: ["es:*"]
```
Wildcard principal with full `es:*` on the domain. Partially mitigated by VPC-only
deployment (`VPCOptions`), but any principal with network reach gets full admin —
no IAM signing required. Also: ES version 7.4 is EOL, and
`rest.action.multi.allow_explicit_index: "true"` weakens index-level restrictions.
**Fix:** Scope `Principal` to specific IAM roles, restrict `Action`, enable
fine-grained access control, upgrade to a supported OpenSearch version.

### H3. Known-vulnerable dependency set (OWASP Juice Shop manifest) — `package.json` / `POM`
Both files are copies of Juice Shop 14.1.1, an *intentionally vulnerable* app:
- `jsonwebtoken` **0.4.0** — forgeable JWTs (alg confusion / none-alg era)
- `express-jwt` **0.1.3** — authorization bypass
- `sanitize-html` **1.4.2** — multiple XSS filter bypasses
- `unzipper` **0.9.15** — zip-slip path traversal
- `notevil`, `request` (deprecated), Node engine pinned to EOL 14–18
- **Triage:** Expected if this is lab/demo content. Risk is accidental reuse: these
  manifests must never seed a real service or CI `npm install`.
- **Remediation:** Keep quarantined in a clearly labeled directory, or delete.

### H4. Vulnerable/obsolete deps in `package1.json` (wmic-service)
`jsonwebtoken ^1.1.1` (verification-bypass vulns fixed only in 4.2.2+),
`restify ^2.8.1` (2014-era), `async ^0.8.0`, `mocha ^1.x`. Also discloses an
internal git host: `git://git.fpd.cat.com/fpd/wmic-service.git` (unencrypted
`git://` protocol, internal hostname leak).

### H5. Container image hygiene — `Dockerfile (1)`, `dockerarm`, `doc`
- `Dockerfile (1)`: no `USER` directive → **runs as root**; commented suggestion of
  `openjdk:9-jdk-alpine` (long-EOL) should be removed.
- `dockerarm`: `node:14` / `node:14-alpine` bases are EOL (no security patches);
  `npm install --unsafe-perm` runs lifecycle scripts as root during build.
- `doc`: `FROM Doc` is not a valid public base ref; proxy values baked into image
  env (leak into every derived layer/container); `pip install -r requirements.txt`
  unpinned/unverified; `apt-get` layer never cleans lists. Runs as `www-data` (good).
**Fix:** pin supported, digest-pinned base images; add non-root `USER`; drop
`--unsafe-perm`; pass proxies as build-time only (`--build-arg` without `ENV`).

---

## MEDIUM

### M1. CI security pipeline is broken/outdated — `.github/workflows/devsec.yml`
- `github/codeql-action/upload-sarif@v1` — **shut down by GitHub**; SARIF upload
  fails, so MSDO findings never reach the Security tab (silent loss of the control
  this workflow exists to provide).
- `actions/checkout@v2`, `actions/setup-dotnet@v1` — deprecated (Node12/16 runtimes).
- `microsoft/security-devops-action@preview` — mutable tag, supply-chain risk.
- No `permissions:` block — the job runs with default (potentially write-all) token
  scope; it needs only `contents: read` + `security-events: write`.

### M2. Internal infrastructure disclosure (multiple files)
Hardcoded AWS account IDs (`478226638351`, `063586453409`, `900182000710`,
`460510738068`, `070133345649`), subnet & security-group IDs, SNS topic ARNs,
S3 bucket names (`ue2`, `ue2-scout2-prod-history`), and internal role names across
`securityaudits3.py`, `template.yaml`, `echo-elasticsearch (1).yaml`. In a public
repo this is reconnaissance material. **Fix:** parameterize; keep environment
mappings in private config.

### M3. `securityaudits3.py` is non-functional and unsafe as committed
- Module docstring opened at line 2 is **never closed** → `SyntaxError` at load;
  the Lambda cannot run.
- `Today_date` defined, `today_date` used (lines 33-34, 37) → `NameError` even if
  the docstring were fixed.
- Bare `except:` clauses swallow real failures (lines 45, 237); `raise e` before the
  alert-append in `writedatatodynamodb` makes the error handling dead code;
  `publish_msg_security_team` references undefined `error` in its handler.
- DynamoDB table auto-creation matches table names by substring (`if table in …`),
  which can silently write findings to the wrong table.

---

## LOW
- `package1.json` invalid JSON; empty `license` field.
- File naming (`Dockerfile (1)`, `pom (2).xml`, `echo-elasticsearch (1).yaml`,
  `tesr`, `doc`) suggests unmanaged uploads; makes tooling (Dependabot, IaC
  scanners) miss files entirely.
- `template.yaml` pulls nested CloudFormation templates from an S3 URL without
  integrity pinning.

---

## Recommended escalation actions (priority order)
1. **Verify no real credentials**: audit IAM for keys matching the committed
   patterns; rotate anything live; purge `secret.tf`/`package1.json`/`tesr` values
   from git history if any were real.
2. **Enable GitHub secret scanning + push protection** on the repo.
3. **Fix the CI workflow** (upload-sarif@v3, checkout@v4, pinned action SHAs,
   least-privilege `permissions:`) so security findings actually flow again.
4. Remediate H1 (Flask debug RCE) and H2 (open ES policy) before any of these
   templates are reused.
5. Quarantine or delete the intentionally vulnerable Juice Shop manifests.
