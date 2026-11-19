# Production checklist

A practical checklist for deploying PATHOS 2.2 to a customer. Work through it top to bottom for each installation and keep the filled-in copy with the customer's records. Every item points to the document with the details. Items marked **(validated)** were exercised on 2026-11-20 in the end-to-end validation ([VALIDATION_REPORT.md](VALIDATION_REPORT.md)). The other items come from the documentation and were not re-tested there.

## 1. Before you start

- [ ] **Release.** Install a tagged release from the signed GHCR images rather than a local build: `PATHOS_IMAGE_PREFIX=ghcr.io/quditmind/` and `PATHOS_VERSION=2.2.0` (or later) in `.env`, then `deploy/scripts/upgrade.sh --pull` ([OPERATIONS.md](OPERATIONS.md#installing-a-release-signed-images)). **(validated)**
- [ ] **Verify the images** with `cosign verify …` before the first start and after every upgrade (same section).
- [ ] **Releases after 2.2.0.** Check that the fixes listed in [VALIDATION_REPORT.md §6](VALIDATION_REPORT.md#6-bugs-found-and-fixed) are in the release you deploy. In 2.2.0 every family-worker scan ends *partial*, the SBOM download is empty, and API targets cannot be scanned without the intrusive flag.
- [ ] **Host.** Docker Engine with the Compose plugin, `linux/amd64`. The host must not run other Compose projects that use the project name `pathos`. The images are tagged `pathos:<version>`, so two local builds of different trees overwrite each other's `:dev` images; use release images or distinct `PATHOS_VERSION` values.
- [ ] **Ports.** 443 and 80 are free. Otherwise set `PATHOS_HTTPS_PORT`/`PATHOS_HTTP_PORT` **and** include the port in `PATHOS_PUBLIC_URL` ([INSTALLATION.md](INSTALLATION.md#configuration)). **(validated on 9443/9080)**

## 2. Sizing

Use [PERFORMANCE.md](PERFORMANCE.md#recommended-sizing-derived-from-these-measurements) for the database and API, and size the workers separately.

| Customer size | Findings | Repositories | PostgreSQL | Host (core stack plus workers) |
|---|---|---|---|---|
| Small | up to about 100,000 | up to 1,000 | Production override defaults: 4 GB, `shared_buffers=1GB` | 8 vCPU, 16 GB RAM, 100 GB SSD |
| Medium | about 1 million | about 10,000 | 6–8 GB, `shared_buffers` a third to a half of that, 8+ cores | 16 vCPU, 32 GB RAM, 300 GB NVMe, or a separate database server |
| Large | 10 million | 10,000+ | Dedicated server with much more than 6 GB | Not supported interactively yet: the dashboard, posture and executive pages take 23–48 s ([PERFORMANCE.md](PERFORMANCE.md#10-million-findings)) |

Worker memory, measured in the validation:

- [ ] `worker-core` and family workers sit at 150–400 MB while idle. Allow **4 GB per concurrent scan** (`PATHOS_WORKER_MEMORY`, the default). Also allow the tmpfs workspace (`PATHOS_WORKER_TMPFS`, 3 GB), which counts as RAM when it fills.
- [ ] gosec was OOM-killed at the 4 GB limit on alertmanager and gitlab-cli (mid-size Go repositories). For Go-heavy customers who enable the SAST family, raise `PATHOS_WORKER_MEMORY` for `worker-sast` to 6–8 GB or leave gosec out of profiles.
- [ ] Scanner caches (the `scanner_cache` volume): the Trivy database is 1.7 GB, Grype about 1 GB, the Dependency-Check NVD data about 250 MB, and the CVE Binary Tool database about 600 MB. Plan **10 GB** for this volume and **2× the uploaded source size** for the `sources` volume.
- [ ] **Concurrency limit.** Only one execution per repository runs at a time, and that includes DAST and image targets attached to it. A 15–30 minute DAST scan holds back that repository's other scans and its CI result imports (409). Attach long-running targets to a separate repository record if CI imports must not wait.

## 3. TLS and domain

- [ ] `PATHOS_PUBLIC_URL=https://pathos.<customer>.com` and `PATHOS_DOMAIN=pathos.<customer>.com`.
- [ ] **Public certificate.** `CADDY_TLS=<ops e-mail>` (Let's Encrypt). Ports 80 and 443 must be reachable from the internet for the ACME challenge.
- [ ] **Internal-only host.** Keep `CADDY_TLS=internal` and distribute Caddy's root certificate (`docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt .`). CI jobs then need `--ca-cert` / `PATHOS_CA_CERT`. **(validated with the CLI, Jenkins, the GitHub Action and the GitLab template)** To use the customer's own CA instead, mount the certificate and key into Caddy (not covered by the validation).
- [ ] **Customer private CA for outbound connections.** Registry connectors, outbound webhooks (Slack, Teams, JSON) and Jira/ServiceNow have **no CA certificate setting**. A target that presents a certificate from a private CA fails with `x509: certificate signed by unknown authority` (validated). Either use publicly trusted certificates on those endpoints, or mount the CA bundle and set `SSL_CERT_FILE` on `jobs` and the workers with a Compose override.
- [ ] The Keycloak admin console is limited by `KEYCLOAK_ADMIN_ALLOW` (required with the production override). Set it to the admin network CIDRs.

## 4. Sign-in and SSO

- [ ] **Bootstrap administrator.** `install.sh` prints the e-mail address and a temporary password. Change the password at first sign-in and store it in the customer's vault. **(validated)**
- [ ] Back up `PATHOS_MASTER_KEY` outside the host (vault or password manager). It is **not** in a backup unless you use `--with-env`.
- [ ] **SSO.** Add the customer's SAML 2.0 or OIDC identity provider in Keycloak (realm `pathos`), as described in [sign-in and SSO](user-guide/sign-in-and-sso.md). Turn on **Trust email** only for the customer's own directory. Keep one local administrator for recovery. Then run `scripts/test-sso-brokering.py` against the stack.
- [ ] **MFA.** Set `PATHOS_REQUIRE_MFA=true` unless the identity provider already enforces MFA.
- [ ] **SMTP.** Configure a real relay with `PATHOS_SMTP_*`, STARTTLS and auth, and set `COMPOSE_PROFILES=` (no Mailpit). Send a test e-mail from **Administration → Notifications → Email**. **(validated with Mailpit: scan notifications delivered)**
- [ ] **API tokens.** Teach CI owners to create personal API tokens with the narrowest scope: `api:read` for gates, `api:write` for imports and scans, `mcp` for assistants. Tokens expire after 90 days at most.

## 5. Install and verify

- [ ] `./deploy/scripts/install.sh`, then edit `.env` (URL, TLS, SMTP, `PATHOS_COMPOSE_PROD=1`, `KEYCLOAK_ADMIN_ALLOW`, `COMPOSE_PROFILES`).
- [ ] `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --wait`. The first start takes about 1 minute. **(validated: 51 s)**
- [ ] `python3 scripts/smoke-test.py` → `90 passed, 0 failed`. **(validated)** If you will keep using the install, set `PATHOS_ADMIN_NEW_PASSWORD` first. Note that `scripts/e2e.sh` reads that variable from the environment, not from `.env`.
- [ ] Import one real repository and run the Default profile. Check that the scan finishes *succeeded* and that the dashboard, findings, SBOM and posture pages show data. **(validated)**

## 6. Network and egress allowlist

The workers reach the internet only through the `egress` Squid proxy. After every change in `deploy/egress/`, run `docker compose restart egress`; there is no reload. Do the restart between scans, because it breaks running downloads. The access log shows every refused host: `docker compose exec egress tail /var/log/squid/access.log | grep TCP_DENIED`.

- [ ] **Default allowlist** (`allowlist.txt`): GitHub, Azure DevOps, the Trivy, Grype and OSV databases, and Sigstore. **GitLab.com and Bitbucket clone hosts are not in it**, so add `.gitlab.com` / `.bitbucket.org` when the customer uses those providers.
- [ ] **Docker Hub image targets:** `index.docker.io`, `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` and `production.cloudfront.docker.com`. **(validated: the hosts in the 2.2.0 documentation were not enough)** Add the customer's own registries too, for example `quay.io` with its `cdn0N.quay.io` hosts.
- [ ] **SCA family registries.** Copy `conf.d/sca-registries.conf.disabled` to `sca-registries.conf`. govulncheck also needs `storage.googleapis.com` (fixed in the file after 2.2.0). Dependency-Check needs an NVD API key in `/etc/pathos/sca.env` in practice: without one it failed on every repository (exit 13).
- [ ] **DAST targets.** Add each application host (`conf.d` override for private addresses). Scan only systems the customer has authorized in writing, and record that in the target's authorization statement.
- [ ] **LLM endpoint targets:** add the endpoint host.
- [ ] **Outbound from api/jobs** (SCM APIs, AI providers, webhooks, feeds) goes through the `edge` network. Set `PATHOS_HTTPS_PROXY` if the customer forces a proxy.

## 7. Which family worker images to enable

Start with `worker-core` only, which covers secrets, SAST (Opengrep), SCA (Trivy, Grype, OSV), IaC (Checkov), CI/CD (actionlint, zizmor), licences and the SBOM. Add families by need, one at a time, and watch memory.

| Family | Enable when | Validation result (2.2.0 plus fixes) | Notes |
|---|---|---|---|
| `sast` | Polyglot code bases; PHP (Psalm), Go (gosec) | Works after fixes (language tools skipped when absent; Psalm report path) | Talisman produces thousands of low-severity "base64/hex content" findings per repository. Leave it out of profiles. detect-secrets took 13+ minutes on juice-shop. |
| `iac` | Terraform, Kubernetes, Helm, CloudFormation customers | Works after the Kubescape fix | KICS and Trivy config find the most issues |
| `sca` | Need language auditors, malicious-package checks, cdxgen | Partial: pip-audit and cdxgen fixed; govulncheck needs `storage.googleapis.com`; Dependency-Check needs an NVD API key | Needs `sca-registries.conf` |
| `dast` | Customer wants DAST of staging apps | Works: Nuclei, ZAP baseline, ZAP API scan (found SQLi and XSS), Schemathesis; intrusive gate enforced. Wapiti, Dalfox, ffuf and Arjun were not reached (Nuclei stalled first on the test API) | Nuclei alone takes 10–30 minutes per target at 20 req/s. Set the repository's profile timeout to 5400 s and the target's rate limit as high as the application allows. Partial Nuclei results are discarded on timeout |
| `mobile` | Android/iOS apps | Works (InsecureBankv2.apk: 634 findings) | Upload the APK/IPA as a mobile app target |
| `binary` | Firmware or shipped binaries | Works. CVE Binary Tool needs its database built first (`cve-db-update`, about 600 MB) | |
| `ai` | AI applications, model files, LLM endpoints | ModelScan works. garak and promptfoo: see the report | LLM endpoint scans need intrusive authorization |
| `fuzz` | Go/Python libraries with fuzz harnesses | Works for self-contained modules. Modules with dependencies fail to build offline ("build-failed"), and the scan still reports *succeeded* | Starts a sandbox runner; keep one runner per fuzz worker |

- [ ] Set `PATHOS_WORKER_MEMORY`/`PATHOS_WORKER_TMPFS` per family, with a Compose override if they need to differ.
- [ ] **Repository onboarding.** The SCM providers (GitHub, GitLab, Bitbucket, Azure DevOps) all **require a token**. There is no anonymous public-repository import, no generic git-URL import and no Gitea/Forgejo provider. For anything else, use archive upload. The AI fix proposals need an SCM connection; they are not available for uploaded repositories.

## 8. Backups and a restore test

- [ ] Nightly cron: `deploy/scripts/backup.sh --keep 14`. Copy `backups/` off the host and keep `.env`/the master key in the vault ([OPERATIONS.md](OPERATIONS.md#backup)). **(validated: online backup of the validation stack, 209 MB, in 11 s)**
- [ ] **Restore test before go-live** and then quarterly: on a staging host with the same `.env`, run `deploy/scripts/restore.sh backups/<dir> --yes`, sign in, and check the counts of repositories, findings and scans. **(validated: see the report)**
- [ ] With S3 object storage, back up the bucket too, because artifacts and source snapshots are no longer in PostgreSQL.

## 9. Upgrades

- [ ] Read the CHANGELOG. Check out the new tag, set `PATHOS_VERSION`, run `deploy/scripts/upgrade.sh --pull` (it takes a backup first) and verify with `scripts/smoke-test.py`.
- [ ] Keep the previous tag and the backup path the script prints, for rollback with `restore.sh`.
- [ ] Upgrade the `pathos` CLI in CI (`integrations/install-cli.sh` verifies the checksum and signature).

## 10. Monitoring

- [ ] `OTEL_EXPORTER_OTLP_ENDPOINT` points at the customer's collector. Alert on: `pathos.scheduler.leader` = 0 for 2 minutes, `pathos.workers.online` = 0 for 5 minutes, `pathos.scan.jobs{status="queued"}` growing for 30 minutes, `pathos.notifications.pending` > 100, and API 5xx > 1 % ([OPERATIONS.md](OPERATIONS.md#monitoring)).
- [ ] Route the built-in "worker offline" and "missed schedule" notifications to an on-call list.
- [ ] Watch the execution status ratio. In the validation, 2.2.0 without fixes had a scan success rate of 86 % on the dashboard. Every family-profile scan was *partial* for avoidable reasons.
- [ ] Logs: JSON on stdout. With the production override, 5 × 20 MB per container. Ship them to the customer's log system.
- [ ] Host: memory (the swap was full on the validation host), the `scanner_cache` and `sources` volume sizes, and the PostgreSQL slow-query log (≥ 1 s).

## 11. Multi-tenancy (optional)

Use it only if one installation must serve several separate customers or business units with isolated data ([MULTI_TENANCY.md](MULTI_TENANCY.md), [OPERATIONS.md](OPERATIONS.md#multi-tenancy)). For 50 customers, **one installation per customer** is simpler and isolates them better. Use multi-tenancy only for small tenants on a shared host.

- [ ] `PATHOS_INSTALLATION_ADMIN_EMAIL`, then `pathosctl multi-tenancy enable`, then restart `api jobs scheduler`.
- [ ] Run **one set of workers per organization** (`PATHOS_WORKER_ORGANIZATION=<slug>`, a separate Compose project). Workers are never shared, so the memory need grows with each tenant.
- [ ] Remember that the vulnerability feeds and the scanner catalog are shared, and that readable keys (QD-REPO-…) are installation-wide sequences.
- [ ] Watch slow queries after enabling it. Row-level security can turn `lower(...)` lookups into sequential scans.

## 12. Known limits (2.2.0, from the validation)

- The SCM import needs a token for every provider, including public repositories. There is no Gitea/Forgejo provider and no git-URL import.
- One running execution per repository, including target scans. Result imports return 409 while any scan of the repository runs.
- Private CAs are not configurable for registries, webhooks or ticketing.
- Go tools (gosec, golangci-lint, the fuzzers) run with `GOPROXY=off`. On modules with non-vendored dependencies they report type errors or "build-failed" instead of findings, and gosec can run out of memory.
- Secret scanners in the SAST family (Talisman, detect-secrets) are noisy: 15,000+ "exposed secrets" across 15 repositories.
- The dashboard, posture and executive pages are slow above about 1 million findings ([PERFORMANCE.md](PERFORMANCE.md)).
- Jira/ServiceNow and the S3 artifact store against AWS itself were not tested.
