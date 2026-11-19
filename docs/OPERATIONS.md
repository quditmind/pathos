# Operations runbook

Day-2 operations for a PATHOS installation deployed with Docker Compose. Every command runs from the repository root.

## Production deployment

1. Run `./deploy/scripts/install.sh`. It generates `.env` (mode 600) with fresh secrets.
2. Edit `.env`:
   - `PATHOS_PUBLIC_URL` and `PATHOS_DOMAIN`, plus `CADDY_TLS=<email>` for a Let's Encrypt certificate.
   - `COMPOSE_PROFILES=` (empty: no Mailpit).
   - The real SMTP relay: `PATHOS_SMTP_*`, with STARTTLS and auth.
   - `PATHOS_COMPOSE_PROD=1`.
   - `KEYCLOAK_ADMIN_ALLOW=<admin network CIDRs>`. This is required in production mode.
   - Optionally `PATHOS_REQUIRE_MFA=true`.
3. Start the stack:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --wait
   ```

   The production override adds:
   - memory and CPU limits per service;
   - bounded JSON logs (5 × 20 MB per container);
   - PostgreSQL tuning for 8–16 GB hosts (`shared_buffers=1GB`, slow-query log ≥ 1 s);
   - a hot-standby scheduler replica.

   It also enforces production mode.
4. Back up `PATHOS_MASTER_KEY` outside the host (vault or password manager). Without it, stored credentials cannot be decrypted.
5. Run `make smoke` to verify the deployment end to end.

The deploy scripts (`backup.sh`, `upgrade.sh`, `restore.sh`) pick up the production override automatically when `PATHOS_COMPOSE_PROD=1`.

## Installing a release (signed images)

Each tagged release publishes these images to the GitHub Container Registry, built and tested by the release workflow:
- `ghcr.io/quditmind/pathos`
- `ghcr.io/quditmind/pathos-proxy`
- `ghcr.io/quditmind/pathos-worker-core`
- `ghcr.io/quditmind/pathos-worker-sast` (opt-in [family worker image](#family-worker-images), built on the signed `pathos-worker-core` of the same release)
- `ghcr.io/quditmind/pathos-worker-dast` (opt-in family worker image for web application and API targets, without sqlmap and Nikto)
- `ghcr.io/quditmind/pathos-worker-mobile`, `pathos-worker-binary`, `pathos-worker-ai` and `pathos-worker-fuzz` (opt-in family worker images, built the same way)

Use them instead of building locally:

```bash
git clone --branch v2.2.0 https://github.com/quditmind/pathos.git && cd pathos
./deploy/scripts/install.sh                 # new installs only
# in .env:  PATHOS_IMAGE_PREFIX=ghcr.io/quditmind/   PATHOS_VERSION=2.2.0
deploy/scripts/upgrade.sh --pull
```

Upgrading to a later release works the same way: check out the new tag, set `PATHOS_VERSION`, and run `upgrade.sh --pull`.

**Verify before you deploy.** Every image is signed with cosign (keyless) by the release workflow at its tag:

```bash
cosign verify ghcr.io/quditmind/pathos:2.2.0 \
  --certificate-identity "https://github.com/quditmind/pathos/.github/workflows/release.yml@refs/tags/v2.2.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The images also carry an SBOM and SLSA provenance attestations. Inspect them with `docker buildx imagetools inspect <image> --format '{{json .SBOM}}'` (or `.Provenance`). The images are built for `linux/amd64`.

## Air-gapped operation

See [AIRGAP.md](AIRGAP.md): images and vulnerability data as offline bundles (`scripts/offline-bundle.sh`), `PATHOS_OFFLINE=true`, and what changes without internet access.

## Backup

```bash
deploy/scripts/backup.sh --keep 14            # e.g. nightly from cron
```

A backup is an online snapshot (no downtime) written to `backups/pathos-<UTC>/`:

| File | Contents |
|---|---|
| `pathos.dump`, `keycloak.dump` | `pg_dump` custom format, each a consistent snapshot |
| `caddy_data.tgz` | TLS certificates and the local CA |
| `objectstore.tgz` | Scan artifacts (and source snapshots when S3 is configured), when the `objectstore` profile runs |
| `sources.tgz` | Uploaded archives and source snapshots from the `sources` volume (encrypted with the master key) |
| `manifest.json` | PATHOS version, schema version, SHA-256 of every file |

`--with-env` also copies `.env`, which holds every secret including the master key. Store such backups encrypted. Without `--with-env`, restoring needs the original `.env`, or at least the same `PATHOS_MASTER_KEY` and database role passwords.

Cron example (02:30 daily, keep two weeks):

```cron
30 2 * * * cd /opt/pathos && deploy/scripts/backup.sh --keep 14 >> backups/backup.log 2>&1
```

Copy `backups/` off the host (object storage, backup system). Measured in platform phase P8: a backup of a 2.7 MB installation took 2 s, and the restore took 40 s, including Keycloak start-up.

### Data, volumes and the master key

- Data lives in named volumes: `pg_data`, `redis_data`, `caddy_data`, `sources` (uploaded archives, source snapshots, Human Eye evidence), `scanner_cache`, plus `s3_data` with the `objectstore` profile. `docker compose down` keeps them; **`docker compose down -v` deletes all data**.
- **Back up `PATHOS_MASTER_KEY` separately** (vault or password manager). Without it, stored credentials, source snapshots and evidence cannot be decrypted. It is not in the `backup.sh` output unless you pass `--with-env`.

## Restore

```bash
deploy/scripts/restore.sh backups/pathos-20261115T133141Z --yes
```

The restore script:
1. Verifies every checksum.
2. Refuses a backup newer than the installed release.
3. Stops the application services.
4. Recreates and restores both databases.
5. Restores certificates and object storage.
6. Runs migrations (so a backup from an older release is upgraded).
7. Starts everything and waits for health checks.

Sessions are not restored, so users sign in again.

## Upgrade

```bash
git fetch && git checkout <new release tag>
deploy/scripts/upgrade.sh            # builds images; --pull for registry images
```

The upgrade script:
1. Validates the configuration.
2. Takes a backup.
3. Builds or pulls the images.
4. Recreates the services. The one-shot `migrate` service applies database migrations before `api`, `jobs` and `scheduler` start.
5. Waits for every health check, then prints the version and schema change.

If the upgrade does not become healthy, it prints the rollback command: check out the previous release, then run `restore.sh <backup> --yes`.

## Multi-tenancy

One installation can host several isolated organizations ([MULTI_TENANCY.md](MULTI_TENANCY.md)). It is **off** by default; an install with multi-tenancy off behaves exactly as before.

**Upgrade.** Migrations 00040–00042 run with every upgrade. On a single-organization install they add row-level security policies (not enforced), installation tables, and composite same-organization foreign keys; the existing organization (`PATHOS_ORG_SLUG`) stays the only one. Validating the new foreign keys reads every referencing table once, so the migration takes longer on large databases. Nothing else changes.

**Enable:**

1. Set `PATHOS_INSTALLATION_ADMIN_EMAIL` in `.env` (the person who will manage organizations; at the first sign-in with a verified email they also join the default organization, without roles) and run `deploy/scripts/upgrade.sh` (or `docker compose up -d`).
2. Turn multi-tenancy on and restart the services that read the mode at startup:
   ```bash
   docker compose run --rm --entrypoint pathosctl migrate multi-tenancy enable
   docker compose restart api jobs scheduler
   ```
   `pathosctl multi-tenancy status` prints the mode and any table that would not be isolated (there must be none; the API refuses to start in multi-tenant mode otherwise).
3. Existing realms: `keycloak-setup` adds the `groups` claim mapper to the `pathos-web` client on its next run (`docker compose up -d keycloak-setup`); new realms have it.
4. Sign in as the installation administrator: **Installation → Organizations** creates organizations (optionally inviting each one's first super administrator by email). People join an organization by invitation, or through a Keycloak group `/pathos/<slug>`.
5. Start one set of workers per organization with `PATHOS_WORKER_ORGANIZATION=<slug>` (for example a second Compose project with its own `.env` that sets it; workers without it serve the default organization). Workers are never shared between organizations.

`pathosctl installation-admin grant|revoke <email>` and `pathosctl installation-admin list` manage installation administrators; `pathosctl organizations` lists organizations with their status.

**Disable:** `pathosctl multi-tenancy disable` works only while one organization exists (delete the others first). With more than one organization and multi-tenancy off, the API, jobs and scheduler refuse to start.

**Rolling back** below migration 00041 drops the multi-tenancy setting; re-applying the migrations leaves multi-tenancy off, and the services then refuse to start while several organizations exist until `pathosctl multi-tenancy enable` is run again.

**Performance.** With row-level security enforced, PostgreSQL cannot use an index for conditions on functions that are not leakproof (such as `lower(name)`) before the policy; lookups by name can scan the organization's rows. Not measured at production volumes; watch the slow query log after enabling it.

## Scaling

| Component | How | Notes |
|---|---|---|
| Scan throughput | `docker compose up -d --scale worker-core=N` (and `--scale worker-sast=N` for family workers) | 1–4 GB RAM per concurrent scan (`PATHOS_WORKER_MEMORY`). Jobs are leased with `SKIP LOCKED`, so any number of workers is safe; scans that use family tools go to family workers |
| Scheduler | `--scale scheduler=2` (production default) | Postgres advisory-lock leader election; standbys take over within 15 s |
| Background jobs | `--scale jobs=N` | Notification, e-mail, webhook, AI review and import queues all use `SKIP LOCKED` claims |
| API | Vertical first: one replica served 80 req/s at p95 < 500 ms with 100k findings (platform phase P8 load test) | Sessions are in Valkey, and rate limits are shared through Valkey. With 1 million findings the database is the limit, not the API: see [PERFORMANCE.md](PERFORMANCE.md) for measurements and sizing |

## Monitoring

- **Health:**
  - `docker compose ps` shows every service's health check.
  - **Scan schedules** in the UI shows scheduler leadership, heartbeat, worker health and queue depth.
  - **Scanners & workers** lists each worker's last contact.
- **Notifications:** the built-in rules email platform administrators about offline workers and missed schedules. Route them to an on-call list in Administration → Notifications.
- **OpenTelemetry:** set `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP/HTTP) to export:
  - **Traces:** server spans named by route (e.g. `GET /api/v1/findings/{id}`), with W3C trace context propagation. `trace_id` appears in access logs.
  - **Metrics:** HTTP server duration and size by route and status, Go runtime metrics, and platform gauges from the scheduler leader: `pathos.scan.jobs{status}`, `pathos.workers.online`, `pathos.notifications.pending`, `pathos.notification_events.backlog`, `pathos.findings.open{severity}` and `pathos.scheduler.leader`.

  The standard `OTEL_*` variables (headers, sampler) apply. For evaluation, `COMPOSE_PROFILES=observability` starts Grafana LGTM on http://127.0.0.1:3001 with `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-lgtm:4318`.
- **Logs:** JSON on stdout, with secrets redacted and a request ID (`X-Request-Id`) on every API response.

Suggested alerts:
- `pathos.scheduler.leader` summed to 0 for 2 minutes.
- `pathos.workers.online` at 0 for 5 minutes.
- `pathos.scan.jobs{status="queued"}` growing for 30 minutes.
- `pathos.notifications.pending` above 100.
- API 5xx rate above 1 %.

## Two-factor authentication

- **Everyone:** set `PATHOS_REQUIRE_MFA=true` and recreate the API (`docker compose up -d api`). Within a minute, and then hourly, every active or invited user without an authenticator is required to enrol one at the next sign-in. That includes your own administrator account, so have your phone's authenticator app ready.
- **Individual users:** open **Users**, choose the user and click **Require MFA**. The drawer shows whether two-factor is enabled, pending or not set up.
- **Recovery codes:** users who set them up sign in with a code when they lose their authenticator (see the [user guide](user-guide/sign-in-and-sso.md#recovery-codes)). The `keycloak-setup` service enables them on every `docker compose up`; if it fails, `docker compose logs keycloak-setup` shows why.
- **Lost authenticator without recovery codes:** an administrator removes the user's OTP credential in the Keycloak admin console (Users → Credentials). Requiring MFA again then starts a fresh enrolment.

## Repository imports

- Imports run in the `jobs` container: `PATHOS_IMPORT_CONCURRENCY` workers per container (default 2), each item bounded by `PATHOS_IMPORT_TIMEOUT` (default 30m). Scale out by running more `jobs` replicas; items are claimed with `FOR UPDATE SKIP LOCKED` and leases, so a crashed worker's items are picked up again within a few minutes.
- Transient provider errors are retried with exponential backoff (3 attempts). Failed items stay visible in **Import history** and can be retried; `import.failed` and `repository.sync_failed` notifications go to the requester and the asset owners and platform administrators.
- Uploads are limited by `PATHOS_UPLOAD_MAX_BYTES` and the archive limits `PATHOS_IMPORT_MAX_FILES`, `PATHOS_IMPORT_MAX_EXTRACTED_BYTES` and `PATHOS_IMPORT_MAX_FILE_BYTES`. Unfinished uploads are deleted after 24 hours; sync history is kept for 180 days.
- Disk: the `sources` volume holds one encrypted snapshot per uploaded version (roughly the compressed size of the code). The `import_work` volume needs free space for the largest archive being processed at once, per worker.
- OAuth tokens are refreshed before they expire (every 10 minutes for tokens expiring within 30 minutes). A connection whose refresh is rejected is marked *expired* and must be reconnected.

## Malware scanning (ClamAV)

1. Add `clamav` to `COMPOSE_PROFILES` and set `PATHOS_CLAMAV_ADDRESS=clamav:3310`. The `clamav` service needs about 2 GB of RAM and downloads signatures through the `edge` network (`freshclam`).
2. Optionally set `PATHOS_CLAMAV_REQUIRED=true`: uploads then wait (source imports) or are refused (build artifacts) while ClamAV is unavailable, instead of proceeding unscanned.
3. `PATHOS_CLAMAV_STREAM_MAX` (default `4000M`) and `PATHOS_CLAMAV_MAX_FILE` (default `1000M`) set clamd's stream and file limits; keep the stream limit above `PATHOS_UPLOAD_MAX_BYTES`.

Source archives are scanned by the `jobs` service; build artifacts are scanned by the `api` service when they are uploaded. `docker-compose.yml` passes `PATHOS_CLAMAV_ADDRESS` and `PATHOS_CLAMAV_REQUIRED` to both services, so one setting covers both.

The same setting enables the **`clamav` scanner** (malware in repository content) in `worker-core`: add **ClamAV (repository content)** to a scan profile. The worker streams each file of the checkout to clamd over the internal `malware` network, which only `worker-core` and `clamav` join, so workers stay off the `data` network. Without `PATHOS_CLAMAV_ADDRESS` the scanner is skipped (*ClamAV is not configured for this worker*); when it is set but clamd does not answer, the scanner fails and the worker does not report its version. Files larger than `PATHOS_CLAMAV_STREAM_MAX`/`PATHOS_CLAMAV_MAX_FILE` are reported as *File could not be scanned for malware* findings. A worker on another host needs its own network path to clamd and the variable in its environment.

## Family worker images

Family images add groups of tools, defined by [tool manifests](SCANNER_CATALOG.md#adding-a-tool-tool-manifests), to the worker. Each family image is built on `worker-core` of the same version (it runs every core tool too), has its own Compose profile and the same isolation as `worker-core`: read-only root file system, no capabilities, unprivileged user, tmpfs workspace, the egress proxy as the only route out, and the `scan`, `worker-api` and `malware` networks.

| Family | Profile | Service | Tools |
|---|---|---|---|
| SAST | `sast` | `worker-sast` | Bandit, njsscan, ShellCheck, gosec, Flawfinder, cppcheck, PHPStan, Psalm, Ruff, ESLint + eslint-plugin-security, Semgrep CE, Bearer CLI (optional, Elastic-2.0), TruffleHog, detect-secrets, Kingfisher, Talisman, Pylint, golangci-lint |
| IaC and CI/CD | `iac` | `worker-iac` | KICS, KubeLinter, Kubescape, TFLint, Conftest (PATHOS policies), Hadolint, cfn-lint, cfn_nag, Polaris, kube-score, Trivy (config), OpenSSF Scorecard (`--local`) |
| SCA, malicious packages and SBOM | `sca` | `worker-sca` | govulncheck, pip-audit, cargo-audit, bundler-audit, Retire.js, npm/yarn/pnpm audit, Composer audit, OWASP Dependency-Check, GuardDog, pathos-depcheck, cdxgen, pathos-reach |
| DAST | `dast` | `worker-dast` | OWASP ZAP (baseline, full and API scans), Wapiti, Dalfox, ffuf, testssl.sh, SSLyze, Schemathesis, Arjun; sqlmap and Nikto only in an opt-in build ([DAST tools](user-guide/dast.md)) |
| Mobile | `mobile` | `worker-mobile` | mobsfscan, APKLeaks, Quark-Engine, mobile app checks (mobile app targets) |
| Binary | `binary` | `worker-binary` | CVE Binary Tool, capa, YARA-X (build artifacts; YARA-X also mobile apps and repositories) |
| AI | `ai` | `worker-ai` | ModelScan (repositories, model artifacts), garak and promptfoo (LLM endpoint targets) |
| Fuzzing | `fuzz` | `worker-fuzz` | Go native fuzzing, Atheris (repositories; builds and runs repository code) |

To enable one:

1. Add the profile to `COMPOSE_PROFILES` in `.env` (for example `COMPOSE_PROFILES=sast`, or `clamav,sast`).
2. Build or pull the image: `docker compose --profile sast build worker-sast` builds `worker-core` first and then the family image on top of it; with released images (`PATHOS_IMAGE_PREFIX`), `deploy/scripts/upgrade.sh --pull` pulls it.
3. Start it: `docker compose up -d worker-sast`. The worker registers with `PATHOS_WORKER_FAMILY=sast` and advertises its tools; they appear as runnable in **Configurations → Scanners & workers** and **Scan coverage**.
4. Add the tools to a scan profile (for example Bandit and ShellCheck).

Routing: a scan that uses a family tool is leased only by a worker that advertises it (every family tool of the scan), so keep at least one family worker running while profiles use its tools. When no online worker has all the tools a scan needs, any worker runs the scan and records the missing tools as *skipped* (*scanner not available in this worker image*). `worker-core` keeps running the scans that use core tools only; both kinds can be scaled (`--scale worker-sast=N`).

The family tools of `worker-sast` and `worker-iac` declare `network: none`: they run without the egress proxy variables and need no allowlist entry (Kubescape's frameworks, KICS' queries and Trivy's misconfiguration checks are part of the image). In `worker-sca`, cargo-audit, bundler-audit, Retire.js, pathos-depcheck, cdxgen and pathos-reach are offline too (advisory snapshots in the image). The others declare `network: registry` and need their registry, which the default allowlist does not contain: govulncheck (`proxy.golang.org`, `sum.golang.org`, `vuln.go.dev` and `storage.googleapis.com`, where the Go module proxy redirects downloads), pip-audit (`pypi.org`), npm, yarn and pnpm audit (`registry.npmjs.org`), Composer audit (`packagist.org`, `repo.packagist.org`), Dependency-Check (`nvd.nist.gov`, or `services.nvd.nist.gov` with an API key) and GuardDog (`pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`). To allow them, rename `deploy/egress/conf.d/sca-registries.conf.disabled` to `sca-registries.conf` (or copy the lines you need) and restart `egress`; without it those tools fail with a connection error. Optional settings for these tools (an NVD API key, a Go module proxy or vulnerability database mirror, a private npm registry) go in a file mounted read-only at `/etc/pathos/sca.env` in `worker-sca` (`NVD_API_KEY=…`, `NVD_DATAFEED_URL=…`, `GOPROXY=…`, `GOVULNDB=…`, `NPM_CONFIG_REGISTRY=…`; other lines are ignored), because the worker passes tools a scrubbed environment. Dependency-Check keeps the NVD data in the worker's cache volume; the first run downloads it (about 250 MB). The tools of `worker-dast` declare `network: target`: they run only for web application and API targets with an authorization statement (intrusive ones also need the target's intrusive testing flag), are added to a target under **Additional tools** rather than to a scan profile, and reach only the target's host through a local scope proxy and then the egress proxy, so the target's host must be on the egress allowlist. Its image is about 1 GB larger than `worker-core` (Java runtime and ZAP). `PATHOS_DAST_WITH_SQLMAP=true` and `PATHOS_DAST_WITH_NIKTO=true` in `.env` build sqlmap and Nikto into it (licence terms in [DAST tools](user-guide/dast.md#opt-in-tools-sqlmap-and-nikto)). The family tools of `worker-mobile`, `worker-binary` and `worker-fuzz`, and ModelScan, also declare `network: none`. garak and promptfoo (`worker-ai`) send requests to an LLM endpoint target through the egress proxy: add the endpoint's host to `deploy/egress/allowlist.txt`. Released family images are signed like the others (`cosign verify ghcr.io/quditmind/pathos-worker-sast:<version> …`). `scripts/security-scan.sh` scans every family image that is built locally (CI requires them).

Mobile app and artifact tools are selected on the scan target (**Scan targets → Additional tools**); repository tools (YARA-X, ModelScan, the fuzzers, the AI-BOM) in a scan profile.

### Mounted rule sets

| Variable | Mounted at | Used by |
|---|---|---|
| `PATHOS_QUARK_RULES_DIR` (default `workers/mobile/quark-rules-extra`, empty) | `/opt/pathos/mobile/quark-rules-extra` in `worker-mobile` | Quark-Engine, in addition to the PATHOS rules (for example the community quark-rules set, which has no licence and is therefore not bundled) |
| `PATHOS_YARA_RULES_DIR` (default `workers/binary/yara-extra`, empty) | `/opt/pathos/binary/yara-extra` in `worker-binary` | YARA-X, in addition to the bundled ReversingLabs and PATHOS rules; compiled at scan time |

### CVE Binary Tool database

CVE Binary Tool (`worker-binary`) matches component versions against a vulnerability database in the worker's cache volume (`/cache/plugins/cve-bin-tool`). The image contains no database and scans never download one: until it is installed, the tool's result is *failed* with a hint. The database is built from the NVD JSON 2.0 feeds (through `cveb.in`, the mirror the CVE Binary Tool project maintains) and curl's advisories (`curl.se`); it is about 600 MB.

Connected installation (the container uses Docker's default network, not the worker networks; run it again to refresh, for example weekly):

```bash
docker run --rm -v pathos_scanner_cache:/cache --entrypoint /opt/pathos/binary/bin/pathos-binary \
  ${PATHOS_IMAGE_PREFIX}pathos-worker-binary:${PATHOS_VERSION} cve-db-update /cache/plugins/cve-bin-tool
```

Air-gapped installation: run the same command on a connected machine with a scratch volume, export the database (`cve-db-export /cache/plugins/cve-bin-tool /cache/cve.db`), copy the file into the air-gapped installation's cache volume and import it there (`cve-db-import /cache/plugins/cve-bin-tool /cache/cve.db`, `--network none`). The volume name depends on the Compose project (`docker volume ls | grep scanner_cache`).

### Fuzzing worker

`worker-fuzz` builds and runs code from the repositories it scans (Go fuzz targets, Atheris harnesses). The worker never runs that code itself. The `fuzz` profile also starts `worker-fuzz-sandbox`, the sandbox runner: the same image with `network_mode: none`, UID 10002, no worker token, and its own memory, CPU and process limits (`PATHOS_FUZZ_MEMORY`, default 4g; `PATHOS_FUZZ_CPUS`, default 2; `PATHOS_FUZZ_PIDS`, default 256). The worker hands it each run through the `fuzz_sandbox` volume, a tmpfs of `PATHOS_FUZZ_SANDBOX_TMPFS` (default 4g). Repository code therefore has no network at all and cannot reach the egress proxy, the API or the worker's credentials ([SECURITY.md](SECURITY.md#scanning)). The fuzzers also run with `GOPROXY=off`, on a copy of the checkout, under per-target CPU-time, file-size and memory limits and a time budget (`FUZZ_SECONDS`, `FUZZ_TOTAL_SECONDS`, `FUZZ_MAX_TARGETS` in `workers/fuzz/tools.d`).

- If `worker-fuzz-sandbox` is not running, fuzzing runs fail after 60 s with "the sandbox runner did not pick the run up". If the worker has no `PATHOS_SANDBOX_DIR`, the fuzzers are skipped with a reason. Other tools of the worker are not affected.
- Run one `worker-fuzz` replica per runner. The worker locks the volume, and a second replica on the same volume skips the fuzzers. Do not set `init: true` on the runner: it must be PID 1 of its container.
- No host or Docker daemon change is needed: no privileged mode, capability, custom seccomp or AppArmor profile, and no Docker socket. Rootless Docker has not been tested.
- `workers/fuzz/test/sandbox-e2e.sh [image]` checks the isolation of a built image: a malicious fuzz harness must fail to reach the network, the worker's environment and anything outside its job directory.

## Endpoint verification, end-of-life data and signatures

- **Declared endpoint verification** runs on `worker-core` through the egress proxy. Add the declared hosts to `deploy/egress/allowlist.txt` (and, for private addresses, an override in `deploy/egress/conf.d`) and restart `egress`; hosts the proxy refuses are reported as *Blocked by egress proxy*. Only ports 80 and 443 pass the default proxy configuration.
- **End-of-life data**: enable the `endoflife` feed in **Risk & intelligence** (daily download of about 3 MB from `endoflife.date` by the `jobs` service through `PATHOS_HTTPS_PROXY` when set), or import the file offline. The `jobs` service also recomputes end-of-life statuses daily.
- **Signature verification** uses the `cosign` binary in `worker-core`. Keyless verification needs `tuf-repo-cdn.sigstore.dev`, `rekor.sigstore.dev` and `fulcio.sigstore.dev`, which the default egress allowlist contains; remove them to allow key-based verification only. Signatures in private registries use the target's registry credentials.
- **Introducing commits** need full history: set **Clone full history** on the repository (larger clones, slower scans). Shallow clones record the introducing commit as unknown.

## Secret validation egress

[Live secret validation](user-guide/secret-validation.md) is off until an administrator enables providers in **Administration → Secret validation**. The worker contacts a provider only through the egress proxy, so each enabled provider also needs its host in `deploy/egress/allowlist.txt` (then `docker compose restart egress`):

```text
# Live secret validation (add only the providers you enable)
sts.amazonaws.com
gitlab.com
slack.com
api.stripe.com
api.openai.com
api.anthropic.com
api.sendgrid.com
api.twilio.com
registry.npmjs.org
generativelanguage.googleapis.com
.blob.core.windows.net
```

GitHub needs no line: `api.github.com` is covered by the default `.github.com` entry (do not add it again; Squid warns about overlapping entries). A provider that is enabled but not allowed fails closed: its findings show *Check failed* with the proxy's refusal, and the secret is not sent. The proxy's access log shows host names only (the requests are HTTPS `CONNECT` tunnels); credentials are never in a URL. There is no configuration to change the provider hosts.

## Kubernetes runtime inventory

The runtime connectors ([user guide](user-guide/runtime.md)) are optional; nothing is contacted until an administrator adds a cluster or a registry under **Assets → Runtime**.

- **Who connects.** Only the `jobs` service synchronises clusters and registries (every minute it picks the connections that are due or whose **Sync now** was requested). The API server stores the request and never calls a cluster or a registry. `jobs` is on the `edge` network: the cluster API server and the registries must be reachable from it. Requests go through `PATHOS_HTTPS_PROXY` when it is set; add private API servers to `NO_PROXY` in that case.
- **Address checks.** The resolved address is checked at connect time: loopback, link-local, cloud metadata, CGNAT and multicast addresses are always refused; RFC 1918 and ULA addresses need **The API server is on a private network address** (per connection). Only `https` is accepted (registries also `http` with `PATHOS_SCM_ALLOW_HTTP=true`, for development). Redirects are followed only to the same host, except blob downloads of registries, which may redirect to an `https` storage host.
- **The ClusterRole.** Apply `deploy/kubernetes/pathos-reader-clusterrole.yaml` in each cluster. It creates the `pathos-reader` namespace, the `pathos-reader` service account (token not mounted in any pod), a `kubernetes.io/service-account-token` Secret for it and a ClusterRole with `get`, `list` and `watch` on `namespaces`, `pods`, `services`, `deployments`, `replicasets`, `statefulsets`, `daemonsets`, `jobs`, `cronjobs`, `ingresses` and `networkpolicies`, and nothing else (no Secrets, ConfigMaps, `pods/log`, `pods/exec` or write verbs). A unit test checks that the role grants exactly what the inventory lists. To restrict PATHOS to some namespaces, replace the ClusterRoleBinding with a RoleBinding to the same ClusterRole in each namespace and list the namespaces in the cluster's settings (namespace objects are then not listed).
- **Rotation.** Delete and re-create the `pathos-reader-token` Secret, then paste the new token into the cluster's settings (**Edit**, Token). Deleting the cluster in PATHOS deletes its encrypted credential and its inventory.
- **Load.** One synchronisation issues one paginated `GET` list per resource kind (500 objects per page, at most 20,000 per kind), per namespace when namespaces are configured, with a 10-minute timeout. Registries: one request per tag list page, manifest and configuration blob, spaced 200 ms apart, at most `max_tags` tags per repository.
- **Air-gapped installations** can connect clusters and registries on the internal network; `PATHOS_OFFLINE` does not disable them.
- **Retention.** Workloads, namespaces and network objects that a complete synchronisation no longer sees are deleted; a partial synchronisation (a resource the role does not grant) removes nothing. Synchronisation runs are kept with their connection.
- **Integration tests** use a fake Kubernetes API server (`httptest`) and, when `PATHOS_TEST_REGISTRY_URL` is set, a `registry:2` container; they never contact a real cluster.

## Configuration reference

`.env.example` documents the settings an installation normally changes. The table lists every variable the PATHOS services read, with the service that reads it. Variables marked *code only* are not passed through by `docker-compose.yml`; add them to the service's `environment` in an override file to change them.

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `PATHOS_PUBLIC_URL`, `PATHOS_DOMAIN` | api, jobs, keycloak, proxy | `https://localhost`, `localhost` | Public address |
| `PATHOS_HTTPS_PORT`, `PATHOS_HTTP_PORT`, `CADDY_TLS` | proxy | `443`, `80`, `internal` | Published ports, certificate (`internal` CA or an ACME e-mail) |
| `KEYCLOAK_ADMIN_ALLOW` | proxy | `private_ranges` | Who may reach the Keycloak admin console; required in production mode |
| `PATHOS_ENV`, `PATHOS_LOG_LEVEL` | all PATHOS services | `production`, `info` | |
| `PATHOS_ORG_NAME`, `PATHOS_ORG_SLUG` | all PATHOS services | `Default Organization`, `default` | The organization created by `migrate`; with multi-tenancy, the default organization (cannot be suspended or deleted) |
| `PATHOS_INSTALLATION_ADMIN_EMAIL` | api | empty | Becomes an installation administrator at the first sign-in with a verified email (multi-tenancy) |
| `PATHOS_OIDC_ORGANIZATION_CLAIM`, `PATHOS_OIDC_ORGANIZATION_PREFIX` | api | `groups`, `/pathos/` | ID-token claim that lists a person's organizations, and the prefix of its entries (`-`: entries are slugs) ([MULTI_TENANCY.md](MULTI_TENANCY.md#4-identity-users-memberships-and-the-switcher)) |
| `PATHOS_WORKER_ORGANIZATION` | workers | empty (default organization) | Slug of the organization a worker serves (multi-tenancy) |
| `PATHOS_MASTER_KEY`, `PATHOS_MASTER_KEYS_PREVIOUS` | all PATHOS services | generated | Envelope encryption; see [rotation](SECURITY.md#secrets-at-rest) |
| `PATHOS_DB_OWNER_PASSWORD`, `PATHOS_DB_APP_PASSWORD`, `POSTGRES_SUPERUSER_PASSWORD`, `KEYCLOAK_DB_PASSWORD`, `VALKEY_PASSWORD` | postgres, migrate, api, jobs, scheduler, valkey, keycloak | generated | Database and Valkey credentials |
| `PATHOS_OIDC_CLIENT_SECRET`, `PATHOS_KEYCLOAK_PROVISIONER_CLIENT_SECRET`, `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD` | api, keycloak, keycloak-setup | generated | Keycloak clients and the Keycloak bootstrap administrator |
| `PATHOS_BOOTSTRAP_ADMIN_EMAIL`, `PATHOS_BOOTSTRAP_ADMIN_PASSWORD` | api, keycloak | generated | The first PATHOS administrator |
| `PATHOS_SESSION_IDLE_TTL`, `PATHOS_SESSION_ABSOLUTE_TTL` | api (*code only*) | `8h`, `24h` | Session lifetime |
| `PATHOS_REQUIRE_MFA` | api | `false` | Enforce TOTP for everyone |
| `PATHOS_RATE_LIMIT_SCALE` | api | `1` | Multiplies every rate limit; `0` disables |
| `PATHOS_SMTP_HOST`, `_PORT`, `_FROM`, `_STARTTLS`, `_AUTH`, `_USER`, `_PASSWORD` | keycloak, migrate (first run only) | Mailpit | Mail relay; afterwards PATHOS e-mail is managed in the UI |
| `PATHOS_SCM_ALLOW_PRIVATE_NETWORKS` | api, jobs | `false` | Allow providers on private addresses |
| `PATHOS_SCM_ALLOW_HTTP` | api, jobs (*code only*) | `false` | Allow `http` provider URLs (development) |
| `PATHOS_HTTPS_PROXY` | api, jobs | empty | Outbound proxy for provider APIs, feeds and integrations |
| `PATHOS_OFFLINE` | api, jobs, worker-core | `false` | Air-gapped mode ([AIRGAP.md](AIRGAP.md)); also disables declared endpoint verification and keyless signature verification |
| `PATHOS_WORKER_BOOTSTRAP_TOKEN` | api, worker-core | generated | Worker registration |
| `PATHOS_WORKER_MEMORY`, `PATHOS_WORKER_TMPFS` | worker-core (Compose limits) | `4g`, `3g` | Memory limit and workspace size per worker |
| `PATHOS_SCANNER_PLUGINS_DIR` | worker-core (*code only*) | `/etc/pathos/scanners.d` | Declarative scanner adapters |
| `PATHOS_SCAN_LOG_RETENTION_DAYS` | jobs (*code only*) | `400` (minimum 360) | Execution logs and stage events |
| `PATHOS_S3_ENDPOINT`, `_REGION`, `_BUCKET`, `_ACCESS_KEY`, `_SECRET_KEY` | all PATHOS services | empty bucket = PostgreSQL | Object storage for artifacts and source snapshots |
| `PATHOS_S3_PATH_STYLE` | all PATHOS services (*code only*) | `true` | Path-style S3 addressing |
| `PATHOS_SOURCE_STORE_DIR`, `PATHOS_SOURCE_S3_PREFIX` | api, jobs | `/var/lib/pathos/sources`, `sources/` | Encrypted source store |
| `PATHOS_UPLOAD_MAX_BYTES`, `PATHOS_IMPORT_MAX_FILES`, `PATHOS_IMPORT_MAX_EXTRACTED_BYTES`, `PATHOS_IMPORT_MAX_FILE_BYTES` | api, jobs | 2 GiB, 200,000, 8 GiB, 1 GiB | Upload and archive limits |
| `PATHOS_IMPORT_CONCURRENCY`, `PATHOS_IMPORT_TIMEOUT` | jobs | `2`, `30m` | Import workers per `jobs` container, per-item timeout |
| `PATHOS_CLAMAV_ADDRESS`, `PATHOS_CLAMAV_REQUIRED` | api, jobs (`PATHOS_CLAMAV_ADDRESS` also worker-core) | empty, `false` | Malware scanning of uploads; in worker-core, the `clamav` scanner for repository content |
| `PATHOS_CLAMAV_STREAM_MAX`, `PATHOS_CLAMAV_MAX_FILE` | clamav | `4000M`, `1000M` | clamd limits |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | all PATHOS services | empty | OpenTelemetry export |
| `COMPOSE_PROFILES` | Compose | `dev` | Optional services: `dev`, `objectstore`, `clamav`, `ollama`, `observability` |
| `PATHOS_COMPOSE_PROD`, `PATHOS_IMAGE_PREFIX`, `PATHOS_VERSION` | deploy scripts, Compose | | Production override, registry images |
| `MAILPIT_UI_PORT`, `OTEL_LGTM_UI_PORT` | mailpit, otel-lgtm | `8025`, `3001` | Local UI ports |

## Rate limiting

The API rate-limits per client (GCRA, shared across replicas through Valkey):

| Class | Key | Sustained | Burst |
|---|---|---|---|
| Login and callback (`/api/auth/*`) | Client IP | 1/s | 20 |
| Unauthenticated API | Client IP | 5/s | 50 |
| Authenticated reads | User | 25/s | 150 |
| Authenticated writes | User | 5/s | 40 |
| SCM webhooks | Connection | 50/s | 200 |
| MCP | Token | 10/s | 60 |

Requests with a personal API token count against their owner's read and write limits. `PATHOS_RATE_LIMIT_SCALE` multiplies every limit (`0` disables limiting). A throttled request gets `429` with a `Retry-After` header. If Valkey is unreachable, the limiter fails open and logs a warning once a minute.

## Object storage

By default, raw scanner reports and SBOMs are stored compressed in PostgreSQL. For larger installations, move them to S3-compatible storage:

1. Choose a backend:
   - **Bundled SeaweedFS:** add `objectstore` to `COMPOSE_PROFILES`, then set `PATHOS_S3_ENDPOINT=http://objectstore:8333` and `PATHOS_S3_BUCKET=pathos-artifacts`. `install.sh` generates the keys.
   - **External S3:** set `PATHOS_S3_ENDPOINT`, `PATHOS_S3_BUCKET`, `PATHOS_S3_REGION`, `PATHOS_S3_ACCESS_KEY` and `PATHOS_S3_SECRET_KEY`. For AWS, leave the endpoint empty.
2. Run `docker compose up -d --wait`. The API creates the bucket if it is missing.
3. Move existing artifacts:

   ```bash
   docker compose run --rm --entrypoint /usr/local/bin/pathosctl migrate migrate-artifacts
   ```

   The move is resumable. Each row switches to its object only after the object is written.

   Uploads, source snapshots and Human Eye evidence written before object storage was enabled are not moved: they stay in the `sources` volume, and the API and jobs read them from there when the bucket does not have them (new objects go to the bucket only). Keep the `sources` volume mounted and in your backups as long as it holds data.

Retention deletes the database row first, then the object. A failure leaves an unreferenced object, never a dangling reference.

## AI review options

| Option | Cost model | Code leaves your network? | Setup |
|---|---|---|---|
| Cloud API (Anthropic, OpenAI, xAI) | Pay per use (API key) | Yes, redacted evidence only | AI settings → Add provider |
| **Claude Pro/Max with Claude Code** (interactive) | Your subscription | Only to your own Claude Code session | API tokens → `claude mcp add …` |
| **Self-hosted model** (Ollama, vLLM, LM Studio, llama.cpp) | Your hardware | No | Provider type "Self-hosted" |

**Claude Pro/Max.** A subscription cannot be used as an API key, so automated reviews need one of the other two options. Interactive review works with the plan you already have:
1. Create a personal API token (user menu → API tokens).
2. Run the `claude mcp add` command shown there. With the default local certificate, start Claude Code with `NODE_EXTRA_CA_CERTS=pathos-local-ca.crt claude` after exporting the CA:

   ```bash
   docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt pathos-local-ca.crt
   ```

3. Ask Claude Code to review pending findings.

Interactive reviews need a second person to approve them. On a single-person installation, enable **Allow self-approval of interactive reviews** in the AI configuration. Each self-approval is marked in the audit log.

**Self-hosted models.** Choose one of these setups:
- **Native Ollama with GPU (recommended):** install Ollama on the host and make it listen on all interfaces (`OLLAMA_HOST=0.0.0.0`, e.g. a systemd override). Then add a Self-hosted provider with base URL `http://host.docker.internal:11434/v1`.
- **Bundled profile:** add `ollama` to `COMPOSE_PROFILES`, pull a model with `docker compose exec ollama ollama pull qwen2.5-coder:7b`, and use base URL `http://ollama:11434/v1`. It runs on CPU unless you add `-f docker-compose.gpu.yml`, which needs the NVIDIA Container Toolkit.

Then create an AI configuration with that provider and the model name. Model guidance (4-bit quantized):

| Hardware | Suggested model | Notes |
|---|---|---|
| CPU only | `qwen2.5-coder:3b` / `7b` | Measured during development: about 30 s per finding with the 3B model on a 20-core CPU |
| 12 GB GPU | `qwen2.5-coder:14b` | Good balance |
| 24 GB GPU | `qwen2.5-coder:32b` | Strong |
| 48 GB+ | 70B-class models | Closest to cloud models |

The same guardrails apply as for cloud models: strict validation of the output schema, the human approval policy, and Critical findings never closed without a person. Smaller models are less consistent, so keep approval at **Always** until you trust their verdicts.

## Security self-tests

```bash
make security        # scripts/security-scan.sh
```

The script runs:
- gosec and govulncheck on the Go code.
- `npm audit` on the frontend.
- Trivy on the three PATHOS images and on the family worker images that are built locally (`PATHOS_REQUIRE_FAMILY_IMAGES=1` makes a missing one fail; CI sets it).
- An OWASP ZAP baseline against the running stack.

It exits non-zero on any gosec issue, on a reachable Go vulnerability, on a high or critical npm advisory, on a fixable high or critical image vulnerability, or on a ZAP FAIL. Reports go to `reports/security/<UTC>/`. Accepted ZAP warnings are listed with reasons in `deploy/security/zap-baseline.conf`.

### Authenticated DAST

```bash
make dast            # scripts/dast.sh --destructive-ok (disposable stacks only)
```

This runs OWASP ZAP's active API scan, signed in as the bootstrap administrator, against every endpoint in the OpenAPI definition except the login flow. **It sends attack payloads and changes data**, so never run it against an installation with real data; CI runs it on its throwaway stack. Turn rate limiting off for the scan (`PATHOS_RATE_LIMIT_SCALE=0`). Any High alert that isn't listed in `deploy/security/zap-api.conf` fails the run.

## Load tests

```bash
scripts/load/run.sh --seed --rate 20 --duration 60s --cleanup
```

The script:
1. Seeds 300 repositories and 100,000 findings.
2. Signs in as the bootstrap administrator.
3. Runs a k6 mix of dashboard, findings browsing and filtering, search, SBOM and repository calls at a constant arrival rate.
4. Removes the synthetic data.

Thresholds: error rate below 1 %, list p95 below 800 ms, detail p95 below 300 ms, dashboard p95 below 1.5 s. Above 25 req/s from one user, raise `PATHOS_RATE_LIMIT_SCALE` on the API for the test.

For tests at scale (10,000 repositories, 1 million findings and more) use a separate, disposable stack (`COMPOSE_PROJECT_NAME`, other host ports): `scripts/load/loadgen.sh seed` fills it, `scripts/load/loadgen.sh ingest` drives the worker API, and `scripts/load/scale.sh sweep|mixed|users` runs k6 against it. [PERFORMANCE.md](PERFORMANCE.md) has the commands, the results and the sizing derived from them.

## Key and credential rotation

- **Master key:** see [SECURITY.md](SECURITY.md#secrets-at-rest) (`pathosctl rotate-master-key`).
- **Worker bootstrap token:** change `PATHOS_WORKER_BOOTSTRAP_TOKEN`, then recreate `api` and the workers. Revoke old workers in **Scanners & workers**.
- **SCM, AI, SMTP, webhook, scan-target and ticket-system credentials:** replace them in the UI. They are write-only and re-encrypted on save.
- **Personal API tokens** expire after at most 90 days; users create a new token and revoke the old one under **API tokens**. Deactivating a user stops all their tokens.
