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

## Backup

```bash
deploy/scripts/backup.sh --keep 14            # e.g. nightly from cron
```

A backup is an online snapshot (no downtime) written to `backups/pathos-<UTC>/`:

| File | Contents |
|---|---|
| `pathos.dump`, `keycloak.dump` | `pg_dump` custom format, each a consistent snapshot |
| `caddy_data.tgz` | TLS certificates and the local CA |
| `objectstore.tgz` | Scan artifacts, when the `objectstore` profile runs |
| `manifest.json` | PATHOS version, schema version, SHA-256 of every file |

`--with-env` also copies `.env`, which holds every secret including the master key. Store such backups encrypted. Without `--with-env`, restoring needs the original `.env`, or at least the same `PATHOS_MASTER_KEY` and database role passwords.

Cron example (02:30 daily, keep two weeks):

```cron
30 2 * * * cd /opt/pathos && deploy/scripts/backup.sh --keep 14 >> backups/backup.log 2>&1
```

Copy `backups/` off the host (object storage, backup system). Validated in Phase 8: a backup of a 2.7 MB installation took 2 s, and the restore took 40 s, including Keycloak start-up.

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

## Scaling

| Component | How | Notes |
|---|---|---|
| Scan throughput | `docker compose up -d --scale worker-core=N` | 1–4 GB RAM per concurrent scan (`PATHOS_WORKER_MEMORY`). Jobs are leased with `SKIP LOCKED`, so any number of workers is safe |
| Scheduler | `--scale scheduler=2` (production default) | Postgres advisory-lock leader election; standbys take over within 15 s |
| Background jobs | `--scale jobs=N` | Outbox, email and AI review queues all use `SKIP LOCKED` claims |
| API | Vertical first: one replica served 80 req/s at p95 < 500 ms with 100k findings (Phase 8 load test) | Sessions are in Valkey, and rate limits are shared through Valkey |

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

`PATHOS_RATE_LIMIT_SCALE` multiplies every limit (`0` disables limiting). A throttled request gets `429` with a `Retry-After` header. If Valkey is unreachable, the limiter fails open and logs a warning once a minute.

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

Retention deletes the database row first, then the object. A failure leaves an unreferenced object, never a dangling reference.

## Security self-tests

```bash
make security        # scripts/security-scan.sh
```

The script runs:
- gosec and govulncheck on the Go code.
- `npm audit` on the frontend.
- Trivy on the three PATHOS images.
- An OWASP ZAP baseline against the running stack.

It exits non-zero on any gosec issue, on a reachable Go vulnerability, on a high or critical npm advisory, on a fixable high or critical image vulnerability, or on a ZAP FAIL. Reports go to `reports/security/<UTC>/`. Accepted ZAP warnings are listed with reasons in `deploy/security/zap-baseline.conf`.

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

## Key and credential rotation

- **Master key:** see [SECURITY.md](SECURITY.md#secrets-at-rest) (`pathosctl rotate-master-key`).
- **Worker bootstrap token:** change `PATHOS_WORKER_BOOTSTRAP_TOKEN`, then recreate `api` and the workers. Revoke old workers in **Scanners & workers**.
- **SCM, AI and SMTP credentials:** replace them in the UI. They are write-only and re-encrypted on save.
