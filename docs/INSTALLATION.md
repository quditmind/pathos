# Installation

## Requirements

- Docker Engine with the Compose plugin (v2+). Nothing else is needed on the host.
- 4+ vCPU, 8 GB RAM and 40 GB of disk for an evaluation install (see ARCHITECTURE §10 for production sizing).
- Ports 443 and 80 free, or set `PATHOS_HTTPS_PORT` / `PATHOS_HTTP_PORT`.

## Quick start

```bash
git clone https://github.com/quditmind/pathos.git && cd pathos
./deploy/scripts/install.sh      # creates .env with generated secrets, prints the admin login
docker compose up -d --wait      # first start takes 1–2 minutes (Keycloak initialises)
```

Open `https://localhost`, choose **Sign in**, and log in with the email and temporary password that `install.sh` printed. Keycloak asks you to set a new password. Your first verified login is granted **Super Administrator**.

The default certificate comes from Caddy's internal CA, so the browser warns until you trust it. Either accept the warning or trust Caddy's root certificate:

```bash
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./pathos-root.crt
```

## What runs

| Service | Purpose |
|---|---|
| `proxy` | Caddy: TLS, security headers, serves the UI, routes `/api` → api and `/auth` → Keycloak |
| `migrate` | One-shot: applies migrations, syncs the RBAC catalog, creates the organization, then exits |
| `api` | PATHOS API (role `api`) |
| `jobs` | Background work (role `jobs`): AI reviews, notification delivery (SMTP), SLA breach detection, risk-acceptance expiry, nightly SCM metadata re-sync, retention |
| `scheduler` | Scan scheduler (role `scheduler`). Leader-elected through a Postgres advisory lock, so `--scale scheduler=2` gives a hot standby |
| `postgres` | PostgreSQL 18 (databases `pathos` and `keycloak`) |
| `valkey` | Sessions and (later) the job queue |
| `keycloak` | Identity: login, MFA, password policy, federation |
| `mailpit` | Dev only (`COMPOSE_PROFILES=dev`): catches outgoing email, UI at http://127.0.0.1:8025 |

Only `proxy` publishes ports (plus Mailpit on 127.0.0.1 in dev). Data stores sit on internal networks.

## Configuration

All settings live in `.env`; `.env.example` documents each one. The common changes:

| Goal | Setting |
|---|---|
| Public hostname | `PATHOS_PUBLIC_URL=https://pathos.example.com`, `PATHOS_DOMAIN=pathos.example.com` |
| Public certificate (Let's Encrypt) | `CADDY_TLS=you@example.com` (ports 80/443 must be reachable) |
| Non-standard port | `PATHOS_HTTPS_PORT=8443` **and** `PATHOS_PUBLIC_URL=https://host:8443` |
| Real SMTP relay | `PATHOS_SMTP_HOST`, `PATHOS_SMTP_PORT`, `PATHOS_SMTP_FROM`, `PATHOS_SMTP_STARTTLS=true`, and `PATHOS_SMTP_AUTH=true` with `PATHOS_SMTP_USER`/`PATHOS_SMTP_PASSWORD`; set `COMPOSE_PROFILES=` |

> After editing the login theme in `deploy/keycloak/themes/pathos`, run `docker compose up -d --force-recreate keycloak` (Keycloak caches compressed theme files inside the container).

> The `PATHOS_SMTP_*` variables configure both Keycloak (invitation and password emails) and, on the first `migrate`, PATHOS notifications. After that, manage PATHOS email in **Administration → Notifications → Email**. There you can send a test email and watch its delivery. The `jobs` service sends the mail, so it must be able to reach the relay. It sits on the `edge` network, which also carries its HTTPS calls to AI providers and SCM APIs.

> Keycloak imports the realm only on **first** start. After the first start, change the public URL, SMTP settings or client secrets in the Keycloak admin console (`https://<host>/auth/admin`, master realm, user `KEYCLOAK_ADMIN_USER`), or reset the install.

## Connecting source providers

**Administration → SCM connections → Connect provider** walks through provider, sign-in method and credentials. Every method below is supported; choose per connection. See `docs/REPOSITORY_ONBOARDING.md` section 7 for the exact permissions.

| Provider | Sign-in methods |
|---|---|
| GitHub / GitHub Enterprise Server (`https://<host>/api/v3`) | GitHub App (recommended, short-lived installation tokens), personal access token (fine-grained: *Contents: read*, *Metadata: read*), OAuth App |
| GitLab.com / self-managed GitLab | Personal, group or project access token (`read_api`, `read_repository`), OAuth application |
| Bitbucket Cloud | Workspace, project or repository access token, Atlassian API token (account e-mail + token), OAuth consumer |
| Azure DevOps Services | Personal access token (*Code: Read*), Microsoft Entra ID sign-in (OAuth), Entra ID service principal (client secret or certificate; list the organizations it was added to) |
| Azure DevOps Server (`https://<host>/<collection>`) | Personal access token |

- **OAuth sign-in** needs an application registered at the provider. Register it under **SCM connections → OAuth applications** (client ID and secret are stored encrypted) with the redirect URI `<PATHOS_PUBLIC_URL>/api/v1/scm-oauth/callback`, then use **Continue with …** in the connect dialog. Expired or revoked authorizations show **Reconnect**.
- Self-hosted servers on private IPs need `PATHOS_SCM_ALLOW_PRIVATE_NETWORKS=true` in `.env`. The API reaches the internet through the `edge` network; set `PATHOS_HTTPS_PROXY` if outbound traffic must use a proxy.
- **Webhooks (optional; scan triggers and synchronization):** choose *New webhook secret* on the connection and copy the URL and secret.
  - GitHub: content type `application/json`, events *Pushes* and *Pull requests*.
  - GitLab: *Push events* and *Merge request events*, the secret as *Secret token*.
  - Bitbucket Cloud: *Repository push* and *Pull request* triggers, the secret as webhook *Secret*.
  - Azure DevOps: service hooks for *Code pushed*, *Pull request created/updated/merged*, with basic authentication (any username, the secret as password).
  - The webhook URL must be reachable from the provider, so set `PATHOS_PUBLIC_URL` to a public hostname.

## Onboarding repositories

**Assets → Repositories → Import** offers three methods that share one registration wizard (general information, ownership, geography, classification, tags and colour, lifecycle):

- **Import from Local PC:** ZIP, TAR or TAR.GZ archives, or a folder (packed in the browser). Uploads are chunked and resumable, verified with SHA-256, optionally scanned by ClamAV (`COMPOSE_PROFILES=…,clamav` and `PATHOS_CLAMAV_ADDRESS=clamav:3310`), and stored encrypted.
- **Import from Git:** GitHub, GitLab or Bitbucket connections; pick organization, search and select repositories and branches.
- **Import from DevOps Project:** Azure DevOps connections; pick organization, project, repositories and branches.

Imports run in the background (**Import history** shows progress, retry and cancel). Administrators set which fields are mandatory, the classification catalogs and colours, and whether imported repositories get an onboarding scan under **Administration → Asset settings**. The CSV bulk import remains under **Import → Bulk CSV import**.

## Scan workers

`docker compose up -d` starts one `worker-core` (Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov) and the `egress` proxy.

- **Scale:** `docker compose up -d --scale worker-core=4`. Each worker runs one scan at a time; plan 1–4 GB of RAM per worker (`PATHOS_WORKER_MEMORY`, `PATHOS_WORKER_TMPFS`).
- **First scans** download vulnerability databases (~1 GB) into the `scanner_cache` volume through the proxy; later scans reuse them.
- **Egress:** allowed destinations are in `deploy/egress/allowlist.txt`. For GitHub Enterprise Server or Azure DevOps Server on a private network, add a file in `deploy/egress/conf.d/` (example inside) and restart `egress`. Access log: `docker compose exec egress tail -f /var/log/squid/access.log`.
- **Opengrep rules:** PATHOS ships its own baseline rules. Mount additional rule sets as `*.yml` in `workers/rules-extra/`; they are read-only at `/rules` in every worker.
- **Workers page:** *Configurations → Scanners & workers* shows online workers and tool versions. Revoking a worker stops it immediately.

## Day-2 operations

```bash
docker compose ps                         # health of every service
docker compose logs -f api                # structured JSON logs (secrets are redacted)
docker compose run --rm migrate           # re-run migrations (idempotent)
docker compose exec api pathosctl migrate-status
```

Upgrades: `deploy/scripts/upgrade.sh` (backup, build, migrate, health check). Backups: `deploy/scripts/backup.sh`; restores: `deploy/scripts/restore.sh <dir> --yes`. Production deployment, monitoring, scaling, rate limits and object storage are covered in [OPERATIONS.md](OPERATIONS.md).

**Data lives in named volumes** (`pg_data`, `redis_data`, `caddy_data`, plus `s3_data` with the `objectstore` profile). `docker compose down` keeps them. **`docker compose down -v` deletes all data.**

**Back up `PATHOS_MASTER_KEY`.** Without it, stored credentials cannot be decrypted. It is deliberately not part of `backup.sh` output unless you pass `--with-env`.

## Verifying an install

```bash
python3 scripts/smoke-test.py
```

The script logs in through Keycloak as the bootstrap admin and exercises the API (35 checks). On a fresh install it completes the forced password change and sets the admin password to `PATHOS_ADMIN_NEW_PASSWORD`, or a value derived from the temporary password if that is unset. Set `PATHOS_ADMIN_NEW_PASSWORD` yourself if you will keep using the install.

## Development

No local Go or Node needed. Every toolchain runs in a container:

```bash
make test               # Go unit tests + frontend tests
make test-integration   # Go tests against a throwaway PostgreSQL
make smoke              # end-to-end against the running stack
scripts/npm.sh run dev  # Vite dev server on :5173, proxied to the running stack
```
