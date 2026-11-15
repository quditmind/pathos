# Installation

## Requirements

- Docker Engine with the Compose plugin (v2+). Nothing else is needed on the host.
- 4+ vCPU, 8 GB RAM and 40 GB of disk for an evaluation install (see ARCHITECTURE §10 for production sizing).
- Ports 443 and 80 free, or set `PATHOS_HTTPS_PORT` / `PATHOS_HTTP_PORT`.

## Quick start

```bash
git clone <repo-url> pathos && cd pathos
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
| `jobs` | Background maintenance (role `jobs`) |
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
| Real SMTP relay | `PATHOS_SMTP_HOST`, `PATHOS_SMTP_PORT`, `PATHOS_SMTP_FROM`; set `COMPOSE_PROFILES=` |

> After editing the login theme in `deploy/keycloak/themes/pathos`, run `docker compose up -d --force-recreate keycloak` (Keycloak caches compressed theme files inside the container).

> Keycloak imports the realm only on **first** start. After the first start, change the public URL, SMTP settings or client secrets in the Keycloak admin console (`https://<host>/auth/admin`, master realm, user `KEYCLOAK_ADMIN_USER`), or reset the install.

## Day-2 operations

```bash
docker compose ps                         # health of every service
docker compose logs -f api                # structured JSON logs (secrets are redacted)
docker compose run --rm migrate           # re-run migrations (idempotent)
docker compose exec api pathosctl migrate-status
```

Upgrades: pull the new version, then `docker compose up -d --build`. `migrate` runs before `api` starts, and migrations are forward-only.

**Data lives in named volumes** (`pg_data`, `redis_data`, `caddy_data`). `docker compose down` keeps them. **`docker compose down -v` deletes all data.**

**Back up `PATHOS_MASTER_KEY`.** Without it, stored credentials cannot be decrypted. Backup and restore scripts arrive in Phase 8. Until then, use `pg_dump` from the `postgres` container.

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
