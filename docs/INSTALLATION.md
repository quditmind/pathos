# Installation

## Requirements

- Docker Engine with the Compose plugin (v2+). Nothing else is needed on the host.
- 4+ vCPU, 8 GB RAM and 40 GB of disk for an evaluation install (see [ARCHITECTURE.md §10](ARCHITECTURE.md#10-resource-requirements) for production sizing).
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
| `proxy` | Caddy: TLS, security headers, serves the UI, routes `/api` and `/mcp` to the API and `/auth` to Keycloak |
| `migrate` | One-shot: applies database migrations, syncs the RBAC and scanner catalogs, creates the organization, then exits |
| `api` | PATHOS API (role `api`), including the MCP server and the internal worker listener (`:8081`) |
| `jobs` | Background work (role `jobs`): AI reviews, notifications, e-mail and outbound webhooks, repository imports and sync, intelligence feeds and risk scoring, policies, ticket sync, scheduled reports, retention |
| `scheduler` | Scan scheduler (role `scheduler`). Leader-elected through a PostgreSQL advisory lock, so `--scale scheduler=2` gives a hot standby |
| `postgres` | PostgreSQL 18 (databases `pathos` and `keycloak`) |
| `valkey` | Sessions, sign-in state and rate limits |
| `keycloak` | Identity: sign-in, MFA, password policy, SSO brokering |
| `keycloak-setup` | One-shot: applies realm settings the realm import cannot (MFA recovery codes). Runs on every `up` and changes nothing when the settings are in place |
| `worker-core` | Scan worker with the bundled scanners (see [Scan workers](#scan-workers)) |
| `egress` | Squid proxy: the workers' only way out, limited to an allowlist |

Optional services, enabled with `COMPOSE_PROFILES`:

| Profile | Service | Purpose |
|---|---|---|
| `dev` (default in `.env.example`) | `mailpit` | Catches outgoing e-mail; UI at http://127.0.0.1:8025 |
| `objectstore` | `objectstore` | SeaweedFS, S3-compatible storage for artifacts ([OPERATIONS.md](OPERATIONS.md#object-storage)) |
| `clamav` | `clamav` | Malware scanning of uploads ([OPERATIONS.md](OPERATIONS.md#malware-scanning-clamav)) |
| `ollama` | `ollama` | Local model server for self-hosted AI ([OPERATIONS.md](OPERATIONS.md#ai-review-options)) |
| `observability` | `otel-lgtm` | Grafana LGTM for traces and metrics, UI at http://127.0.0.1:3001 |

Only `proxy` publishes ports (plus Mailpit and Grafana on 127.0.0.1). Data stores sit on internal networks; [ARCHITECTURE.md §7](ARCHITECTURE.md#7-docker-deployment-architecture) shows the networks and volumes.

## Configuration

All settings live in `.env`; `.env.example` documents the usual ones, and [OPERATIONS.md](OPERATIONS.md#configuration-reference) lists every variable. The common changes:

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

Connections are made in the UI (**Administration → SCM connections → Connect provider**); the [user guide](user-guide/provider-integrations.md) walks through every provider and sign-in method, and [REPOSITORY_ONBOARDING.md §7](REPOSITORY_ONBOARDING.md#7-provider-registration) lists the scopes each one needs. What the installation must provide:

- **OAuth redirect URI:** register `<PATHOS_PUBLIC_URL>/api/v1/scm-oauth/callback` at the provider. OAuth applications are stored in PATHOS (encrypted), not in `.env`.
- **Self-hosted servers on private addresses** (GitHub Enterprise Server, GitLab self-managed, Azure DevOps Server) need `PATHOS_SCM_ALLOW_PRIVATE_NETWORKS=true`, and an egress override in `deploy/egress/conf.d/` so workers can clone (see below).
- **Outbound proxy:** the API and jobs reach the internet through the `edge` network; set `PATHOS_HTTPS_PROXY` if outbound traffic must use a proxy.
- **Webhooks** (optional; scan triggers and synchronization) must reach `<PATHOS_PUBLIC_URL>/api/webhooks/…` from the provider, so `PATHOS_PUBLIC_URL` must be a hostname the provider can reach. Per-provider settings: [user guide: Webhooks](user-guide/provider-integrations.md#webhooks).

## Onboarding repositories

Repositories are imported from **Assets → Repositories → Import** (local upload, Git providers, Azure DevOps); see the [user guide](user-guide/repository-import.md). Imports run in the `jobs` service; their limits and tuning are in [OPERATIONS.md](OPERATIONS.md#repository-imports). To scan uploads for malware, enable the `clamav` profile ([OPERATIONS.md](OPERATIONS.md#malware-scanning-clamav)).

## Scan workers

`docker compose up -d` starts one `worker-core` and the `egress` proxy. The worker image contains Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov, zizmor, actionlint and Nuclei ([SCANNER_CATALOG.md](SCANNER_CATALOG.md)).

- **Scale:** each worker runs one scan at a time; see [OPERATIONS.md](OPERATIONS.md#scaling).
- **First scans** download vulnerability databases (~1 GB) into the `scanner_cache` volume through the proxy; later scans reuse them.
- **Egress:** allowed destinations are in `deploy/egress/allowlist.txt`. For GitHub Enterprise Server or Azure DevOps Server on a private network, add a file in `deploy/egress/conf.d/` (example inside) and restart `egress`. Access log: `docker compose exec egress tail -f /var/log/squid/access.log`.
- **Scan targets:** container registries, web applications and APIs scanned from *Scanning → Scan targets* must be reachable through the proxy. Docker Hub and `ghcr.io` are allowed out of the box (3.0.3). Add other hosts to `deploy/egress/allowlist.txt` (for example `quay.io` with its `cdn0N.quay.io` hosts) and restart `egress`. Applications on private addresses also need a `conf.d` override. A scan of a host the proxy blocks fails with that explanation and names the refused host (a registry uses several hosts, so repeat until the scan passes; `docker compose exec egress tail /var/log/squid/access.log` lists every `TCP_DENIED` host).
- **Opengrep rules:** PATHOS ships its own baseline rules. Mount additional rule sets as `*.yml` in `workers/rules-extra/`; they are read-only at `/rules` in every worker. Rules can also be managed in the UI (custom rules).
- **Scanner plugins:** additional tools (SARIF, a result import format or a JSON mapping) can be declared in `deploy/scanners.d/` ([SCANNER_CATALOG.md](SCANNER_CATALOG.md#adding-a-tool-tool-manifests)).
- **Air-gapped hosts:** see [AIRGAP.md](AIRGAP.md).
- **Workers page:** *Configurations → Scanners & workers* shows online workers and tool versions. Revoking a worker stops it immediately.

## Verifying an install

```bash
python3 scripts/smoke-test.py
```

The script logs in through Keycloak as the bootstrap admin and exercises the API end to end (`make smoke` runs the same script). On a fresh install it completes the forced password change and sets the admin password to `PATHOS_ADMIN_NEW_PASSWORD`, or a value derived from the temporary password if that is unset. Set `PATHOS_ADMIN_NEW_PASSWORD` yourself if you will keep using the install.

## Next steps

- Production deployment, backup, upgrade, scaling and monitoring: [OPERATIONS.md](OPERATIONS.md).
- Security controls and key rotation: [SECURITY.md](SECURITY.md).
- Using PATHOS: the [user guide](user-guide/introduction.md), also in the in-app Help Center.
- Development and tests: [README](../README.md#development) and [CONTRIBUTING.md](../CONTRIBUTING.md).
