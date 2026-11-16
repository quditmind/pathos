# Repository asset management and onboarding

This document is the target architecture for the enterprise repository
onboarding module: three import methods (local upload, Git providers,
Azure DevOps) that share one asset registration wizard, one background
ingestion engine and one enterprise asset model. It extends the existing
`repos`, `scm`, `scans` and `worker` packages; nothing existing is replaced.

## 1. Assessment of the existing application

| Area | Existing implementation | Consequence for this module |
|---|---|---|
| Backend | Go 1.27, `net/http` mux, pgx, packages under `backend/internal` | New code is Go in the same packages. No Python, Celery or SQLAlchemy |
| Database | PostgreSQL 18, goose migrations in `backend/migrations`, UUIDv7 keys, text enums with CHECK, composite `(organization_id, id)` foreign keys | One new migration `00009_asset_onboarding.sql`, same conventions |
| Tenancy | One organization per install; every row carries `organization_id`, composite FKs keep references inside the organization | Every new table follows the same rule; cross-organization access is tested |
| AuthN | Keycloak OIDC, server-side sessions in Valkey, CSRF header on mutations | OAuth callbacks for SCM providers are authenticated session routes |
| AuthZ | Permission catalog in Go, system and custom roles, assignments scoped to organization, region, business unit or repository; checks in every handler | New permissions `tags.manage` and `assets.configure`, a `repository_contributor` system role, owner-based edit rights |
| Secrets | Envelope encryption (AES-256-GCM, per-secret DEK, versioned master key) in `secrets` table | All provider credentials, OAuth tokens and OAuth client secrets use it; nothing is returned to the browser |
| SCM | GitHub (PAT, GitHub App) and Azure DevOps (PAT); discovery, branches, webhooks, nightly metadata re-sync; SSRF-safe HTTP client | Extended with GitLab, Bitbucket Cloud, OAuth, Entra ID and service principals behind one interface |
| Import | Synchronous `POST /repositories/import` and CSV import with placement, criticality, environment and tags | Kept for compatibility; the new wizard uses background import jobs |
| Scanning | `scan_jobs` queue in PostgreSQL leased by isolated workers that `git clone` (shallow, hardened) and run Gitleaks, Opengrep, Trivy, SBOM tools | Workers additionally fetch encrypted upload snapshots through the worker API |
| Object storage | Optional S3-compatible store for scan artifacts | Source snapshots use S3 when configured, otherwise an encrypted file store on a volume |
| Frontend | React 19, TanStack Router/Query, Tailwind 4, Radix dialogs, light and dark themes | New pages reuse `PageHeader`, `Card`, `DataTable`, `FilterBar`, `Dialog`, `KpiCard` |
| Background work | `jobs` role (re-sync, retention), `scheduler` role | Import engine and sync run in the `jobs` role, never in API request handlers |

## 2. Architecture

```
 Browser ──► API (pathos api)                         jobs role (pathos jobs)
   │          ├─ asset registration + validation       ├─ import engine (N workers, SKIP LOCKED)
   │          ├─ SCM connections / OAuth / discovery   │    VALIDATING → IMPORTING → REGISTERING
   │          ├─ upload sessions (chunked, encrypted)  ├─ archive normalizer (no extraction to disk)
   │          ├─ import jobs API (poll)                ├─ malware scan (clamd, optional)
   │          └─ worker API: /jobs/{id}/source         ├─ repository sync (schedule, webhooks)
   │                                                   └─ token refresh, upload expiry
   ▼
 Source store (encrypted)  ◄────────────────────────────┘
   └─ file volume or S3                     scan workers ──► worker API (snapshot download)
```

### 2.1 Provider and authentication framework (`internal/scm`)

`scm.Client` is the provider-independent interface used by discovery,
import, sync and scanning:

```go
type Client interface {
    Check(ctx) (Identity, error)
    ListOrganizations(ctx) ([]Organization, error)
    ListProjects(ctx, org string) ([]Project, error)           // ErrNotSupported if none
    ListRepositoriesPage(ctx, RepoQuery) (RepoPage, error)     // org, project, search, page token
    ListRepositories(ctx) ([]RemoteRepo, error)                // full listing (re-sync, legacy import)
    GetRepository(ctx, RepoRef) (RemoteRepo, error)            // permission check before import
    ListBranches(ctx, RemoteRepo) ([]string, error)
    ListBranchHeads(ctx, RepoRef) ([]Branch, error)
    LatestCommit(ctx, RepoRef, branch string) (Commit, error)
    CloneCredential(ctx) (Credential, error)
    Revoke(ctx) error                                          // best effort
}
```

Authentication is separated from the provider adapters: an adapter asks a
`TokenSource` for an HTTP authorization header. Token sources:

| Auth type | Providers | Mechanism |
|---|---|---|
| `pat` | GitHub, GitHub Enterprise, GitLab (personal, group and project access tokens), Bitbucket Cloud (workspace, project and repository access tokens), Azure DevOps Services and Server | Static token; rotation by replacing it |
| `github_app` | GitHub, GitHub Enterprise | App JWT → installation token (1 h), cached and renewed |
| `oauth` | GitHub (OAuth App), GitHub Enterprise, GitLab (gitlab.com and self-managed), Bitbucket Cloud (OAuth consumer), Azure DevOps Services (Microsoft Entra ID, delegated) | Authorization code (+PKCE where supported); refresh tokens rotated and persisted under a row lock |
| `api_token` | Bitbucket Cloud | Atlassian account e-mail + API token (HTTP Basic) |
| `service_principal` | Azure DevOps Services | Microsoft Entra ID client credentials with client secret or certificate (JWT client assertion); token cached until expiry |

Not offered, with reason: Bitbucket app passwords (retired by Atlassian),
Azure DevOps OAuth (`app.vssps.visualstudio.com`, deprecated for new
registrations; Entra ID replaces it), Azure managed identity (only available
to workloads running on Azure, and the instance metadata endpoint is blocked
by the SSRF policy), GitLab deploy tokens (clone only, no API access).

OAuth applications are registered by an administrator in **Admin → SCM
connections → OAuth applications** (client ID, client secret, tenant for
Entra ID, base URL for self-managed servers). The redirect URI to register
at the provider is `<PATHOS_PUBLIC_URL>/api/v1/scm-oauth/callback`. Section 7
lists the provider settings.

Credential lifecycle:

- Stored only in `secrets` (envelope encrypted). OAuth secrets are JSON
  `{access_token, refresh_token, expires_at, token_type, scope}`.
- `scm_connections.token_expires_at` drives proactive refresh (jobs role,
  every 10 minutes for tokens expiring within 30 minutes). A refresh that the
  provider rejects marks the connection `expired`; the UI offers
  **Reconnect**, which re-runs the OAuth flow for the same connection.
- Rotation: `PATCH /scm-connections/{id}` with a new credential, or
  reconnect. Revocation: `DELETE /scm-connections/{id}` calls the provider's
  revoke endpoint where one exists (GitHub, GitLab), then overwrites the
  stored secret.
- Every request goes through the existing SSRF-safe client (connect-time IP
  check, no cross-host redirects). Token endpoints are fixed per provider
  (or derived from the validated base URL for self-managed servers).

### 2.2 Unified ingestion engine (`internal/repos/ingest*.go`)

All three import methods create a `repository_import_jobs` row with one
`repository_import_items` row per repository. The API validates the
registration metadata synchronously (so the wizard can show field errors)
and stores it with the item; the jobs role processes items:

| Stage | Git / DevOps item | Upload item |
|---|---|---|
| `QUEUED` | waiting for a worker | waiting for a worker |
| `VALIDATING` | resolve connection, `GetRepository` (proves read permission), validate branch | verify parts, SHA-256 of the whole archive, size limits |
| `IMPORTING` | latest commit on the branch, languages, size | malware scan, archive normalization into an encrypted snapshot, language and manifest detection |
| `REGISTERING` | one transaction: repository row, metadata, owners, compliance scopes, tags, sync run, audit entry; optional onboarding scan | same, plus `source_snapshots` row |
| `COMPLETED` / `FAILED` / `NEEDS_ATTENTION` / `CANCELLED` | | |

- Leases (`lease_expires_at`, heartbeat) make crashed workers recoverable.
- Retries: transient errors (network, provider 5xx, rate limits) retry with
  exponential backoff up to 3 attempts; permanent errors fail immediately
  with an `error_code`. Users can retry failed items manually.
- Idempotency: `Idempotency-Key` (wizard-generated) is unique per
  organization; a repeated submission returns the existing job.
- Duplicates: same connection + external ID → `already_imported`; same clone
  URL through another connection, or the same archive SHA-256 → 
  `NEEDS_ATTENTION` (`duplicate`), resolvable by retrying with
  `allow_duplicate`.
- Cancellation: queued items cancel immediately; running items stop at the
  next stage boundary.
- Concurrency (`PATHOS_IMPORT_CONCURRENCY`) and per-item timeout
  (`PATHOS_IMPORT_TIMEOUT`) are configurable; the engine runs only in the
  `jobs` role and can be scaled by running more `jobs` containers.
- Progress: the UI polls `GET /repository-imports/{id}` every 2 seconds while
  a job is active (reliable through the reverse proxy; no new real-time
  infrastructure).

### 2.3 Local upload pipeline

1. `POST /source-uploads` declares file name, size and SHA-256; the API
   checks format (`.zip`, `.tar`, `.tar.gz`, `.tgz`) and the size limit.
2. The browser sends 8 MiB parts (`PUT /source-uploads/{id}/parts/{n}`), each
   with its own SHA-256. Parts are encrypted immediately and written to the
   source store. Interrupted uploads resume: `GET /source-uploads/{id}` lists
   received parts. Folder uploads are packed into a tar archive in the
   browser.
3. `POST /source-uploads/{id}/complete` seals the upload; the import item
   references it.
4. The jobs role streams the parts, verifies the overall SHA-256, optionally
   streams the archive to ClamAV (`INSTREAM`), then **normalizes** it: every
   entry is read, validated and re-written into a gzip tar snapshot. Nothing
   is extracted to the file system and nothing is executed.
   - Rejected: absolute paths, `..`, drive letters, backslash paths, NUL
     bytes, duplicate paths, over-long names.
   - Skipped and reported: symlinks, hard links, devices, FIFOs, nested
     archives are kept as plain files (not expanded).
   - ZIP bomb limits: entry count, total uncompressed size, per-file size,
     compression ratio; all configurable.
   - A single top-level directory (as in GitHub "Download ZIP") is stripped.
5. The snapshot is encrypted (streaming AES-256-GCM, 64 KiB chunks, per-object
   key wrapped by the master key) and its SHA-256 recorded. The staging parts
   are deleted. Expired or abandoned uploads are deleted after 24 hours.
6. Scan workers download the snapshot through the worker API (the API
   decrypts; workers hold no storage credentials), verify its SHA-256 and
   extract it with the same path rules into their tmpfs workspace.

### 2.4 Synchronization

- `POST /repositories/{id}/sync` (manual), nightly scheduled reconciliation
  in the jobs role, and webhooks (GitHub, Azure DevOps, GitLab, Bitbucket).
- Each run records a `repository_sync_runs` row: branch, previous and new
  commit SHA, outcome (`ok`, `failed`, `missing`, `permission_denied`,
  `archived_upstream`).
- Only metadata and the head commit are fetched; source is not downloaded.
  Changed commits feed the existing scan triggers (push webhooks) and the
  optional onboarding scan.
- Failures raise the `repository.sync_failed` notification; failed imports
  raise `import.failed`.
- Uploaded repositories are updated by uploading a new snapshot to the same
  asset (`target_repository_id`); every snapshot is kept with its SHA-256.

### 2.5 Security scanning integration

- After registration the repository is eligible for scanning. An onboarding
  scan is queued only when **Admin → Asset settings → Scan on import** is on
  (default off).
- Scan jobs for uploaded repositories carry `snapshot_id`; Git scans record
  the commit the worker actually checked out, so every result is tied to an
  identified source version.
- Full-history import (`full_history`) makes the worker clone the complete
  history and run Gitleaks in git-history mode; default is a shallow clone.
- `GET /repositories/{id}/security` returns the latest scan (status, commit,
  profile, scanner versions and result counts) and open findings by severity.

## 3. Database design (`00009_asset_onboarding.sql`)

Existing tables are extended rather than duplicated. The specification's
`assets` entity is the existing `repositories` row (one asset per
repository) plus `applications` for grouping; `asset_audit_logs` is the
existing append-only `audit_logs` with old and new values in `metadata`.

| Table | Change |
|---|---|
| `repositories` | `scm_connection_id` nullable with `source_type` (`scm`/`upload`); SCM organization and project; display and asset name; application type; business purpose; business, technical and application owner (users); responsible and supporting team; department (child business unit); cost centre; business region and data residency region (regions); hosting region; operational location; data classification; internet exposure; lifecycle status, go-live and retirement dates; colour; full-history flag; latest commit; size, file count, languages; sync status and timestamps; current snapshot |
| `applications` | `external_ref` (CMDB application ID) |
| `asset_classifications` | per-organization catalogs: criticality labels and colours, data classifications, environments, application types, internet exposure, compliance scopes, hosting regions, lifecycle statuses |
| `asset_settings` | required-field policy, scan on import |
| `repository_compliance_scopes` | many-to-many repository ↔ compliance scope |
| `tags` | `description`, hex colours, `created_by` |
| `scm_connections` | providers `gitlab`, `bitbucket`; auth types `oauth`, `api_token`, `service_principal`; OAuth app, account, token expiry, allowed organizations; statuses `expired`, `revoked` |
| `scm_oauth_apps` | OAuth application registrations (client secret in `secrets`) |
| `scm_oauth_states` | short-lived OAuth state + PKCE verifier, bound to the user |
| `source_uploads`, `source_upload_parts` | resumable upload sessions |
| `source_snapshots` | immutable source versions of uploaded repositories |
| `repository_import_jobs`, `repository_import_items` | import engine |
| `repository_sync_runs` | sync history |
| `scan_jobs` | `snapshot_id` |
| `permissions` | `tags.manage`, `assets.configure` (granted to existing roles that had `repos.manage` org-wide) |

Every table has `organization_id`, composite foreign keys to same-organization
rows, indexes for the list filters, and a reversible `Down` section.
Row-level security is not used: PATHOS runs one organization per install and
enforces scope in every query, as the rest of the schema does.

## 4. API

Existing conventions are kept: `/api/v1`, JSON, cursor pagination
(`next_cursor`), error body `{"error": {"code", "message"}}`, CSRF header on
mutations, per-user rate limits. The specification's endpoint names map to
existing resources (`integrations` → `scm-connections`, `tags` → existing tag
endpoints, `import-jobs` → `repository-imports`).

| Area | Endpoints |
|---|---|
| Providers | `GET /scm-providers` (providers, auth methods and their fields) |
| OAuth apps | `GET/POST /scm-oauth-apps`, `PATCH/DELETE /scm-oauth-apps/{id}` |
| Connections | existing CRUD, test, webhook secret, resync; `POST /scm-connections/oauth/start`, `GET /scm-oauth/callback` |
| Discovery | `GET /scm-connections/{id}/organizations`, `/projects?organization=`, `/remote-repositories?organization=&project=&q=&page_token=`, `/remote-repositories/details?…` |
| Uploads | `POST /source-uploads`, `GET/DELETE /source-uploads/{id}`, `PUT /source-uploads/{id}/parts/{n}`, `POST /source-uploads/{id}/complete` |
| Imports | `POST /repository-imports/validate`, `POST/GET /repository-imports`, `GET /repository-imports/{id}`, `POST /repository-imports/{id}/cancel`, `POST /repository-imports/{id}/retry` |
| Repositories | existing list (new filters and sorting), get, patch (all metadata), archive, delete; `GET /repositories/insights`, `POST /repositories/{id}/sync`, `GET /repositories/{id}/sync-runs`, `GET /repositories/{id}/snapshots`, `GET /repositories/{id}/security` |
| Settings | `GET/PATCH /asset-settings`, `POST /asset-classifications`, `PATCH /asset-classifications/{id}` |
| Tags | existing endpoints + `GET /tags?q=`, `PATCH /tags/{id}` |
| Directory | `GET /directory/users?q=`, `GET /directory/teams?q=` (owner pickers for importers without `users.read`) |
| Worker | `GET /internal/worker/v1/jobs/{id}/source` |

Request and response bodies are defined once in `frontend/src/api/types.ts` (the Go handlers marshal the same shapes).

## 5. Access control

| Specification role | PATHOS role (permissions) |
|---|---|
| Platform administrator | `platform_admin` / `super_admin` |
| Security administrator | `security_manager` (+ `tags.manage`, `assets.configure` via `platform_admin`) |
| Asset owner | any role with `repos.read` in scope; being the business, technical or application owner of a repository (or a member of its responsible team) grants editing of that repository's descriptive and ownership metadata |
| Repository contributor | new `repository_contributor`: read-only + `repos.manage`, `scans.run` |
| Security analyst | `security_analyst` |
| Auditor | `auditor` |

Rules enforced server-side: importing requires `repos.manage` at the target
business unit (or region, or organization); creating and editing tags
requires `tags.manage`; classification catalogs and required fields require
`assets.configure`; connections and OAuth apps require `scm.manage`; import
jobs are visible to their requester and to holders of `repos.manage`
organization-wide.

## 6. Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PATHOS_SOURCE_STORE_DIR` | `/var/lib/pathos/sources` | encrypted source store when no S3 bucket is configured (volume shared by `api` and `jobs`) |
| `PATHOS_SOURCE_S3_PREFIX` | `sources/` | key prefix when the S3 store (`PATHOS_S3_*`) is used |
| `PATHOS_UPLOAD_MAX_BYTES` | `2147483648` (2 GiB) | maximum archive size |
| `PATHOS_IMPORT_MAX_FILES` | `200000` | maximum archive entries |
| `PATHOS_IMPORT_MAX_EXTRACTED_BYTES` | `8589934592` (8 GiB) | maximum uncompressed size |
| `PATHOS_IMPORT_MAX_FILE_BYTES` | `1073741824` (1 GiB) | maximum single file |
| `PATHOS_IMPORT_CONCURRENCY` | `2` | import workers per `jobs` process |
| `PATHOS_IMPORT_TIMEOUT` | `30m` | per item |
| `PATHOS_IMPORT_WORK_DIR` | `/tmp/pathos-import` | scratch space for ZIP central directories (deleted after each item) |
| `PATHOS_CLAMAV_ADDRESS` | empty | `host:port` of clamd; empty records `not_configured` |
| `PATHOS_CLAMAV_REQUIRED` | `false` | fail imports when clamd is unavailable |

No provider client IDs or secrets are environment variables: OAuth
applications are registered in the UI and stored encrypted, so they follow
the same backup, rotation (`pathosctl rotate-master-key`) and audit path as all
other credentials.

## 7. Provider registration

| Provider | Register | Redirect URI | Scopes / permissions |
|---|---|---|---|
| GitHub OAuth App | Settings → Developer settings → OAuth Apps | `<public URL>/api/v1/scm-oauth/callback` | `repo read:org` (GitHub OAuth has no read-only private repo scope; prefer a GitHub App for least privilege) |
| GitHub App | Settings → Developer settings → GitHub Apps; install on the organization | – | Contents: read, Metadata: read, Pull requests: read, Webhooks optional |
| GitLab | User or group settings → Applications | same | `read_api read_repository` |
| Bitbucket Cloud | Workspace settings → OAuth consumers (private consumer with callback URL) | same | `repository account` (+ `webhook` for automatic webhooks) |
| Azure DevOps (Entra ID, delegated) | Entra admin center → App registrations; API permission Azure DevOps `user_impersonation` | same (Web platform) | `499b84ac-1321-427f-aa17-267ca6975798/.default offline_access` |
| Azure DevOps (service principal) | App registration + client secret or certificate; add the service principal to each Azure DevOps organization with Basic access and Reader on the projects | – | Code (read), Project and team (read) via group membership |

## 8. Testing

| Level | Coverage |
|---|---|
| Unit (Go) | metadata and required-field validation, classification catalogs, archive normalizer (traversal, bombs, symlinks, duplicates, top-level strip), streaming encryption, upload part handling, provider adapters and token sources against `httptest` servers (pagination, refresh, rotation, revoke, auth errors, SSRF), webhook signature verification, state machine transitions |
| Integration (Go, real PostgreSQL) | upload → import → snapshot → scan lease → source download; Git and DevOps imports through a fake provider; duplicates; retry and cancel; idempotency; RBAC (contributor, owner edit, analyst read-only); cross-organization isolation; audit entries; sync runs |
| Frontend (Vitest) | wizard validation and required fields, tar packing of folder uploads, chunked upload resume, import progress view |
| End-to-end (Playwright, running stack) | local ZIP onboarding through to the repository list with metadata after reload; failure and retry; permission enforcement |

Live provider tests need credentials that are not available in CI; the
adapters are tested against recorded API shapes, and real connections are
verified manually with the steps in section 7.

## 9. Deployment and rollback

- `docker compose up -d --build --wait` runs the migration (`migrate`
  service) before `api` and `jobs` start. The new `sources` volume is mounted
  into `api` and `jobs`. `clamav` is an optional Compose profile.
- Backups: the `sources` volume (or the S3 prefix) must be backed up with
  PostgreSQL; snapshots are encrypted with the master key, so the master key
  backup applies to them too.
- Rollback: `pathosctl migrate-down 8` reverts the schema. Uploaded
  repositories (no SCM connection) are deleted by the down migration because
  the previous schema cannot represent them; export them first if needed.
  New providers' connections are archived by the down migration.
