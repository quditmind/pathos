# Repository asset management and onboarding: design notes

Engineering design of the repository onboarding module: three import methods (local upload, Git providers, Azure DevOps) that share one asset registration wizard, one background ingestion engine and one asset model. It was built on the existing `repos`, `scm`, `scans` and `worker` packages (migrations `00009` and `00010`).

- How to use it: the user guide pages [Repository import](user-guide/repository-import.md), [Repository management](user-guide/repository-management.md), [Import history](user-guide/import-history.md) and [Provider integrations](user-guide/provider-integrations.md) (also in the in-app Help Center).
- Endpoints: the API reference pages [Repositories](api-reference/repositories.md), [Imports and uploads](api-reference/imports.md) and [SCM integrations](api-reference/integrations.md).
- Security controls: [SECURITY.md](SECURITY.md#repository-onboarding-and-uploads).

## 1. Design constraints

The module follows the platform's conventions rather than introducing new ones:

- Go code in the existing packages and the `jobs` role for background work; no new runtime or queue (the import engine uses PostgreSQL `SKIP LOCKED` claims).
- One goose migration per change, with UUIDv7 keys, text enums with CHECK constraints and composite `(organization_id, id)` foreign keys.
- Every provider credential, OAuth token and OAuth client secret is envelope-encrypted in `secrets` and never returned to the browser.
- Authorization through the permission catalog: new permissions `tags.manage` and `assets.configure`, a `repository_contributor` system role, and owner-based edit rights.
- Source snapshots go to S3-compatible storage when it is configured, otherwise to an encrypted file store on a volume.
- The synchronous `POST /repositories/import` and the CSV import were kept for compatibility; the wizard uses background import jobs.

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

### 2.2 Unified ingestion engine (`internal/repos/imports.go`, `import_worker.go`)

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
- Manual, webhook and import runs always record a `repository_sync_runs`
  row; scheduled reconciliation records one only when the commit or status
  changed (unchanged repositories just update `last_sync_at`). A row holds
  branch, previous and new commit SHA, and the outcome (`ok`, `failed`, `missing`, `permission_denied`,
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

### 3.1 Repository identity and exposure (`00010_repository_identity_exposure.sql`)

| Object | Purpose |
|---|---|
| `repositories.repository_key` | Permanent human-readable Repository ID such as `QD-REPO-000042`. Assigned by a `BEFORE INSERT` trigger from the `repository_key_seq` sequence (concurrency-safe, never reused, numbers may have gaps), unique index, and a `BEFORE UPDATE` trigger that rejects any change. The UUID stays the primary key. The prefix is `asset_settings.repository_key_prefix` (default `QD-REPO`) and only affects new IDs. Existing repositories were numbered in registration order. |
| `repositories.staging_url`, `production_url` | Application URLs (absolute http(s), normalized), separate from the repository URL |
| `repositories.public_exposure` | Mandatory answer `yes` / `no` / `unknown`; backfilled from `internet_exposure` (`public` → yes, `internal`/`private` → no). `internet_exposure` remains the optional network-reachability detail and must not contradict it |
| `repositories.exposure_notes` | Free-text notes |
| `repository_public_endpoints` | Public-facing URLs, domains (`*.example.com` allowed) and public IP addresses, one row each (`kind`, `value`, order), unique per repository |

Rules: `yes` needs at least one public URL, domain or IP; `no` allows none; IPs must be public. URLs, domains and IPs are metadata only: PATHOS never fetches, resolves or scans them, so registering them creates no SSRF surface. Verifying exposure is a separate, authorized assessment. The Repository ID appears in the inventory, details, dashboards, scan jobs, findings, CSV exports, global search and the audit log (`metadata.repository_key`).

## 4. API

The endpoints are documented in the API reference: [Repositories](api-reference/repositories.md), [Imports and uploads](api-reference/imports.md) (upload sessions and import jobs) and [SCM integrations](api-reference/integrations.md) (providers, connections, discovery, OAuth applications, webhook receivers). Asset settings, classifications, tags and the directory pickers are in [Assets](api-reference/assets.md). The worker downloads snapshots with `GET /internal/worker/v1/jobs/{id}/source`.

The specification's names map to existing resources: `integrations` → `scm-connections`, `import-jobs` → `repository-imports`, `tags` → the existing tag endpoints.

## 5. Access control

| Specification role | PATHOS role (permissions) |
|---|---|
| Platform administrator | `platform_admin` / `super_admin` |
| Security administrator | `security_manager` (has `tags.manage`; `assets.configure` stays with `platform_admin` and `super_admin`) |
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
| `PATHOS_IMPORT_WORK_DIR` | `/tmp/pathos-import` (Compose: `/var/lib/pathos/work` on the `import_work` volume) | scratch space for ZIP central directories (deleted after each item) |
| `PATHOS_CLAMAV_ADDRESS` | empty | `host:port` of clamd; empty records `not_configured` |
| `PATHOS_CLAMAV_REQUIRED` | `false` | fail imports when clamd is unavailable |

No provider client IDs or secrets are environment variables: OAuth
applications are registered in the UI and stored encrypted, so they follow
the same backup, rotation (`pathosctl rotate-master-key`) and audit path as all
other credentials.

## 7. Provider registration

The scopes and permissions each sign-in method needs. Step-by-step registration is in the [user guide](user-guide/provider-integrations.md#oauth-applications).

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
- Rollback to a release before this module: `docker compose run --rm --entrypoint /usr/local/bin/pathosctl migrate migrate-down 8` reverts the schema to migration 00008, which also reverts every later migration (and the data they hold). Restoring a backup taken before the upgrade ([OPERATIONS.md](OPERATIONS.md#restore)) is usually the better path. Uploaded
  repositories (no SCM connection) are deleted by the down migration because
  the previous schema cannot represent them; export them first if needed.
  New providers' connections are archived by the down migration.

## 10. Implementation status

| Area | Verified by |
|---|---|
| Schema, up / down / up with onboarding data | migration replay against PostgreSQL 18 |
| Metadata validation, required fields, catalogs, owner rights, audit old/new values | Go integration tests (`test/integration/onboarding_test.go`) |
| Git import engine: idempotency, duplicates, not-found / permission errors, retry, cancel, sync, insights, notifications | Go integration tests with an in-memory provider |
| Uploads: part checksums, whole-archive SHA-256, traversal rejection, snapshots, new versions, duplicates, cross-organization isolation | Go integration tests, real encrypted file store |
| Provider adapters and every sign-in method (token exchange, refresh, rotation, revoke, service-principal assertion, pagination, page-token tampering, webhooks) | `internal/scm` unit tests against recorded API shapes |
| Archive normalizer, extraction, streaming encryption, ClamAV protocol, worker snapshot download | unit tests (`internal/ingest`, `internal/platform/sourcestore`, `internal/worker`) |
| Local PC onboarding through the browser, background processing in the `jobs` container, persistence after reload | Playwright (`e2e/tests/onboarding.spec.ts`) against the running stack |
| Malware scanning | real `clamav/clamav:1.5`: the EICAR test file is rejected (`malware_detected`), clean code is imported with `malware_scan: clean` |

Not yet verified against real provider accounts (no credentials were
available while building): GitHub, GitLab, Bitbucket and Azure DevOps
connections, OAuth consent flows and Microsoft Entra ID service principals.
Follow section 7 to register applications, then check each provider once:
connect, list organizations and repositories, import one repository, sync it
and scan it. Known provider-specific points to watch:

- Azure DevOps with Entra ID tokens clones with an `Authorization: Bearer`
  header; VSSPS profile and account calls use API version 6.0.
- Bitbucket workspaces are listed through `/user/permissions/workspaces`;
  repository listing without a selected workspace requires a single
  workspace. Bitbucket has no token revocation API.
- GitHub search within an organization uses the search API (1,000 result
  cap, lower rate limit).
