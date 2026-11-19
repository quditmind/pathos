Quditmind PATHOS · applies to v2.2.0 · status: Planned

# PATHOS integration technical specification

The integration and protocol matrix for the lifecycle release. It is part of the M0 approval pack and the base for milestone M2 (Connectors).

Status values used in this document:

- **Existing**: in PATHOS 2.2.0 today, with a code reference.
- **Partial**: exists today, but part of what the design asks for is missing.
- **Planned**: in scope for the lifecycle release (mostly M2). Not built.
- **After lifecycle release**: listed in the design, out of scope for this release.

Nothing marked Planned exists in the code. Every `PTH-CONN-*` and `PTH-SYNC-*` code in this document is **Planned**: PATHOS 2.2.0 has no `PTH-` error codes yet (the API error today is `{code, message, details, fields}` with short string codes, `backend/internal/platform/httpx/httpx.go:22`).

## Purpose

1. List every connector in the lifecycle design (the Connectors page, 46 entries) and every external system PATHOS 2.2.0 already talks to.
2. For each connector, record what exists today, how it authenticates, the least privilege it needs, the vendor API it uses, webhook, rate-limit and pagination behaviour, proxy, private CA and air-gapped behaviour, how its credential is stored, and the error codes M2 will add.
3. Define the shared protocols: webhook verification, incremental and full sync, retry and backoff, health checks, and the health and AI-troubleshooting flow.

Vendor facts were checked against the vendor's official documentation on **2026-11-20**. Each fact carries its source URL. A fact that could not be confirmed from an official page says **not verified**. Connectors outside the M2 priority list say **to verify in M2**.

## Scope

In scope:

- The 46 connectors of the design's Connectors page, grouped in its nine categories: SCM & IDE, CI/CD, Cloud, Containers, Security, IAM & Secrets, APIs, Databases, Monitoring.
- External systems PATHOS 2.2.0 already integrates with that the design list does not name: Azure DevOps Server, AI providers, live secret validation providers, deps.dev, endoflife.date, OSV.dev, the egress proxy.
- Shared protocols and the `PTH-CONN` / `PTH-SYNC` code ranges.

Out of scope:

- The diagnostic engine itself (`PTH-` catalogue package, `<ErrorPanel>`, `/help/troubleshooting`): M1. This document only reserves codes.
- Scanner tools (the tool catalogue, M6). Tools are not connectors.
- Multi-tenancy. It exists in 2.2.0 (optional, off by default); connectors keep working per organization as today and nothing new is built for it.

## Architecture

### Today (2.2.0)

Integrations live in separate packages with their own storage, pages and status fields. There is no shared connector model.

| Family | Package | Page today | Who calls out |
|---|---|---|---|
| SCM providers | `backend/internal/scm`, `backend/internal/repos` | `/admin/scm` | `api` (wizard, test), `jobs` (import, daily re-sync), workers (clone) |
| Ticketing | `backend/internal/tickets` | `/admin/integrations` | `api` (create, test), `jobs` (status sync every 10 min) |
| Notifications (e-mail, outbound webhooks, Slack, Teams) | `backend/internal/notify` | `/admin/notifications` | `jobs` (delivery queue) |
| Kubernetes and registries | `backend/internal/runtimectx` | Assets → Runtime | `jobs` only (`docs/OPERATIONS.md`, "Who connects") |
| Vulnerability feeds | `backend/internal/intel`, `backend/internal/eol` | `/admin/risk-intelligence` | `jobs` |
| Live secret validation | `backend/internal/scanners/secretproviders.go`, `backend/internal/worker/secretcheck.go` | Secret validation settings | workers, through the egress proxy |
| AI providers | `backend/internal/ai` | `/admin/ai` | `api`, `jobs` |
| MCP server and API tokens | `backend/internal/mcp` | `/admin/mcp`, `/settings/tokens` | inbound only |
| Sign-in and SSO | Keycloak, `backend/internal/auth` | Keycloak admin | Keycloak |
| Object storage | `backend/internal/platform/objstore` | none (environment) | all services |
| Telemetry | `backend/internal/platform/telemetry` | none (environment) | all services |

Shared pieces that exist and that M2 reuses:

- **Outbound address policy.** `scm.NetPolicy` (`backend/internal/scm/safehttp.go`) checks the resolved IP at connect time. Loopback, link-local (cloud metadata), CGNAT and multicast are always blocked. RFC 1918 and ULA addresses need `allow_private` per connection. Only `https` unless `PATHOS_SCM_ALLOW_HTTP=true`. Redirects only to the same host. Ticketing and runtime connectors use the same policy (`backend/internal/tickets/service.go:337`, `backend/internal/runtimectx`).
- **Proxy.** The transport uses `http.ProxyFromEnvironment` (`safehttp.go:102`); deployments set `PATHOS_HTTPS_PROXY` (`docs/OPERATIONS.md`, configuration reference). Workers reach the internet only through the Squid egress proxy with an allowlist (`deploy/egress/allowlist.txt`).
- **Encrypted, write-only credentials.** `backend/internal/secrets/store.go` (see Security requirements).
- **Error classification.** `scm.StatusError`, `scm.IsTransient` (`backend/internal/scm/http.go`) and the import error codes (`backend/internal/repos/import_worker.go:45`).

### Lifecycle release (Planned, M2)

One `/connectors` page with tabs Connectors · Authentication · Configuration · Health. Each connector is a row in one shared registry (Planned) with: category, kind, status, auth method, granted scopes (as reported by the vendor, where the vendor reports them), credential reference, base URL, `allow_private`, CA bundle reference, sync settings and last health result. The existing tables (`scm_connections`, `ticket_connections`, `outbound_webhooks`, `runtime_clusters`, `registry_connections`, AI providers) stay the source of truth. The registry is a view over them first; nothing is migrated destructively (rule 1). `/admin/scm` and `/admin/integrations` redirect only after parity tests pass.

## Components

### Connector inventory

46 design entries plus 8 existing integrations the design does not list. "Design" is the status the design page shows; "2.2.0" is what the code shows. Where they differ, the code wins and the row is listed under Known limitations → Conflicts.

| # | Connector | Category | Design | 2.2.0 status | Code evidence | M2 priority |
|---|---|---|---|---|---|---|
| 1 | GitHub | SCM & IDE | today | **Existing** | `scm/github.go`, `scm/auth.go`, `repos/webhooks.go` | Yes |
| 2 | GitLab | SCM & IDE | today | **Existing** | `scm/gitlab.go`, `repos/webhooks.go:97` | Yes |
| 3 | Bitbucket Cloud | SCM & IDE | today | **Existing** | `scm/bitbucket.go`, `repos/webhooks.go:126` | Yes |
| 4 | Azure DevOps | SCM & IDE | today | **Existing** | `scm/azure.go`, `repos/webhooks.go:73` | Yes |
| 5 | GitHub Enterprise Server | SCM & IDE | new | **Partial** (provider exists; no per-connection CA) | `scm/contract.go` `GitHubEnterprise`, `scm/providers.go` | Yes |
| 6 | GitLab Self-Managed | SCM & IDE | extend | **Partial** (same provider as gitlab.com; no per-connection CA) | `scm/contract.go:12` | Yes |
| 7 | Bitbucket Data Center | SCM & IDE | new | **Planned** | `scm/bitbucket.go:17` says "Bitbucket Data Center is not supported" | Yes |
| 8 | Generic Git (HTTPS/SSH) | SCM & IDE | new | **Planned** (upload and archive import exist; no generic clone connector) | none | No |
| 9 | PATHOS CLI | SCM & IDE | today | **Existing** | `backend/cmd/pathos-cli`, `integrations/install-cli.sh` | Inbound |
| 10 | VS Code | SCM & IDE | today | **Existing** (0.1.0) | `ide/vscode` | Inbound |
| 11 | JetBrains IDEs | SCM & IDE | new | **Existing** (0.1.0) | `ide/jetbrains` | Inbound |
| 12 | Visual Studio | SCM & IDE | later | **After lifecycle release** | none | No |
| 13 | GitHub Actions | CI/CD | today | **Existing** | `integrations/github-action/action.yml` | Inbound |
| 14 | GitLab CI/CD | CI/CD | today | **Existing** | `integrations/gitlab/pathos.gitlab-ci.yml` | Inbound |
| 15 | Azure Pipelines | CI/CD | today | **Existing** | `integrations/azure-pipelines/pathos.yml` | Inbound |
| 16 | Jenkins | CI/CD | today | **Existing** | `integrations/jenkins/Jenkinsfile` | Inbound |
| 17 | pre-commit / pre-receive | CI/CD | today | **Existing** | `integrations/pre-commit`, `integrations/pre-receive`, `backend/internal/pushprotect` | Inbound |
| 18 | Bitbucket Pipelines | CI/CD | new | **Planned** | none | No |
| 19 | Argo CD / deploy gate | CI/CD | later | **After lifecycle release** | none | No |
| 20 | AWS | Cloud | new | **Planned** | none (only live validation of AWS keys: `worker/secretcheck.go:970`) | Yes |
| 21 | Microsoft Azure | Cloud | new | **Planned** | none (only live validation of storage keys) | Yes |
| 22 | Google Cloud | Cloud | new | **Planned** | none (only live validation of Google API keys) | Yes |
| 23 | S3-compatible storage | Cloud | today | **Partial** (static access key only; no IAM role) | `platform/objstore/objstore.go:58` | No |
| 24 | Container registries | Containers | extend | **Partial** (generic OCI registry; no ECR/ACR/GCP token exchange) | `runtimectx/registry.go` | Yes |
| 25 | Kubernetes | Containers | new | **Existing** | `runtimectx/k8s.go`, `runtimectx/kubeconfig.go`, `deploy/kubernetes/pathos-reader-clusterrole.yaml` | Yes |
| 26 | Sigstore / cosign | Containers | today | **Existing** | `scans/signature.go` | No |
| 27 | Scanner result import | Security | today | **Existing** | `scanners/importformats.go` | Inbound |
| 28 | Vulnerability feeds | Security | today | **Existing** | `intel/service.go`, `intel/osv.go`, `eol/feed.go` | No |
| 29 | SIEM (Splunk, Sentinel, Elastic) | Security | new | **Planned** (generic signed JSON webhook exists) | `notify/webhooks.go` | Yes |
| 30 | Keycloak (built in) | IAM & Secrets | today | **Existing** | `backend/internal/identity/keycloak.go`, `docs/SECURITY.md:19` | No |
| 31 | SAML / OIDC SSO | IAM & Secrets | today | **Existing** (brokered by Keycloak) | `docs/user-guide/sign-in-and-sso.md:28` | No |
| 32 | HashiCorp Vault | IAM & Secrets | new | **Planned** | none | Yes |
| 33 | Cloud secret managers | IAM & Secrets | new | **Planned** | none | No (follows Vault) |
| 34 | OpenAPI / Swagger | APIs | extend | **Partial** (file upload for API scan targets) | `scans/targets.go:237` `ValidateAPISpec` | No |
| 35 | Postman collections | APIs | new | **Planned** | none | No |
| 36 | GraphQL schema | APIs | new | **Planned** | none | No |
| 37 | API gateways | APIs | later | **After lifecycle release** | none | No |
| 38 | PATHOS REST API & MCP | APIs | today | **Existing** | `backend/internal/mcp/server.go`, `mcp/tokens.go` | Inbound |
| 39 | PostgreSQL / MySQL / SQL Server | Databases | later | **After lifecycle release** | none | No |
| 40 | MongoDB / Oracle | Databases | later | **After lifecycle release** | none | No |
| 41 | OpenTelemetry | Monitoring | today | **Existing** | `platform/telemetry/telemetry.go` | No |
| 42 | Prometheus | Monitoring | new | **Planned** (no `/metrics` endpoint) | none | No |
| 43 | Slack · Microsoft Teams | Monitoring | today | **Partial** (Slack Existing; Teams works only with an unauthenticated Workflows URL since connectors were retired) | `notify/webhooks.go:38,470-493` | Yes |
| 44 | Email (SMTP) | Monitoring | today | **Existing** | `notify/smtp.go` | No |
| 45 | Webhooks | Monitoring | today | **Existing** | `notify/webhooks.go` | No |
| 46 | Jira · ServiceNow | Monitoring | today | **Existing** | `tickets/connectors.go` | Yes |
| E1 | Azure DevOps Server | SCM & IDE | not listed | **Existing** (PAT only) | `scm/azure.go:53`, `scm/providers.go` | Yes |
| E2 | AI providers (Anthropic, OpenAI, xAI, self-hosted OpenAI-compatible) | not listed (proposed: APIs) | not listed | **Existing** | `ai/provider.go:16` | No |
| E3 | Live secret validation (12 checkable providers) | not listed (proposed: Security) | not listed | **Existing** | `scanners/secretproviders.go:26` | No |
| E4 | deps.dev package health | not listed (Security) | not listed | **Existing** | `intel/depsdev.go` | No |
| E5 | endoflife.date | not listed (Security) | not listed | **Existing** | `eol/feed.go` | No |
| E6 | OSV.dev records | not listed (Security) | not listed | **Existing** | `intel/osv.go` | No |
| E7 | MCP registry (outbound MCP servers, approval) | not listed (APIs) | not listed | **Existing** | `mcp/registry.go:75` | No |
| E8 | Egress proxy (Squid allowlist) | not listed (platform) | not listed | **Existing** | `deploy/egress/allowlist.txt` | No |

Counts (54 rows): Existing 31, Partial 6, Planned 12, After lifecycle release 5. The design's 46 entries: Existing 23, Partial 6, Planned 12, After lifecycle release 5. The 8 extra rows are all Existing.

### Connector records

Each record uses the same fields. "Sources" are official vendor pages checked on **2026-11-20**. "Not verified" means the official page did not state the fact. Every error code in a record is **Planned**. The shared codes `PTH-CONN-1001`–`1019` and `PTH-SYNC-1001`–`1010` (Error handling) apply to every connector, so the records list only the extra connector-specific codes.

**Credential storage rule (applies to every record unless it says otherwise).** The credential is write-only. It goes through `secrets.Store` (AES-256-GCM envelope, AAD `pathos:secret:<kind>:<id>`), is revealed only inside the job that uses it, is never logged or returned, is never sent to an AI model, and is deleted with the connection. Records name the secret kind used today, or the kind planned.

#### SCM & IDE

##### GitHub (github.com) — Existing

| Field | Value |
|---|---|
| Evidence | `scm/github.go`, `scm/auth.go` (App JWT and installation tokens), `scm/providers.go:19-43`, webhooks `repos/webhooks.go:42-63`, statuses `scm/status.go:72`, fix PRs `scm/pullrequest.go:180-301` |
| Auth (PATHOS) | GitHub App (recommended), fine-grained PAT, classic PAT, OAuth App |
| Auth (vendor) | Installation tokens expire after 1 hour and can be limited to at most 500 repositories and to a subset of the app's permissions. GitHub recommends fine-grained PATs over classic ones. A fine-grained PAT covers one resource owner, can expire in 1–366 days or never (an org policy can cap this), may need org approval, and does **not** support the Checks API or Packages. Unused PATs are removed after 1 year. Source [1][2] |
| Least privilege, read | Metadata: read, Contents: read, Pull requests: read (as the wizard says today). Source [3] |
| Least privilege, write (only if the feature is on) | Commit statuses: write (PR checks), Contents: write + Pull requests: write (fix PRs; Workflows: write if a workflow file changes), Pull requests: write or Issues: write (PR comments), Webhooks: write (Planned auto-registration). Checks: write is GitHub App only. Source [3][4] |
| OAuth App scopes | `repo` gives full read and write on private repos; there is no read-only private-repo scope. Hence the GitHub App is the least-privilege choice. Source [5] |
| API style and version | REST, `X-GitHub-Api-Version: 2022-11-28` (`scm/github.go:52-55`, `scm/github.go:585`). Supported versions: `2026-03-10` and `2022-11-28`; `2022-11-28` reaches end of support on 2028-03-10. M2: test on `2026-03-10` and move before 2028. Source [6] |
| Webhooks | `X-Hub-Signature-256: sha256=<hex>` HMAC-SHA256 of the raw body, constant-time compare (SHA-1 `X-Hub-Signature` is legacy). `X-GitHub-Delivery` GUID is reused on redelivery. The receiver must answer 2xx within 10 s. GitHub does not redeliver automatically; manual redelivery covers the last 3 days. Payloads up to 25 MB, **but PATHOS accepts 5 MiB** (`repos/webhooks.go:18`) — push events with large payloads are rejected; M2 must decide whether to raise it. Source [7][8][9][10] |
| Rate limits | Unauthenticated 60/h per IP. PAT or user token 5,000/h. App installation 5,000/h plus 50/h per repository and per user above 20, capped at 12,500 (15,000 on Enterprise Cloud). Secondary limits: 100 concurrent requests, 900 points/min REST, content creation 80/min and 500/h; honour `retry-after`. Headers `x-ratelimit-limit/-remaining/-used/-reset/-resource`. Source [11] |
| Pagination | `Link` header (`next`, `last`), `per_page` max 100. PATHOS follows `next` on the same origin only (`scm/github.go:64`). Source [12] |
| Proxy and CA | Proxy: `PATHOS_HTTPS_PROXY`. CA: public CA, no setting needed |
| Offline | Not available (needs github.com). Shows Disabled (offline) |
| Credential storage | Kind `scm` (token, App private key, OAuth tokens); webhook secret kind `webhook` |
| Health check | `GET /installation/repositories?per_page=1` (App) or `GET /user` (PAT), plus `GET /rate_limit` to record remaining quota. Healthy = 2xx and the expected permissions present. Warning = PAT expires within 14 days, fewer than 10% of the hourly limit left, or no webhook delivery in 7 days while pushes are seen in re-sync |
| Error codes | PTH-CONN-1101 App installation not found or suspended · PTH-CONN-1102 Fine-grained token cannot use this API (Checks, Packages) · PTH-CONN-1103 Organization requires SAML SSO authorization for the token · PTH-CONN-1104 API version no longer supported · PTH-CONN-1106 Webhook payload larger than PATHOS accepts |

Sources (checked 2026-11-20): [1] https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app · [2] https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens · [3] https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens · [4] https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps · [5] https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps · [6] https://docs.github.com/en/rest/about-the-rest-api/api-versions · [7] https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries · [8] https://docs.github.com/en/webhooks/webhook-events-and-payloads · [9] https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks · [10] https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/redelivering-webhooks · [11] https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api · [12] https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api. Not verified: GitHub App JWT maximum lifetime.

##### GitHub Enterprise Server — Partial

| Field | Value |
|---|---|
| Evidence | Provider `github_enterprise` (`scm/contract.go`), same client and auth as GitHub, base URL required (`scm/providers.go:52-56`) |
| Missing | Per-connection CA bundle; a version check |
| Auth, scopes, webhooks, pagination | As GitHub. REST base `https://HOST/api/v3`, GraphQL `https://HOST/api/graphql`. Source [1][2] |
| Supported versions | 3.19 (end of support 2026-12-09), 3.20 (2027-03-17), 3.21 (2027-06-11), 3.22 (2027-09-08). 3.18 is out of support. M2: read the server version (`GET /meta` returns `installed_version` — not verified) and warn below the oldest supported release. Source [3] |
| Rate limits | Disabled by default on GHES; a site administrator can enable them, including secondary limits. PATHOS still applies its own per-connection bucket. Source [4] |
| Proxy and CA | Usually on a private network: `allow_private` per connection, `NO_PROXY` for the host. Private CA: **gap** (see Known limitations); vendor guidance for API clients behind a private CA: not verified |
| Offline | Works (internal server) |
| Credential storage | As GitHub |
| Health check | As GitHub, plus the version check |
| Error codes | PTH-CONN-1105 GitHub Enterprise Server version out of support · plus the GitHub codes |

Sources (checked 2026-11-20): [1] https://docs.github.com/en/enterprise-server@latest/rest/quickstart · [2] https://docs.github.com/en/enterprise-server@latest/graphql/guides/forming-calls-with-graphql · [3] https://docs.github.com/en/enterprise-server@latest/admin/all-releases · [4] https://docs.github.com/en/enterprise-server@latest/rest/using-the-rest-api/rate-limits-for-the-rest-api

##### GitLab (gitlab.com) and GitLab Self-Managed — Existing / Partial

| Field | Value |
|---|---|
| Evidence | `scm/gitlab.go` (one provider for both, `scm/contract.go:12`), webhooks `repos/webhooks.go:97`, statuses `scm/status.go:88`, MRs `scm/pullrequest.go:309-391` |
| Missing (self-managed) | Per-connection CA bundle; version check |
| Auth (PATHOS) | Personal, group or project access token; OAuth application |
| Auth (vendor) | PAT, project and group tokens: default and maximum lifetime 365 days (admins can change the maximum on 17.6+). Project and group access tokens on gitlab.com need Premium or Ultimate; on self-managed any licence. OAuth 2.0: authorization code (with PKCE) and device grant; refresh rotates both tokens. Source [1][2][3][4] |
| Least privilege, read | `read_api` + `read_repository` (as the wizard says). Reporter role for group and project tokens |
| Least privilege, write | `api` with Developer role for commit statuses, MR notes and fix MRs. `write_repository` does not work for API calls. That `api` is the minimum for these writes is inferred from the scope list (not verified as a direct statement). Source [1] |
| API style and version | REST v4, `https://HOST/api/v4`. Source [5] |
| Webhooks | **Change since PATHOS was written:** GitLab now signs webhooks with HMAC-SHA256 per the Standard Webhooks spec (GA in 19.1): headers `webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<base64>`, signed string `{id}.{timestamp}.{body}`, secret prefixed `whsec_`. `X-Gitlab-Token` is now called legacy. PATHOS verifies only `X-Gitlab-Token` today (`scm/webhook.go:172`). M2: support the signing token and prefer it; keep the token for older self-managed versions. Auto-disable: after 4 consecutive failures temporarily (1 min, backing off to 24 h), permanently after 40. gitlab.com timeout 10 s, payload 25 MB. Source [6][7] |
| Rate limits | gitlab.com: authenticated API 2,000 requests/min per user; unauthenticated 500/min per IP. Headers `RateLimit-Limit`, `RateLimit-Remaining`; on 429 `Retry-After` and `RateLimit-ResetTime` (Projects, Groups and Users APIs omit the headers). Self-managed: off by default; when enabled, the authenticated API default is 7,200 per hour. Source [8][9] |
| Pagination | Offset: `page`, `per_page` (max 100), `X-Next-Page`, `Link`; above 10,000 records `X-Total` and `rel="last"` are omitted. Keyset (`pagination=keyset`) on some endpoints. PATHOS follows `Link` (`scm/gitlab.go:58`). Source [5] |
| Proxy and CA | gitlab.com: proxy only. Self-managed: `allow_private`, `NO_PROXY`; private CA is a gap |
| Offline | gitlab.com not available; self-managed works |
| Credential storage | Kind `scm`; webhook secret kind `webhook` (M2: the signing token is stored the same way) |
| Health check | `GET /api/v4/personal_access_tokens/self` (returns scopes and expiry — endpoint name not verified in this pass; fall back to `GET /api/v4/user`), then `GET /api/v4/version` for self-managed. Warning when expiry is within 14 days or a needed scope is missing |
| Error codes | PTH-CONN-1110 Token lacks a required scope (shows which) · PTH-CONN-1111 GitLab disabled the webhook after failures · PTH-CONN-1112 Webhook uses the legacy secret token (warning) · PTH-CONN-1113 Group or project tokens need a paid tier on gitlab.com · PTH-CONN-1114 GitLab version below supported minimum |

Sources (checked 2026-11-20): [1] https://docs.gitlab.com/security/tokens/access_token_scopes/ · [2] https://docs.gitlab.com/user/profile/personal_access_tokens/ · [3] https://docs.gitlab.com/user/project/settings/project_access_tokens/ and https://docs.gitlab.com/user/group/settings/group_access_tokens/ · [4] https://docs.gitlab.com/api/oauth2/ · [5] https://docs.gitlab.com/api/rest/ · [6] https://docs.gitlab.com/user/project/integrations/webhooks/ · [7] https://docs.gitlab.com/user/gitlab_com/ · [8] https://docs.gitlab.com/user/gitlab_com/rate_limits/ · [9] https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/. Not verified: self-managed default webhook timeout; GitLab's supported-version policy (to verify in M2).

##### Bitbucket Cloud — Existing

| Field | Value |
|---|---|
| Evidence | `scm/bitbucket.go`, webhooks `repos/webhooks.go:126`, statuses `scm/status.go:105`, PRs `scm/pullrequest.go:399-473` |
| Auth (PATHOS) | Workspace, project or repository access token; Atlassian API token (e-mail + token, Basic); OAuth consumer |
| Auth (vendor) | App passwords are deprecated and **stopped working after 2026-07-28**; PATHOS does not offer them (good). API tokens use Basic auth with the Atlassian e-mail; they cannot be viewed after creation. OAuth 2.0: authorization code only; access tokens last 1 h; unused refresh tokens expire after 3 months; since 2026-05-04 OAuth calls must go to `api.bitbucket.org` with `Bearer`. Source [1][2] |
| Least privilege, read | API token: `read:repository:bitbucket` (+ `read:pullrequest:bitbucket` for PR data). Access token / OAuth: `repository` (read), `pullrequest` (read and comment; implies `repository`). Note: the wizard's API-token text lists `read:user`, `read:workspace`, `read:project`, `read:repository` (`scm/providers.go:86`); M2 should check that list against the scope reference. Source [1] |
| Least privilege, write | `repository:write` (statuses), `pullrequest:write` (create PRs; implies `repository:write`), `webhook` (Planned auto-registration). API-token equivalents `write:pullrequest:bitbucket`, `write:webhook:bitbucket`. Source [1] |
| API style and version | REST 2.0, `https://api.bitbucket.org/2.0` (fixed) |
| Webhooks | `X-Hub-Signature: sha256=<hex>` HMAC-SHA256 of the raw body, constant-time compare. PATHOS dedupes on `X-Request-UUID`. Headers, timeout and retries: not verified. Source [3] |
| Rate limits | Per user, rolling hour: repository data 1,000/h (scaled up to 10,000/h for Standard/Premium workspaces with 100+ paid users using an access token: 1,000 + (paid users − 100) × 10); webhook management 1,000/h; raw files 5,000/h. Anonymous 60/h. Headers `X-RateLimit-Limit`, `X-RateLimit-Resource`, `X-RateLimit-NearLimit`. Source [4] |
| Pagination | `values`, `next` (follow it), `pagelen` 10–100. Source [1] |
| Proxy and CA | Proxy only; public CA |
| Offline | Not available |
| Credential storage | Kind `scm`; webhook secret kind `webhook` |
| Health check | `GET /2.0/user` or, for access tokens, `GET /2.0/repositories/{workspace}?pagelen=10`. Warning when `X-RateLimit-NearLimit` is true |
| Error codes | PTH-CONN-1120 App passwords no longer work; use an API or access token · PTH-CONN-1121 Token lacks a required Bitbucket scope · PTH-CONN-1122 OAuth call sent to the wrong host or without Bearer |

Sources (checked 2026-11-20): [1] https://developer.atlassian.com/cloud/bitbucket/rest/intro/ · [2] https://support.atlassian.com/bitbucket-cloud/docs/revoke-an-app-password/ · [3] https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/ · [4] https://support.atlassian.com/bitbucket-cloud/docs/api-request-limits/. Not verified: API token maximum expiry; webhook headers, timeout and retries.

##### Bitbucket Data Center — Planned (M2)

| Field | Value |
|---|---|
| Evidence | None. `scm/bitbucket.go:17`: "Bitbucket Data Center is not supported" |
| Auth | HTTP access tokens: personal, project, repository (project and repository tokens need a Data Center licence). Permissions read / write / admin. Project and repository tokens: `Bearer` (or Basic with user `x-token-auth`); personal tokens: Basic. Expiry optional unless an admin requires it. Tokens cannot merge PRs. Source [1] |
| Least privilege | Project or repository token with **read** for inventory; **write** only for statuses and fix PRs. Repository-level permission must be at least the project-level one. Source [1] |
| API style and version | REST `/rest/api/1.0/…` (`/rest/api/latest/…` in examples). Supported releases: 9.4 LTS (end of support 2026-12-03) to 10.4 (2028-07-21); 2 years each. M2 minimum: 9.4, warn before its end date. Source [2][3] |
| Webhooks | `X-Hub-Signature: sha256=<hex>` HMAC-SHA256 (same verifier as Bitbucket Cloud). Circuit breaker: after 5 failures the hook is skipped, skip time grows from 10 s to 10 h; at most 250 deliveries in flight. Source [4] |
| Rate limits | Token bucket per user, default size 60, refill 5/s, 429 when exceeded; per cluster node. Whether it is on by default: not verified. Source [5] |
| Pagination | `start`, `limit` (often 25 by default; admin cap), `isLastPage`, `nextPageStart`. Source [2] |
| Proxy and CA | Private network, `allow_private`, private CA likely: needs the CA field |
| Offline | Works |
| Credential storage | Kind `scm` |
| Health check | `GET /rest/api/1.0/application-properties` (version) and a 1-item repository list |
| Error codes | PTH-CONN-1123 Bitbucket Data Center version out of support · PTH-CONN-1124 HTTP access token lacks the permission (read/write) |

Sources (checked 2026-11-20): [1] https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html · [2] https://developer.atlassian.com/server/bitbucket/rest/v1000/intro/ · [3] https://confluence.atlassian.com/support/atlassian-support-end-of-life-policy-201851003.html · [4] https://confluence.atlassian.com/bitbucketserver/manage-webhooks-938025878.html · [5] https://confluence.atlassian.com/bitbucketserver/improving-instance-stability-with-rate-limiting-976171954.html. Not verified: SSH access details, webhook timeout and headers, `application-properties` endpoint name.

##### Azure DevOps Services and Azure DevOps Server — Existing

| Field | Value |
|---|---|
| Evidence | `scm/azure.go` (`adoAPIVersion = "7.1"`, line 30), Server PAT only (`scm/azure.go:53`), service hooks `repos/webhooks.go:73`, statuses `scm/status.go:128` |
| Auth (PATHOS) | Services: Entra ID service principal (secret or certificate), PAT, Entra ID OAuth (`user_impersonation`). Server: PAT |
| Auth (vendor) | Microsoft recommends Entra ID: managed identity, then service principal, then Entra OAuth (MSAL). PATs only for personal, legacy or Server use. The old Azure DevOps OAuth app model is deprecated: no new registrations since April 2025, existing apps stop working in 2026 (PATHOS uses Entra OAuth, not this model). **Global PATs are being retired:** the same Microsoft page gives both 2026-12-01 and 2027-01-27 (conflict on the vendor page; treat the earlier date as binding). PATs are used as Basic auth with an empty user name. Source [1][2][3] |
| Least privilege, read | `vso.code` (Code read) and Project and Team read (as the wizard says). Org-scoped PAT, not global. Source [2][3] |
| Least privilege, write | `vso.code_status` (commit and PR statuses), `vso.code_write` (fix PRs), `vso.threads_full` (PR comments). Source [2] |
| API style and version | REST `api-version=7.1` (Services; Server 2022.1 = 7.1, Server 2022 = 7.0). Docs default view is 7.2. Source [4] |
| Webhooks | Service hooks, consumer `webHooks`, action `httpRequest`. No HMAC signing option documented. PATHOS verifies the basic-auth password (constant time) — HTTPS is required for basic auth. Custom headers are visible to anyone who can read the subscription, so the secret must go in basic auth, not a header. Retry and timeout: not verified. Source [5][6] |
| Rate limits | 200 TSTU per sliding 5 minutes per user and per pipeline; requests are delayed up to 30 s, then blocked with 429 (TF400733). Headers `Retry-After`, `X-RateLimit-Resource/-Delay/-Limit/-Remaining/-Reset`. Source [7] |
| Pagination | Per endpoint: `continuationToken` query parameter and `$top` (e.g. Git refs max 1,000). PATHOS paginates repositories client-side with an offset cursor (`scm/pagetoken.go`). `x-ms-continuationtoken` response header: not verified. Source [8] |
| Proxy and CA | Services: proxy only. Server: private network, private CA gap |
| Offline | Services not available; Server works |
| Credential storage | Kind `scm` (PAT, client secret, certificate private key); webhook secret kind `webhook` |
| Health check | `GET https://dev.azure.com/{org}/_apis/projects?$top=1&api-version=7.1`; for service principals also token acquisition. Warning when `X-RateLimit-Delay` is present or a PAT expires within 14 days |
| Error codes | PTH-CONN-1130 Global PATs are retired; create an organization-scoped PAT · PTH-CONN-1131 PAT blocked by an organization or tenant policy · PTH-CONN-1132 Service principal is not a member of the organization · PTH-CONN-1133 Requests delayed by Azure DevOps (TSTU) |

Sources (checked 2026-11-20): [1] https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/authentication-guidance · [2] https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth · [3] https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate and https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-pats-with-policies-for-administrators · [4] https://learn.microsoft.com/en-us/rest/api/azure/devops/?view=azure-devops-rest-7.1 · [5] https://learn.microsoft.com/en-us/azure/devops/service-hooks/consumers · [6] https://learn.microsoft.com/en-us/azure/devops/service-hooks/services/webhooks · [7] https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits · [8] https://learn.microsoft.com/en-us/rest/api/azure/devops/git/refs/list?view=azure-devops-rest-7.1. Not verified: global PAT end date (vendor page conflicts), service hook retry and timeout, PAT default maximum lifetime.

##### Generic Git (HTTPS/SSH) — Planned (owner to confirm M2 or later)

Read-only clone of any Git server with an SSH deploy key or HTTPS token. No API, no webhooks, no rate-limit headers: sync is a scheduled `git ls-remote` per repository. SSH needs a pinned host key (known_hosts) stored with the connection. Credential kind `scm`. Codes: PTH-CONN-1140 SSH host key mismatch · PTH-CONN-1141 Git authentication failed. Vendor facts: not applicable.

##### PATHOS CLI, VS Code, JetBrains IDEs — Existing (inbound); Visual Studio — After lifecycle release

| Field | Value |
|---|---|
| Evidence | CLI `backend/cmd/pathos-cli` (`--ca-cert`, `client.go:103`); VS Code `ide/vscode` (0.1.0; token in VS Code SecretStorage, `src/config.ts`); JetBrains `ide/jetbrains` (0.1.0; token in PasswordSafe, `settings/TokenStore.kt`) |
| Auth | PATHOS personal API token (`mcp/tokens.go`), stored as a SHA-256 hash on the server; scopes `mcp`, `api:read`, `api:write`, expiry and revocation |
| Least privilege | IDEs: `api:read`. CLI uploads: `api:write` |
| API | PATHOS REST `/api/v1` |
| Webhooks, vendor rate limits | None. PATHOS's own API rate limits apply (`platform/ratelimit`, `PATHOS_RATE_LIMIT_SCALE`) |
| Proxy and CA | CLI: `--ca-cert`. IDEs use the editor's proxy and trust settings (not checked further) |
| Offline | Works against an internal PATHOS |
| Credential storage | Client side: OS keychain via the editor; server side: hash only |
| Health check | Planned: last-seen time per token and client version (from `User-Agent`), shown under Health. Not a vendor check |
| Error codes | PTH-CONN-1801 API token expired or revoked · PTH-CONN-1802 API token lacks the scope · PTH-CONN-1803 Client does not trust the PATHOS certificate · PTH-CONN-1804 Client version not compatible with this server |

#### CI/CD

##### GitHub Actions, GitLab CI/CD, Azure Pipelines, Jenkins, pre-commit / pre-receive — Existing (inbound)

Templates: `integrations/github-action/action.yml`, `integrations/gitlab/pathos.gitlab-ci.yml`, `integrations/azure-pipelines/pathos.yml`, `integrations/jenkins/Jenkinsfile`, `integrations/pre-commit`, `integrations/pre-receive`. All authenticate with a PATHOS API token (`api:write`) kept in the CI system's own secret store (GitHub secret, GitLab masked variable, Azure variable group, Jenkins credentials). PATHOS never stores the CI system's credentials. No webhooks, no vendor rate limits (PATHOS limits apply). Offline: works with an internal PATHOS and the CLI installed from `integrations/install-cli.sh`. Health (Planned): last upload per pipeline and the template version in use. Codes: the inbound 18xx codes, plus PTH-CONN-1810 CI upload rejected (format or size). Vendor facts: not needed (PATHOS is called by the pipeline).

##### Bitbucket Pipelines — Planned · Argo CD / deploy gate — After lifecycle release

Bitbucket Pipelines: a template like the others, token in a secured repository variable. To verify in M2. Argo CD: after the lifecycle release.

#### Cloud

##### AWS — Planned (M2)

| Field | Value |
|---|---|
| Evidence | None (only live validation of leaked AWS keys, `worker/secretcheck.go:970`) |
| Auth | Cross-account IAM role: PATHOS calls `sts:AssumeRole` with an `ExternalId`. The trust policy requires `sts:ExternalId` (`StringEquals`). AWS says the external ID must be unique per customer and generated by the vendor (PATHOS generates it per connection; the customer cannot choose it). Session default 1 h, minimum 15 min, maximum the role's setting (up to 12 h); role chaining caps at 1 h. The source identity for AssumeRole (a PATHOS-side IAM user or instance role) is configured by the operator. Source [1][2] |
| Least privilege | Start from `SecurityAudit` (reads security configuration metadata; no `GetSecretValue`, no `s3:GetObject`) or `ViewOnlyAccess`; never `ReadOnlyAccess` (reads S3 and DynamoDB data). AWS notes managed policies are not least privilege; M2 ships a custom policy. Source [3][4] |
| API style and version | AWS SDK for Go v2, SigV4 (requests must reach AWS within 5 minutes of their timestamp). Source [5] |
| Webhooks | None (pull) |
| Rate limits | Per service and per Region. SDK retry modes `standard` (default, 3 attempts), `adaptive`, `legacy`. The new 2026 retry behaviour (full jitter, cap 20 s, `x-amz-retry-after`) applies only with `AWS_NEW_RETRIES_2026=true`. Source [6] |
| Pagination | `NextToken` on most APIs; IAM uses `Marker` + `IsTruncated` (`MaxItems` max 1,000). Source [7] |
| Proxy and CA | `HTTPS_PROXY` (CLI page; per-SDK statement not verified). Custom CA: `AWS_CA_BUNDLE` / `ca_bundle`, supported by the Go v2 SDK. Private networks: STS interface VPC endpoints exist in most Regions. Source [8][9][10] |
| Offline | Not available (AWS is a public cloud; VPC endpoints still need AWS) |
| Credential storage | No long-lived secret when PATHOS runs with an instance or pod role. The external ID is not a secret but is stored in the connection. If a static access key is used for the source identity, kind `integration` |
| Health check | `sts:GetCallerIdentity` with the assumed role, then one read call per enabled service in one Region. Healthy = both succeed |
| Error codes | PTH-CONN-1401 AssumeRole denied (trust policy) · PTH-CONN-1402 External ID does not match · PTH-CONN-1403 Region disabled or not opted in · PTH-CONN-1404 AWS throttling (per service) · PTH-CONN-1405 Policy lacks a read permission (shows the action) |

Sources (checked 2026-11-20): [1] https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html · [2] https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html · [3] https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html · [4] https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html · [5] https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html · [6] https://docs.aws.amazon.com/sdkref/latest/guide/feature-retry-behavior.html · [7] https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html and https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-pagination.html · [8] https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-proxy.html · [9] https://docs.aws.amazon.com/sdkref/latest/guide/feature-gen-config.html · [10] https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_sts_vpce.html. Not verified: `HTTPS_PROXY` in every SDK.

##### Microsoft Azure — Planned (M2)

| Field | Value |
|---|---|
| Evidence | None (only live validation of storage account keys, `scanners/secretproviders.go:54`) |
| Auth | Preferred: workload identity federation (federated credential on an app registration; audience `api://AzureADTokenExchange`, max 20 per app, propagation delay can cause AADSTS70021) or managed identity when PATHOS runs on Azure. Fallback: service principal with a **certificate**. Microsoft says client secrets should not be used in production (max 24 months). Source [1][2][3] |
| Least privilege | `Reader` (`*/read`, no data actions, cannot read Key Vault secret values) on the subscriptions or management group. `Security Reader` is for Defender for Cloud data, not inventory. Source [4][5] |
| API style and version | Azure Resource Manager REST, `api-version` required on every call; Azure SDK for Go (`azidentity`) proposed. Source [6] |
| Webhooks | None (pull) |
| Rate limits | Token bucket per region: subscription and tenant reads bucket 250, refill 25/s; writes 200, refill 10/s; per subscription, per principal and per operation type. 429 with `Retry-After`; headers `x-ms-ratelimit-remaining-subscription-reads` and others. Resource providers add their own limits. Source [7] |
| Pagination | Follow `nextLink` until absent. Source [6] |
| Proxy and CA | Proxy through `PATHOS_HTTPS_PROXY`; public CA |
| Offline | Not available |
| Credential storage | Certificate private key or client secret: kind `integration`. Federation: no stored secret |
| Health check | Token acquisition, then `GET /subscriptions?api-version=…` and check the expected subscriptions are listed |
| Error codes | PTH-CONN-1410 Federated credential does not match (AADSTS70021) · PTH-CONN-1411 Client secret or certificate expired · PTH-CONN-1412 ARM throttling · PTH-CONN-1413 No Reader role on the subscription |

Sources (checked 2026-11-20): [1] https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials · [2] https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation · [3] https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations · [4] https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general · [5] https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security · [6] https://learn.microsoft.com/en-us/rest/api/azure/ · [7] https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling. Not verified: SDK default retry policy for ARM 429.

##### Google Cloud — Planned (M2)

| Field | Value |
|---|---|
| Evidence | None (only live validation of Google API keys) |
| Auth | Workload Identity Federation (AWS, Azure, OIDC, SAML 2.0, X.509, GitHub, GitLab) returning short-lived tokens. Service account keys are discouraged, and key creation is disabled by default for organizations created on or after 2024-05-03. Source [1][2] |
| Least privilege | `roles/cloudasset.viewer` for Cloud Asset Inventory, `roles/iam.securityReviewer` for IAM policies. Not `roles/viewer` (Google: do not grant basic roles in production). Source [3][4][5] |
| API style and version | Cloud Asset Inventory API v1 (`cloudasset.googleapis.com/v1/{parent}/assets`). Source [6] |
| Webhooks | None (pull) |
| Rate limits | Per consumer project per minute: ListAssets 100, SearchAllResources 400, SearchAllIamPolicies 400, ExportAssets 60 (higher per organization). Truncated exponential backoff with jitter (32–64 s max). Source [7][8] |
| Pagination | `pageSize` (max 1,000), `pageToken` / `nextPageToken`; tokens expire 72 h after the first page. Source [6] |
| Proxy and CA | Proxy through `PATHOS_HTTPS_PROXY`. Private Google Access and Private Service Connect for private networks. Source [9] |
| Offline | Not available |
| Credential storage | Federation config (not secret) in the connection; a key file only if the operator insists: kind `integration` |
| Health check | Token exchange, then `ListAssets` with `pageSize=1` on the configured parent |
| Error codes | PTH-CONN-1420 Workload identity token exchange failed · PTH-CONN-1421 Cloud Asset API not enabled in the project · PTH-CONN-1422 Google Cloud quota exceeded · PTH-CONN-1423 Service account key creation disabled by organization policy (use federation) |

Sources (checked 2026-11-20; Google now serves docs from `docs.cloud.google.com`): [1] https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys · [2] https://docs.cloud.google.com/iam/docs/workload-identity-federation · [3] https://docs.cloud.google.com/iam/docs/roles-overview · [4] https://docs.cloud.google.com/iam/docs/roles-permissions/iam · [5] https://docs.cloud.google.com/asset-inventory/docs/access-control · [6] https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list · [7] https://docs.cloud.google.com/asset-inventory/docs/quota · [8] https://docs.cloud.google.com/iam/docs/retry-strategy · [9] https://docs.cloud.google.com/vpc/docs/private-google-access. Not verified: whether `roles/viewer` includes `cloudasset.*`; full `securityReviewer` permission list; a Google-wide 429 retry statement.

##### S3-compatible storage (PATHOS artifact store) — Partial

Evidence: `platform/objstore/objstore.go` (AWS SDK for Go v2 S3 client, static `aws.Credentials` from `PATHOS_S3_ACCESS_KEY` / `_SECRET_KEY`, line 58; path-style default). Missing: IAM role / instance profile, so the design's "IAM role" is Planned. Credentials live in the environment (`.env`), not in `secrets.Store`; they are platform configuration, not a connector credential. Custom CA: system trust store only; `AWS_CA_BUNDLE` is not wired because the client is built from fixed options (to verify in M2). Offline: works with MinIO or another internal S3. Health: `HeadBucket` (already called at start-up, `objstore.go:79`). Codes: PTH-CONN-1430 Object store bucket not reachable · PTH-CONN-1431 Object store access denied. Vendor facts: to verify in M2.

#### Containers

##### Container registries (Docker Hub, GHCR, ECR, ACR, Artifact Registry, Harbor) — Partial

| Field | Value |
|---|---|
| Evidence | Generic OCI Distribution v2 client `runtimectx/registry.go`: auth `none`, `basic`, `bearer`; follows the Docker `WWW-Authenticate: Bearer` token challenge (realm must be https, `registry.go:147-200`); tag list with `n` and `Link` pagination (`registry.go:233-270`); 200 ms between requests; `max_tags` |
| Missing | Vendor token exchange for ECR (AWS), ACR (Entra) and Artifact Registry (Google). Today these work only with a manually pasted short-lived token, which expires (ECR 12 h, ACR Entra 3 h, Artifact Registry 60 min) |
| Protocol | OCI Distribution Spec v1.1.1: `tags/list?n=&last=`, prefer the `Link` header; referrers API `GET /v2/<name>/referrers/<digest>` with fallback to the tag schema on 404. Source [1] |
| Docker Hub | PAT scopes: Public Repo Read-only (default), Repo Read-only, Read & Write, …; organization access tokens (Team/Business) with per-repo scopes and expiry. Pull limits per 6 h: anonymous 100 per IPv4 or IPv6 /64, personal 200, paid unlimited (fair use); 429 when over. Headers `ratelimit-limit`, `ratelimit-remaining` (`;w=21600`). A HEAD on a manifest does not count as a pull. Least privilege: Repo Read-only PAT or OAT. Source [2][3][4][5] |
| GHCR | Classic PAT only, `read:packages` (fine-grained PATs are not documented as supported; treat as unsupported). `GITHUB_TOKEN` inside Actions. Source [6] |
| ECR | `GetAuthorizationToken` → Docker user `AWS`, 12 h, Region-bound. Policy `AmazonEC2ContainerRegistryReadOnly` covers token, `BatchGetImage`, `GetDownloadUrlForLayer`, `DescribeImages`, `ListImages`. M2: obtain the token through the AWS connector's assumed role. Source [7][8] |
| ACR | Entra token (3 h, user `00000000-0000-0000-0000-000000000000`) with role `AcrPull`, or repository-scoped tokens (`content/read`, `metadata/read`; cannot list the catalog; set an expiry). Admin user is discouraged (full push/pull, single user). Source [9][10] |
| Artifact Registry | User `oauth2accesstoken` with a 60-minute access token; role Artifact Registry Reader (role ID `roles/artifactregistry.reader` not verified). Source [11] |
| Harbor | Project robot account with Pull Repository (system robots can span projects; cap to pull). Default expiry 30 days, secret shown once, "Refresh Secret" rotates. API v2.0 (Swagger at `/devcenter-api-2.0`; base path `/api/v2.0` not verified on goharbor.io). Supported: the three most recent minor releases. Source [12][13][14] |
| Webhooks | Planned only for Harbor (push and scan events; auth header field; header name not verified). Others: pull |
| Proxy and CA | Proxy; private registries need `allow_private`; private CA is a gap for registries (the cluster CA field exists only for Kubernetes) |
| Offline | Works against internal registries (`docs/OPERATIONS.md`: `PATHOS_OFFLINE` does not disable them) |
| Credential storage | Kind `integration` (`runtimectx/api.go:681`) |
| Health check | `GET /v2/` with the credential (expects 200 or a challenge that the token flow resolves), then one `tags/list?n=1` on a configured repository. Docker Hub: record `ratelimit-remaining` |
| Error codes | PTH-CONN-1501 Registry token challenge failed · PTH-CONN-1502 Docker Hub pull limit reached · PTH-CONN-1503 Registry token expired (ECR 12 h, ACR 3 h, Artifact Registry 1 h) · PTH-CONN-1504 ACR admin user in use (warning) · PTH-CONN-1505 GHCR needs a classic token with read:packages · PTH-CONN-1506 Harbor robot account expired |

Sources (checked 2026-11-20): [1] https://github.com/opencontainers/distribution-spec/blob/main/spec.md · [2] https://docs.docker.com/security/access-tokens/reference/ · [3] https://docs.docker.com/enterprise/security/access-tokens/ · [4] https://docs.docker.com/docker-hub/usage/pulls/ · [5] https://docs.docker.com/reference/api/registry/auth/ · [6] https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry · [7] https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetAuthorizationToken.html · [8] https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEC2ContainerRegistryReadOnly.html · [9] https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication · [10] https://learn.microsoft.com/en-us/azure/container-registry/container-registry-token-based-repository-permissions · [11] https://docs.cloud.google.com/artifact-registry/docs/docker/authentication · [12] https://goharbor.io/docs/main/administration/robot-accounts/ · [13] https://goharbor.io/docs/main/working-with-projects/project-configuration/configure-webhooks/ · [14] https://github.com/goharbor/harbor/blob/main/SECURITY.md. Not verified: Docker Hub PAT expiry options and the effective date of the pull-limit change; Harbor webhook header name and API base path.

##### Kubernetes — Existing

| Field | Value |
|---|---|
| Evidence | `runtimectx/k8s.go`, `runtimectx/kubeconfig.go`, `deploy/kubernetes/pathos-reader-clusterrole.yaml`, `runtimectx/clusterrole_test.go`, `docs/user-guide/runtime.md` |
| Auth (PATHOS) | Inline kubeconfig or API server + token. Service-account token or client certificate. `exec` and `auth-provider` plugins, file references and `insecure-skip-tls-verify` are refused (`kubeconfig.go:123-165`) — this matches Kubernetes' warning that untrusted kubeconfigs can run code. Source [1] |
| Auth (vendor) | Bound tokens from the TokenRequest API expire (1 h default); Secret-based tokens "don't expire and don't rotate" and are not recommended. Since 1.29, unused legacy tokens are invalidated after 1 year. **PATHOS's manifest creates a `kubernetes.io/service-account-token` Secret** (long-lived) — M2 should offer a short-lived token flow or document rotation clearly. Source [2][3] |
| Least privilege | Custom ClusterRole `get`/`list`/`watch` on 11 resource kinds, no Secrets, ConfigMaps, logs, exec or write verbs; namespace-limited RoleBindings supported (`docs/OPERATIONS.md`). The built-in `view` role also excludes Secrets, but PATHOS's role is narrower. Source [4] |
| API style and version | Kubernetes REST. Supported upstream: 1.35, 1.36, 1.37 (1.34 reached end of life on 2026-10-27). Source [5] |
| Webhooks | None (pull) |
| Rate limits | API Priority and Fairness (on by default); rejected requests get 429. `Retry-After` on APF 429: not verified. Source [6] |
| Pagination | `limit` + `continue` (PATHOS: 500 per page, `k8s.go:103`). Continue tokens expire after about 5 minutes → 410 Gone; restart the list. Source [7] |
| Watch (Planned) | Resume from `resourceVersion`; on 410 Gone relist and re-watch; `allowWatchBookmarks=true`. Source [7] |
| Proxy and CA | `certificate-authority-data` per cluster (Existing). Proxy via `PATHOS_HTTPS_PROXY`; private API servers in `NO_PROXY`. kubeconfig `proxy-url` is not read by PATHOS. Source [1] |
| Offline | Works (internal clusters) |
| Credential storage | Kind `integration` (`runtimectx/api.go:277`) |
| Health check | `GET /version` and `SelfSubjectRulesReview` (or one `list` per kind with `limit=1`); healthy = all granted kinds readable; warning = partial (a kind not granted); also warn when the server version is out of upstream support |
| Error codes | PTH-CONN-1510 kubeconfig uses an exec or auth-provider plugin · PTH-CONN-1511 kubeconfig disables TLS verification · PTH-CONN-1512 Role does not grant a resource kind (partial sync) · PTH-CONN-1513 Kubernetes version out of upstream support · PTH-CONN-1514 Long-lived service-account token in use (warning) |

Sources (checked 2026-11-20): [1] https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/ and https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/ · [2] https://kubernetes.io/docs/concepts/security/service-accounts/ · [3] https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/ · [4] https://kubernetes.io/docs/reference/access-authn-authz/rbac/ · [5] https://kubernetes.io/releases/ · [6] https://kubernetes.io/docs/concepts/cluster-administration/flow-control/ · [7] https://kubernetes.io/docs/reference/using-api/api-concepts/

##### Sigstore / cosign — Existing

Evidence: `scans/signature.go` (public key or keyless policy per target), egress allowlist `tuf-repo-cdn.sigstore.dev`, `rekor.sigstore.dev`, `fulcio.sigstore.dev`. Auth: public keys (stored as configuration, not secrets); keyless uses the public-good instance. Offline: key-based only; keyless reported as skipped (`docs/AIRGAP.md`). Health: TUF root fetch succeeds (online) — Planned. Codes: PTH-CONN-1520 Sigstore transparency log unreachable. Vendor facts: to verify in M2.

#### Security

##### Scanner result import — Existing (inbound)

`scanners/importformats.go` and `scanners/import_*.go`; upload by API token (`api:write`) or UI. No outbound call. Codes: PTH-CONN-1810 upload rejected. The design says 25 formats; the code registers far more (see Known limitations).

##### Vulnerability feeds, OSV.dev, deps.dev, endoflife.date — Existing

Evidence: EPSS and CISA KEV `intel/feeds.go`, `intel/service.go` (per-feed URL and `interval_hours` 1–720, checked every 15 min, line 421); OSV records `intel/osv.go` (refreshed after 7 days); deps.dev `intel/depsdev.go`; endoflife.date API v1 `eol/feed.go`. Auth: none (public). Offline: EPSS, KEV, OSV and endoflife.date by file import; deps.dev not available (`docs/AIRGAP.md`). Health: last successful run per feed and its age (Existing data in feed runs). Codes: PTH-SYNC-1020 Feed download failed · PTH-SYNC-1021 Feed file format not recognised · PTH-SYNC-1022 Feed data older than twice its interval. Vendor facts (formats, limits): to verify in M2.

##### Live secret validation — Existing

`scanners/secretproviders.go:26-57`: AWS (STS `GetCallerIdentity`), GitHub, GitLab.com, Slack, Stripe, OpenAI, Anthropic, SendGrid, Twilio, npm, Google, Azure Storage are checkable; PyPI recognised but not checked. Each check is one read-only "who am I" request to the provider's own host, through the egress proxy allowlist. The checked credential is a finding, not a connector credential: it is never stored as a connector secret and never sent to AI. Codes: PTH-CONN-1530 Validation host not allowed by the egress proxy. Vendor facts: to verify in M2.

##### SIEM: Splunk HEC, Microsoft Sentinel, Elastic — Planned (M2)

Today the generic signed JSON webhook (`notify/webhooks.go`) can feed a SIEM collector that accepts HMAC-signed JSON; none of the three vendors' native ingestion APIs is implemented. All three are push-only, queued with the outbound-webhook retry schedule, and send findings and audit events without source code or secret values.

| Field | Splunk HEC | Microsoft Sentinel (Logs Ingestion API) | Elastic |
|---|---|---|---|
| Endpoint | `/services/collector/event` (or `/raw`), `/services/collector/health`. Default port 8088 (Enterprise), 443 (Cloud, `http-inputs-<stack>.splunkcloud.com`) [1][2] | `POST {endpoint}/dataCollectionRules/{dcrImmutableId}/streams/{stream}?api-version=2023-01-01` (version from the tutorial and SDK, REST reference page returned 404) [5][6] | `_bulk` NDJSON; data streams accept only `create` [8] |
| Auth | `Authorization: Splunk <token>` [2] | Entra ID token, audience `https://monitor.azure.com`; managed identity or federation preferred, app certificate as fallback [5] | `Authorization: ApiKey <base64(id:key)>`; keys never expire by default — PATHOS should set an expiry [9] |
| Least privilege | A dedicated HEC token bound to one index | **Monitoring Metrics Publisher** on the DCR only [5] | `create_doc` on the target data stream (+ `auto_configure` if it may create it) [8][10] |
| Limits | Errors: code 4 / 403 invalid token, 9 / 503 busy, 10 / 400 channel missing, 26–27 / 429 queue full [3]. `max_content_length` 800 MB (9.1 page) | 1 MB per call, 12,000 requests/min and 2 GB/min per DCR; honour `Retry-After`; TLS 1.2+ [7] | 429 `es_rejected_execution_exception`: back off exponentially and shrink the batch [11] |
| Delivery guarantee | Optional indexer acknowledgment with `X-Splunk-Request-Channel` (Splunk Cloud supports ack only for Firehose) [4] | 2xx = accepted | Per-item `status` in the bulk response; retry only failed items |
| Legacy | — | The HTTP Data Collector API (shared key) reached **end of support on 2026-09-14**; PATHOS must not implement it [12] | — |
| CA | Self-managed HEC often uses a private CA: needs the CA field | Public CA | Self-managed uses `http_ca.crt`: needs the CA field [13] |
| Offline | Works (internal Splunk) | Not available | Works (self-managed) |
| Credential | Kind `integration` | Certificate or federation config; kind `integration` | Kind `integration` |
| Health check | `GET /services/collector/health` + a test event to a test sourcetype (on demand) | Token acquisition (automatic); one test record sent only when an administrator starts **Send test** | `GET /_security/_authenticate` and `has_privileges` for the target |
| Error codes | PTH-CONN-1701 HEC token invalid or disabled · PTH-CONN-1702 HEC busy or queue full · PTH-CONN-1703 HEC data channel missing | PTH-CONN-1710 Missing Monitoring Metrics Publisher on the DCR · PTH-CONN-1711 Batch larger than 1 MB · PTH-CONN-1712 Legacy Data Collector API configured | PTH-CONN-1720 Elasticsearch rejected the request (429) · PTH-CONN-1721 API key lacks index privilege · PTH-SYNC-1023 Bulk request partly failed |

Sources (checked 2026-11-20): [1] https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/http-event-collector-rest-api-endpoints · [2] https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web and https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.2.2510/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web · [3] https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/troubleshoot-http-event-collector · [4] https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/about-http-event-collector-indexer-acknowledgment (read via search excerpt) · [5] https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview · [6] https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-code · [7] https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits · [8] https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk · [9] https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key · [10] https://www.elastic.co/docs/reference/elasticsearch/security-privileges · [11] https://www.elastic.co/docs/troubleshoot/elasticsearch/rejected-requests · [12] https://learn.microsoft.com/en-us/previous-versions/azure/azure-monitor/logs/data-collector-api · [13] https://www.elastic.co/docs/reference/elasticsearch/clients/python/connecting. Not verified: whether HEC SSL is on by default; current-version `max_content_length`; Sentinel Logs Ingestion api-version on the REST reference page; Elastic `_authenticate` and `has_privileges` endpoint names (to confirm in M2).

#### IAM & Secrets

##### Keycloak (built in) and SAML / OIDC SSO — Existing

Keycloak handles local sign-in, TOTP MFA and recovery codes, and brokers external OIDC or SAML 2.0 identity providers (`docs/user-guide/sign-in-and-sso.md:28`, `docs/SECURITY.md:19`, `backend/internal/identity/keycloak.go`). PATHOS validates Keycloak's OIDC tokens (`backend/internal/auth/oidc.go`). IdP credentials (client secrets, signing certificates) live in Keycloak's database, not in PATHOS's secret store. Offline: works with an internal IdP. Health (Planned): Keycloak discovery document reachable, per-IdP last successful broker sign-in. Codes: PTH-CONN-1805 Identity provider unreachable from Keycloak · PTH-CONN-1806 SAML signing certificate expired or changed. IdP vendor facts: to verify in M2.

##### HashiCorp Vault — Planned (M2)

| Field | Value |
|---|---|
| Purpose | Keep connector credentials outside PATHOS: PATHOS stores a reference (mount, path, key) and reads the value at use time |
| Auth | AppRole (`auth/approle/login`, `role_id` + `secret_id`; set `secret_id_ttl`, `secret_id_num_uses`, `secret_id_bound_cidrs`/`token_bound_cidrs`; deliver `secret_id` with response wrapping) or Kubernetes auth (`auth/kubernetes/login` with the pod's service-account JWT; role bound by `bound_service_account_names` and `_namespaces`). Prefer Kubernetes auth when PATHOS runs in Kubernetes. Source [1][2][3] |
| Least privilege | Policy with `read` on `<mount>/data/<pathos-prefix>/*` only (KV v2 reads go to `data/`; `list` would need `metadata/`, which PATHOS does not need). Source [4][5] |
| API | Vault HTTP API v1, KV v2. Namespaces via `X-Vault-Namespace` (Enterprise or HCP only). Source [4][6] |
| Licence note | Vault is under the Business Source License 1.1. OpenBao is an OpenSSF fork. PATHOS speaks the HTTP API only and bundles neither; the licence affects customers' own deployment, not PATHOS (owner to confirm whether OpenBao is listed as compatible). Source [7][8] |
| Webhooks | None |
| Rate limits | Vault has configurable rate-limit quotas; defaults: not verified (to verify in M2) |
| Pagination | Not needed (single reads) |
| Proxy and CA | Usually internal: `allow_private`, private CA field required |
| Offline | Works |
| Credential storage | The AppRole `secret_id` is the one secret PATHOS keeps (kind `integration`); Kubernetes auth needs none |
| Health check | Login, then `GET /v1/sys/health` (sealed/standby) and a `read` of a configured canary path |
| Error codes | PTH-CONN-1601 AppRole secret ID expired or used up · PTH-CONN-1602 Vault policy denies the path · PTH-CONN-1603 Vault namespace not found · PTH-CONN-1604 Vault is sealed · PTH-CONN-1605 Kubernetes auth role does not match the service account |

Sources (checked 2026-11-20): [1] https://developer.hashicorp.com/vault/docs/auth/approle · [2] https://developer.hashicorp.com/vault/api-docs/auth/approle · [3] https://developer.hashicorp.com/vault/docs/auth/kubernetes · [4] https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2 · [5] https://developer.hashicorp.com/vault/docs/concepts/policies · [6] https://developer.hashicorp.com/vault/docs/enterprise/namespaces · [7] https://github.com/hashicorp/vault/blob/main/LICENSE · [8] https://openbao.org/. Not verified: an official plain `secret/data/... read` policy example; `/v1/sys/health` response codes; rate-limit quota defaults.

##### Cloud secret managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) — Planned (after Vault in M2)

Same reference model as Vault, authenticated through the matching cloud connector.

- **AWS Secrets Manager:** `secretsmanager:GetSecretValue` scoped to specific secret ARNs (+ `kms:Decrypt` on a customer key). `GetSecretValue` quota 10,000/s per Region. Source: https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html, https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html
- **Azure Key Vault:** RBAC is the default for new vaults from API version 2026-02-01; role **Key Vault Secrets User** on the secret or vault. Limit: 4,000 secret GETs per 10 s per vault; 429 when exceeded. Source: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide, https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits
- **GCP Secret Manager:** `roles/secretmanager.secretAccessor` granted on the secret. Access quota 90,000/min per project. Source: https://docs.cloud.google.com/secret-manager/docs/access-control, https://docs.cloud.google.com/secret-manager/quotas

All checked 2026-11-20. Offline: not available. Codes: PTH-CONN-1610 Cloud secret manager denied access to the secret · PTH-CONN-1611 Secret version not found.

#### APIs

##### OpenAPI / Swagger — Partial · Postman collections, GraphQL schema — Planned · API gateways — After lifecycle release

OpenAPI 3 and Swagger 2 files (max 2 MiB) are accepted for API scan targets (`scans/targets.go:237-248`) and drive Nuclei DAST templates. Missing: fetch from a URL with a token, and an API inventory view. Postman (file, or Postman API key) and GraphQL (file, or introspection with a token) are Planned; introspection must be off by default because it sends queries to the target. Credential kind `scan_target` is listed in `docs/SECURITY.md:75` but not in the `secrets` constants (`secrets/store.go:20-28`) — to verify in M2. Codes: PTH-CONN-1901 API specification could not be fetched · PTH-CONN-1902 API specification is invalid. Vendor facts: to verify in M2.

##### PATHOS REST API & MCP — Existing (inbound)

MCP server: JSON-RPC 2.0 over Streamable HTTP, protocol version `2025-06-18` (`mcp/server.go:29`), personal API token with scope `mcp`. MCP registry (outbound MCP servers with administrator approval and per-tool allow lists): `mcp/registry.go:75-79`, secrets kind `mcp`. Codes: the inbound 18xx codes; PTH-CONN-1807 MCP client uses an unsupported protocol version.

##### AI providers — Existing (not in the design's list)

`ai/provider.go:16-21`: Anthropic (official Go SDK), OpenAI, xAI (`https://api.x.ai/v1`), self-hosted OpenAI-compatible (Ollama, vLLM, LM Studio, llama.cpp; key optional). Keys kind `ai`. Offline: self-hosted only. AI failures belong to the `PTH-AI` area (M1/M7), not `PTH-CONN`; the Connectors Health tab shows their status. Vendor facts: to verify in M7.

#### Databases

PostgreSQL / MySQL / SQL Server and MongoDB / Oracle: **After lifecycle release**. Design rule recorded for later: read-only metadata account, schema metadata only, never row data.

#### Monitoring

##### OpenTelemetry — Existing · Prometheus — Planned

OTLP over HTTP for traces and metrics when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; the standard `OTEL_*` variables apply, including headers for collector auth (`platform/telemetry/telemetry.go:2-45`). Headers live in the environment, not in the secret store. Prometheus: no `/metrics` endpoint today; Planned as an internal-only scrape endpoint. Codes: PTH-CONN-1340 Telemetry exporter cannot reach the collector. Vendor facts: to verify in M2.

##### Webhooks (outbound, signed JSON) — Existing

See Protocols → Webhook verification (outbound). Formats `json`, `slack`, `teams` (`notify/webhooks.go:38`). URL and signing secret: kind `integration`, URL shown only as host after creation. Retries: 6 attempts. Offline: internal endpoints with `allow_private`. Health: last delivery status and the delivery log (Existing). Codes: PTH-CONN-1330 Webhook receiver rejected the delivery (4xx) · PTH-SYNC-1005.

##### Jira (Cloud and Data Center) and ServiceNow — Existing

| Field | Jira Cloud | Jira Data Center | ServiceNow |
|---|---|---|---|
| Evidence | `tickets/connectors.go` (`jira`, REST API v2: `/rest/api/2/myself`, `/rest/api/2/issue`, lines 218-302) | Same code (v2 works on both) | `tickets/connectors.go` (`/api/now/table/{table}`, lines 233-315) |
| Auth (PATHOS) | Basic (e-mail + API token) or bearer (`connectors.go:148-152`) | Bearer (personal access token) or basic | Basic (integration user) or bearer |
| Auth (vendor) | Basic auth with `email:api_token`. Scoped API tokens are recommended over unscoped ones, expire in 1–365 days, and must call `https://api.atlassian.com/ex/jira/{cloudId}` instead of the site URL — **PATHOS calls the site URL, so scoped tokens do not work today** (M2). OAuth 2.0 (3LO) is authorization code only; refresh tokens rotate and expire after 90 days unused. [1][2][3] | Personal access tokens (`Bearer`, Jira 8.14+), optional expiry up to 365 days by default; admins can disable them. [6] | Basic or OAuth by default; certificate-based (mutual TLS) supported. OAuth client credentials need `glide.oauth.inbound.client.credential.grant_type.enabled=true`. Current release family: Brazil. [9][10][11] |
| Least privilege | Classic `read:jira-work` + `write:jira-work`; granular (beta) `read:issue:jira`, `write:issue:jira`, `write:comment:jira`. Plus Jira project permissions Browse and Create issues. [4] | Project permissions Browse projects, Create issues | Incident: role `sn_incident_write` (Incident Management plugin) on a dedicated integration user. Security incidents (`sn_si_incident`): `sn_si.integration_user`, documented for external tools that create and update security incidents. Whether `itil` alone is enough: not verified. [12][13] |
| API style and version | REST v2 used by PATHOS. Cloud v3 is the latest; v2 and v3 have the same operations, v3 uses Atlassian Document Format for rich text. [5] | REST v2 | Table API (`POST` inserts one record) [9] |
| Webhooks | Not used by PATHOS (status is polled). Admin webhooks can carry a secret: `X-Hub-Signature: sha256=<hex>`; up to 5 retries; dedupe on `X-Atlassian-Webhook-Identifier`. [7] | Optional secret, `X-Hub-Signature: sha256=…` (default HMAC-SHA256). [8] | Not used |
| Rate limits | API-token traffic: per-second burst limits only (GET/POST 100/s, PUT/DELETE 50/s per endpoint) and per-issue writes (20 per 2 s). Points-based hourly quotas (from 2026-03-02) apply to OAuth 3LO, Forge and Connect apps — relevant when M2 adds OAuth. 429 with `Retry-After` and `RateLimit-Reason`. [14] | Off unless an administrator enables it; per user and per node; 429 with `Retry-After`. [15] | Rate limit rules per user or role per hour; 429 with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Reset`. [16] |
| Pagination | `startAt`/`maxResults` on most lists; JQL search moved to `/rest/api/3/search/jql` with `nextPageToken`, and the old `/rest/api/3/search` is "being removed" (CHANGE-2046; date not verified). PATHOS does not search today, so it is not affected. [4] | `startAt`/`maxResults` | `sysparm_limit` (default 10,000), `sysparm_offset`, `Link` header, `X-Total-Count` [9] |
| Proxy and CA | Proxy; public CA | `allow_private`; private CA gap | Proxy; public CA (on-premises instances: CA gap) |
| Offline | Not available | Works | Not available (cloud instances) |
| Credential storage | Kind `integration` | Kind `integration` | Kind `integration` |
| Health check | Existing **Test** button: `GET /rest/api/2/myself` and the configured project (`connectors.go:212-222`). M2: run it on a schedule and on **Verify** | Same | Existing: `GET /api/now/table/{table}?sysparm_limit=1` (`connectors.go:229-233`) |
| Status sync | Every 10 min, each open ticket at most every 15 min (`tickets/service.go:561-567`) | Same | Same |
| Error codes | PTH-CONN-1201 Jira project or issue type not found · PTH-CONN-1202 Jira requires a field PATHOS does not send · PTH-CONN-1203 Scoped Jira token used with the site URL | PTH-CONN-1204 Personal access tokens are disabled on this Jira | PTH-CONN-1210 ServiceNow user lacks the role for this table · PTH-CONN-1211 ServiceNow rate limit rule reached |

Sources (checked 2026-11-20): [1] https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/ · [2] https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/ · [3] https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/ · [4] https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json (spec behind https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/) · [5] https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/ · [6] https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html · [7] https://developer.atlassian.com/cloud/jira/platform/webhooks/ · [8] https://confluence.atlassian.com/spaces/ADMINJIRASERVER/pages/938846912/Managing+webhooks · [9] https://www.servicenow.com/docs/bundle/brazil-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html · [10] https://www.servicenow.com/docs/bundle/brazil-api-reference/page/integrate/inbound-rest/concept/c_RESTAPI.html · [11] https://www.servicenow.com/docs/r/platform-security/authentication/create-cc-sys-prop.html · [12] https://www.servicenow.com/docs/r/t~YvqQkg2oQX4L7ySrpyuQ/ldnVh~S9D~wQlifnyjFFAw · [13] https://www.servicenow.com/docs/r/9rlb2awQeTeY3Z9jGMo5DQ/Bq5cClKVDRPSPABXKrKkGg · [14] https://developer.atlassian.com/cloud/jira/platform/rate-limiting/ · [15] https://confluence.atlassian.com/adminjiraserver/improving-instance-stability-with-rate-limiting-983794911.html · [16] https://www.servicenow.com/docs/bundle/australia-api-reference/page/integrate/inbound-rest/concept/inbound-REST-API-rate-limiting.html. Not verified: removal date of `/rest/api/3/search`; deprecation of unscoped Jira tokens; Jira DC REST v2 path on the version-specific reference (page needs JavaScript); ServiceNow password grant and token endpoint; whether `itil` alone suffices; `X-RateLimit-Remaining` on ServiceNow.

##### Slack — Existing (incoming webhook)

| Field | Value |
|---|---|
| Evidence | Format `slack` in `notify/webhooks.go:38,470-480` (`text` with escaped `&<>`, `unfurl_links: false`) |
| Auth | The incoming-webhook URL is the secret ("Your webhook URL contains a secret"); Slack revokes leaked URLs. No auth header (implied by the example; explicit statement not verified). Alternative (Planned, optional): bot token with `chat:write` (and `chat:write.public` to post without joining) for `chat.postMessage`. [1][3] |
| Least privilege | Incoming webhook bound to one channel; channel cannot be overridden |
| API | HTTPS POST of JSON (`text`, optional `blocks`) |
| Webhooks (inbound) | Not used. If M2 adds interactive actions: verify `X-Slack-Signature` (`v0=` HMAC-SHA256 of `v0:{ts}:{body}`), reject timestamps more than 5 min off. [4] |
| Rate limits | Incoming webhooks: 1 message per second, short bursts allowed; Web API 429 with `Retry-After`. [2] |
| Errors | `invalid_payload`, `channel_not_found`, `channel_is_archived`, `action_prohibited`, `no_service`, `team_disabled`, `invalid_token`, … (no documented mapping to HTTP statuses beyond 400/403/404 examples). [1] |
| Proxy and CA | Proxy; public CA |
| Offline | Not available |
| Credential storage | URL: kind `integration`, shown only as host (`notify/webhooks.go:44,180`) |
| Health check | No read-only check exists for incoming webhooks: health = last delivery result, plus an explicit **Send test** (Existing) |
| Error codes | PTH-CONN-1301 Slack webhook was removed (`no_service`) · PTH-CONN-1302 Slack channel archived or not found · PTH-CONN-1303 Slack rejected the payload |

Sources (checked 2026-11-20): [1] https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/ · [2] https://docs.slack.dev/apis/web-api/rate-limits/ · [3] https://docs.slack.dev/reference/methods/chat.postMessage/ · [4] https://docs.slack.dev/authentication/verifying-requests-from-slack/

##### Microsoft Teams — Partial

| Field | Value |
|---|---|
| Evidence | Format `teams`: Adaptive Card 1.4 inside `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive",…}]}` (`notify/webhooks.go:482-493`) |
| Vendor change | Office 365 Connectors, including connector-based Incoming Webhooks, **were retired in May 2026** (final rollout 18–22 May 2026); they no longer work. The replacement is a Workflows (Power Automate) flow with the trigger "When a Teams webhook request is received", whose documented body is the same `message` + Adaptive Card envelope PATHOS sends. So PATHOS's payload fits; only Workflows URLs work. [1][2][3] |
| Why Partial | PATHOS sends no auth header, so only a Workflows trigger set to **Anyone** works. Tenant-restricted triggers ("Any user in my tenant", "Specific users") need an Entra OAuth token: Planned. The UI and docs must say that old `webhook.office.com` connector URLs no longer work (how they now respond is not documented) |
| Least privilege | A dedicated flow that only posts to one channel, with co-owners so it is not orphaned when its owner leaves [1][3] |
| Rate limits | Trigger: about 1,000 concurrent calls; 4,500 or 45,000 invokes per 5 min depending on the plan profile. Posting actions: about 28 KB per message. [3] |
| Alternative | Microsoft Graph `POST /teams/{id}/channels/{id}/messages` needs delegated `ChannelMessage.Send`; application permission exists only for migration, so a background service cannot post this way. Not recommended. [4] |
| Proxy and CA | Proxy; public CA |
| Offline | Not available |
| Credential storage | URL: kind `integration` (the URL carries a signature; it is a secret) |
| Health check | Last delivery result and **Send test** |
| Error codes | PTH-CONN-1310 Teams connector URL retired; create a Workflows webhook · PTH-CONN-1311 Workflows trigger requires authentication · PTH-CONN-1312 Teams message too large |

Sources (checked 2026-11-20): [1] https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/what-are-webhooks-and-connectors · [2] https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/ · [3] https://learn.microsoft.com/en-us/connectors/teams/ · [4] https://learn.microsoft.com/en-us/graph/api/channel-post-messages?view=graph-rest-1.0. Not verified: Workflows OAuth claim details; response of retired connector URLs; outgoing-webhook timeout (Microsoft pages say 5 s and 10 s; not used by PATHOS).

##### Email (SMTP) — Existing

| Field | Value |
|---|---|
| Evidence | `notify/smtp.go` (TLS modes `starttls`, `tls`, `none`; strict STARTTLS with no downgrade, line 142-180; TLS 1.2 minimum), password kind `smtp` (`notify/defaults.go:111`), retries `notify/dispatch.go:433` |
| Standards | RFC 3207 (STARTTLS); RFC 8314 (implicit TLS on port 465; recommends supporting both 587 STARTTLS and 465). [1][2] |
| Auth | SMTP AUTH user and password (optional) |
| Proxy and CA | Direct connection (no HTTP proxy). Private CA for an internal relay: gap |
| Offline | Works with an internal relay |
| Health check | Connect, EHLO, STARTTLS/TLS and AUTH without sending a message (Planned); **Send test** e-mail (Existing pattern) |
| Error codes | PTH-CONN-1320 Mail server does not offer STARTTLS · PTH-CONN-1321 Mail server rejected the login · PTH-CONN-1322 Mail server rejected the recipient or sender |

Sources (checked 2026-11-20): [1] https://www.rfc-editor.org/rfc/rfc3207.html · [2] https://www.rfc-editor.org/rfc/rfc8314.html

## Data flow

Outbound pull (SCM listing and re-sync, tickets status, Kubernetes, registries, feeds):

1. `jobs` picks due connections (database row lock, `FOR UPDATE SKIP LOCKED` where queued).
2. It reveals the credential from the secret store for the duration of the call only.
3. It calls the vendor API through `NetPolicy.Client()` (address check, proxy, timeouts).
4. It writes normalized results and a run record (status, counts, error) in one transaction.
5. The API and UI read run records. They never call the vendor to render a page.

Inbound push (SCM webhooks):

1. `POST /api/webhooks/{provider}/{connection_id}` (`backend/internal/repos/service.go:76-79`). The body is read up to 5 MiB (`repos/webhooks.go:18`).
2. The connection's webhook secret is revealed and the request is verified (see Protocols → Webhook verification). Failures are rejected and audited (`rejectWebhook`).
3. The event is normalized and stored once per delivery ID (`recordDelivery`, `repos/webhooks.go:144`; replays are ignored).
4. Scans are queued from the stored delivery, not from the HTTP request.

Outbound push (notifications, outbound webhooks, Slack, Teams, Planned SIEM):

1. Events create queued deliveries in the database.
2. A dispatcher sends them with backoff and records each attempt (`notify/webhooks.go:589-660`).

Inbound clients (CLI, IDE, CI, MCP): they call the PATHOS API with a personal API token. PATHOS stores only a SHA-256 hash of the token (`mcp/tokens.go:49`).

## Dependencies

- Go standard library HTTP client, `github.com/aws/aws-sdk-go-v2/service/s3` (object store), `github.com/anthropics/anthropic-sdk-go/v2` (Anthropic), OpenTelemetry OTLP HTTP exporters.
- Keycloak for SSO brokering.
- The Squid egress proxy for workers.
- Planned for M2, to be decided in an ADR: whether to use vendor SDKs (AWS SDK v2 for STS/ECR/Secrets Manager, Azure SDK for Go `azidentity`, Google Cloud Go client libraries) or signed plain HTTP. Recommendation: vendor SDKs for the three clouds (credential chains, SigV4 and token refresh are error-prone to reimplement), plain HTTP elsewhere as today.

## APIs

Existing (2.2.0):

| Endpoint | Purpose | Code |
|---|---|---|
| `GET/POST/PUT/DELETE /api/v1/scm-connections…`, `POST …/{id}/webhook-secret` | SCM connections, webhook secret rotation (returned once) | `repos/connections.go:33` |
| `POST /api/webhooks/{github,gitlab,bitbucket,azure-devops}/{id}` | Inbound SCM webhooks | `repos/service.go:76-79` |
| `GET/POST/PUT/DELETE /api/v1/ticket-connections`, `POST …/{id}/test` | Jira and ServiceNow | `tickets/service.go:41-45` |
| `…/api/v1/notifications/webhooks…`, `POST …/{id}/test`, `GET …/{id}/deliveries` | Outbound webhooks, Slack, Teams | `notify/webhooks.go:78-81` |
| `…/api/v1/runtime/clusters…`, `POST …/{id}/sync`, registries | Kubernetes and registries | `runtimectx/api.go:34` |
| `GET/POST/DELETE /api/v1/me/tokens` | Personal API tokens (scopes `mcp`, `api:read`, `api:write`) | `mcp/tokens.go:56-58`, `:101` |
| `/api/v1/mcp-servers…` | MCP registry | `mcp/registry.go:75-79` |

Planned (M2; full request/response design belongs in `PATHOS_API_DESIGN.md` and `docs/api-reference`):

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/connectors` | One list over all connector tables: category, kind, status, last health |
| `GET /api/v1/connectors/{kind}/{id}/health` | Last health result with `PTH-` code and checks |
| `POST /api/v1/connectors/{kind}/{id}/health-check` | Run the health check now (the **Verify** button) |
| `POST /api/v1/connectors/{kind}/{id}/sync` | Request an incremental sync; `?full=true` for a full sync |
| `POST /api/v1/connectors/{kind}/{id}/troubleshoot` | AI troubleshooting with redacted context (see Protocols) |

Every endpoint keeps the existing permission model (`scm.manage`, `integrations.manage`, and so on) and is added to `make rbac-matrix`.

## Protocols

### Webhook verification

Inbound (vendor → PATHOS):

| Provider | 2.2.0 (Existing) | Header | Method | Code |
|---|---|---|---|---|
| GitHub, GHES | Yes | `X-Hub-Signature-256` | HMAC-SHA256 of the raw body, constant-time compare | `scm/webhook.go:19` |
| GitLab | Yes (token only) | `X-Gitlab-Token` | Shared secret token, constant-time compare (not a signature). GitLab now also signs with HMAC-SHA256 (Standard Webhooks, `webhook-signature`, GA in 19.1) and calls the token legacy: Planned for M2 (see the GitLab record) | `scm/webhook.go:172` |
| Bitbucket Cloud | Yes | `X-Hub-Signature` | HMAC-SHA256 (`sha256=<hex>`) | `scm/webhook.go:235` |
| Azure DevOps | Yes | `Authorization: Basic` | Service hook basic-auth password = PATHOS secret, constant-time compare | `scm/webhook.go:39` |
| Bitbucket Data Center | Planned | `X-Hub-Signature` | HMAC-SHA256 | — |

Rules (Existing for the four providers above; M2 applies them to every new inbound webhook):

1. Read at most 5 MiB of raw body before verifying (`repos/webhooks.go:18`).
2. Verify before parsing. Use constant-time comparison.
3. A failed check returns the same response as an unknown connection and is audited. It never says which part failed.
4. Store each delivery once, keyed by the vendor's delivery ID (`X-GitHub-Delivery`, `X-Gitlab-Event-UUID`, `X-Request-UUID`, Azure DevOps event ID). Replays are ignored (`repos/webhooks.go:63,87,111,135`).
5. Secrets are 1 per connection, generated by PATHOS, shown once, rotatable (`repos/connections.go:303,532`).
6. Planned (M2): where the vendor signs with a timestamp, reject deliveries older than 5 minutes. Where the vendor offers HMAC and a plain token (GitLab, see its record), prefer HMAC.
7. Planned (M2): PATHOS registers the webhook itself when the credential has the permission; today the administrator copies the URL and secret into the provider.

Outbound (PATHOS → receiver), Existing for JSON webhooks:

- Headers `X-PATHOS-Event`, `X-PATHOS-Delivery`, `X-PATHOS-Timestamp`, `X-PATHOS-Signature: sha256=<hex>` where the HMAC-SHA256 input is `"<timestamp>.<body>"` (`notify/webhooks.go:520-548`).
- Receivers should reject timestamps older than 5 minutes and dedupe on `X-PATHOS-Delivery`.
- Slack and Teams formats send no signature: the webhook URL is the secret, stored encrypted (`notify/webhooks.go:180`).

### Incremental sync and scheduled full sync

| Connector | Incremental (2.2.0) | Full (2.2.0) | Planned (M2) |
|---|---|---|---|
| SCM | Webhook push events queue scans; head commits are looked up only when the listing shows a push since the last known commit (`repos/resync.go:26-32`) | Daily metadata re-sync of every connection (`cmd/pathos/main.go:432`, 24 h ticker): metadata, head commit, deleted/archived/permission changes. Source is not downloaded | Per-connection interval; "Sync now" on `/connectors`; a full sync also reconciles webhook deliveries missed while PATHOS was down (`PTH-SYNC-1007`) |
| Tickets | Status refresh of open tickets every 10 min, each ticket at most every 15 min, 100 per run (`tickets/service.go:561-567`) | none | Keep |
| Kubernetes | none (no watch) | Every `sync_interval_minutes` or on "Sync now": paginated list per kind, 500 per page, max 20,000 per kind, 10 min timeout; objects not seen in a complete sync are deleted, a partial sync deletes nothing (`docs/OPERATIONS.md`, `runtimectx/sync.go:57`) | Optional watch with `resourceVersion` (see Kubernetes record); full list stays the source of truth |
| Registries | none | Same scheduler; tags list paginated, at most `max_tags`, 200 ms between requests (`runtimectx/sync.go:379`) | Per-vendor token exchange (ECR, ACR, GCP) |
| Feeds | none | Per feed `interval_hours` (1–720), checked every 15 min (`intel/service.go:201,421`); OSV records refreshed after 7 days (`intel/osv.go:38`) | Keep |
| Cloud (AWS, Azure, GCP) | — | — | Full inventory on a schedule (default 24 h); incremental via the cloud's change feed is out of scope for this release |
| SIEM | — | — | Push only (queued deliveries) |

Rules for every sync (Planned for new connectors, Existing for Kubernetes):

1. A sync is a recorded run: start, end, trigger, counts, warnings, `PTH-` code.
2. Only a **complete** full sync may delete. A partial or failed sync never removes data.
3. Cursors and page tokens are bound to the query and the configured host (`scm/pagetoken.go`).
4. One run per connection at a time; a run older than 30 min counts as stale (`runtimectx/sync.go:58`).

### Retry and backoff

Existing:

| Path | Retries | Schedule | Not retried | Code |
|---|---|---|---|---|
| Repository import items | up to `max_attempts` | `2^attempts × 15 s` | not found, forbidden, auth failed, blocked address; token expired needs attention | `repos/import_worker.go:45-60,322` |
| Outbound webhooks | 6 attempts | 1 min, 5 min, 30 min, 2 h, 6 h | 4xx except 408 and 429 | `notify/webhooks.go:41,651` |
| E-mail | until expiry | 1 min, 5 min, 30 min, 2 h (then every 2 h) | — | `notify/dispatch.go:433` |
| Push protection diff scans | `maxAttempts` | re-queued | non-transient | `pushprotect/service.go:139` |
| Transient classification | — | — | — | `scm.IsTransient`: 429, 5xx, 408, timeouts, resets, refused; 403 with `X-RateLimit-Remaining: 0`, `RateLimit-Remaining: 0` or `Retry-After` counts as rate limited (`scm/http.go:63-92`) |

Planned rules for every connector (M2):

1. Honour `Retry-After` (seconds or HTTP date) and vendor reset headers when present; never retry sooner.
2. Otherwise exponential backoff with full jitter: base 1 s for interactive calls (max 3 tries), base 15 s for background jobs (max 6 tries, cap 6 h).
3. Never retry 400, 401, 403 (except rate-limit 403), 404, 422, certificate errors or blocked addresses. Report them with a `PTH-CONN` code at once.
4. One token bucket per connection, set below the vendor's documented limit (see each record), so PATHOS does not trip secondary limits.
5. A retried write must be idempotent: ticket creation and fix PRs check for an existing item before creating another.

### Health checks

"Healthy" means a real, recent check against the vendor succeeded. PATHOS never shows an assumed or cached-forever status (rule 4, nothing fake).

Health states (Planned for `/connectors`; some fields exist per family today):

| State | Meaning |
|---|---|
| Healthy | The last health check succeeded within its interval and the last sync (if any) completed |
| Warning | Working, but something needs attention soon: token expires within 14 days, partial sync, missing optional permission, rate limit hit in the last hour, webhook deliveries failing |
| Failing | The last health check failed. Shows the `PTH-` code |
| Not checked | Never checked, or the check is older than 2 × its interval. Never shown as healthy |
| Disabled | Turned off by an administrator, or blocked by `PATHOS_OFFLINE` |

Existing status fields: SCM `status`, `status_message`, `last_checked_at`, `token_expires_at` (`repos/service.go:173-182`); tickets `sync_error`, `synced_at` (`tickets/service.go:374-377`); outbound webhooks `last_status`, `last_delivery_at` and the delivery log (`notify/webhooks.go:56-57,319`); clusters and registries `last_status`, `last_error`, `last_sync_at` (`runtimectx/api.go:116`).

What each health check does, per connector, is in its record ("Health check"). Every check is read-only and side-effect free, except "send test" for outbound webhooks and chat, which an administrator starts explicitly (Existing: `POST …/webhooks/{id}/test`).

### Health and AI troubleshooting flow (Planned, M1 engine + M2 connectors)

1. A health check or sync fails. The connector maps the failure to one `PTH-CONN` or `PTH-SYNC` code (table in Error handling). The mapping is deterministic code, not AI.
2. The Health tab shows `<ErrorPanel>` (M1) with: code, request ID, confirmed cause (when the code proves it, e.g. HTTP 401 → authentication failed), probable causes, impact, numbered fixes with links, **Verify** (re-runs the health check), docs link.
3. These catalogue steps are always shown. They work with AI disabled, with no AI provider configured and offline.
4. **Troubleshoot with AI** is offered only when the catalogue entry allows it and an AI model is set for troubleshooting. The default is the organization's self-hosted (local) model; a cloud model must be chosen explicitly by an administrator.
5. Context sent to the model, after redaction: the `PTH-` code and title, the error message with URLs reduced to scheme and host, the connector kind and category, non-secret configuration metadata (auth method name, `allow_private`, proxy set yes/no, CA bundle set yes/no, vendor API version, PATHOS version), HTTP status codes, and the last 20 log lines for that connection after the existing redaction (`platform/logging/logging.go`) and secret-pattern stripping.
6. Never sent: credentials, tokens, webhook URLs (Slack and Teams URLs are secrets), private keys, kubeconfigs, signing secrets, request or response bodies, source code, finding contents, user e-mail addresses, internal host names beyond the connection's own host.
7. The AI answer is labelled **AI-inferred** and uses the same structure (confirmed / probable / steps / verify). It cannot mark a connector healthy; only a successful **Verify** can.
8. The AI never asks the user to paste a credential. A prompt guard rejects answers that request one.

## Authentication

Summary of what PATHOS accepts and recommends. Details and least-privilege scopes are in each connector record.

| Connector | 2.2.0 methods | Recommended | Planned additions |
|---|---|---|---|
| GitHub / GHES | GitHub App (installation tokens), fine-grained or classic PAT, OAuth App (`scm/providers.go:19-43`) | GitHub App | — |
| GitLab | PAT / group / project access token, OAuth application | Group or project access token with `read_api`, `read_repository` | — |
| Bitbucket Cloud | Workspace/project/repository access token, Atlassian API token, OAuth consumer | Repository or project access token | — |
| Bitbucket Data Center | — | — | HTTP access token (project or repository) |
| Azure DevOps Services | Entra ID service principal (secret or certificate), PAT, Entra ID OAuth | Service principal (certificate) | Managed identity / workload identity federation |
| Azure DevOps Server | PAT only (`scm/azure.go:53`) | PAT | — |
| Jira, ServiceNow | Basic (user + token/password) or bearer (`tickets/connectors.go:148-152`) | Jira: API token; ServiceNow: dedicated integration user | OAuth 2.0 |
| Kubernetes | Service-account token or client certificate from an inline kubeconfig; exec and auth-provider plugins refused (`runtimectx/kubeconfig.go:152`) | Service-account token, CA data inline | Bound short-lived tokens |
| Registries | none, basic, bearer; Docker token challenge (`runtimectx/registry.go:26`) | Read-only robot/registry token | ECR, ACR, Artifact Registry token exchange |
| AWS, Azure, GCP | — | — | AssumeRole + external ID; workload identity federation / service principal certificate; workload identity federation |
| Vault | — | — | AppRole, Kubernetes auth |
| SIEM | — | — | Splunk HEC token, Entra app for Logs Ingestion, Elastic API key |
| Inbound (CLI, IDE, CI, MCP) | Personal API token, hashed at rest, scoped `mcp` / `api:read` / `api:write`, expiry, revocation (`mcp/tokens.go`) | `api:write` only for CI uploads; `api:read` for IDEs | — |

## Security requirements

1. **Credentials are write-only and encrypted.** Existing: AES-256-GCM envelope encryption with a fresh data key per secret, wrapped by the versioned master key; both layers bind `pathos:secret:<kind>:<id>` as associated data, so a ciphertext cannot be moved to another row or kind (`backend/internal/secrets/store.go:17-36`, `docs/SECURITY.md:72-81`). Kinds in code: `scm`, `ai`, `mcp`, `smtp`, `webhook`, `worker`, `integration`. Ticketing, outbound webhook URLs and signing secrets, Kubernetes and registry credentials use `integration` (`runtimectx/api.go:277,681`, `notify/webhooks.go:180,187`). API responses return only `has_*` flags or the host (`notify/webhooks.go:44`, `runtimectx/api.go:99`).
2. **Rule for every new connector (M2):** the credential goes into `secrets.Store` with kind `integration` (or a new kind added to the AAD list), is revealed only inside the job that uses it, is never logged, never returned, never sent to an AI model, and is destroyed when the connection is deleted. When an external secret manager is configured (Vault, Planned), PATHOS stores only the reference (mount, path, key) and reads the value at use time; the reference is not a secret but is still not sent to AI.
3. **Least privilege.** Each record lists the minimum scopes. Write scopes are requested only for features that write (commit statuses, fix PRs, tickets). The UI shows read and write needs separately.
4. **Outbound address policy** for every connector (`scm.NetPolicy`): no metadata endpoints, no loopback, private ranges only per connection.
5. **TLS.** `https` only (except the development flag). TLS 1.2 minimum. `insecure-skip-tls-verify` is refused (`runtimectx/kubeconfig.go:123`). Private CAs: see Known limitations.
6. **Inbound webhooks** follow Protocols → Webhook verification.
7. **Audit.** Create, update, delete, test, rotate and rejected webhooks are audited (existing pattern: `runtimectx/api.go:288`, `repos/webhooks.go` `rejectWebhook`).
8. **Air-gapped.** With `PATHOS_OFFLINE=true`, connectors that need the internet are disabled and show **Disabled (offline)**, not Failing. Connectors to internal systems keep working (`docs/AIRGAP.md`).

## Error handling (with error codes)

All codes below are **Planned**. Format `PTH-<AREA>-<NNNN>` (prompt §3.1). M1 builds the catalogue; M2 adds these entries. Ranges:

| Range | Use |
|---|---|
| `PTH-CONN-1001`–`1099` | Shared connection failures (all connectors) |
| `PTH-CONN-11xx` | SCM providers (incl. Generic Git) |
| `PTH-CONN-12xx` | Ticketing |
| `PTH-CONN-13xx` | Chat, e-mail, outbound webhooks, telemetry |
| `PTH-CONN-14xx` | Cloud providers and the S3 object store |
| `PTH-CONN-15xx` | Registries, Kubernetes, Sigstore, secret validation hosts |
| `PTH-CONN-16xx` | Secret managers |
| `PTH-CONN-17xx` | SIEM |
| `PTH-CONN-19xx` | API specifications (OpenAPI, Postman, GraphQL) |
| `PTH-CONN-18xx` | Inbound clients (CLI, IDE, CI, MCP) and SSO |
| `PTH-SYNC-1001`–`1099` | Sync failures (1001–1019 shared, 1020–1029 feeds and SIEM delivery) |

Shared connection codes:

| Code | Title | Confirmed when | Maps from today |
|---|---|---|---|
| PTH-CONN-1001 | Host not reachable | DNS failure, connection refused, reset | `transportError` (`scm/http.go:41`), `provider_unavailable` |
| PTH-CONN-1002 | Request timed out | Context deadline or client timeout | `timeout` |
| PTH-CONN-1003 | Destination address not allowed | `ErrBlockedAddress` | `blocked_address` |
| PTH-CONN-1004 | Connection uses an untrusted certificate | x509 unknown authority (same code as the prompt's example) | transport error text |
| PTH-CONN-1005 | Certificate name or validity mismatch | x509 hostname or expiry error | transport error text |
| PTH-CONN-1006 | Proxy refused or failed the connection | CONNECT 403/407/502 from the proxy | transport error text |
| PTH-CONN-1007 | Authentication failed | HTTP 401 | `authentication_failed`, `ErrAuth` |
| PTH-CONN-1008 | Credential expired | Vendor says expired, or `token_expires_at` passed | `token_expired`, `ErrTokenExpired` |
| PTH-CONN-1009 | Missing permission or scope | HTTP 403 without rate-limit headers | `permission_denied`, `ErrForbidden` |
| PTH-CONN-1010 | Rate limited by the vendor | 429, or 403 with rate-limit headers | `ErrRateLimited` |
| PTH-CONN-1011 | Resource or base URL not found | HTTP 404 | `repository_not_found`, `ErrNotFound` |
| PTH-CONN-1012 | Vendor server error | HTTP 5xx after retries | `provider_error` |
| PTH-CONN-1013 | Unexpected response format | JSON decode failure, wrong content type (often a login page or wrong base URL) | tickets "unexpected response" |
| PTH-CONN-1014 | Unsupported vendor version | Version endpoint below the supported minimum | none |
| PTH-CONN-1015 | Connector disabled in offline mode | `PATHOS_OFFLINE=true` and the connector needs the internet | intel `offline` flag |
| PTH-CONN-1016 | Credential could not be decrypted | AAD or master-key mismatch | secrets `Reveal` error |
| PTH-CONN-1017 | Inbound webhook signature invalid | Verification failed | `ErrSignature` |
| PTH-CONN-1018 | No webhook deliveries received | No delivery within the expected window while the vendor reports pushes | none |
| PTH-CONN-1019 | Plain HTTP refused | `http` URL without the development flag | `ValidateBaseURL` |

Shared sync codes:

| Code | Title |
|---|---|
| PTH-SYNC-1001 | Sync completed partially (some resources not readable) |
| PTH-SYNC-1002 | Item no longer visible to the credential (deleted, moved or access removed) |
| PTH-SYNC-1003 | Page token invalid or expired; sync restarted from the first page |
| PTH-SYNC-1004 | Sync timed out |
| PTH-SYNC-1005 | Delivery failed after all retries (outbound) |
| PTH-SYNC-1006 | Duplicate delivery ignored (informational) |
| PTH-SYNC-1007 | Full sync found changes missed by webhooks |
| PTH-SYNC-1008 | Result truncated by a limit (`max_tags`, 20,000 objects per kind, 5,000 repositories) |
| PTH-SYNC-1009 | Sync already running (stale run released after 30 min) |
| PTH-SYNC-1010 | Remote item status could not be refreshed (tickets, fix PRs) |
| PTH-SYNC-1020 | Feed download failed |
| PTH-SYNC-1021 | Feed file format not recognised |
| PTH-SYNC-1022 | Feed data older than twice its interval |
| PTH-SYNC-1023 | SIEM bulk request partly failed |

Connector-specific codes are listed in each connector record.

## Operations

- **Where calls originate.** `jobs` for scheduled work, `api` for wizard tests, workers only through the egress proxy. M2 keeps this: the Health tab's **Verify** queues a check for `jobs` or runs it from `api` with the same `NetPolicy`; it never runs in the browser.
- **Proxy.** `PATHOS_HTTPS_PROXY` for `api` and `jobs`; private API servers go in `NO_PROXY` (`docs/OPERATIONS.md`, Kubernetes runtime inventory). Workers: add vendor hosts to `deploy/egress/allowlist.txt`.
- **Private networks.** Per connection `allow_private`; global `PATHOS_SCM_ALLOW_PRIVATE_NETWORKS` (api, jobs).
- **Rotation.** Webhook secrets: `POST /api/v1/scm-connections/{id}/webhook-secret`. Tokens: edit the connection (write-only field). Master key: `docs/SECURITY.md:77`.
- **Monitoring.** OTLP traces and metrics when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (`platform/telemetry/telemetry.go:2`). Planned: per-connector health counters and a Prometheus endpoint.
- **Testing.** Integration tests use fake vendor servers (`httptest`) and a local `registry:2` when `PATHOS_TEST_REGISTRY_URL` is set; they never contact real vendors (`docs/OPERATIONS.md`). M2 keeps this: every connector gets a recorded-fixture test and no test needs real credentials.

## Implementation status

| Area | Status |
|---|---|
| SCM connectors (GitHub, GHES, GitLab, Bitbucket Cloud, Azure DevOps Services and Server) | Existing |
| Inbound SCM webhook verification and replay protection | Existing |
| Commit statuses and fix PRs on all four SCM families | Existing (`scm/status.go`, `scm/pullrequest.go`) |
| Jira, ServiceNow | Existing (REST API v2 for Jira) |
| Outbound signed webhooks, Slack, SMTP | Existing |
| Microsoft Teams | Partial (unauthenticated Workflows URLs only) |
| Kubernetes and generic OCI registries | Existing |
| Feeds, deps.dev, endoflife.date, OSV | Existing |
| Live secret validation | Existing |
| CLI, VS Code, JetBrains, CI templates, pre-commit, pre-receive, MCP | Existing |
| Keycloak SSO (OIDC, SAML) | Existing |
| S3 object store | Partial (static keys) |
| GHES / GitLab self-managed with private CA | Partial |
| Container registries (cloud vendor token exchange) | Partial |
| OpenAPI | Partial (file upload) |
| `/connectors` page, connector registry, Health tab | Planned (M2) |
| `PTH-CONN` / `PTH-SYNC` codes | Planned (M1 engine, M2 entries) |
| Bitbucket Data Center, AWS, Azure, GCP, Vault, cloud secret managers, SIEMs, Prometheus | Planned (M2) |
| Generic Git, Bitbucket Pipelines, Postman, GraphQL | Planned (M2 or later; owner to confirm) |
| Visual Studio, Argo CD, API gateways, databases | After lifecycle release |

## Known limitations

### Conflicts between the design and the code (the code wins)

1. **Kubernetes** is "new" in the design but exists (`runtimectx/k8s.go`, read-only ClusterRole, `docs/user-guide/runtime.md`).
2. **JetBrains IDEs** is "new" in the design but exists (`ide/jetbrains`, plugin 0.1.0, shipped in 2.2.0 per `git log`).
3. **GitHub Enterprise Server** is "new" in the design but exists as a provider (`scm/contract.go` `GitHubEnterprise`). What is missing is the per-connection CA ("custom base URL + CA").
4. **GitLab Self-Managed** is "extend": correct. Same gap (per-connection CA).
5. **Container registries** "extend": correct. A generic OCI registry connector exists; Docker Hub, GHCR and Harbor work through it with basic or bearer credentials. ECR, ACR and Artifact Registry need a vendor token exchange that does not exist.
6. **S3-compatible storage** "Access key · IAM role": only static access keys exist (`objstore.go:58`, `aws.CredentialsProviderFunc` with fixed keys). IAM role is Planned.
7. **Scanner result import** "25 formats": the code registers far more (the lead's audit counts 232; `scanners/importformats.go` and the `import_*.go` files). Use the code count.
8. **Slack · Microsoft Teams** "Incoming webhook": PATHOS sends Teams messages as an Adaptive Card in a `message` envelope (`notify/webhooks.go:482-493`). See the Teams record for the retirement of Office 365 connectors and what URL type works.
9. **Jira · ServiceNow** "API token · OAuth": only basic and bearer exist; OAuth is Planned.
10. **The design does not list** Azure DevOps Server, the AI providers, live secret validation, deps.dev, endoflife.date, OSV, the MCP registry or the egress proxy. They are integrations PATHOS ships; M2 must show them (proposed categories in the inventory) or explicitly exclude them.
11. **Design header assumes 1.1.1 / "PATHOS 2.0"**: the code is 2.2.0. This document says "lifecycle release".

### Gaps in 2.2.0 that M2 must close

1. **No per-connection private CA.** Only Kubernetes (`certificate-authority-data`, `runtimectx/kubeconfig.go:34`) and the CLI (`--ca-cert`, `cmd/pathos-cli/client.go:103`) accept a CA. Every other connector uses the system trust store of a distroless image (`backend/Dockerfile:14`). Go reads `SSL_CERT_FILE` on Linux, so mounting a bundle and setting that variable would work, but it is not documented or passed through by `docker-compose.yml`. Planned: a per-connection PEM CA bundle field (stored as configuration, not a secret) appended to the system pool.
2. **No connector health model** across families; status fields differ per table.
3. **No automatic webhook registration**: administrators copy the URL and secret.
4. **No retry with `Retry-After`** for SCM listing calls; rate limits are classified but the wizard and re-sync do not wait and retry.
5. **Jira scoped API tokens do not work.** Atlassian recommends scoped tokens, which must call `https://api.atlassian.com/ex/jira/{cloudId}`; PATHOS calls the site URL with REST v2 (`tickets/connectors.go:218,260`). v2 itself is still offered on Jira Cloud with the same operations as v3.
6. **SCM pagination limit**: at most 5,000 repositories per listing (`scm/scm.go:95`).
7. **GitLab webhook signing.** PATHOS verifies only `X-Gitlab-Token`, which GitLab now calls legacy; the HMAC signing token (GitLab 19.1+) is not supported yet.
8. **Microsoft Teams.** Office 365 connector webhooks were retired in May 2026. PATHOS's Adaptive Card payload matches the Workflows trigger, but PATHOS sends no auth header, so only triggers open to "Anyone" work. Tenant-restricted triggers need Entra OAuth (Planned).
9. **Webhook body limit.** PATHOS reads at most 5 MiB per inbound delivery (`repos/webhooks.go:18`); GitHub and gitlab.com send up to 25 MB. Large push events are rejected today.
10. **Kubernetes token.** The shipped manifest creates a long-lived `kubernetes.io/service-account-token` Secret; Kubernetes recommends bound, expiring tokens for external clients.
11. **Bitbucket API-token scope text.** The wizard lists `read:user`, `read:workspace`, `read:project`, `read:repository` (`scm/providers.go:86`); the current scope names in Atlassian's reference end in `:bitbucket` (e.g. `read:repository:bitbucket`). Check and correct in M2.
12. **Azure DevOps global PATs** are being retired (Microsoft gives both 2026-12-01 and 2027-01-27 on the same page). PATHOS should warn on global PATs.
13. **GitHub API version.** PATHOS pins `2022-11-28`, supported until 2028-03-10; `2026-03-10` is current.

## Future improvements

- Kubernetes watch-based incremental sync.
- Change-feed-based incremental cloud sync (AWS Config, Azure Resource Graph change history, Cloud Asset Inventory feeds).
- Outbound webhook receivers SDK snippets (verify `X-PATHOS-Signature`) in `docs/api-reference`.
- External secret manager as the store for **all** connector credentials (Vault first), with PATHOS keeping only references.
- Prometheus `/metrics` with per-connector health and rate-limit gauges.
- After the lifecycle release: Visual Studio, Argo CD deploy gate, API gateways, database metadata connectors.
