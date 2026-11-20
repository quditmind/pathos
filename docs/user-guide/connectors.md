---
title: Connectors
section: user-guide
group: connect
order: 4
version: "3.0"
updated: 2026-11-20
summary: One place for every system PATHOS connects to (SCM, ticketing, chat, e-mail, Kubernetes, registries, AI providers, feeds, platform services) with real health checks, a check history, error codes and AI troubleshooting.
---
# Connectors

Quditmind PATHOS · applies to v3.0 (unreleased) · status: Prototype (behind the `connectors` feature flag)

**Connectors** (`/connectors`) lists every system PATHOS talks to, shows whether each connection works, and helps you fix the ones that do not. It is part of **1 · Connect**.

The module is off by default. An administrator with `settings.manage` turns it on under **Administration → Feature flags** (flag `connectors`). While it is off, `/connectors` explains that the feature is disabled and the API answers `feature_disabled` (`PTH-PLAT-1007`). **SCM connections** and **Integrations** keep working exactly as before whatever the flag.

## What the page shows

- **Every connection PATHOS already has**, from the pages that manage them today: SCM connections, Jira and ServiceNow, outbound webhooks (JSON, Slack, Microsoft Teams), the e-mail relay, Kubernetes clusters and container registries, AI providers, the vulnerability and end-of-life feeds, live secret validation, object storage and the egress proxy. The Connectors page **points at** those connections: nothing is copied, and credentials stay where they are (encrypted, write-only).
- **The catalogue of connector kinds**: every kind PATHOS supports, partly supports or plans, with its category (SCM & IDE, CI/CD, Cloud, Containers, Security, IAM & Secrets, APIs, Databases, Monitoring), its authentication methods and whether it works offline. Planned kinds are shown as planned, never as available.
- **Health**: the result of the last real check of each connection.

Existing connections are still created and edited on their own pages (each row links to it). The Connectors page takes over creating them only once it does everything the old pages do.

## The page

The page has four tabs and a category rail on the left.

| Part | What it shows |
|---|---|
| **Category rail** | *All categories* and the nine categories: SCM & IDE, CI/CD, Cloud, Containers, Security, IAM & Secrets, APIs, Databases, Monitoring. Each shows the number of connected systems and, after the slash, the number of kinds PATHOS supports in it (both from the API). A red dot marks a category with a failing connector. |
| **Connectors** tab | One card per connected system, then one card per kind that is not connected yet. |
| **Authentication** tab | Per connection: sign-in method, whether a credential is set, where it is kept, expiry and scopes. |
| **Configuration** tab | Per connection: non-secret settings such as base URL, proxy, custom CA certificate (yes or no) and scopes. |
| **Health** tab | Every connector with its status, last error code and time since the last check, with a status filter and a search. The tab shows how many connectors are failing or degraded. |

The selected tab, category, connector and filters are kept in the address, so a link opens the same view.

## Connector cards

A card of a connected system shows its **name**, its **kind** (for example *GitHub* or *Jira*), its **status**, the **last check** and the **last sync**.

The status uses the states below; a connection that no check has run for yet reads **Never checked**.

A card of a kind that is not connected shows **Available** (works today), **Partial** (works with limits listed in the integration specification) or **Planned** (not available yet), **Offline OK** when it works without internet access, and **Connect**:

- For kinds PATHOS already had before 3.0, **Connect** opens the page that creates them: SCM providers open **SCM connections** inside the hub, Jira and ServiceNow open **Integrations** inside the hub, webhooks and e-mail open **Notifications**, Kubernetes clusters and container registries open **Runtime**, AI providers open **AI settings**.
- For new kinds, **Connect** opens the **Add connector** dialog (also in the page header).
- Planned kinds have no **Connect**.

## Details and health checks

Select a connected card to open its details below the cards: status, last check, last sync, sign-in method and whether it works offline.

- **Check now** runs a real health check at once and records the result. Success shows a confirmation; a failure shows the error panel.
- **Health history** lists the recent checks with their time, result, duration and error code.
- **Manage in …** opens the page that manages the connection (for example **SCM connections** in the hub, with that connection highlighted). Connectors of new kinds have **Edit** and delete instead.

When a check fails, the error panel shows the error code (copyable), the confirmed or probable cause, the impact, numbered fixes and **Verify**, which runs the check again. **Troubleshoot with AI** asks the AI model set for troubleshooting for an explanation of this failure; PATHOS sends only redacted context (the error code, the message and non-secret configuration) and never a credential. The answer is labelled *AI-inferred*. When AI is off or unavailable, the catalogue steps still apply.

## SCM connections and Integrations in the hub

The hub contains the full **SCM connections** and **Integrations** pages:

- **SCM & IDE › Manage in SCM connections** (`/connectors?category=scm_ide&manage=scm`): connect a provider, OAuth applications, test, reconnect, rotate a credential, new webhook secret, re-sync metadata and delete. See [Provider integrations](provider-integrations.md).
- **Monitoring › Manage in Integrations** (`/connectors?category=monitoring&manage=integrations`): add, test, edit and delete Jira and ServiceNow connections. See [Reporting and integrations](reporting-and-integrations.md).

**All connectors** returns to the cards. While the `connectors` flag is on, the old addresses `/admin/scm` and `/admin/integrations` (and their sidebar items) open these hub views, keeping any parameters such as `?connect=git` or the OAuth result. While the flag is off, the old pages open as before.

## Add a connector (new kinds)

**Required permissions.** The manage permission of the kind.

1. Select **Add connector**, or **Connect** on the card of a new kind.
2. Choose the **Kind**, enter a **Name** and choose the **Authentication method**.
3. Enter the **Base URL** and, if needed, an **HTTPS proxy**, the **Scopes** granted at the vendor and a **Custom CA certificate** (PEM) for a server with a private certificate authority.
4. Under **Credential**, paste the secret, or, where the kind supports it, choose **Reference a secret in HashiCorp Vault or OpenBao** and enter the secret store, path and key. PATHOS then stores only the reference.
5. Select **Add connector**, then **Check now** on its card.

Credentials are **write-only**. PATHOS encrypts them, never shows them again and never sends them to an AI model. The Authentication and Configuration tabs show only *Set* or *Not set*. On **Edit**, leave the credential empty to keep the stored one.

## Health states

| State | Meaning |
|---|---|
| **Healthy** | The last check succeeded, within the check interval |
| **Degraded** | It works, but something needs attention soon (a credential expiring within 14 days, a partial Kubernetes inventory, failed deliveries in the last 24 hours, an old feed) |
| **Failing** | The last check failed. The row shows the error code |
| **Never checked** | No check has run yet (the page shows this instead of *Unknown*) |
| **Unknown** | Never checked, the check has no safe way to run (see webhooks below), or the last check is older than twice the interval |
| **Disabled** | Turned off, not configured, or needs the internet while PATHOS runs offline (`PTH-CONN-1015`) |

PATHOS never shows a connection as healthy without a successful check. An AI answer can never mark a connection healthy; only a check can.

## Checking a connection

**Check now** runs the check immediately and records it. You need the permission that manages the connection on its own page (for example `scm.manage` for an SCM connection, `notifications.manage` for a webhook). Viewing needs the permission that shows it on its own page (for example `repos.read` for SCM connections).

- Most checks run at once and the result appears directly.
- **Kubernetes clusters, container registries and the egress proxy are checked by the jobs service only**: the PATHOS API server never calls them. **Check now** asks the jobs service, waits up to 25 seconds, and otherwise shows *Check requested*; the result appears in the history shortly after.
- The jobs service also checks every connection of an organization with the flag on, once per interval (default one hour, `PATHOS_CONNECTOR_CHECK_INTERVAL`).

Each check is a list of steps (reachability, TLS, authentication, scopes, API version, rate limit, webhook, credential expiry). The **history** keeps 30 days, and at least the last 200 checks of each connection.

Every check is read-only and sends nothing a person would see:

| Kind | What the check does |
|---|---|
| SCM (GitHub, GitLab, Bitbucket, Azure DevOps) | The connection's own test: the authenticated account (GitHub App: the installation's repositories) with the stored credential. Warns when the credential expires within 14 days, and for GitLab when deliveries are verified with the legacy token instead of a signing token |
| Jira, ServiceNow | The Test button: Jira `GET /rest/api/2/myself` and the project; ServiceNow one record of the table (`sysparm_limit=1`) |
| Webhooks, Slack, Teams | **No message is posted** (a webhook has no read-only endpoint). The state comes from the last recorded delivery. For a Teams trigger with authentication, PATHOS also requests a Microsoft Entra token, which proves the app credentials. With no delivery yet, the state is *unknown*: use **Send test** on the Notifications page |
| E-mail (SMTP) | Connects, greets, starts TLS and logs in, then quits. **No message is sent** |
| Kubernetes | `GET /version`, then a one-item list of each resource kind the inventory reads |
| Container registries | `GET /v2/`, then one `tags/list?n=1` of the first configured repository |
| AI providers | Lists the provider's models (no tokens are generated, nothing is billed) |
| Vulnerability feeds | The last run of the feed: failed, older than twice its interval, or succeeded |
| Live secret validation | **Configuration only**: a live check would need a real secret, so none is sent. It checks the enabled providers are known and checkable and lists the hosts the egress allowlist must contain |
| Object storage | `HeadBucket` on the configured bucket (nothing is written) |
| Egress proxy | Opens a connection to the proxy and asks it for a reserved name (`pathos-egress-check.invalid`); any HTTP answer proves it is up. Nothing leaves your network |

## Connector kinds

The kinds below appear in the catalogue (`GET /api/v1/connectors/kinds`). *Checked by* says where the check runs.

### SCM & IDE

<a id="github"></a>
- **GitHub** (`github`) — existing. GitHub App, fine-grained or classic token, OAuth App. Checked by the API. Not available offline.
<a id="github_enterprise"></a>
- **GitHub Enterprise Server** (`github_enterprise`) — existing, with a per-connection [private CA bundle](provider-integrations.md#private-ca-bundle-self-hosted-servers) and a [version check](provider-integrations.md#version-checks). Works offline.
<a id="gitlab"></a>
- **GitLab** (`gitlab`) — existing, gitlab.com and self-managed (with a per-connection [private CA bundle](provider-integrations.md#private-ca-bundle-self-hosted-servers)). See [GitLab webhook signing](#gitlab-webhook-signing).
<a id="bitbucket"></a>
- **Bitbucket Cloud** (`bitbucket`) — existing. API token, access token, OAuth consumer.
<a id="azure_devops"></a>
- **Azure DevOps Services** (`azure_devops`) — existing. Service principal, organization-scoped token, Entra OAuth.
<a id="azure_devops_server"></a>
- **Azure DevOps Server** (`azure_devops_server`) — existing. Personal access token; per-connection [private CA bundle](provider-integrations.md#private-ca-bundle-self-hosted-servers). Works offline.
<a id="pathos_cli"></a><a id="vscode"></a><a id="jetbrains"></a><a id="visual_studio"></a>
- **PATHOS CLI** (`pathos_cli`), **VS Code** (`vscode`), **JetBrains IDEs** (`jetbrains`) — existing, inbound (they call PATHOS with a personal API token; no connector row). **Visual Studio** (`visual_studio`) — planned, after the lifecycle release.
<a id="generic_git"></a><a id="bitbucket_data_center"></a>
- **Generic Git** (`generic_git`) — existing: one repository over HTTPS (user name + token) or SSH (deploy key, pinned host key); created with **Add connector** or on SCM connections. See [Generic Git](provider-integrations.md#generic-git-https-or-ssh). Works offline.
- **Bitbucket Data Center** (`bitbucket_data_center`) — existing: HTTP access tokens or user tokens, signed webhooks, per-connection CA; created with **Add connector** or on SCM connections. See [Bitbucket Data Center](provider-integrations.md#bitbucket-data-center). Works offline.

### CI/CD

<a id="github_actions"></a><a id="gitlab_ci"></a><a id="azure_pipelines"></a><a id="jenkins"></a><a id="pre_commit"></a>
- **GitHub Actions** (`github_actions`), **GitLab CI/CD** (`gitlab_ci`), **Azure Pipelines** (`azure_pipelines`), **Jenkins** (`jenkins`), **pre-commit and pre-receive** (`pre_commit`) — existing, inbound templates that call PATHOS with an API token (see [CI/CD integration](ci-cd-integration.md)).
<a id="bitbucket_pipelines"></a><a id="argo_cd"></a>
- **Bitbucket Pipelines** (`bitbucket_pipelines`) — existing, inbound template (see [Bitbucket Pipelines](ci-cd-integration.md#bitbucket-pipelines)). **Argo CD / deploy gate** (`argo_cd`) — planned, after the lifecycle release.

### Cloud

<a id="object_storage"></a>
- **S3-compatible object storage** (`object_storage`) — partial (static access keys only). Configured by the environment (`PATHOS_S3_*`); disabled when artifacts are kept in PostgreSQL. Checked by the API.
<a id="aws"></a><a id="azure"></a><a id="gcp"></a>
- **AWS** (`aws`), **Microsoft Azure** (`azure`), **Google Cloud** (`gcp`) — planned (last in this milestone).

### Containers

<a id="kubernetes"></a>
- **Kubernetes** (`kubernetes`) — existing, read-only (see [Runtime context](runtime.md)). Checked by the jobs service.
<a id="container_registry"></a>
- **Container registries** (`container_registry`) — partial (generic OCI; no ECR, ACR or Artifact Registry token exchange). Checked by the jobs service.
<a id="sigstore"></a>
- **Sigstore signature verification** (`sigstore`) — existing, catalogue only (keyless verification needs the internet).

### Security

<a id="vulnerability_feed"></a>
- **Vulnerability and end-of-life feeds** (`vulnerability_feed`): EPSS, CISA KEV, OSV.dev, end-of-life dates — existing. One row per feed; the check reads the last run.
<a id="deps_dev"></a>
- **deps.dev** (`deps_dev`) — existing, catalogue only; not available offline.
<a id="secret_validation"></a>
- **Live secret validation** (`secret_validation`) — existing (see [Live secret validation](secret-validation.md)); checked as configuration only, so its status stays **Unknown** even when the configuration is valid (no live call is made).
<a id="egress_proxy"></a>
- **Egress proxy** (`egress_proxy`) — existing: the Squid proxy scanners use for internet access. Set `PATHOS_EGRESS_PROXY_URL` (for example `http://egress:3128`) on the jobs service to check it; checked by the jobs service.
<a id="scanner_import"></a>
- **Scanner result import** (`scanner_import`) — existing, inbound.
<a id="splunk"></a><a id="sentinel"></a><a id="elastic"></a>
- **Splunk HEC** (`splunk`), **Microsoft Sentinel** (`sentinel`), **Elastic** (`elastic`) — planned.

### IAM & Secrets

<a id="keycloak_sso"></a>
- **Keycloak and SAML/OIDC SSO** (`keycloak_sso`) — existing, catalogue only (identity providers are configured in Keycloak).
<a id="vault"></a><a id="cloud_secret_manager"></a>
- **HashiCorp Vault / OpenBao** (`vault`) — existing: created with **Add connector** (AppRole or Kubernetes auth); the credentials of other connectors may then be `vault:<mount>/<path>#<key>` references resolved at use time. See [Secret references](secret-references.md). **Cloud secret managers** (`cloud_secret_manager`) — planned, after Vault.

### APIs

<a id="ai_provider"></a>
- **AI providers** (`ai_provider`): Anthropic, OpenAI, xAI and self-hosted OpenAI-compatible servers — existing. Self-hosted servers work offline.
<a id="mcp_api"></a><a id="mcp_registry"></a>
- **PATHOS REST API and MCP** (`mcp_api`) — existing, inbound. **MCP registry** (`mcp_registry`) — existing, catalogue only (no health check yet).
<a id="openapi"></a><a id="postman"></a><a id="graphql"></a><a id="api_gateway"></a>
- **OpenAPI / Swagger** (`openapi`) — partial (file upload for API scan targets). **Postman** (`postman`) and **GraphQL** (`graphql`) — planned with API discovery. **API gateways** (`api_gateway`) — planned, after the lifecycle release.

### Databases

<a id="database"></a>
- **Databases** (`database`) — planned, after the lifecycle release (metadata only, never row data).

### Monitoring

<a id="jira"></a>
- **Jira** (`jira`) — existing. Basic (e-mail and API token), **scoped API token**, or bearer (Data Center personal access token). See [Jira scoped API tokens](#jira-scoped-api-tokens).
<a id="servicenow"></a>
- **ServiceNow** (`servicenow`) — existing.
<a id="webhook"></a>
- **Webhooks (signed JSON)** (`webhook`) — existing.
<a id="slack"></a>
- **Slack** (`slack`) — existing (incoming webhook; the URL is the credential).
<a id="teams"></a>
- **Microsoft Teams** (`teams`) — existing, Workflows triggers only. See [Microsoft Teams Workflows](#microsoft-teams-workflows).
<a id="smtp"></a>
- **E-mail (SMTP)** (`smtp`) — existing.
<a id="opentelemetry"></a><a id="prometheus"></a>
- **OpenTelemetry** (`opentelemetry`) — existing, configured by the environment. **Prometheus** (`prometheus`) — planned.

## GitLab webhook signing

GitLab 19.0 and later can sign webhook deliveries with HMAC-SHA256 (a *signing token*, generally available in 19.1). The older *secret token* (`X-Gitlab-Token`) is sent unchanged with every request and GitLab now calls it legacy.

1. In GitLab, open the webhook that points at PATHOS and select **Generate signing token**. Copy it (GitLab shows it once; it starts with `whsec_`).
2. In PATHOS, store it on the SCM connection: `PUT /api/v1/scm-connections/{id}/webhook-signing-token` with `{"token": "whsec_…"}` (`scm.manage`).

From then on PATHOS accepts only deliveries with a valid `webhook-signature` whose `webhook-timestamp` is within 5 minutes; the legacy token alone is refused. `DELETE` on the same path goes back to the legacy token (for GitLab versions before 19.0). The connector shows a warning (`PTH-CONN-1112`) while the legacy token is used.

## Jira scoped API tokens

Atlassian API tokens can be created **with scopes**. Such tokens only work through the Atlassian API gateway, `https://api.atlassian.com/ex/jira/{cloudId}`; the site URL refuses them. The two kinds of token look the same, so choose the **token type** on the Jira connection (`config.token_type`: `unscoped`, the default, or `scoped`). For a scoped token PATHOS finds the site's cloud ID from `https://<site>.atlassian.net/_edge/tenant_info`, or uses the one you enter (`config.cloud_id`). Links to issues still use the site URL. The scopes PATHOS needs: `read:jira-work` and `write:jira-work` (or the granular `read:issue:jira`, `write:issue:jira`, `write:comment:jira`).

## Microsoft Teams Workflows

Office 365 connector webhooks (`…webhook.office.com`) were retired in May 2026. Post to Teams through a Workflows flow with the trigger **When a Teams webhook request is received**; PATHOS refuses retired connector URLs (`PTH-CONN-1310`).

The trigger's **Who can trigger the flow** decides the authentication:

- **Anyone**: no authentication. Paste the URL; nothing else is needed (the URL is the credential and is stored encrypted).
- **Any user in my tenant** or **Specific users in my tenant**: the trigger needs an OAuth bearer token from Microsoft Entra. Register an app in Entra, create a client secret, and set **Trigger authentication** on the webhook: tenant ID, client (application) ID, client secret and the audience of your cloud (public cloud `https://service.flow.microsoft.com/`). For *Specific users*, add the app's service principal object ID to the allowed users. PATHOS obtains the token with the client credentials grant and sends it as `Authorization: Bearer`. The client secret is write-only.

Microsoft documents no signature or shared-secret header for this trigger; the bearer token is the only authentication it supports.

## AI troubleshooting

When a connection fails, its error panel offers **Troubleshoot with AI** (when the error code allows it and an AI provider is configured). PATHOS builds the context on the server from the connection's **non-secret** metadata (kind, host without path or query, authentication method name, API version, `allow_private`, the steps and error code of the last check) and sends it, redacted, to the troubleshooting model. **It never sends** the credential, a webhook or Slack URL (only its host), a request or response body, an e-mail address or source code. The answer is labelled *AI-inferred*, and the catalogue steps are always shown, also with AI off.

## Offline installations

With `PATHOS_OFFLINE=true`, connections that need the internet (github.com, gitlab.com, Bitbucket Cloud, Azure DevOps Services, Atlassian Cloud, Slack, Teams, cloud AI providers, public registries) are shown as **Disabled (offline)**, not failing. Connections to internal systems keep being checked.

## Troubleshooting

| Code | Meaning | Fix |
|---|---|---|
| `PTH-PLAT-1007` | The `connectors` feature is not enabled | An administrator turns the flag on under Administration → Feature flags |
| `PTH-CONN-1001` | Host not reachable | Check the URL, DNS and firewall from the api or jobs container |
| `PTH-CONN-1002` | Request timed out | Retry; check proxies and latency |
| `PTH-CONN-1003` | Destination address not allowed | Enable *Allow private network* for an internal system, or fix the URL |
| `PTH-CONN-1004` | Untrusted certificate | For an SCM connection, add the private CA bundle on its card (SCM connections → Private CA bundle); otherwise install the private CA in the api and jobs containers |
| `PTH-CONN-1005` | Certificate name or validity mismatch | Use the host name of the certificate; renew it |
| `PTH-CONN-1006` | Proxy refused or failed the connection | Allow the host on the proxy, or add it to `NO_PROXY` |
| `PTH-CONN-1007` | The vendor rejected the credential | Create a new token and update the connection |
| `PTH-CONN-1008` | Credential expired | Reconnect or replace the credential |
| `PTH-CONN-1009` | Missing permission or scope | Add the scope or role listed in the code's page |
| `PTH-CONN-1010` | Rate limited by the vendor | Wait; use a dedicated token |
| `PTH-CONN-1011` | Not found at the vendor | Check the URL, project or repository |
| `PTH-CONN-1012` | Vendor server error | Check the vendor's status; retry |
| `PTH-CONN-1013` | Unexpected response format | Point the URL at the API, not the web interface |
| `PTH-CONN-1015` | Disabled in offline mode | Use an internal system or file imports |
| `PTH-CONN-1016` | Credential could not be decrypted | Restore the previous master key or enter the credential again |
| `PTH-CONN-1019` | Plain HTTP refused | Use the https URL |
| `PTH-CONN-1021` | Credential expires soon | Replace it before it expires |
| `PTH-CONN-1022` | AI provider lists no models | Pull or load a model on the server |
| `PTH-CONN-1105` | GitHub Enterprise Server version out of support | Upgrade the server |
| `PTH-CONN-1106` | Webhook payload larger than 25 MB | Re-sync the repository |
| `PTH-CONN-1112` | GitLab webhook uses the legacy token | Add the GitLab signing token |
| `PTH-CONN-1123` | Bitbucket Data Center version out of support | Upgrade the server |
| `PTH-CONN-1124` | HTTP access token lacks the permission | Give the token Project/Repository read (and admin for webhooks) |
| `PTH-CONN-1140` | SSH host key does not match the pinned key | Confirm the fingerprint with the server administrator; update `known_hosts` |
| `PTH-CONN-1141` | Git authentication failed | Check the token or deploy key and its access to the repository |
| `PTH-CONN-1201` | Jira project not found | Fix the project key or the account's permissions |
| `PTH-CONN-1203` | Scoped Jira token used with the site URL | Set the token type to scoped |
| `PTH-CONN-1205` | Jira cloud ID not found | Enter the cloud ID on the connection |
| `PTH-CONN-1210` | ServiceNow user lacks the role | Give the integration user the table's role |
| `PTH-CONN-1211` | ServiceNow rate limit | Wait, or raise the instance's rule |
| `PTH-CONN-1301` | Slack webhook removed | Create a new incoming webhook |
| `PTH-CONN-1302` | Slack channel archived or not allowed | Unarchive the channel or use another one |
| `PTH-CONN-1303` | Slack rejected the payload | Send test; report the request ID if it persists |
| `PTH-CONN-1310` | Teams connector URL retired | Create a Workflows webhook |
| `PTH-CONN-1311` | Workflows trigger requires authentication | Configure trigger authentication, or set the trigger to Anyone |
| `PTH-CONN-1312` | Teams message too large | Narrow the events or severity |
| `PTH-CONN-1313` | Microsoft Entra token request failed | Check the tenant, client ID, secret and audience |
| `PTH-CONN-1320` | Mail server does not offer STARTTLS | Use port 587 with starttls or 465 with tls |
| `PTH-CONN-1321` | Mail server rejected the login | Fix the SMTP credentials |
| `PTH-CONN-1325` | E-mail delivery failed | Send a test e-mail; check the relay |
| `PTH-CONN-1330` | Webhook receiver rejected the delivery | Fix the receiver URL or signature check |
| `PTH-CONN-1430` | Object store bucket not reachable | Check the object store and `PATHOS_S3_*` |
| `PTH-CONN-1431` | Object store access denied | Fix the access keys or bucket policy |
| `PTH-CONN-1502` | Docker Hub pull limit reached | Use an account token or a mirror |
| `PTH-CONN-1512` | Role does not grant a resource kind | Apply the shipped ClusterRole again |
| `PTH-CONN-1513` | Kubernetes version out of support | Upgrade the cluster |
| `PTH-CONN-1514` | Long-lived service-account token | Rotate it, or use a bound token |
| `PTH-CONN-1531` | Egress proxy not reachable | Check the egress service and `PATHOS_EGRESS_PROXY_URL` |
| `PTH-CONN-1532` | Secret validation provider cannot be checked | Review the enabled providers |
| `PTH-CONN-1601` | Vault AppRole login refused | Check the role ID and secret ID |
| `PTH-CONN-1602` | Vault policy denies the path | Grant `read` on the path to the role's policy |
| `PTH-CONN-1603` | Vault namespace not found | Fix the namespace |
| `PTH-CONN-1604` | Vault is sealed | Unseal Vault |
| `PTH-CONN-1605` | Kubernetes auth role does not match the service account | Bind the role to the PATHOS service account |
| `PTH-CONN-1606` | Referenced secret or key not found | Fix the reference's path or key |
| `PTH-CONN-1607` | Reference outside the allowed path prefix | Use a path under the connector's prefix |
| `PTH-CONN-1608` | No Vault/OpenBao connection for references | Add a Vault/OpenBao connector |
| `PTH-SYNC-1005` | Delivery failed after all retries | Open the deliveries; fix the receiver |
| `PTH-SYNC-1020` | Feed download failed | Check egress to the feed host, or import the file |
| `PTH-SYNC-1022` | Feed data older than twice its interval | Run the feed, or import a current file |

Each code has a full page in the [Troubleshooting centre](/help/troubleshooting/conn) with confirmed and probable causes, numbered fixes and verification steps.
