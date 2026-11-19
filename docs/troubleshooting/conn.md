---
title: Troubleshooting: Connections
section: troubleshooting
order: 103
version: "1.0"
updated: 2026-11-20
summary: SCM providers, ticketing, e-mail, outbound webhooks and inbound webhooks: reachability, certificates, credentials, scopes and rate limits (60 codes, PTH-CONN-*)
---

# Troubleshooting: Connections

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

SCM providers, ticketing, e-mail, outbound webhooks and inbound webhooks: reachability, certificates, credentials, scopes and rate limits.

| Code | Title | Severity |
|---|---|---|
| [PTH-CONN-1001](#PTH-CONN-1001) | Provider host not reachable | error |
| [PTH-CONN-1002](#PTH-CONN-1002) | Provider request timed out | warning |
| [PTH-CONN-1003](#PTH-CONN-1003) | Destination address not allowed | warning |
| [PTH-CONN-1004](#PTH-CONN-1004) | Connection uses an untrusted certificate | error |
| [PTH-CONN-1005](#PTH-CONN-1005) | Certificate name or validity mismatch | error |
| [PTH-CONN-1006](#PTH-CONN-1006) | Proxy refused or failed the connection | error |
| [PTH-CONN-1007](#PTH-CONN-1007) | Provider rejected the credential | error |
| [PTH-CONN-1008](#PTH-CONN-1008) | Provider authorization expired | error |
| [PTH-CONN-1009](#PTH-CONN-1009) | Credential lacks a permission or scope | error |
| [PTH-CONN-1010](#PTH-CONN-1010) | Rate limited by the provider | warning |
| [PTH-CONN-1011](#PTH-CONN-1011) | Not found at the provider | warning |
| [PTH-CONN-1012](#PTH-CONN-1012) | Provider error | error |
| [PTH-CONN-1013](#PTH-CONN-1013) | Unexpected response format | error |
| [PTH-CONN-1015](#PTH-CONN-1015) | Connector disabled in offline mode | info |
| [PTH-CONN-1016](#PTH-CONN-1016) | Credential could not be decrypted | critical |
| [PTH-CONN-1017](#PTH-CONN-1017) | Inbound webhook signature invalid | warning |
| [PTH-CONN-1019](#PTH-CONN-1019) | Plain HTTP refused | warning |
| [PTH-CONN-1020](#PTH-CONN-1020) | Not supported by this provider | info |
| [PTH-CONN-1021](#PTH-CONN-1021) | Credential expires soon | warning |
| [PTH-CONN-1022](#PTH-CONN-1022) | AI provider lists no models | warning |
| [PTH-CONN-1105](#PTH-CONN-1105) | GitHub Enterprise Server version out of support | warning |
| [PTH-CONN-1106](#PTH-CONN-1106) | Webhook payload larger than PATHOS accepts | warning |
| [PTH-CONN-1112](#PTH-CONN-1112) | GitLab webhook uses the legacy secret token | info |
| [PTH-CONN-1123](#PTH-CONN-1123) | Bitbucket Data Center version out of support | warning |
| [PTH-CONN-1124](#PTH-CONN-1124) | HTTP access token lacks the permission | error |
| [PTH-CONN-1140](#PTH-CONN-1140) | SSH host key does not match the pinned key | error |
| [PTH-CONN-1141](#PTH-CONN-1141) | Git authentication failed | error |
| [PTH-CONN-1201](#PTH-CONN-1201) | Jira project or issue type not found | error |
| [PTH-CONN-1203](#PTH-CONN-1203) | Scoped Jira token used with the site URL | warning |
| [PTH-CONN-1205](#PTH-CONN-1205) | Jira cloud ID could not be found | error |
| [PTH-CONN-1210](#PTH-CONN-1210) | ServiceNow user lacks the role for this table | error |
| [PTH-CONN-1211](#PTH-CONN-1211) | ServiceNow rate limit rule reached | warning |
| [PTH-CONN-1250](#PTH-CONN-1250) | Ticket could not be created | error |
| [PTH-CONN-1301](#PTH-CONN-1301) | Slack webhook was removed | error |
| [PTH-CONN-1302](#PTH-CONN-1302) | Slack channel archived or not allowed | error |
| [PTH-CONN-1303](#PTH-CONN-1303) | Slack rejected the payload | warning |
| [PTH-CONN-1310](#PTH-CONN-1310) | Teams connector URL retired | error |
| [PTH-CONN-1311](#PTH-CONN-1311) | Workflows trigger requires authentication | error |
| [PTH-CONN-1312](#PTH-CONN-1312) | Teams message too large | warning |
| [PTH-CONN-1313](#PTH-CONN-1313) | Microsoft Entra token request failed | error |
| [PTH-CONN-1320](#PTH-CONN-1320) | Mail server does not offer STARTTLS | error |
| [PTH-CONN-1321](#PTH-CONN-1321) | Mail server rejected the login | error |
| [PTH-CONN-1325](#PTH-CONN-1325) | E-mail delivery failed | error |
| [PTH-CONN-1330](#PTH-CONN-1330) | Webhook receiver rejected the delivery | error |
| [PTH-CONN-1430](#PTH-CONN-1430) | Object store bucket not reachable | error |
| [PTH-CONN-1431](#PTH-CONN-1431) | Object store access denied | critical |
| [PTH-CONN-1502](#PTH-CONN-1502) | Docker Hub pull limit reached | warning |
| [PTH-CONN-1512](#PTH-CONN-1512) | Role does not grant a resource kind | warning |
| [PTH-CONN-1513](#PTH-CONN-1513) | Kubernetes version out of upstream support | warning |
| [PTH-CONN-1514](#PTH-CONN-1514) | Long-lived service-account token in use | info |
| [PTH-CONN-1531](#PTH-CONN-1531) | Egress proxy not reachable | error |
| [PTH-CONN-1532](#PTH-CONN-1532) | Secret validation provider cannot be checked | warning |
| [PTH-CONN-1601](#PTH-CONN-1601) | Vault AppRole login refused | error |
| [PTH-CONN-1602](#PTH-CONN-1602) | Vault policy denies the path | error |
| [PTH-CONN-1603](#PTH-CONN-1603) | Vault namespace not found | error |
| [PTH-CONN-1604](#PTH-CONN-1604) | Vault is sealed | critical |
| [PTH-CONN-1605](#PTH-CONN-1605) | Kubernetes auth role does not match the service account | error |
| [PTH-CONN-1606](#PTH-CONN-1606) | Referenced secret or key not found | error |
| [PTH-CONN-1607](#PTH-CONN-1607) | Reference outside the allowed Vault path prefix | error |
| [PTH-CONN-1608](#PTH-CONN-1608) | No Vault/OpenBao connection for secret references | error |

<a id="PTH-CONN-1001"></a>

## PTH-CONN-1001: Provider host not reachable

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `import:provider_unavailable` |
| Raised in | internal/scm/http.go (transportError), internal/repos/import_worker.go |

**What it means.** PATHOS could not connect to the provider (DNS failure, connection refused or reset).

**Confirmed cause.** The connection to the provider host failed before any HTTP response. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. Wrong base URL or host name
2. A firewall or the egress proxy blocks the host
3. The provider is down

**Impact.** Listing, importing, re-syncing and status updates for this connection fail; queued work is retried.

**How to fix**

1. Check the connection's base URL (Configurations → SCM connections).
2. From the api container, check the host resolves and port 443 is reachable.
3. If an egress proxy is used, allow the host (docs/OPERATIONS.md, egress).

**Verify**

1. Use Test connection; it reports the authenticated account.


<a id="PTH-CONN-1002"></a>

## PTH-CONN-1002: Provider request timed out

| | |
|---|---|
| Severity | warning |
| Category | connectivity |
| HTTP status | 504 |
| AI help | offered |
| Short codes | `import:timeout` |
| Raised in | internal/scm/http.go (IsTransient), internal/repos/import_worker.go |

**What it means.** The provider did not answer within the client timeout.

**Confirmed cause.** The request to the provider exceeded its timeout. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The provider is slow or overloaded
2. A very large organization listing
3. Network latency through a proxy

**Impact.** The operation is retried automatically for background work; interactive calls must be repeated.

**How to fix**

1. Retry later.
2. Narrow the listing (organization or project filter).

**Verify**

1. Test connection answers within a few seconds.


<a id="PTH-CONN-1003"></a>

## PTH-CONN-1003: Destination address not allowed

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | 502 |
| AI help | not offered |
| Short codes | `import:blocked_address`, `import:untrusted_clone_url` |
| Raised in | internal/scm/safehttp.go (ErrBlockedAddress) |

**What it means.** The provider URL resolves to a private, loopback, link-local or metadata address, which outbound requests refuse unless the connection allows private networks.

**Confirmed cause.** The destination address is blocked by the outbound network policy. Confirmed automatically when this code is raised.

**Probable causes**

1. A self-hosted provider on an internal network without "allow private network"
2. DNS returns an internal address for a public name

**Impact.** No request is sent to this host.

**How to fix**

1. For an internal server, enable "Allow private network" on the connection (administrators only).
2. Otherwise correct the URL.

**Verify**

1. Test connection succeeds.


<a id="PTH-CONN-1004"></a>

## PTH-CONN-1004: Connection uses an untrusted certificate

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | 502 |
| AI help | offered |
| Raised in | internal/scm/http.go (transportError: x509) |

**What it means.** TLS verification failed: the server certificate is signed by an authority the API does not trust, or its name or validity does not match.

**Confirmed cause.** The provider's TLS certificate could not be verified. Confirmed automatically when this code is raised.

**Probable causes**

1. A server certificate issued by a private certificate authority that is neither in the connection's CA bundle nor in the trust store of the api and jobs images
2. A TLS-inspecting proxy
3. An expired certificate or a host name mismatch

**Impact.** No request reaches the provider.

**How to fix**

1. For an SCM connection (GitHub Enterprise Server, GitLab self-managed, Bitbucket Data Center, Azure DevOps Server, Generic Git), add the private CA certificate(s) as the connection's CA bundle (PEM): the connection's card on SCM connections (also inside Connectors) → Private CA bundle → Add or Replace CA bundle. It applies to that connection and its clones only.
2. For other connectors, install the private CA in the trust store of the api and jobs containers.
3. Renew the provider's certificate if it expired.
4. Use the provider's exact host name in the base URL.

**Verify**

1. Test connection succeeds.
2. The connection shows the CA certificate's subject, expiry and SHA-256 fingerprint.


<a id="PTH-CONN-1005"></a>

## PTH-CONN-1005: Certificate name or validity mismatch

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/classify.go (x509.HostnameError, x509.CertificateInvalidError) |

**What it means.** TLS verification failed because the server certificate does not name the host PATHOS called, or it is expired or not yet valid.

**Confirmed cause.** The server certificate does not match the host name or its validity period. Confirmed automatically when this code is raised.

**Probable causes**

1. The base URL uses another name than the certificate (an IP address or an internal alias)
2. The certificate expired
3. The server clock or the PATHOS clock is wrong

**Impact.** No request reaches the system.

**How to fix**

1. Use the exact host name the certificate was issued for in the connection's URL.
2. Renew the certificate if it expired.
3. Check the clocks of the server and of the PATHOS hosts (NTP).

**Verify**

1. Run the connector's health check (Connectors → Check now); the TLS step passes.


<a id="PTH-CONN-1006"></a>

## PTH-CONN-1006: Proxy refused or failed the connection

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/classify.go (proxyconnect) |

**What it means.** The HTTP proxy configured for outbound requests (PATHOS_HTTPS_PROXY / HTTPS_PROXY) refused the CONNECT request or failed to reach the host.

**Confirmed cause.** The outbound proxy refused or failed the connection. Confirmed automatically when this code is raised.

**Probable causes**

1. The proxy's allowlist does not include the host
2. Proxy authentication is required
3. An internal host is missing from NO_PROXY

**Impact.** No request reaches the system through the proxy.

**How to fix**

1. Allow the host on the proxy, or add an internal host to NO_PROXY for the api and jobs services.
2. Check the proxy URL and credentials in the environment.

**Verify**

1. Run the connector's health check; it passes the reachability step.


<a id="PTH-CONN-1007"></a>

## PTH-CONN-1007: Provider rejected the credential

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `import:authentication_failed` |
| Raised in | internal/scm/http.go (statusError → ErrAuth), internal/repos/service.go |

**What it means.** The provider answered HTTP 401: the token, app credential or password is wrong or was revoked.

**Confirmed cause.** The provider rejected the connection's credential (HTTP 401). Confirmed automatically when this code is raised.

**Probable causes**

1. The token was revoked or regenerated
2. A token for another host or account
3. The token was copied incompletely

**Impact.** All operations of this connection fail until the credential is replaced.

**How to fix**

1. Create a new token with the scopes in docs/user-guide/provider-integrations.md.
2. Edit the connection and paste the new token (it is stored encrypted and never shown again).

**Verify**

1. Test connection reports the authenticated account.


<a id="PTH-CONN-1008"></a>

## PTH-CONN-1008: Provider authorization expired

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | 502 |
| AI help | not offered |
| Short codes | `import:token_expired` |
| Raised in | internal/scm/contract.go (ErrTokenExpired), internal/repos/import_worker.go |

**What it means.** The OAuth authorization or token of the connection expired or was revoked, and could not be refreshed.

**Confirmed cause.** The connection's authorization expired or was revoked. Confirmed automatically when this code is raised.

**Probable causes**

1. The refresh token expired
2. The user who authorized the connection revoked access or left

**Impact.** The connection stops working until it is reconnected.

**How to fix**

1. Reconnect the connection (Configurations → SCM connections → Reconnect).
2. Retry failed imports afterwards.

**Verify**

1. Test connection succeeds; retried imports complete.


<a id="PTH-CONN-1009"></a>

## PTH-CONN-1009: Credential lacks a permission or scope

| | |
|---|---|
| Severity | error |
| Category | authorization |
| HTTP status | 502 |
| AI help | offered |
| Raised in | internal/scm/http.go (statusError → ErrForbidden), internal/repos/service.go |

**What it means.** The provider answered HTTP 403 without rate-limit headers: the credential is valid but not allowed to do this.

**Confirmed cause.** The provider refused the operation for this credential (HTTP 403). Confirmed automatically when this code is raised.

**Probable causes**

1. The token lacks a scope (for example repository read or webhook write)
2. Organization policy (SSO authorization, IP allow list) blocks the token

**Impact.** The specific operation fails; others may work.

**How to fix**

1. Add the missing scope to the token or app (docs/user-guide/provider-integrations.md lists them).
2. Authorize the token for SSO if the organization enforces it.

**Verify**

1. Repeat the operation; it succeeds.


<a id="PTH-CONN-1010"></a>

## PTH-CONN-1010: Rate limited by the provider

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/scm/http.go (rateLimited, ErrRateLimited) |

**What it means.** The provider answered 429, or 403 with rate-limit headers.

**Confirmed cause.** The provider's API rate limit for this credential is exhausted. Confirmed automatically when this code is raised.

**Probable causes**

1. Large imports or re-syncs at the same time
2. Other tools share the same token

**Impact.** Requests are refused until the provider's window resets; background work is retried.

**How to fix**

1. Wait for the limit to reset.
2. Use a dedicated token or a GitHub App for PATHOS.

**Verify**

1. Test connection succeeds after the reset.


<a id="PTH-CONN-1011"></a>

## PTH-CONN-1011: Not found at the provider

| | |
|---|---|
| Severity | warning |
| Category | not-found |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/scm/http.go (statusError → ErrNotFound), internal/repos/service.go |

**What it means.** The provider answered 404: the repository, branch or base URL does not exist or is not visible to the credential.

**Confirmed cause.** The provider reports the item as not found for this credential. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The repository was renamed, moved or deleted
2. The credential cannot see private repositories
3. A wrong base URL (API path) for a self-hosted server

**Impact.** The operation on this item fails.

**How to fix**

1. Check the item exists at the provider.
2. Grant the credential access, or correct the base URL.

**Verify**

1. Refresh the inventory; the repository is listed.


<a id="PTH-CONN-1012"></a>

## PTH-CONN-1012: Provider error

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `scm_error`, `import:provider_error` |
| Raised in | internal/repos/service.go, internal/repos/resync.go, internal/scm/http.go |

**What it means.** The provider answered with a server error (5xx) or an unexpected response.

**Confirmed cause.** The provider returned an error response. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The provider has an outage
2. A proxy in between returned an error page

**Impact.** The operation failed; background work is retried.

**How to fix**

1. Check the provider's status page.
2. Retry later.

**Verify**

1. Test connection succeeds.


<a id="PTH-CONN-1013"></a>

## PTH-CONN-1013: Unexpected response format

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/classify.go, internal/tickets/connectors.go (HTTPError.Unreadable) |

**What it means.** The system answered, but not with the JSON PATHOS expects: often a sign-in page, a proxy error page or a wrong base URL.

**Confirmed cause.** The response could not be read as the expected JSON. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The base URL points at the web interface instead of the API
2. A single sign-on or proxy page intercepted the request
3. The server version answers differently

**Impact.** The operation fails until the URL or the intermediary is fixed.

**How to fix**

1. Check the connection's base URL against the API base documented for the vendor.
2. Bypass the intercepting proxy or SSO page for API calls.

**Verify**

1. Run the connector's health check; it passes.


<a id="PTH-CONN-1015"></a>

## PTH-CONN-1015: Connector disabled in offline mode

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/runner.go, internal/connectors/registry.go (EffectiveStatus) |

**What it means.** PATHOS runs with PATHOS_OFFLINE=true and this connection needs the internet (a cloud service). It is shown as disabled, not failing.

**Confirmed cause.** Offline mode is on and the connection's host is on the internet. Confirmed automatically when this code is raised.

**Probable causes**

1. The installation is air-gapped by design

**Impact.** The connection is not used; internal systems keep working.

**How to fix**

1. Use an internal system instead (for example GitHub Enterprise Server or a self-hosted model), or import data from files.
2. Turn offline mode off only if the installation may reach the internet.

**Verify**

1. The connector shows disabled (offline) rather than failing.


<a id="PTH-CONN-1016"></a>

## PTH-CONN-1016: Credential could not be decrypted

| | |
|---|---|
| Severity | critical |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/classify.go (crypto.ErrDecrypt) |

**What it means.** The stored credential of the connection could not be decrypted with the configured master keys.

**Confirmed cause.** Decrypting the stored credential failed. Confirmed automatically when this code is raised.

**Probable causes**

1. PATHOS_MASTER_KEYS changed and the previous key is not listed
2. The database was restored next to other master keys

**Impact.** Every operation of the connection fails until the credential is readable again or replaced.

**How to fix**

1. Restore the previous master key in PATHOS_MASTER_KEYS_PREVIOUS (docs/SECURITY.md, key rotation).
2. Otherwise enter the credential again on the connection's page.

**Verify**

1. Run the connector's health check; the authentication step passes.


<a id="PTH-CONN-1017"></a>

## PTH-CONN-1017: Inbound webhook signature invalid

| | |
|---|---|
| Severity | warning |
| Category | authentication |
| HTTP status | 401 |
| AI help | not offered |
| Short codes | `invalid_signature` |
| Raised in | internal/repos/webhooks.go, internal/scm/webhook.go (ErrSignature) |

**What it means.** A webhook delivery's signature or token did not match the connection's webhook secret.

**Confirmed cause.** The webhook signature does not match the stored secret. Confirmed automatically when this code is raised.

**Probable causes**

1. The webhook secret was changed at the provider or in PATHOS
2. A delivery for another installation
3. A forged request

**Impact.** The delivery was ignored; push-triggered scans do not start.

**How to fix**

1. Re-register the webhook from the repository page (PATHOS sets a new secret).
2. Remove stale webhooks that point at PATHOS.

**Verify**

1. Redeliver a push from the provider; PATHOS answers 2xx and a scan is queued.


<a id="PTH-CONN-1019"></a>

## PTH-CONN-1019: Plain HTTP refused

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/scm/safehttp.go (ErrPlainHTTP) |

**What it means.** The connection URL uses http:// while plain HTTP is allowed only in development (PATHOS_SCM_ALLOW_HTTP).

**Confirmed cause.** The URL uses http:// and plain HTTP is not allowed. Confirmed automatically when this code is raised.

**Probable causes**

1. The URL was entered without https
2. A development URL was copied to production

**Impact.** No request is sent.

**How to fix**

1. Use the https:// URL of the system.

**Verify**

1. Run the connector's health check; it passes the configuration step.


<a id="PTH-CONN-1020"></a>

## PTH-CONN-1020: Not supported by this provider

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/scm/contract.go (ErrNotSupported), internal/repos/service.go |

**What it means.** The provider adapter does not implement the requested operation.

**Confirmed cause.** The provider does not support this operation in PATHOS. Confirmed automatically when this code is raised.

**Probable causes**

1. The feature exists only for some providers

**Impact.** The operation is unavailable for this connection.

**How to fix**

1. See docs/user-guide/provider-integrations.md for what each provider supports.

**Verify**

1. Not applicable.


<a id="PTH-CONN-1021"></a>

## PTH-CONN-1021: Credential expires soon

| | |
|---|---|
| Severity | warning |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (expiryStep) |

**What it means.** The credential of the connection expires within 14 days (the provider reported its expiry).

**Confirmed cause.** The credential's expiry date is less than 14 days away. Confirmed automatically when this code is raised.

**Probable causes**

1. The token was created with a short lifetime
2. An organization policy caps token lifetimes

**Impact.** The connection keeps working until the expiry date, then fails with PTH-CONN-1008.

**How to fix**

1. Create a new token with the same scopes and replace it on the connection's page before it expires.

**Verify**

1. The connector's credential step passes without a warning.


<a id="PTH-CONN-1022"></a>

## PTH-CONN-1022: AI provider lists no models

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkAI) |

**What it means.** The AI provider accepted the credential but its model list is empty.

**Confirmed cause.** The provider returned an empty model list. Confirmed automatically when this code is raised.

**Probable causes**

1. A self-hosted server (Ollama, vLLM) has no model pulled or loaded
2. The API key's project has no model access

**Impact.** AI features that use this provider fail until a model is available.

**How to fix**

1. Pull or load a model on the self-hosted server (for example ollama pull <model>).
2. Grant the key's project access to a model.

**Verify**

1. Run the connector's health check; it lists at least one model.


<a id="PTH-CONN-1105"></a>

## PTH-CONN-1105: GitHub Enterprise Server version out of support

| | |
|---|---|
| Severity | warning |
| Category | compatibility |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/scm/version.go (ErrGHESVersion) |

**What it means.** GET /api/v3/meta reports an installed_version older than the oldest GitHub Enterprise Server release GitHub still supports.

**Confirmed cause.** The server reports a release past its end of support. Confirmed automatically when this code is raised.

**Probable causes**

1. The server has not been upgraded
2. A release reached its end of support since the last upgrade

**Impact.** The connection keeps working, but the server no longer receives security fixes and API behaviour may differ from what PATHOS expects.

**How to fix**

1. Plan an upgrade to a supported release (docs.github.com/enterprise-server@latest/admin/all-releases).
2. Run the health check again after the upgrade.

**Verify**

1. The connector's health check shows the new version without a warning.


<a id="PTH-CONN-1106"></a>

## PTH-CONN-1106: Webhook payload larger than PATHOS accepts

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | 413 |
| AI help | not offered |
| Raised in | internal/repos/webhooks.go (maxWebhookBody) |

**What it means.** An inbound SCM webhook delivery was larger than 25 MB, the most PATHOS reads (GitHub and gitlab.com send at most 25 MB).

**Confirmed cause.** The delivery body exceeded 25 MB. Confirmed automatically when this code is raised.

**Probable causes**

1. A push with a very large number of commits or files

**Impact.** This delivery was refused; the daily re-sync still picks up the push.

**How to fix**

1. Nothing is required; re-sync the repository to scan the latest commit now.

**Verify**

1. The repository's last sync shows the new head commit.


<a id="PTH-CONN-1112"></a>

## PTH-CONN-1112: GitLab webhook uses the legacy secret token

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkSCM), internal/repos/webhooks.go |

**What it means.** GitLab deliveries for this connection are verified with X-Gitlab-Token, which GitLab now calls legacy. GitLab 19.0 and later can sign deliveries with HMAC-SHA256 (webhook signing token).

**Confirmed cause.** No webhook signing token is set on the connection. Confirmed automatically when this code is raised.

**Probable causes**

1. The connection was created before PATHOS supported signing tokens
2. The GitLab instance is older than 19.0

**Impact.** Deliveries still work; a token is weaker than a signature (it is sent with every request and does not cover the body).

**How to fix**

1. In GitLab, open the project's or group's webhook and select Generate signing token.
2. In PATHOS, paste it on the SCM connection (PUT /api/v1/scm-connections/{id}/webhook-signing-token).

**Verify**

1. Redeliver a push from GitLab; PATHOS accepts it and the connector's webhook step passes.


<a id="PTH-CONN-1123"></a>

## PTH-CONN-1123: Bitbucket Data Center version out of support

| | |
|---|---|
| Severity | warning |
| Category | compatibility |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/scm/version.go, internal/scm/bitbucketdc.go (ErrBBDCVersion) |

**What it means.** GET /rest/api/1.0/application-properties reports a version older than the oldest Bitbucket Data Center release Atlassian still supports.

**Confirmed cause.** The server reports a release past its end of support. Confirmed automatically when this code is raised.

**Probable causes**

1. The server has not been upgraded
2. The Long Term Support release reached its end of support

**Impact.** The connection keeps working, but the server no longer receives security fixes.

**How to fix**

1. Upgrade to a supported release (Atlassian end of life policy).
2. Run the health check again after the upgrade.

**Verify**

1. The connector's health check shows the new version without a warning.


<a id="PTH-CONN-1124"></a>

## PTH-CONN-1124: HTTP access token lacks the permission

| | |
|---|---|
| Severity | error |
| Category | authorization |
| HTTP status | 502 |
| AI help | offered |
| Raised in | internal/scm/bitbucketdc.go (ErrTokenPermission) |

**What it means.** Bitbucket Data Center answered 403 to a project or repository HTTP access token: the token's permission level (read, write) does not cover the operation, or the token is scoped to another project or repository.

**Confirmed cause.** Bitbucket Data Center refused the operation for this HTTP access token (HTTP 403). Confirmed automatically when this code is raised.

**Probable causes**

1. A repository token used to list a whole project
2. The token has no Project read / Repository read permission
3. Write is needed (commit statuses, fix pull requests) but the token is read-only

**Impact.** The operation fails; inventory or status updates for this connection stop.

**How to fix**

1. In Bitbucket, open the project or repository settings → HTTP access tokens and check the token's permissions.
2. Create a token with Read (Write only for statuses and fix pull requests) and replace it on the connection.
3. For a repository token, set the connection's project key and import only that repository.

**Verify**

1. Run the health check; it lists repositories.


<a id="PTH-CONN-1140"></a>

## PTH-CONN-1140: SSH host key does not match the pinned key

| | |
|---|---|
| Severity | error |
| Category | security |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/scm/gitremote.go (ErrHostKeyMismatch), internal/repos/connections.go (validKnownHosts) |

**What it means.** The Git server presented an SSH host key that is not in the connection's pinned known_hosts entries, or no entry exists for the host and port. PATHOS never accepts an unknown host key.

**Confirmed cause.** The server's host key is not one of the pinned keys. Confirmed automatically when this code is raised.

**Probable causes**

1. The server's host key was rotated
2. The known_hosts entry is for another host name or port (non-standard ports are written [host]:port)
3. A machine in the network path impersonates the server

**Impact.** No connection is made: health checks, sync and scans of this repository fail until the key is confirmed.

**How to fix**

1. Ask the Git server administrator for the current host key fingerprint (ssh-keygen -lf on the server).
2. Only if it matches, update the connection's known_hosts entry and fingerprint.
3. If the administrator did not rotate the key, treat it as a possible interception and investigate before trusting it.

**Verify**

1. Run the health check; ls-remote succeeds.


<a id="PTH-CONN-1141"></a>

## PTH-CONN-1141: Git authentication failed

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | 502 |
| AI help | offered |
| Raised in | internal/scm/gitremote.go (ErrGitAuth) |

**What it means.** The Git server rejected the connection's credential: the HTTPS token (HTTP 401) or the SSH key.

**Confirmed cause.** The Git server rejected the credential. Confirmed automatically when this code is raised.

**Probable causes**

1. The token or deploy key was revoked or expired
2. The deploy key is not added to this repository
3. The HTTPS user name does not match the token

**Impact.** Health checks, sync and scans of this repository fail.

**How to fix**

1. Add the deploy key to the repository (read-only), or create a new read-only token.
2. Replace the credential on the connection (it is stored encrypted and never shown again).

**Verify**

1. Run the health check; ls-remote lists the branches.


<a id="PTH-CONN-1201"></a>

## PTH-CONN-1201: Jira project or issue type not found

| | |
|---|---|
| Severity | error |
| Category | not-found |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkTicket) |

**What it means.** Jira did not find the configured project (or issue type) for the connection's credential.

**Confirmed cause.** Jira answered 404 for the configured project. Confirmed automatically when this code is raised.

**Probable causes**

1. The project key is wrong
2. The account cannot browse the project

**Impact.** Tickets cannot be created with this connection.

**How to fix**

1. Correct the project key on Integrations, or grant the account Browse projects and Create issues.

**Verify**

1. Test the connection; the project is found.


<a id="PTH-CONN-1203"></a>

## PTH-CONN-1203: Scoped Jira token used with the site URL

| | |
|---|---|
| Severity | warning |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkTicket), internal/tickets/connectors.go (apiBase) |

**What it means.** Atlassian API tokens with scopes only work through the Atlassian API gateway (https://api.atlassian.com/ex/jira/{cloudId}); the site URL refuses them. The two kinds of token look alike, so PATHOS cannot tell which one was entered.

**Confirmed cause.** Not confirmed automatically: Jira Cloud refused the token at the site URL. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The token was created with scopes and the connection's token type is unscoped
2. The token was revoked

**Impact.** Every Jira operation of the connection fails.

**How to fix**

1. Set the connection's token type to scoped (Integrations → Jira → Token type). PATHOS then looks up the site's cloud ID and calls the gateway.
2. Otherwise create a new token.

**Verify**

1. Test the connection; it reports the account.


<a id="PTH-CONN-1205"></a>

## PTH-CONN-1205: Jira cloud ID could not be found

| | |
|---|---|
| Severity | error |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/tickets/connectors.go (ErrCloudID) |

**What it means.** A scoped Jira token needs the site's cloud ID; PATHOS could not read it from the site (https://<site>/_edge/tenant_info).

**Confirmed cause.** The cloud ID lookup failed. Confirmed automatically when this code is raised.

**Probable causes**

1. The base URL is not a Jira Cloud site
2. The site is not reachable from PATHOS

**Impact.** Every Jira operation of the connection fails.

**How to fix**

1. Enter the cloud ID on the connection (config.cloud_id). An administrator finds it in the Atlassian administration or at https://<site>.atlassian.net/_edge/tenant_info.

**Verify**

1. Test the connection; it reports the account.


<a id="PTH-CONN-1210"></a>

## PTH-CONN-1210: ServiceNow user lacks the role for this table

| | |
|---|---|
| Severity | error |
| Category | authorization |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkTicket) |

**What it means.** ServiceNow refused access to the configured table for the integration user (HTTP 403).

**Confirmed cause.** ServiceNow answered 403 for the table. Confirmed automatically when this code is raised.

**Probable causes**

1. The user has no role on the table (for example sn_incident_write for incident)
2. An ACL blocks the user

**Impact.** Tickets cannot be created with this connection.

**How to fix**

1. Give the integration user the role the table needs (incident: sn_incident_write; security incidents: sn_si.integration_user).

**Verify**

1. Test the connection; it succeeds.


<a id="PTH-CONN-1211"></a>

## PTH-CONN-1211: ServiceNow rate limit rule reached

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkTicket) |

**What it means.** ServiceNow answered 429: an inbound REST rate limit rule for the user or role was reached.

**Confirmed cause.** ServiceNow refused the request with 429. Confirmed automatically when this code is raised.

**Probable causes**

1. A rate limit rule of the instance applies to the integration user
2. Other integrations share the user

**Impact.** Requests fail until the rule's window resets; status refreshes retry later.

**How to fix**

1. Wait for the window to reset.
2. Ask the ServiceNow administrator to raise the rule for the integration user.

**Verify**

1. Test the connection after the reset; it succeeds.


<a id="PTH-CONN-1250"></a>

## PTH-CONN-1250: Ticket could not be created

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `ticket_failed` |
| Raised in | internal/tickets/service.go |

**What it means.** The ticketing system (Jira, Azure Boards, GitHub or GitLab issues) refused or failed the issue creation.

**Confirmed cause.** The ticketing system returned an error for the new issue. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The project or issue type does not exist
2. A required field is not sent by PATHOS
3. The token expired or lacks permission

**Impact.** No ticket was created; the finding is unchanged.

**How to fix**

1. Test the ticket connection.
2. Check project key and issue type.
3. Read the redacted provider message in the error.

**Verify**

1. Create the ticket again; the issue link appears on the finding.


<a id="PTH-CONN-1301"></a>

## PTH-CONN-1301: Slack webhook was removed

| | |
|---|---|
| Severity | error |
| Category | not-found |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkWebhook) |

**What it means.** Slack answered 404 or 410 (no_service): the incoming webhook was removed or revoked (Slack revokes leaked webhook URLs).

**Confirmed cause.** Slack reports that the webhook no longer exists. Confirmed automatically when this code is raised.

**Probable causes**

1. The Slack app or webhook was removed
2. Slack revoked the URL after it leaked

**Impact.** Messages to this channel are not delivered.

**How to fix**

1. Create a new incoming webhook in Slack and update the URL on Notifications → Webhooks.

**Verify**

1. Send test; the delivery succeeds.


<a id="PTH-CONN-1302"></a>

## PTH-CONN-1302: Slack channel archived or not allowed

| | |
|---|---|
| Severity | error |
| Category | authorization |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkWebhook) |

**What it means.** Slack answered 403 (for example channel_is_archived or action_prohibited).

**Confirmed cause.** Slack refused to post to the channel. Confirmed automatically when this code is raised.

**Probable causes**

1. The channel was archived
2. A workspace policy blocks the app

**Impact.** Messages to this channel are not delivered.

**How to fix**

1. Unarchive the channel or create a webhook for another channel.

**Verify**

1. Send test; the delivery succeeds.


<a id="PTH-CONN-1303"></a>

## PTH-CONN-1303: Slack rejected the payload

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkWebhook) |

**What it means.** Slack answered 400 (invalid_payload) for a delivery.

**Confirmed cause.** Slack refused the message body. Confirmed automatically when this code is raised.

**Probable causes**

1. The message was too long or malformed

**Impact.** This message was not delivered.

**How to fix**

1. Send test; if it succeeds, the failed message was an exception. Otherwise report it with the delivery's request ID.

**Verify**

1. Send test; the delivery succeeds.


<a id="PTH-CONN-1310"></a>

## PTH-CONN-1310: Teams connector URL retired

| | |
|---|---|
| Severity | error |
| Category | configuration |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/notify/webhooks.go, internal/connectors/existing.go (checkWebhook) |

**What it means.** The URL is an Office 365 connector webhook (webhook.office.com). Microsoft retired these connectors in May 2026; they no longer accept messages.

**Confirmed cause.** The webhook URL is a retired Office 365 connector URL. Confirmed automatically when this code is raised.

**Probable causes**

1. The webhook was created before May 2026

**Impact.** No message reaches Teams.

**How to fix**

1. In Teams, create a flow with the Workflows template "Post to a channel when a webhook request is received" (trigger "When a Teams webhook request is received").
2. Paste its URL on Notifications → Webhooks.

**Verify**

1. Send test; the message appears in the channel.


<a id="PTH-CONN-1311"></a>

## PTH-CONN-1311: Workflows trigger requires authentication

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/notify/webhooks.go (sendWebhook), internal/connectors/existing.go |

**What it means.** The Teams Workflows trigger answered 401 or 403: it is restricted to users of the tenant and PATHOS sent no token, or a token the trigger does not accept.

**Confirmed cause.** The Workflows trigger refused the request. Confirmed automatically when this code is raised.

**Probable causes**

1. The trigger's "Who can trigger the flow" is Any user in my tenant or Specific users, and no trigger authentication is configured
2. The Entra app is not in the trigger's allowed users
3. The audience does not match the cloud

**Impact.** No message reaches Teams.

**How to fix**

1. Configure trigger authentication on the webhook: tenant ID, client ID and secret of an Entra app registration.
2. For Specific users, add the app's service principal object ID to the trigger's allowed users.
3. Or set the trigger to Anyone (no authentication).

**Verify**

1. Send test; the message appears in the channel.


<a id="PTH-CONN-1312"></a>

## PTH-CONN-1312: Teams message too large

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkWebhook) |

**What it means.** The Workflows trigger refused a message as too large (HTTP 413; posting actions accept about 28 KB).

**Confirmed cause.** The message exceeded the size Teams accepts. Confirmed automatically when this code is raised.

**Probable causes**

1. A notification with many findings

**Impact.** This message was not delivered.

**How to fix**

1. Narrow the webhook's events or minimum severity.

**Verify**

1. The next deliveries succeed.


<a id="PTH-CONN-1313"></a>

## PTH-CONN-1313: Microsoft Entra token request failed

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/notify/teamsauth.go (entraToken) |

**What it means.** PATHOS could not obtain the bearer token for a Teams Workflows trigger (client credentials grant).

**Confirmed cause.** Microsoft Entra refused the token request. Confirmed automatically when this code is raised.

**Probable causes**

1. The client secret expired or is wrong (AADSTS7000215, AADSTS7000222)
2. Wrong tenant or client ID (AADSTS90002, AADSTS700016)
3. The audience is not the flow service of this cloud

**Impact.** Messages to the restricted trigger are not delivered.

**How to fix**

1. Create a new client secret for the app registration and enter it on the webhook.
2. Check the tenant ID, client ID and audience.

**Verify**

1. Run the connector's health check; the authentication step passes.


<a id="PTH-CONN-1320"></a>

## PTH-CONN-1320: Mail server does not offer STARTTLS

| | |
|---|---|
| Severity | error |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkSMTP), internal/notify/smtp.go |

**What it means.** The TLS mode is starttls but the server did not offer STARTTLS; PATHOS never falls back to clear text.

**Confirmed cause.** The server's EHLO answer has no STARTTLS. Confirmed automatically when this code is raised.

**Probable causes**

1. The port is the implicit TLS port (465) with mode starttls
2. A relay without TLS

**Impact.** No e-mail is sent.

**How to fix**

1. Use port 587 with starttls, or port 465 with tls (RFC 8314).
2. Use mode none only for a relay on a trusted network without credentials.

**Verify**

1. Run the connector's health check; the TLS step passes.


<a id="PTH-CONN-1321"></a>

## PTH-CONN-1321: Mail server rejected the login

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkSMTP) |

**What it means.** The SMTP server refused the user name and password (AUTH).

**Confirmed cause.** SMTP AUTH failed. Confirmed automatically when this code is raised.

**Probable causes**

1. Wrong user name or password
2. The account needs an app password or forbids SMTP AUTH

**Impact.** No e-mail is sent.

**How to fix**

1. Enter the correct credentials on Notifications → E-mail.
2. Enable SMTP AUTH or create an app password for the account.

**Verify**

1. Run the connector's health check; the authentication step passes.


<a id="PTH-CONN-1325"></a>

## PTH-CONN-1325: E-mail delivery failed

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/notify/dispatch.go |

**What it means.** Sending a notification e-mail through the configured SMTP server failed.

**Confirmed cause.** The SMTP server refused or failed the message. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. Wrong SMTP host, port or TLS mode
2. The SMTP login was rejected
3. The recipient or sender address is refused

**Impact.** Notification e-mails are not delivered; in-app notifications still work.

**How to fix**

1. Send a test e-mail from Administration → Notifications → E-mail.
2. Check the SMTP settings and credentials.

**Verify**

1. The test e-mail arrives; failed notifications can be resent.


<a id="PTH-CONN-1330"></a>

## PTH-CONN-1330: Webhook receiver rejected the delivery

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkWebhook) |

**What it means.** The receiver of an outbound webhook answered with a client error (4xx other than 408 and 429); PATHOS does not retry it.

**Confirmed cause.** The receiver refused the delivery. Confirmed automatically when this code is raised.

**Probable causes**

1. The receiver's URL changed
2. The receiver rejects the signature (secret changed)
3. The receiver rejects the payload

**Impact.** Events are not delivered to this receiver.

**How to fix**

1. Open the webhook's deliveries for the status.
2. Fix the URL or the receiver and use Send test.

**Verify**

1. Send test; the delivery succeeds.


<a id="PTH-CONN-1430"></a>

## PTH-CONN-1430: Object store bucket not reachable

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkObjectStore) |

**What it means.** HeadBucket on the configured object store failed: the endpoint is unreachable or the bucket does not exist.

**Confirmed cause.** The bucket could not be reached. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The object store service is down
2. PATHOS_S3_ENDPOINT or PATHOS_S3_BUCKET is wrong
3. The bucket was deleted

**Impact.** Scan artifacts and source snapshots cannot be stored or read.

**How to fix**

1. Check the object store service and PATHOS_S3_ENDPOINT / PATHOS_S3_BUCKET.
2. Restart the api and jobs services once it is back (the bucket is created at start-up).

**Verify**

1. Run the connector's health check; the bucket answers.


<a id="PTH-CONN-1431"></a>

## PTH-CONN-1431: Object store access denied

| | |
|---|---|
| Severity | critical |
| Category | authorization |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkObjectStore) |

**What it means.** The object store refused the configured access key (HTTP 401 or 403 on HeadBucket).

**Confirmed cause.** The object store denied the credential. Confirmed automatically when this code is raised.

**Probable causes**

1. PATHOS_S3_ACCESS_KEY or PATHOS_S3_SECRET_KEY is wrong or was rotated
2. A bucket policy denies the key

**Impact.** Scan artifacts and source snapshots cannot be stored or read.

**How to fix**

1. Set the correct keys in the environment of the api and jobs services and restart them.
2. Check the bucket policy grants the key read and write.

**Verify**

1. Run the connector's health check; the bucket answers.


<a id="PTH-CONN-1502"></a>

## PTH-CONN-1502: Docker Hub pull limit reached

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkRegistry) |

**What it means.** Docker Hub reports no pulls left in the current window (ratelimit-remaining 0) or answered 429.

**Confirmed cause.** Docker Hub's pull limit for this account or address is used up. Confirmed automatically when this code is raised.

**Probable causes**

1. Anonymous pulls share the limit of the public address
2. Many scans pull the same images

**Impact.** Registry inventory and image reads fail until the window resets.

**How to fix**

1. Use a Docker Hub account (a personal access token with read-only scope) on the registry connection.
2. Pull through an internal mirror.

**Verify**

1. Run the connector's health check after the reset; it passes.


<a id="PTH-CONN-1512"></a>

## PTH-CONN-1512: Role does not grant a resource kind

| | |
|---|---|
| Severity | warning |
| Category | authorization |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkCluster) |

**What it means.** The cluster role PATHOS uses cannot list some resource kinds the inventory reads (403 or 404); the inventory is partial.

**Confirmed cause.** Some resource kinds are not readable with the credential. Confirmed automatically when this code is raised.

**Probable causes**

1. The ClusterRole is older than the shipped one
2. A namespace-limited RoleBinding

**Impact.** Workloads of the missing kinds are absent from the runtime inventory.

**How to fix**

1. Apply deploy/kubernetes/pathos-reader-clusterrole.yaml again, or bind it in the namespaces PATHOS reads.

**Verify**

1. Run the connector's health check; every kind is readable.


<a id="PTH-CONN-1513"></a>

## PTH-CONN-1513: Kubernetes version out of upstream support

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkCluster) |

**What it means.** The API server reports a Kubernetes release older than the oldest upstream-supported minor release.

**Confirmed cause.** The server version is older than the supported releases. Confirmed automatically when this code is raised.

**Probable causes**

1. The cluster was not upgraded

**Impact.** PATHOS still reads the cluster, but it is not tested against unsupported releases and the cluster gets no security fixes.

**How to fix**

1. Upgrade the cluster to a supported release (https://kubernetes.io/releases/).

**Verify**

1. Run the connector's health check; the version step passes.


<a id="PTH-CONN-1514"></a>

## PTH-CONN-1514: Long-lived service-account token in use

| | |
|---|---|
| Severity | info |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkCluster) |

**What it means.** The cluster connection uses a bearer token whose expiry PATHOS cannot see; the shipped manifest creates a long-lived service-account token Secret, which Kubernetes does not recommend for external clients.

**Confirmed cause.** The connection uses a static token credential. Confirmed automatically when this code is raised.

**Probable causes**

1. The connection uses the token from deploy/kubernetes/pathos-reader-clusterrole.yaml

**Impact.** Nothing fails; a leaked token stays valid until it is deleted.

**How to fix**

1. Rotate the token regularly (delete and recreate the Secret, then update the connection), or use a bound token with an expiry.

**Verify**

1. Not applicable (advice).


<a id="PTH-CONN-1531"></a>

## PTH-CONN-1531: Egress proxy not reachable

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/connectors/existing.go (checkEgress) |

**What it means.** The jobs service could not reach the egress proxy that scanners use for internet access (PATHOS_EGRESS_PROXY_URL).

**Confirmed cause.** The egress proxy did not accept a connection or did not answer HTTP. Confirmed automatically when this code is raised.

**Probable causes**

1. The egress service is stopped or unhealthy
2. PATHOS_EGRESS_PROXY_URL is wrong

**Impact.** Scanners that need the internet (vulnerability databases, live secret validation, DAST) fail.

**How to fix**

1. Check the egress service (docker compose ps egress) and its logs.
2. Correct PATHOS_EGRESS_PROXY_URL (default http://egress:3128).

**Verify**

1. Run the connector's health check; the proxy answers.


<a id="PTH-CONN-1532"></a>

## PTH-CONN-1532: Secret validation provider cannot be checked

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/connectors/existing.go (checkSecretValidation) |

**What it means.** An enabled secret validation provider is unknown to this version or is recognised but never checked live.

**Confirmed cause.** The configuration lists a provider PATHOS does not check. Confirmed automatically when this code is raised.

**Probable causes**

1. A provider removed in this version
2. A recognised-only provider (for example PyPI) was enabled

**Impact.** Findings of that provider stay not checked.

**How to fix**

1. Review the providers on Configurations → Secret validation.

**Verify**

1. Run the connector's health check; the configuration step passes.


<a id="PTH-CONN-1601"></a>

## PTH-CONN-1601: Vault AppRole login refused

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrSecretIDInvalid) |

**What it means.** Vault or OpenBao refused the AppRole login: the secret ID expired, was used up, is bound to other addresses, or the role ID is wrong.

**Confirmed cause.** The AppRole login was refused. Confirmed automatically when this code is raised.

**Probable causes**

1. secret_id_ttl or secret_id_num_uses reached
2. secret_id_bound_cidrs does not include the PATHOS api/jobs addresses
3. The role was recreated (new role ID)

**Impact.** Every credential stored as a vault: reference fails to resolve; the connectors that use them fail.

**How to fix**

1. Generate a new secret ID for the PATHOS role.
2. Replace it on the Vault/OpenBao connector.
3. Check the role's CIDR bindings.

**Verify**

1. Run the Vault connector's health check; login passes.


<a id="PTH-CONN-1602"></a>

## PTH-CONN-1602: Vault policy denies the path

| | |
|---|---|
| Severity | error |
| Category | authorization |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrPermissionDenied) |

**What it means.** The Vault token PATHOS obtained may not read the referenced KV path (HTTP 403).

**Confirmed cause.** Vault refused the read for this path. Confirmed automatically when this code is raised.

**Probable causes**

1. The policy grants read on another prefix
2. The policy targets <mount>/<path> instead of <mount>/data/<path> (KV version 2)

**Impact.** The connector that uses this reference fails.

**How to fix**

1. Grant read on <mount>/data/<prefix>/* to the PATHOS role's policy.
2. Or move the secret under the allowed prefix and update the reference.

**Verify**

1. Run the health check of the connector that uses the reference.


<a id="PTH-CONN-1603"></a>

## PTH-CONN-1603: Vault namespace not found

| | |
|---|---|
| Severity | error |
| Category | configuration |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrNamespace) |

**What it means.** The namespace configured on the Vault connector (X-Vault-Namespace, Vault Enterprise and HCP only) does not exist.

**Confirmed cause.** Vault reports the namespace as unknown. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A typing error in the namespace
2. Open-source Vault or OpenBao without namespaces

**Impact.** No reference can be resolved.

**How to fix**

1. Correct the namespace, or clear it for servers without namespaces.

**Verify**

1. Run the Vault connector's health check.


<a id="PTH-CONN-1604"></a>

## PTH-CONN-1604: Vault is sealed

| | |
|---|---|
| Severity | critical |
| Category | availability |
| HTTP status | 503 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrSealed) |

**What it means.** GET /v1/sys/health answered 503 (sealed) or 501 (not initialized).

**Confirmed cause.** Vault reports itself sealed or not initialized. Confirmed automatically when this code is raised.

**Probable causes**

1. Vault restarted and was not unsealed
2. Auto-unseal lost access to its key

**Impact.** No reference can be resolved: every connector whose credential is a vault: reference fails.

**How to fix**

1. Unseal Vault (or fix auto-unseal).
2. Run the health checks again.

**Verify**

1. The Vault connector's health check passes.


<a id="PTH-CONN-1605"></a>

## PTH-CONN-1605: Kubernetes auth role does not match the service account

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrKubernetesRole) |

**What it means.** The Kubernetes auth login was refused: the role's bound_service_account_names or bound_service_account_namespaces do not include the PATHOS pod's service account, or no service account token is mounted.

**Confirmed cause.** Vault refused the Kubernetes login, or the token file is missing. Confirmed automatically when this code is raised.

**Probable causes**

1. PATHOS runs under another service account or namespace
2. PATHOS does not run in Kubernetes (use AppRole)
3. automountServiceAccountToken is false

**Impact.** No reference can be resolved.

**How to fix**

1. Bind the role to the PATHOS service account and namespace.
2. Or switch the connector to AppRole.

**Verify**

1. Run the Vault connector's health check; login passes.


<a id="PTH-CONN-1606"></a>

## PTH-CONN-1606: Referenced secret or key not found

| | |
|---|---|
| Severity | error |
| Category | not-found |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrSecretNotFound) |

**What it means.** The KV version 2 secret of a vault: reference does not exist, or has no field with the referenced key (or the field is not a string).

**Confirmed cause.** Vault has no such secret or key. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The secret was moved or deleted
2. A typing error in the reference
3. The key name differs (references are case-sensitive)

**Impact.** The connector that uses the reference fails.

**How to fix**

1. Check the secret in Vault (vault kv get <mount>/<path>).
2. Correct the reference: vault:<mount>/<path>#<key>.

**Verify**

1. Run the health check of the connector that uses the reference.


<a id="PTH-CONN-1607"></a>

## PTH-CONN-1607: Reference outside the allowed Vault path prefix

| | |
|---|---|
| Severity | error |
| Category | security |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrRefOutsidePrefix) |

**What it means.** A vault: reference points outside the path prefix configured on the Vault/OpenBao connector; PATHOS refuses it before contacting Vault.

**Confirmed cause.** The reference is outside the allowed prefix. Confirmed automatically when this code is raised.

**Probable causes**

1. A reference to another team's secrets
2. The prefix on the connector is too narrow

**Impact.** The reference is not resolved.

**How to fix**

1. Move the secret under the allowed prefix, or ask an administrator to widen the prefix if appropriate.

**Verify**

1. Run the health check of the connector that uses the reference.


<a id="PTH-CONN-1608"></a>

## PTH-CONN-1608: No Vault/OpenBao connection for secret references

| | |
|---|---|
| Severity | error |
| Category | configuration |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/vault/vault.go (ErrNotConfigured), internal/secrets/store.go (ErrRefUnavailable) |

**What it means.** A credential is stored as a vault: reference, but the organization has no enabled Vault/OpenBao connector to resolve it.

**Confirmed cause.** No Vault/OpenBao connector is configured for the organization. Confirmed automatically when this code is raised.

**Probable causes**

1. The Vault connector was deleted or disabled
2. The connectors feature is off

**Impact.** Every connector whose credential is a reference fails.

**How to fix**

1. Create or enable the Vault/OpenBao connector (Connectors → IAM & Secrets).
2. Or replace the reference with the secret value.

**Verify**

1. Run the health check of the connector that uses the reference.

