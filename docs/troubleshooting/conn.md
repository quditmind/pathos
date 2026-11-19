---
title: Troubleshooting: Connections
section: troubleshooting
order: 103
version: "1.0"
updated: 2026-11-20
summary: SCM providers, ticketing, e-mail, outbound webhooks and inbound webhooks: reachability, certificates, credentials, scopes and rate limits (14 codes, PTH-CONN-*)
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
| [PTH-CONN-1007](#PTH-CONN-1007) | Provider rejected the credential | error |
| [PTH-CONN-1008](#PTH-CONN-1008) | Provider authorization expired | error |
| [PTH-CONN-1009](#PTH-CONN-1009) | Credential lacks a permission or scope | error |
| [PTH-CONN-1010](#PTH-CONN-1010) | Rate limited by the provider | warning |
| [PTH-CONN-1011](#PTH-CONN-1011) | Not found at the provider | warning |
| [PTH-CONN-1012](#PTH-CONN-1012) | Provider error | error |
| [PTH-CONN-1017](#PTH-CONN-1017) | Inbound webhook signature invalid | warning |
| [PTH-CONN-1020](#PTH-CONN-1020) | Not supported by this provider | info |
| [PTH-CONN-1250](#PTH-CONN-1250) | Ticket could not be created | error |
| [PTH-CONN-1325](#PTH-CONN-1325) | E-mail delivery failed | error |

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

1. A private certificate authority not installed in the API image
2. A TLS-inspecting proxy
3. An expired certificate or a host name mismatch

**Impact.** No request reaches the provider.

**How to fix**

1. Install the private CA in the trust store of the api and jobs containers.
2. Renew the provider's certificate if it expired.
3. Use the provider's exact host name in the base URL.

**Verify**

1. Test connection succeeds.


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

