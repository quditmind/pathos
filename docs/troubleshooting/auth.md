---
title: Troubleshooting: Authentication and access
section: troubleshooting
order: 102
version: "1.0"
updated: 2026-11-20
summary: Sign-in, sessions, CSRF, API tokens, permissions, organizations and the identity provider (19 codes, PTH-AUTH-*)
---

# Troubleshooting: Authentication and access

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Sign-in, sessions, CSRF, API tokens, permissions, organizations and the identity provider.

| Code | Title | Severity |
|---|---|---|
| [PTH-AUTH-1001](#PTH-AUTH-1001) | Sign-in required | info |
| [PTH-AUTH-1002](#PTH-AUTH-1002) | Permission denied | info |
| [PTH-AUTH-1003](#PTH-AUTH-1003) | Missing or invalid CSRF token | warning |
| [PTH-AUTH-1004](#PTH-AUTH-1004) | API token invalid, expired or revoked | warning |
| [PTH-AUTH-1005](#PTH-AUTH-1005) | API tokens cannot be used for this endpoint | info |
| [PTH-AUTH-1006](#PTH-AUTH-1006) | API token is read-only | info |
| [PTH-AUTH-1007](#PTH-AUTH-1007) | Organization suspended | warning |
| [PTH-AUTH-1008](#PTH-AUTH-1008) | Browser session required | info |
| [PTH-AUTH-1009](#PTH-AUTH-1009) | Identity provider unreachable | critical |
| [PTH-AUTH-1010](#PTH-AUTH-1010) | Identity provider administration failed | error |
| [PTH-AUTH-1011](#PTH-AUTH-1011) | MFA management unavailable | warning |
| [PTH-AUTH-1012](#PTH-AUTH-1012) | Four-eyes rule: another person must approve | info |
| [PTH-AUTH-1013](#PTH-AUTH-1013) | Account deactivated | warning |
| [PTH-AUTH-1014](#PTH-AUTH-1014) | Identity provider returned an error at sign-in | warning |
| [PTH-AUTH-1015](#PTH-AUTH-1015) | Sign-in could not be verified | warning |
| [PTH-AUTH-1016](#PTH-AUTH-1016) | Sign-in token exchange or validation failed | error |
| [PTH-AUTH-1017](#PTH-AUTH-1017) | No organization membership | warning |
| [PTH-AUTH-1018](#PTH-AUTH-1018) | Account provisioning failed | error |
| [PTH-AUTH-1019](#PTH-AUTH-1019) | Shared identity account | info |

<a id="PTH-AUTH-1001"></a>

## PTH-AUTH-1001: Sign-in required

| | |
|---|---|
| Severity | info |
| Category | authentication |
| HTTP status | 401 |
| AI help | not offered |
| Short codes | `unauthenticated` |
| Raised in | internal/auth/oidc.go (RequireAuth), internal/scans/worker_api.go |

**What it means.** The request has no valid session or API token.

**Confirmed cause.** No valid session or API token was presented. Confirmed automatically when this code is raised.

**Probable causes**

1. The session expired or was signed out
2. A script did not send the Authorization header

**Impact.** Nothing was read or changed.

**How to fix**

1. Sign in again.
2. For scripts, send `Authorization: Bearer <token>` with a valid API token.

**Verify**

1. GET /api/v1/me answers 200.


<a id="PTH-AUTH-1002"></a>

## PTH-AUTH-1002: Permission denied

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `forbidden` |
| Raised in | internal/platform/httpx/httpx.go (ErrForbidden), internal/authz |

**What it means.** Your roles do not grant the permission this action needs at this scope.

**Confirmed cause.** None of your role assignments grants the required permission here. Confirmed automatically when this code is raised.

**Probable causes**

1. The role is scoped to another business unit or region
2. The permission is organization-only and your role is scoped narrower

**Impact.** Nothing was changed.

**How to fix**

1. Ask an administrator for a role with the permission (docs/RBAC_MATRIX.md lists them).

**Verify**

1. After the role is granted, sign out and in; the action succeeds.


<a id="PTH-AUTH-1003"></a>

## PTH-AUTH-1003: Missing or invalid CSRF token

| | |
|---|---|
| Severity | warning |
| Category | authentication |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `csrf_failed` |
| Raised in | internal/auth/oidc.go |

**What it means.** A state-changing browser request must carry the session's X-CSRF-Token header.

**Confirmed cause.** The X-CSRF-Token header is missing or does not match the session. Confirmed automatically when this code is raised.

**Probable causes**

1. The page was open across a sign-in in another tab
2. A browser extension or proxy strips headers

**Impact.** Nothing was changed.

**How to fix**

1. Reload the page and repeat the action.
2. Sign out and in if it persists.

**Verify**

1. The action succeeds after reloading.


<a id="PTH-AUTH-1004"></a>

## PTH-AUTH-1004: API token invalid, expired or revoked

| | |
|---|---|
| Severity | warning |
| Category | authentication |
| HTTP status | 401 |
| AI help | not offered |
| Short codes | `invalid_token` |
| Raised in | internal/auth/oidc.go (token authentication) |

**What it means.** The bearer token does not match an active personal API token.

**Confirmed cause.** The API token is unknown, expired or revoked. Confirmed automatically when this code is raised.

**Probable causes**

1. The token expired
2. The token was revoked or its owner deactivated
3. A truncated or wrong secret in the CI variable

**Impact.** CLI, CI, IDE and MCP calls with this token fail.

**How to fix**

1. Create a new token (Profile → API tokens) and update the CI secret or IDE setting.

**Verify**

1. `pathos findings --limit 1` succeeds with the new token.


<a id="PTH-AUTH-1005"></a>

## PTH-AUTH-1005: API tokens cannot be used for this endpoint

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `token_not_allowed` |
| Raised in | internal/auth/oidc.go |

**What it means.** Some endpoints (account security, installation administration) need a browser session.

**Confirmed cause.** This endpoint refuses API tokens. Confirmed automatically when this code is raised.

**Probable causes**

1. A script calls an interactive-only endpoint

**Impact.** Nothing was changed.

**How to fix**

1. Use the web interface for this action.

**Verify**

1. The action succeeds from the browser.


<a id="PTH-AUTH-1006"></a>

## PTH-AUTH-1006: API token is read-only

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `token_read_only` |
| Raised in | internal/auth/oidc.go |

**What it means.** The token has only the api:read scope; this request changes data.

**Confirmed cause.** The token lacks the api:write scope. Confirmed automatically when this code is raised.

**Probable causes**

1. The token was created read-only

**Impact.** Nothing was changed.

**How to fix**

1. Create a token with api:write for pipelines that import results or start scans.

**Verify**

1. The import or scan starts with the new token.


<a id="PTH-AUTH-1007"></a>

## PTH-AUTH-1007: Organization suspended

| | |
|---|---|
| Severity | warning |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `organization_suspended` |
| Raised in | internal/auth/oidc.go, internal/scans/worker_api.go |

**What it means.** The installation administrator suspended this organization; its users, tokens and workers are refused.

**Confirmed cause.** Your organization is suspended. Confirmed automatically when this code is raised.

**Probable causes**

1. An installation administrator suspended the organization

**Impact.** Nobody in the organization can use PATHOS until it is reactivated; data is kept.

**How to fix**

1. Switch to another organization if you belong to one.
2. Contact the installation administrator.

**Verify**

1. After reactivation, the dashboard loads.


<a id="PTH-AUTH-1008"></a>

## PTH-AUTH-1008: Browser session required

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `session_required` |
| Raised in | internal/auth/organizations.go |

**What it means.** Switching organization needs a browser session, not an API token.

**Confirmed cause.** The request was authenticated with an API token. Confirmed automatically when this code is raised.

**Probable causes**

1. A script tried to switch organization

**Impact.** Nothing was changed.

**How to fix**

1. Switch organization in the web interface; tokens are bound to one organization.

**Verify**

1. The organization switcher shows the new organization.


<a id="PTH-AUTH-1009"></a>

## PTH-AUTH-1009: Identity provider unreachable

| | |
|---|---|
| Severity | critical |
| Category | connectivity |
| HTTP status | 503 |
| AI help | offered |
| Short codes | `idp_unavailable`, `login:idp_unavailable` |
| Raised in | internal/auth/oidc.go (HandleLogin, HandleCallback) |

**What it means.** PATHOS could not load the OIDC discovery document of the identity provider (Keycloak).

**Confirmed cause.** The identity provider did not answer. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The keycloak container is starting or stopped
2. PATHOS_OIDC_ISSUER is wrong
3. A TLS or DNS problem between the API and the provider

**Impact.** Nobody can sign in. Existing sessions keep working.

**How to fix**

1. Check `docker compose ps keycloak` and its log.
2. Check PATHOS_OIDC_ISSUER resolves from the api container.

**Verify**

1. Open /api/auth/login; it redirects to the sign-in page.


<a id="PTH-AUTH-1010"></a>

## PTH-AUTH-1010: Identity provider administration failed

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `idp_error` |
| Raised in | internal/identity/http.go |

**What it means.** A Keycloak admin API call (MFA status, reset or recovery) failed.

**Confirmed cause.** The identity provider's admin API returned an error. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The PATHOS service client lost its admin roles in Keycloak
2. Keycloak is restarting

**Impact.** MFA management for users is unavailable; sign-in is unaffected.

**How to fix**

1. Check the Keycloak log for the request time.
2. Check the pathos-admin client's service-account roles (docs/user-guide/sign-in-and-sso.md).

**Verify**

1. Open a user's MFA panel; the status loads.


<a id="PTH-AUTH-1011"></a>

## PTH-AUTH-1011: MFA management unavailable

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `mfa_unavailable` |
| Raised in | internal/identity/http.go |

**What it means.** MFA management needs the Keycloak admin integration, or the user is not linked to the identity provider yet.

**Confirmed cause.** MFA cannot be managed for this account here. Confirmed automatically when this code is raised.

**Probable causes**

1. The Keycloak admin client is not configured
2. The user has never signed in (no identity link)

**Impact.** MFA cannot be reset from PATHOS.

**How to fix**

1. Configure the admin client, or ask the user to sign in once.

**Verify**

1. The MFA panel shows the user's status.


<a id="PTH-AUTH-1012"></a>

## PTH-AUTH-1012: Four-eyes rule: another person must approve

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `four_eyes` |
| Raised in | internal/releases/vexapi.go |

**What it means.** The person who proposed a change cannot also approve it.

**Confirmed cause.** You proposed this item, so you cannot approve it. Confirmed automatically when this code is raised.

**Probable causes**

1. Self-approval is not allowed for this decision

**Impact.** The item stays pending.

**How to fix**

1. Ask a colleague with the approval permission to decide.

**Verify**

1. The item shows the colleague's approval.


<a id="PTH-AUTH-1013"></a>

## PTH-AUTH-1013: Account deactivated

| | |
|---|---|
| Severity | warning |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `login:deactivated` |
| Raised in | internal/auth/oidc.go (HandleCallback), internal/identity |

**What it means.** The PATHOS account linked to this identity is deactivated, so sign-in is refused.

**Confirmed cause.** Your PATHOS account is deactivated. Confirmed automatically when this code is raised.

**Probable causes**

1. An administrator deactivated the account

**Impact.** You cannot sign in to this organization.

**How to fix**

1. Ask an administrator to reactivate the account (Administration → Users).

**Verify**

1. Sign-in succeeds.


<a id="PTH-AUTH-1014"></a>

## PTH-AUTH-1014: Identity provider returned an error at sign-in

| | |
|---|---|
| Severity | warning |
| Category | provider |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Short codes | `login:idp_error` |
| Raised in | internal/auth/oidc.go (HandleCallback) |

**What it means.** The identity provider redirected back with an OAuth error instead of an authorization code.

**Confirmed cause.** The identity provider reported an error for this sign-in. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. Sign-in was cancelled
2. The PATHOS client in the provider is disabled or misconfigured (redirect URI)
3. An external identity provider refused the user

**Impact.** Sign-in did not complete.

**How to fix**

1. Try signing in again.
2. An administrator checks the Keycloak event log and the client's redirect URI (PATHOS_PUBLIC_URL/api/auth/callback).

**Verify**

1. Sign-in completes.


<a id="PTH-AUTH-1015"></a>

## PTH-AUTH-1015: Sign-in could not be verified

| | |
|---|---|
| Severity | warning |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `login:invalid_state`, `login:expired` |
| Raised in | internal/auth/oidc.go (HandleCallback) |

**What it means.** The sign-in callback did not match the flow started by this browser (state or flow cookie), or the flow expired.

**Confirmed cause.** The callback does not belong to a sign-in started in this browser, or it expired. Confirmed automatically when this code is raised.

**Probable causes**

1. The sign-in page was left open too long
2. Cookies are blocked for this site
3. The sign-in link was opened in another browser

**Impact.** Sign-in did not complete.

**How to fix**

1. Start sign-in again from the PATHOS login page.
2. Allow cookies for the PATHOS site.

**Verify**

1. Sign-in completes.


<a id="PTH-AUTH-1016"></a>

## PTH-AUTH-1016: Sign-in token exchange or validation failed

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Short codes | `login:exchange_failed`, `login:invalid_token` |
| Raised in | internal/auth/oidc.go (HandleCallback) |

**What it means.** Exchanging the authorization code, or validating the returned ID token, failed.

**Confirmed cause.** The identity provider's tokens could not be obtained or verified. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The client secret (PATHOS_OIDC_CLIENT_SECRET) does not match the provider
2. Clock skew between the API host and the provider
3. The issuer URL differs between browser and server

**Impact.** Nobody can complete sign-in while this persists.

**How to fix**

1. Compare PATHOS_OIDC_CLIENT_SECRET with the client's secret in Keycloak.
2. Check NTP on the hosts.
3. Check PATHOS_OIDC_ISSUER matches the issuer in the tokens.

**Verify**

1. Sign-in completes.


<a id="PTH-AUTH-1017"></a>

## PTH-AUTH-1017: No organization membership

| | |
|---|---|
| Severity | warning |
| Category | authorization |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `login:no_organization` |
| Raised in | internal/auth/oidc.go (provisionIn) |

**What it means.** The identity is valid but has no active membership in any organization (with multi-tenancy, organization groups decide membership).

**Confirmed cause.** Your identity is not a member of any active organization. Confirmed automatically when this code is raised.

**Probable causes**

1. You were not invited
2. The identity provider group for the organization is missing
3. Your email is not verified

**Impact.** You cannot sign in.

**How to fix**

1. Ask an administrator to invite you or add the organization group in the identity provider.

**Verify**

1. Sign-in completes and the organization is listed.


<a id="PTH-AUTH-1018"></a>

## PTH-AUTH-1018: Account provisioning failed

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Short codes | `login:provisioning_failed` |
| Raised in | internal/auth/oidc.go (HandleCallback) |

**What it means.** Creating or linking the PATHOS account during sign-in failed.

**Confirmed cause.** The account could not be created or linked. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The email is already linked to another identity
2. A database error during provisioning

**Impact.** You cannot sign in.

**How to fix**

1. Retry sign-in.
2. An administrator checks the API log ("login rejected") for the time of the attempt.

**Verify**

1. Sign-in completes.


<a id="PTH-AUTH-1019"></a>

## PTH-AUTH-1019: Shared identity account

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `shared_account` |
| Raised in | internal/identity/http.go |

**What it means.** The person also belongs to another organization of this installation, so their Keycloak account is shared; one organization does not change its MFA or recovery codes.

**Confirmed cause.** The person has a membership in another organization. Confirmed automatically when this code is raised.

**Probable causes**

1. Multi-tenancy is on and the person was invited by more than one organization

**Impact.** MFA and recovery-code requirements cannot be set from this organization; the MFA status can still be read.

**How to fix**

1. Ask the person to manage MFA and recovery codes themselves (account settings at sign-in), or ask an installation administrator.

**Verify**

1. The person's MFA panel shows the status they set.

