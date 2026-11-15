# Security Model (Phase 1)

This page describes the controls implemented so far. For the overall design (worker isolation, AI data handling), see ARCHITECTURE.md.

## Authentication

- **Backend-for-frontend OIDC.** The API runs Authorization Code + PKCE (S256) against Keycloak as a confidential client. `state` is single-use (stored in Valkey) and bound to the browser by an HttpOnly cookie. `nonce` is checked. ID tokens are verified (signature, issuer, audience, expiry) with go-oidc.
- **Sessions.** The browser holds only an opaque 256-bit token in `__Host-pathos_session` (HttpOnly, Secure, SameSite=Lax, Path=/). Valkey stores the session under the token's **SHA-256**, so a dump of the store does not yield usable cookies. Idle timeout 8h (sliding) and absolute timeout 24h are configurable. A new session is issued at every login.
- **Logout** deletes the PATHOS session and sends the browser to Keycloak's end-session endpoint with `id_token_hint`.
- **Deactivation** deletes every session of the user at once, disables the Keycloak account and logs it out of Keycloak. Every request re-checks the user's status in PostgreSQL, so even a session that somehow survives is rejected.
- **Keycloak realm policy:** minimum 12 characters, not username or email, last 5 passwords remembered, brute-force lockout after 5 failures, self-registration off. The bootstrap administrator must change the generated password at first login.
- **JIT provisioning.** A login links to an invited PATHOS user only if Keycloak asserts `email_verified`. The bootstrap `super_admin` grant also requires a verified email, applies only while no active super admin exists, and is serialized with an advisory lock.

## CSRF and request hygiene

- Unsafe methods need `X-CSRF-Token` (a per-session synchronizer token, constant-time compare). If an `Origin` header is present, it must equal the public origin.
- JSON bodies are size-limited (1 MiB). Unknown fields and trailing data are rejected.
- `return_to` after login accepts only same-origin relative paths (open-redirect protection).
- Internal errors return a generic message plus `request_id`. Details go only to the logs.

## Authorization

Scoped RBAC is enforced in the API; see [RBAC_MATRIX.md](RBAC_MATRIX.md). Privilege-escalation checks apply to both granting and revoking roles. Every denial is audited.

## Secrets at rest

- AES-256-GCM envelope encryption (`internal/platform/crypto`, `internal/secrets`). Each secret gets a fresh data key, which is wrapped by the versioned master key.
- Both layers authenticate `pathos:secret:<kind>:<id>` as associated data. A ciphertext copied to another row, or relabelled as another kind (e.g. an SCM token presented as an AI key), fails to decrypt.
- **Master key rotation:**
  1. Generate a key: `docker compose run --rm --entrypoint pathosctl migrate gen-key`.
  2. In `.env`, set `PATHOS_MASTER_KEY=v2:<new>` and `PATHOS_MASTER_KEYS_PREVIOUS=v1:<old>`.
  3. Run `docker compose run --rm --entrypoint pathosctl migrate rotate-master-key`. Only the data keys are rewrapped, in one transaction.
  4. Remove the old key from `PATHOS_MASTER_KEYS_PREVIOUS` and run `docker compose up -d`.

## Database privileges

- `pathos_owner` owns the schema and runs migrations. The API and jobs connect as **`pathos_app`**, which:
  - cannot create objects;
  - cannot `UPDATE`, `DELETE` or `TRUNCATE` the audit log, its default partition or any monthly partition;
  - cannot modify the permission catalog or migration history.
- Integration tests assert each of these denials (`backend/test/integration`).

## Audit log

Append-only and partitioned monthly. Records sign-ins (including denied ones), invitations, provisioning results, role grants and revocations, (de)activation, business-unit changes and authorization denials. Each entry carries actor, IP (the rightmost `X-Forwarded-For` hop set by Caddy, which discards client-supplied values), user agent and request ID.

## Transport and headers

- Caddy terminates TLS (internal CA by default; ACME when `CADDY_TLS` is an email address) and sends HSTS, `nosniff`, a strict `Referrer-Policy` and a `Permissions-Policy`.
- The UI is served with a CSP that allows no inline scripts and only same-origin connections (`script-src 'self'; connect-src 'self'; frame-ancestors 'none'`).
- API responses add `Cache-Control: no-store` and `default-src 'none'`.
- `/healthz` and `/readyz` are not exposed through the proxy.

## Containers

The API, jobs and migrate containers use a distroless static image as non-root UID 65532, with a read-only root filesystem, `cap_drop: ALL` and `no-new-privileges`. Valkey gets its password over stdin, never in process arguments. All images are pinned by digest.

## Logging

slog JSON with redaction of sensitive keys (password, secret, token, cookie, authorization, …) and of token-shaped values (JWTs, bearer tokens, GitHub/Anthropic/OpenAI/xAI/AWS keys, private-key headers, credentials in URLs), including inside error strings.

## SCM integration (Phase 3)

- **Credentials:** PATs and GitHub App private keys are envelope-encrypted (kind `scm`). They are write-only in the API: never returned, never logged, and wiped when a connection is deleted. GitHub Apps are preferred, because PATHOS only ever holds installation tokens that expire within an hour.
- **SSRF protection:** SCM base URLs are administrator input.
  - Outbound requests use a dialer that checks the *resolved* IP at connect time, which defeats DNS rebinding.
  - Loopback, link-local and cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are always refused, as are CGNAT, multicast and reserved ranges.
  - RFC 1918 / ULA ranges are refused unless `PATHOS_SCM_ALLOW_PRIVATE_NETWORKS=true` (needed for self-hosted GitHub Enterprise or Azure DevOps Server).
  - Only `https` is accepted (`http` only in development). Redirects to other hosts and pagination links to other hosts are not followed.
- **Webhooks:** `/api/webhooks/*` are unauthenticated endpoints that require proof of origin:
  - GitHub: HMAC-SHA256 `X-Hub-Signature-256` over the raw body, constant-time compared.
  - Azure DevOps: basic-auth password equal to the webhook secret.
  - Secrets are per connection, random 256-bit, rotatable and shown once.
  - Bodies are capped at 5 MB. Deliveries are de-duplicated by delivery ID, so replays are ignored, and rejected deliveries are audited (`webhook.rejected`).
- **Authorization:** repository access follows the scope hierarchy (repository → business unit chain → region of its country → organization).
  - Moving a repository needs `repos.manage` at both the source and the destination.
  - Out-of-scope repositories return 404, not 403, so their existence is not disclosed.
- **Input hygiene:** scan branches are validated as git ref names and cannot start with `-` (option injection when workers clone in Phase 4). CSV **export** in the UI prefixes formula-leading cells (`= + - @`) to prevent spreadsheet formula injection.

## Known gaps (tracked)

- The Keycloak admin console is reachable at `/auth/admin` through the proxy. Production overrides that restrict it by network arrive in Phase 8.
- MFA is available in Keycloak but not enforced by default. Enforce it per realm in the Keycloak admin console.
- Rate limiting on PATHOS endpoints is not implemented yet. Keycloak's brute-force protection covers credential guessing.
- Personal API tokens (needed for the MCP server) arrive in Phase 5.
