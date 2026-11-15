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

## Scanning (Phase 4)

- **Trust boundary:** repository content is untrusted. Workers run in separate containers on two internal networks: `scan`, which reaches only the egress proxy, and `worker-api`, which reaches only the API's worker listener.
  - Workers never reach PostgreSQL, Valkey, Keycloak or the user API, and never hold platform secrets.
  - The worker container runs non-root with a read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, a tmpfs workspace, and memory and PID limits.
- **Worker identity:** `PATHOS_WORKER_BOOTSTRAP_TOKEN` only registers a worker; each registration gets a fresh random token, stored as SHA-256. Revoking a worker invalidates its token immediately, and the name cannot re-register until an administrator deletes the record. The bootstrap token is removed from the agent's environment before any scanner runs, and scanners get a scrubbed environment.
- **Clone hardening:**
  - The credential travels in `GIT_CONFIG_*` environment variables (an HTTP header), never in argv, the URL or `.git/config`.
  - Hooks are disabled, `file://` and `ext::` transports are forbidden, symlinks are not checked out, objects are fsck'd, redirects are not followed, refs are validated against option injection, and repository size is capped.
  - `.git` is deleted before scanners run, and the workspace is removed after every job.
  - Repository code is never built or executed.
- **Process control:** each tool runs in its own process group; on timeout or cancellation the whole group is killed. Tool output and stderr captures are size-limited, and credentials in error text are redacted.
- **Egress:** Squid allows only the domains in `deploy/egress/allowlist.txt`. It denies RFC 1918, loopback, link-local/metadata, CGNAT and multicast destinations whatever DNS returns, strips `Via`/`X-Forwarded-For`, and logs every request to the `egress_logs` volume.
- **Ingestion:**
  - Uploads are size-limited (96 MB request, 256 MB decompressed, zip-bomb safe) and accepted only from the worker holding the job's lease, once per scanner.
  - Parsing happens in the API, not the worker. Secret values are never stored: Gitleaks runs with `--redact`, and finding text passes through the log redactor.
  - Raw reports are downloadable only with `scans.read` on the repository.
- **Integrity:** every scan records the immutable profile version and the scanner versions it ran with.

## AI review and MCP (Phase 5)

- **No subscription credentials:** automated reviews use provider API keys only. Claude subscriptions are used solely by a person's own assistant through the MCP server (ARCHITECTURE §6).
- **Data minimization:** evidence is the finding metadata plus at most ±5 lines of code. It passes through redaction three times (worker capture → ingest → prompt), using built-in secret patterns plus organization patterns. Secret findings never include code. The SHA-256 of every transmitted request is stored with the review.
- **Prompt injection:** evidence is JSON-encoded inside a delimiter carrying a random per-request nonce; the system prompt forbids following embedded instructions. Provider output must match a strict schema, and unknown fields are rejected, so a model cannot introduce actions.
- **Guardrails:** AI never closes a Critical finding and never overrides a human decision. Approval policy is per configuration, with four-eyes for interactive reviews and a written justification for closing Critical findings.
- **MCP:** personal tokens are random 256-bit values, stored hashed with the prefix `pathos_pat_` (recognisable by secret scanners), limited to 90 days, revocable, and scoped to the MCP endpoint only. They carry the owner's live permissions. Every tool call is audited (`mcp.tool_call`). The registry can disable the server or individual tools at once.

## Vulnerability management (Phase 6)

- **Tamper-evident lifecycle:** status history is written by a database trigger, not application code. The app role has no UPDATE/DELETE/TRUNCATE on `finding_status_history`.
- **Separation of duties:** risk acceptances need an approver other than the requester, enforced both in the service and by a CHECK constraint. Acceptances are capped at 365 days and expire automatically. Closing a Critical finding as a false positive requires `findings.accept_risk`.
- **Scope:** every triage, bulk and SBOM query is filtered by the caller's scoped permissions. A bulk action fails as a whole if any finding is out of scope.

## Known gaps (tracked)

- The Keycloak admin console is reachable at `/auth/admin` through the proxy. Production overrides that restrict it by network arrive in Phase 8.
- MFA is available in Keycloak but not enforced by default. Enforce it per realm in the Keycloak admin console.
- Rate limiting on PATHOS endpoints is not implemented yet. Keycloak's brute-force protection covers credential guessing.
