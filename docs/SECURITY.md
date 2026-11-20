# Security controls

The security controls implemented in PATHOS, by topic. For the overall design (trust boundaries, worker isolation, AI data handling) see [ARCHITECTURE.md](ARCHITECTURE.md). To report a vulnerability in PATHOS, follow the [security policy](../SECURITY.md).

## Authentication

- **Backend-for-frontend OIDC.** The API runs Authorization Code + PKCE (S256) against Keycloak as a confidential client. `state` is single-use (stored in Valkey) and bound to the browser by an HttpOnly cookie. `nonce` is checked. ID tokens are verified (signature, issuer, audience, expiry) with go-oidc.
- **Sessions.** The browser holds only an opaque 256-bit token in `__Host-pathos_session` (HttpOnly, Secure, SameSite=Lax, Path=/). Valkey stores the session under the token's **SHA-256**, so a dump of the store does not yield usable cookies. Idle timeout 8 hours (sliding) and absolute timeout 24 hours, configurable with `PATHOS_SESSION_IDLE_TTL` and `PATHOS_SESSION_ABSOLUTE_TTL`. A new session is issued at every login.
- **Logout** deletes the PATHOS session and sends the browser to Keycloak's end-session endpoint with `id_token_hint`.
- **Deactivation** deletes every session of the user at once, disables the Keycloak account and logs it out of Keycloak. Every request re-checks the user's status in PostgreSQL, so even a session that somehow survives is rejected, and the user's API tokens stop working.
- **Keycloak realm policy:** minimum 12 characters, not the username or e-mail, last 5 passwords remembered, brute-force lockout after 5 failures, self-registration off. The bootstrap administrator must change the generated password at first login.
- **Just-in-time provisioning.** A login links to an invited PATHOS user only if Keycloak asserts `email_verified`. The bootstrap `super_admin` grant also requires a verified e-mail, applies only while no active super administrator exists, and is serialized with an advisory lock.

## MFA, recovery codes and single sign-on

- **Enforced MFA.** With `PATHOS_REQUIRE_MFA=true`, every active or invited account without an authenticator must enrol TOTP at its next sign-in. An hourly idempotent sweep by the API covers existing users too, including the bootstrap administrator. Keycloak then asks for the code at every sign-in.
- **Per user.** Administrators can require MFA for one user (`POST /api/v1/users/{id}/require-mfa`, `users.manage`, audited).
- **Recovery codes.** Keycloak issues the codes and keeps them; PATHOS never sees them. Each code works once. The `keycloak-setup` job enables the recovery-code form as an alternative to the authenticator. It runs with the Keycloak bootstrap administrator, so PATHOS's own service account keeps user-management rights only. People request codes for themselves (`POST /api/v1/me/recovery-codes`), and administrators can require new codes for a user (`POST /api/v1/users/{id}/recovery-codes`, `users.manage`). Both are audited (`user.recovery_codes`, `user.require_recovery_codes`).
- **Single sign-on** is brokered by Keycloak (external OIDC or SAML 2.0 identity providers); PATHOS receives the same signed identity from Keycloak.
  - A first SSO sign-in creates a PATHOS user **without roles**.
  - An invitation is linked only when the e-mail address is verified, which for brokered users means the identity provider is set to *Trust email*. Enable that only for providers whose addresses you control.
  - An existing Keycloak account with the same e-mail address is not taken over: the default *first broker login* flow asks the person to sign in to it first.
  - Deactivation in PATHOS blocks sign-in even when the identity provider still accepts the person.

  Setup and the end-to-end test (`scripts/test-sso-brokering.py`) are in the [user guide](user-guide/sign-in-and-sso.md).

## API tokens and MCP

Personal API tokens serve both the MCP server and the REST API.

- **Format and storage.** Random 256-bit values with the prefix `pathos_pat_` (recognisable by secret scanners), stored as SHA-256. They are valid for 1 to 90 days and revocable, with at most 10 active tokens per user.
- **Scopes.**
  - `mcp` allows the MCP endpoint (`/mcp`) only.
  - `api:read` allows safe methods (GET, HEAD, OPTIONS) on `/api/`.
  - `api:write` allows every method on `/api/`.

  A REST request with a token sends `Authorization: Bearer` and no session cookie, so CSRF does not apply.
- **Restricted to `/api/`, with a deny-list.** A token can never be used for token management (`/api/v1/me/tokens`), sign-in (`/api/auth/`), recovery codes (`/api/v1/me/recovery-codes`) or MFA (`/api/v1/me/mfa`). A token therefore cannot mint new tokens or change how its owner signs in.
- **Permissions.** A token acts with its owner's **current** role assignments, never more. Deactivating the owner stops every token at once.
- **Audit.** Every audit entry made with a token records the token ID. Every MCP tool call is audited (`mcp.tool_call`), and the MCP registry can disable the server or individual tools at once.

## CSRF and request hygiene

- Unsafe methods with a session need `X-CSRF-Token` (a per-session synchronizer token, compared in constant time). If an `Origin` header is present, it must equal the public origin.
- JSON bodies are size-limited (1 MiB unless an endpoint documents more). Unknown fields and trailing data are rejected.
- `return_to` after login accepts only same-origin relative paths (open-redirect protection).
- Internal errors return a generic message plus `request_id`. Details go only to the logs.

## Rate limiting

- Every API request is classified and limited with GCRA: sign-in per client IP, unauthenticated calls per IP, reads and writes per user, SCM webhooks per connection, MCP per token. The limits are listed in [OPERATIONS.md](OPERATIONS.md#rate-limiting).
- The state lives in Valkey, so limits hold across replicas. A throttled request gets `429` with `Retry-After`.
- If Valkey is unavailable the limiter fails open (availability over strictness) and logs a warning. Keycloak's brute-force detection still protects the password form.

## Authorization

Scoped RBAC is enforced in the API; see [RBAC_MATRIX.md](RBAC_MATRIX.md). Privilege-escalation checks apply to both granting and revoking roles. Every denial is audited (`authz.denied`). Resources outside the caller's scope return 404, not 403, so their existence is not disclosed. Authorization resolves every repository, business unit and region target inside the caller's organization, also for organization-wide grants, so another organization's resource is treated like a missing one.

## Tenant isolation

With multi-tenancy enabled, one installation hosts several organizations ([MULTI_TENANCY.md](MULTI_TENANCY.md)). Isolation has two independent layers and database constraints:

- **Application:** the organization of every request comes only from the authenticated session, API token, MCP token, worker token or webhook connection, never from client input; every query filters by it; authorization proves each target belongs to it. Static tests fail when code adds a request field or parameter carrying an organization, widens the database scope without review, or serves a route outside the authenticated router.
- **Row-level security** on every tenant table: the connection pool sets `app.organization_id` (or, for reviewed system work, `app.rls_bypass`) on every connection checkout from the request's context; without either, tenant tables look empty. The application role is subject to the policies; the migration owner is not. New tables with an `organization_id` column get the policy automatically.
- **Same-organization foreign keys** on every reference between two tenant tables, so the database rejects a row pointing at another organization's row.
- Workers belong to one organization and see only its jobs; shared workers are not supported. Object storage keys carry the organization id. Suspension blocks sign-in, tokens and workers; deletion removes the organization's rows (including its audit log) and stored objects.
- An installation administrator manages organizations only and gets no access to their data.
- The isolation suite calls every API route as each role of one organization with another organization's ids, with and without row-level security, and checks that nothing leaks and nothing changes (`backend/test/integration/zz_tenant_isolation_test.go`).

Residual risks (row-level security query plans, installation-wide sequence numbers, shared reference data, claim-based memberships not being removed automatically) are listed in [MULTI_TENANCY.md](MULTI_TENANCY.md#6-limits-and-residual-risks).

## Secrets at rest

- AES-256-GCM envelope encryption (`internal/platform/crypto`, `internal/secrets`). Each secret gets a fresh data key, which is wrapped by the versioned master key.
- Both layers authenticate `pathos:secret:<kind>:<id>` as associated data. A ciphertext copied to another row, or relabelled as another kind (an SCM token presented as an AI key, for example), fails to decrypt. The kinds are `scm`, `ai`, `mcp`, `smtp`, `webhook`, `worker`, `scan_target` and `integration`.
- Credentials are write-only in the API: never returned, never logged, and destroyed when their owner (connection, provider, endpoint) is deleted.
- **Master key rotation:**
  1. Generate a key: `docker compose run --rm --entrypoint pathosctl migrate gen-key`.
  2. In `.env`, set `PATHOS_MASTER_KEY=v2:<new>` and `PATHOS_MASTER_KEYS_PREVIOUS=v1:<old>`.
  3. Run `docker compose run --rm --entrypoint pathosctl migrate rotate-master-key`. Only the data keys are rewrapped, in one transaction.
  4. Remove the old key from `PATHOS_MASTER_KEYS_PREVIOUS` and run `docker compose up -d`.

### Secret references (Vault / OpenBao)

- A connector credential may be stored as `vault:<mount>/<path>#<key>`. `secrets.Store.Reveal` resolves it at use time (credential kinds `scm`, `ai`, `mcp`, `smtp`, `integration`, `scan_target`; never `webhook` or `worker`). The value is returned to the caller in memory only: never written to disk or the database, never cached, never logged, never sent to AI. Only the Vault client token is cached, in memory, until 30 s before its lease ends (max 1 h).
- PATHOS authenticates with AppRole (the secret ID is the one secret it stores, encrypted) or Kubernetes auth (no stored secret). Anyone who can manage a connector can type a reference, so PATHOS can be made to read anything its Vault role may read: keep the role's policy to `read` on `<mount>/data/<prefix>/*` and set the same allowed path prefix on the connector; PATHOS refuses other paths before contacting Vault (`PTH-CONN-1607`).
- A compromise of the PATHOS server (master key and database, or code execution in api/jobs) still yields everything the PATHOS role can read. References centralise rotation and revocation; they are not a defence against a compromised server. Bind the AppRole to the PATHOS addresses (`secret_id_bound_cidrs`, `token_bound_cidrs`) and limit `secret_id_ttl`.
- Vault errors are reported with Vault's own error strings (truncated); the secret ID, tokens and values never appear in errors or logs. See [Secret references](user-guide/secret-references.md).

## Database privileges

- `pathos_owner` owns the schema and runs migrations. The API, jobs and scheduler connect as **`pathos_app`**, which:
  - cannot create objects;
  - cannot `UPDATE`, `DELETE` or `TRUNCATE` the audit log, its default partition or any monthly partition;
  - cannot modify the permission catalog or migration history;
  - cannot change or delete append-only history (finding status history, Human Eye decisions, approvals, comments and history);
  - adds scanner catalog rows only through two `SECURITY DEFINER` functions, restricted to import keys (`import-…`) and plugin keys (`plugin-…`);
  - has no privileges on audit log partitions (it writes and reads through the parent table);
  - cannot change the installation settings (multi-tenancy mode) or rewrite the installation audit log;
  - is subject to row-level security on every tenant table once multi-tenancy is enabled.
- `pathos_apply_app_grants()` re-applies these grants at the end of every migration. Integration tests assert the denials (`backend/test/integration`).

## Audit log

Append-only and partitioned monthly. It records sign-ins (including denied ones), invitations, provisioning results, role grants and revocations, (de)activation, MFA and recovery-code requests, configuration and credential changes, authorization denials and every change made through the modules. Each entry carries the actor, IP (the rightmost `X-Forwarded-For` hop set by Caddy, which discards client-supplied values), user agent, request ID and, for token requests, the API token ID.

## Transport and headers

- Caddy terminates TLS (internal CA by default; ACME when `CADDY_TLS` is an e-mail address) and sends HSTS on all responses, `nosniff`, a strict `Referrer-Policy` and a `Permissions-Policy`. `default_sni` is set, so clients that omit SNI get a certificate rather than an alert.
- The single-page app is served with a strict CSP: `script-src 'self'`, `connect-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`. `style-src` allows `'unsafe-inline'` because the Radix scroll lock injects a `<style>` element with runtime values that cannot be hash-pinned; inline CSS cannot execute code. COOP, COEP and CORP are set to same-origin.
- API responses add `Cache-Control: no-store`, `default-src 'none'` and a CORP header.
- `/healthz`, `/readyz` and `/internal/*` are not exposed through the proxy.
- **Keycloak administration:** `/auth/admin`, the admin REST API and the master realm are served only to `KEYCLOAK_ADMIN_ALLOW` (default: private networks). Production mode requires an explicit value. PATHOS reaches Keycloak on the internal network and is unaffected.

## Containers and images

- The API, jobs, scheduler and migrate containers use a distroless static image as non-root UID 65532, with a read-only root filesystem, `cap_drop: ALL` and `no-new-privileges`. Valkey gets its password over stdin, never in process arguments.
- All images are pinned by digest and all downloaded binaries by SHA-256. Gitleaks, Nuclei and Caddy are rebuilt from checksum-verified Go modules with a current toolchain and patched dependencies; actionlint is built from its module. The worker runtime contains no package manager.
- Release images are signed with cosign (keyless) and carry an SBOM and SLSA provenance; see [OPERATIONS.md](OPERATIONS.md#installing-a-release-signed-images).

## Logging

slog JSON with redaction of sensitive keys (password, secret, token, cookie, authorization, …) and of token-shaped values (JWTs, bearer tokens, GitHub, Anthropic, OpenAI, xAI and AWS keys, private-key headers, credentials in URLs), including inside error strings.

## Source providers

- **Credentials:** PATs, API tokens, GitHub App keys, service-principal secrets and certificates, OAuth tokens and OAuth client secrets are envelope-encrypted (kind `scm`) and write-only. GitHub Apps are preferred, because PATHOS then only ever holds installation tokens that expire within an hour.
- **OAuth:** `state` is bound to the initiating user (stored hashed, 10-minute lifetime, single use), with PKCE where the provider supports it; the post-login redirect accepts same-origin paths only. Refresh tokens are rotated under a row lock, so concurrent processes never reuse one. Deleting a connection revokes OAuth tokens at the provider where an API exists (GitHub, GitLab).
- **SSRF protection.** Provider base URLs are administrator input.
  - Outbound requests use a dialer that checks the *resolved* IP at connect time, which defeats DNS rebinding.
  - Loopback, link-local and cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are always refused, as are CGNAT, multicast and reserved ranges.
  - RFC 1918 and ULA ranges are refused unless `PATHOS_SCM_ALLOW_PRIVATE_NETWORKS=true` (needed for self-hosted servers on a private network).
  - Only `https` is accepted (`http` only with `PATHOS_SCM_ALLOW_HTTP=true`, for development). Redirects, pagination links and page tokens are followed only to the configured host.
  - The same policy protects outbound webhooks and ticket connections (see below).
- **Inbound webhooks** (`/api/webhooks/*`) are unauthenticated endpoints that require proof of origin:
  - GitHub: HMAC-SHA256 `X-Hub-Signature-256` over the raw body, compared in constant time. GitLab and Bitbucket use their own secret mechanisms; Azure DevOps uses a basic-auth password equal to the webhook secret.
  - Secrets are per connection, random 256-bit, rotatable and shown once.
  - Bodies are capped at 5 MB. Deliveries are de-duplicated by delivery ID, so replays are ignored, and rejected deliveries are audited (`webhook.rejected`).
- **Private CA per connection** (Connectors feature): a PEM bundle is *added* to the system pool for that connection and its clones; verification is never disabled; TLS 1.2 minimum. Stored as configuration because CA certificates are public and the trust decision must stay reviewable; private keys are refused.
- **Generic Git over SSH:** the host key is pinned. Creating the connection requires the administrator's `SHA256:` fingerprint to match the pasted `known_hosts` line; the health check (pure Go, `golang.org/x/crypto/ssh`) and the worker's clone (`StrictHostKeyChecking=yes`, only the pinned file, no agent, `BatchMode=yes`) refuse any other key. There is no trust-on-first-use. The deploy key is encrypted (kind `scm`) and reaches a worker only for one job; it is written to a 0600 file in a private temporary directory for the duration of one git command and then deleted. The SSH dial uses the same connect-time address policy as HTTP.
- **Bitbucket Data Center webhooks** are verified like Bitbucket Cloud (`X-Hub-Signature`, HMAC-SHA256, constant time) and de-duplicated on `X-Request-Id`.
- **Repository access** follows the scope hierarchy (repository → business unit chain → region of its country → organization). Moving a repository needs `repos.manage` at both the source and the destination.
- **Input hygiene:** scan branches are validated as git ref names and cannot start with `-` (option injection). CSV exports prefix formula-leading cells (`= + - @`) to prevent spreadsheet formula injection.
- **Commit statuses** for pull request checks are written with the connection's own credential (opt-in per repository).

## Repository onboarding and uploads

- **Uploads:** only users with `repos.manage` can upload, and upload sessions are private to their uploader. Every 8 MiB part carries its own SHA-256, and the whole archive is verified against the browser-computed SHA-256 before processing. Parts and snapshots are encrypted at rest (AES-256-GCM in 64 KiB chunks with a per-object key wrapped by the master key; truncation, reordering and object swaps are detected).
- **Archives are never extracted on the API or jobs host and never executed.** The jobs role reads every entry, rejects absolute paths, `..`, drive letters, backslashes, control characters, duplicate paths and encrypted entries, skips symlinks, hard links and devices, and enforces entry-count, size, per-file and compression-ratio limits on the bytes actually read, writing a normalized tar snapshot. Scan workers extract that snapshot into their tmpfs with the same rules (`os.Root`, `O_NOFOLLOW`) after verifying its SHA-256.
- **Malware scanning** of uploads: optional ClamAV (`PATHOS_CLAMAV_ADDRESS`). With `PATHOS_CLAMAV_REQUIRED=true` imports wait instead of proceeding unscanned. The result is recorded per snapshot.
- **Authorization:** importing needs `repos.manage` at the chosen placement (checked again when each item is registered, so revoked rights stop pending imports); `tags.manage` for tags; `assets.configure` for catalogs and required fields; `scm.manage` for connections and OAuth applications. Business, technical and application owners (and members of the responsible team) may edit descriptive and ownership metadata of their assets but not placement or scan settings. Every change is audited with old and new values.
- **Application URLs and public endpoints are metadata.** They are validated and normalized (absolute http(s) without credentials, valid domain names, public IP addresses) but never fetched, resolved or scanned by PATHOS.
- **Repository IDs** are assigned by the database and protected by a trigger, so neither users nor the application can set or change them.
- **Compliance scope** records applicability only; PATHOS never marks an asset compliant because a scope is assigned.

## Scanning

- **Trust boundary:** repository content is untrusted. Workers run in separate containers on two internal networks: `scan`, which reaches only the egress proxy, and `worker-api`, which reaches only the API's worker listener.
  - Workers never reach PostgreSQL, Valkey, Keycloak or the user API, and never hold platform secrets.
  - The worker container runs non-root with a read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, a tmpfs workspace, and memory and PID limits.
- **Worker identity:** `PATHOS_WORKER_BOOTSTRAP_TOKEN` only registers a worker; each registration gets a fresh random token, stored as SHA-256. Revoking a worker invalidates its token immediately, and the name cannot re-register until an administrator deletes the record. The bootstrap token is removed from the agent's environment before any scanner runs, and scanners get a scrubbed environment.
- **Clone hardening:**
  - The credential travels in `GIT_CONFIG_*` environment variables (an HTTP header), never in argv, the URL or `.git/config`.
  - Hooks are disabled, `file://` and `ext::` transports are forbidden, symlinks are not checked out, objects are fsck'd, redirects are not followed, refs are validated against option injection, and repository size is capped.
  - `.git` is deleted before scanners run, and the workspace is removed after every job.
  - Repository code is never built or executed in a worker container. The only tools that run it, the opt-in fuzzers of the `worker-fuzz` family image (Go native fuzzing, Atheris; a scan profile must select them), run it in the sandbox runner described below, never in the worker and never on the API or jobs host.
  - Code context for AI evidence is read only from paths whose fully resolved location (`EvalSymlinks`) stays inside the checkout.
- **Sandbox runner for repository code:** tools whose manifest says `sandbox: true` (the fuzzers), and any other caller of `Sandbox.RunUntrusted` in the worker, run in a sibling container, `worker-fuzz-sandbox`, started from the same image as `pathos-worker sandbox-runner`. Docker and the kernel enforce the isolation, not the tool:
  - **No network:** `network_mode: none`. The container has only a loopback interface, so there is no route to the egress proxy, the API, other containers or the internet, and no DNS. A `network: none` tool in an ordinary worker only loses its proxy variables; the runner has no network at all.
  - **No credentials:** the runner's environment has no worker token, API URL or proxy settings, and repository code gets only `PATH`, `LANG`, `HOME`, `TMPDIR` and the manifest's variables. The worker's processes are in another container, so another PID namespace: they are not visible in `/proc`, cannot be signalled, and their environment and memory cannot be read. The runner itself is not dumpable (`PR_SET_DUMPABLE` 0), so code running under its UID cannot read its `/proc/1/environ` or memory, or ptrace it.
  - **Other user, read-only, no capabilities:** UID 10002 (the worker is 10001), group 10001 to share job files, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, `ipc: none` (no `/dev/shm`). The only writable place is the job directory of the run in progress on the shared `fuzz_sandbox` volume. The volume's root, its request queue and other job directories are not writable by the runner.
  - **Limits:** the container's cgroup limits memory (`PATHOS_FUZZ_MEMORY`, default 4g, no swap), CPU (`PATHOS_FUZZ_CPUS`, default 2) and processes (`PATHOS_FUZZ_PIDS`, default 256: a fork bomb stops there). Each run has a wall-time limit, after which every process is killed. Commands inherit `RLIMIT_CORE` 0 and `RLIMIT_FSIZE` 1 GiB. The shared volume is a tmpfs of `PATHOS_FUZZ_SANDBOX_TMPFS` (default 4g). The log kept from a run is at most 64 KiB, and the output file copied back is at most 256 MiB. `pathos-fuzz` adds per-target CPU-time, address-space and time limits.
  - **Nothing survives a run:** the runner is PID 1 and child subreaper of its container. After each run it kills every process of its UID (`kill(-1, SIGKILL)`) until none is left, before it reports the result. If processes cannot be killed, it exits and Docker restarts the container. The runner handles one run at a time.
  - **Results cannot be forged:** each request carries a one-time key. The worker deletes the request before the runner starts the command, and the runner signs its result with the key (HMAC-SHA256). The worker accepts only a result that verifies, so a run cannot make the worker move on while its processes are alive. The worker reads files from the job directory through `os.Root` with `O_NOFOLLOW` and `O_NONBLOCK`, and only if they are regular files, so links and FIFOs planted by a run are refused. Output is parsed as untrusted data, as for every tool.
  - **Without a runner** (no `PATHOS_SANDBOX_DIR`, or the volume is locked by another worker), sandbox tools are skipped with a reason. The worker never falls back to running repository code itself.
  - **Tested** in the built image by `workers/fuzz/test/sandbox-e2e.sh`. A malicious Go fuzz target and Atheris harness try TCP connections to the egress proxy, the API (by name and by IP address) and 1.1.1.1, DNS lookups, reading the environment of every visible process and `/proc/1/environ` and `/proc/1/mem`, writes outside the job directory, a fork bomb, and a daemon that would outlive the run. All of these fail: no route, no DNS, `EACCES`, `EROFS`, `EAGAIN` at the pids limit, and the daemon is killed. The planted bugs of the fuzz sample are still reported. The same probe run unsandboxed in the worker container (the control) reaches the proxy and the API and reads the token.
- **Reverse engineering (static tier, flag `reverse_engineering`):** build artifacts are parsed only by `pathos-rea` in the sandbox runner `worker-rea-sandbox` (same controls as above: `network_mode: none`, UID 10002, read-only, no capabilities, `ipc: none`, CPU, memory and pids limits, a tmpfs volume shared only with its worker), and never executed. The `worker-rea` agent is on the internal `worker-api` network only (no `scan` network, no egress proxy), leases only reverse-engineering executions, and nothing else leases them. By default only artifacts from the organization's own builds are analysed (a verified signature or SLSA provenance attestation for the artifact's SHA-256); other artifacts need an audited per-artifact authorisation with a reason (`rea.authorize`), and the policy "own builds only" forbids those. Strings and code views are redacted by the analyser and again by the API; decompiled code is never sent to an AI model in M10, and the setting that will govern it defaults to none. Tested by `workers/rea/test/rea-e2e.sh` (an isolation probe through the real runner) and the integration test of the input policy. See [PATHOS_REVERSE_ENGINEERING.md](aspm/PATHOS_REVERSE_ENGINEERING.md#security-requirements).
  - **Not covered:** the runner shares the host kernel, as every container does, so a kernel exploit escapes it. Repository code can make its own run fail or time out, and it can end the runner process (same UID; the container restarts). It can read the source copy and its own job files, which hold no secrets. The runner image contains the Go toolchain and Python, which repository code can use. Network isolation depends on Docker's `none` network mode. Docker requirements: Compose with named-volume `driver_opts` (tmpfs), cgroup pids, memory and CPU controllers (cgroup v2 or v1), and the default seccomp and AppArmor profiles (no changes needed). Rootless Docker has not been tested.
- **Process control:** each tool runs in its own process group; on timeout or cancellation the whole group is killed. Tool output and stderr captures are size-limited, and credentials in error text are redacted.
- **Egress:** Squid allows only the domains in `deploy/egress/allowlist.txt`. It denies RFC 1918, loopback, link-local and metadata, CGNAT and multicast destinations whatever DNS returns, strips `Via` and `X-Forwarded-For`, and logs every request to the `egress_logs` volume.
- **Ingestion:**
  - Uploads are size-limited (96 MB request, 256 MB decompressed, zip-bomb safe) and accepted only from the worker holding the job's lease, once per scanner.
  - Parsing happens in the API, not the worker. Secret values are never stored: Gitleaks runs with `--redact`, and finding text passes through the log redactor.
  - Raw reports are downloadable only with `scans.read` on the repository.
- **Integrity:** every scan records the immutable profile version and the scanner versions it ran with.
- **CI/CD workflows:** zizmor and actionlint audit GitHub Actions workflows offline. actionlint runs without shellcheck and pyflakes, so no script from the repository is executed.

### Scan targets

- A web application or API target can be added only with a recorded statement that the person adding it is authorized to test it (user and time). Changing its address needs a new statement. Every target change is audited.
- An OpenAPI document must declare only servers on the authorized host, so an API scan cannot be pointed at another system.
- Nuclei runs only a reviewed template subset installed in the image: no OSINT or token-spray templates (they contact third parties), no default-login or credential-stuffing templates, and never templates tagged `dos`, `intrusive` or `bruteforce`. URL scans do not fuzz. Out-of-band (interactsh) testing and template updates are disabled; the request rate is capped at 100 per second (default 20).
- Targets are reached only through the egress proxy. A target host is scanned only after an administrator adds it to the allowlist. Before scanning, the worker checks that the proxy lets it through and otherwise fails the scan with an explanation, so a blocked target is never "scanned" against the proxy's error page.
- Target credentials (registry tokens, passwords, header values) are encrypted (kind `scan_target`), never returned by the API, given only to the worker holding the job's lease, and redacted from scan logs.
- An SBOM target is served to the worker with its SHA-256, which the worker verifies before Grype reads it.

### Declared endpoint verification

- Verifying a repository's declared public URLs, domains and IPs is **opt-in** per repository and needs a recorded authorization statement (user, time, optional reference; audited as `endpoint_verification.*`). The statement covers the endpoints declared at that moment (`authorized_scope`); endpoints added later are skipped until someone confirms again, and enabling the Nuclei exposure templates needs a new statement too.
- Checks run on a **worker**, never on the API server, and only against the declared hosts: redirects to other hosts are not followed, wildcard domains are skipped, and the worker contacts the hosts only through the egress proxy (CONNECT tunnels for TLS, the proxy for HTTP), so the proxy's allowlist and private-address rules apply. Requests are spaced at the configured rate (1–10 per second, default 2).
- Nothing intrusive is sent: DNS lookups, at most four TLS handshakes per endpoint (certificate and protocol observation, legacy-protocol and weak-cipher probes), one HTTPS request (plus at most three same-host redirects) and one HTTP request, each reading at most 64 KiB. The optional Nuclei run is limited to the exposure, exposed-panel and takeover templates with `dos`, `intrusive`, `bruteforce` and `fuzz` excluded.
- With `PATHOS_OFFLINE=true` endpoint verification cannot be enabled or run, and the worker refuses such jobs.

### Signature verification

- Image and artifact signatures are verified on the worker with the pinned **cosign** binary (built from its Go module, module hash pinned). The public key and identities are policy, not secrets; registry credentials are written to a per-job Docker configuration file, never to cosign's command line.
- Verification results are evidence: they are stored per scan (`signature_verifications`) whatever the outcome, and cosign's raw report is kept with the scan. Only when a target **requires** a signature does a failure become a finding (`supply-chain`, high) and fail the security gate.
- Keyless verification contacts the Sigstore public-good services (`tuf-repo-cdn.sigstore.dev`, `rekor.sigstore.dev`, `fulcio.sigstore.dev`) through the egress proxy; they are in the default allowlist. Offline, only key-based verification runs (without the transparency log) and keyless verification is reported as `skipped`.

### Introducing commits

- `git blame` runs on the worker against its own full-history checkout of the scanned commit, with hooks and fsmonitor disabled and only regular files inside the checkout. Only the commit SHA, the author's **name** and the commit date are sent to PATHOS; author e-mail addresses are never collected. Shallow clones are reported as unknown rather than guessed.

### Build artifacts

- Uploads need `repos.manage` on the repository and are limited to 200 MiB. The file is stored gzip-compressed in the object store or the database.
- **Malware scanning:** when `PATHOS_CLAMAV_ADDRESS` is set for the `api` service, the API streams every artifact to ClamAV before accepting it. A detection rejects the upload (`422 malware_detected`) and is audited (`scan_target.malware_detected`). With `PATHOS_CLAMAV_REQUIRED=true`, uploads are refused while ClamAV is unavailable; otherwise they are accepted and their malware status is recorded as `unavailable`.
- Archives are extracted on the worker with the snapshot extractor (no links, no traversal, bomb limits) after their SHA-256 is verified. Java archives and binaries are scanned whole. Nothing is executed.

### Content scanners

- **Malware (`clamav`)**: the worker streams repository files to clamd (`zINSTREAM`) over the internal `malware` Compose network, which only `worker-core` and `clamav` join; the worker gains no route to PostgreSQL, Valkey or the API's internal listener. Nothing from the checkout is executed; files are opened through `os.Root`, symbolic links are counted, never followed. clamd accepts its full command set from any client on that network (including `SHUTDOWN`); a compromised worker could at worst stop clamd, which `restart: unless-stopped` brings back, and scans then fail instead of passing. Detections are critical findings; files clamd could not scan are reported, and a skipped or failed run never closes malware findings.
- **Binary hardening (`binary-hardening`)**: executables and libraries are parsed with the Go standard library (`debug/elf`, `debug/pe`, `debug/macho`), never loaded or run; a panic on a malformed file is recovered and logged.
- **File licences (`licensecheck`)**: reads at most 16 KiB of each file (1 MiB of licence files), skips binary content and links; detections are stored as the repository's file licence inventory, and only policy violations become findings.
- **Framework configuration rules**: the Django `SECRET_KEY` rule matches the key itself, so its code context is not stored on the finding; the raw Opengrep report (scan artifact, kept for the profile's retention) still contains the matched line, as for every Opengrep rule.

### Scanner plugins

Tool manifests let PATHOS and operators add tools without code ([SCANNER_CATALOG.md](SCANNER_CATALOG.md#adding-a-tool-tool-manifests)). The trust model:

- **Manifests are files**, never API input: first-party manifests are read-only in the family images (`/opt/pathos/tools.d`); operator plugins are on the worker host (`deploy/scanners.d`, mounted read-only). A PATHOS administrator, or anyone with API access, cannot make a worker run a program.
- The command must be an absolute path to an existing executable that is not writable by group or others. Arguments are passed without a shell; only the documented placeholders are substituted.
- Extra environment variables cannot set `PATH`, `HOME`, `LD_*`, proxy variables or `PATHOS_*`. Tools that declare `network: none` run without the egress proxy variables.
- Tools run exactly like built-in scanners: the worker's unprivileged user, the read-only source checkout, the sandbox and egress policy, and the job's timeout.
- A tool that declares `network: target` runs only for url and api targets with an authorization statement; an `intrusive` tool also needs the target's **intrusive testing authorized** flag, which is recorded (who, when, reference), audited (`scan_target.intrusive_authorize`, `scan_target.intrusive_revoke`) and withdrawn when the address changes. The API checks both when a scan is queued; workers skip intrusive tools for targets without the flag. Repository scan profiles cannot select such tools.
- First-party manifests can only name catalog tools that are not built into the core image; operator plugins always get `plugin-<category>-<name>` keys, so neither can replace a built-in tool. The worker registers plugins through a database function that accepts only plugin keys, cannot change built-in entries, and never lowers a tool's network or intrusive declaration. At most 500 first-party manifests and 50 operator plugins load; invalid files are skipped with a log message.
- A worker's result upload may name the parser of a manifest tool (an import format or a JSON mapping): parsing is data only, on the API server, and the parser is accepted only for manifest tools.

### Result imports and the CLI

[Result imports](api-reference/result-imports.md) parse reports of 232 formats on the API server. Parsing is data only; nothing in a report is executed or fetched. A Fortify FPR (a zip archive) is read in memory with bounded sizes; nothing is extracted to disk.

- Uploads need `scans.run` on the repository and are limited to 64 MiB (gzip expanded to at most 256 MiB); at most 20 000 findings per report.
- **XML** (ZAP, Burp, Nessus, OpenVAS, Checkmarx) is parsed with Go's `encoding/xml` in strict mode: DTDs and external entities are never processed or resolved (no XXE, no external fetches), only the five predefined entities are accepted (entity-expansion bombs fail), nesting depth is bounded by the standard library, and only UTF-8, US-ASCII and ISO-8859-1 / Windows-1252 are accepted.
- **Secrets in reports:** secret values reported by Gitleaks, TruffleHog and Trivy are removed before the report is parsed or stored; finding identity never depends on them. Burp and ZAP request/response bodies are not kept in findings' original output. Every kept record is passed through the credential redaction used for scanner output.
- **No suppression:** records a tool marks as false positive or not exploitable are imported with low confidence and the tool's verdict, never dropped or auto-dismissed.
- A named `format` must agree with the detected one, so a report cannot be parsed under the wrong schema.

The **`pathos` CLI** ([CI/CD integration](user-guide/ci-cd-integration.md)) authenticates with a REST API token (the owner's permissions, `api:read` or `api:write`). It always verifies TLS certificates (an extra CA with `--ca-cert`; there is no switch to disable verification), refuses plain HTTP except to loopback unless `--allow-http` is given, sends the token only to the configured host (never on a redirect elsewhere), never prints or logs it, and bounds every response it reads. Release binaries are listed with their SHA-256 in `checksums.txt`, which the release workflow signs with cosign keyless; the CI templates verify the checksum before running the binary.

### Material change detection

For branch scans of Git repositories the worker compares the scanned commit with the previously scanned commit of the same ref. It fetches only those two commits (the clone credential is still held for this step and dropped afterwards) into a private bare repository in the job workspace, runs `git diff` with `--no-ext-diff --no-textconv` and the clone hardening options (no hooks, no `file`/`ext` protocols, no redirects, fsck on transfer) and applies regular-expression rules to the changed lines. Nothing from the repository is executed. Only the matches are sent to the API, which redacts secrets in the matched line again before storing it. Uploads and scan targets are not compared.

### Developer attribution and privacy

Attribution of findings to people is **off by default** (`developer_insight_settings`). While it is off, the lease does not ask the worker for commit authors and the API discards any it receives. When an administrator (`settings.manage`) turns it on, workers send commit author **names** only; author e-mail addresses are never read or stored. Names map to PATHOS users only through links an administrator (`users.manage`) creates. Views of people data need the organization-wide `insights.people` permission. Turning attribution off deletes every stored author name, attribution and link in one transaction; switching and linking are audited.

### Live secret validation

Validation of detected secrets against their providers is **off by default** (`secret_validation_settings`). An administrator (`settings.manage`, audited as `secret_validation.settings.update`) enables providers one by one; each provider's host must also be added to the egress allowlist.

- **Where the secret is held (design choice).** Two designs were considered: (a) validate inside the worker during the scan, before anything is uploaded, and send only the verdict; (b) send the secret to the platform and keep it encrypted for a short time so a background job can check it. PATHOS implements **(a)**. The secret never leaves the worker except in the one request to its own provider: it is not uploaded, not stored (encrypted or not), not queued and not logged. The cost of (a) is that a re-check cannot run from stored data: **Re-check** queues a new scan, and the worker reads the secret from the fresh checkout again.
- **How the worker gets the value.** Scanners keep their own verification off (Gitleaks `--redact`, TruffleHog `--no-verification`, Kingfisher `--no-validate`), so the reports contain no usable value. After the scanners ran, the worker parses its own copies of the secret findings, reads the reported line (and up to three lines around it, for pairs such as an AWS key ID and its secret access key) from its checkout, inside the checkout only (for secrets Gitleaks found in the Git history of a full-history clone, from the commit that added them, with `git cat-file`: no hooks, filters or textconv drivers run), and recognizes the credential with fixed patterns. Values are kept in memory for the check and added to the job's log redaction list.
- **What is sent and to whom.** Exactly one read-only "who am I" request per distinct credential and scan (listed in [Live secret validation](user-guide/secret-validation.md#providers)), to a fixed host of that provider. The worker refuses any other host, does not follow redirects, times out after 10 seconds, reads at most 64 KiB of the answer, and spaces requests at the configured rate (1–10 per second, default 1) up to the per-scan limit (1–500, default 50). Requests go only through the egress proxy (`NO_PROXY` is ignored): without a proxy, or when the proxy refuses the host, the check fails closed with an error and the remaining checks of that provider are not attempted. Google keys go in a request header, never in the URL. Mutating endpoints are never used; PyPI tokens are not checked because PyPI has no read-only token check.
- **What PATHOS stores.** The verdict (`active`, `inactive`, `error`, `not_checked`), provider, check time, the request (method and documented URL, never the credential), HTTP status, a generated explanation and, for active credentials, a non-secret identity (account ID, user login, organization ID). Response bodies are not stored; identities and explanations that would contain any part of the secret are dropped or redacted. The API also discards verdicts for providers that are not enabled, and ignores validation for pull request scans and scan targets.
- **Audit.** Every uploaded batch is audited as `secret_validation.batch` with the number of verdicts per provider and status (no values, no identities); every re-check as `secret_validation.recheck`.
- **Effect.** An active verdict raises the finding to critical (the previous severity is kept in `secret_validation_severity_before` and shown as evidence) and sets the exploit likelihood of its risk score to the maximum; an inactive verdict restores the severity. An inconclusive verdict never overwrites an earlier conclusive one.
- With `PATHOS_OFFLINE=true` the lease never carries validation, so nothing is checked.

## External data and offline mode

PATHOS sends nothing to third parties unless a feature is configured.

| Outbound call | Made by | What is sent | Default |
|---|---|---|---|
| EPSS and CISA KEV feeds | `jobs` | Nothing but the download request | Enabled, daily |
| OSV lookups | `jobs` | The CVE and GHSA identifiers of open findings | Enabled |
| deps.dev package health | `jobs` | **Package names** from the inventories, which can include private names | **Disabled**; an administrator enables it in **Risk & intelligence** |
| endoflife.date end-of-life data | `jobs` (and `api` for **Download now**) | Nothing but the download request (`https://endoflife.date/api/v1/products/full`) | **Disabled**; an administrator enables it in **Risk & intelligence** |
| Declared endpoint verification | workers, through the egress proxy | DNS lookups, TLS handshakes and GET requests to the repository's **declared** endpoints only | **Disabled**; enabled per repository with an authorization statement; never offline |
| Live secret validation | workers, through the egress proxy | One read-only "who am I" request per detected credential, to that credential's own provider (the credential is the request's authentication) | **Disabled**; enabled per provider by an administrator, and each provider's host must be on the egress allowlist; never offline |
| Sigstore (keyless signature verification) | workers, through the egress proxy | The image reference's signature lookup in Rekor; TUF trust root download | Only for targets configured for keyless verification; never offline |
| AI providers | `jobs`, `api` | Redacted evidence (see below) | Only when a provider is configured |
| Outbound webhooks, Jira, ServiceNow | `jobs`, `api` | Event and finding facts (redacted, no code) | Only when configured |
| Kubernetes API servers (runtime inventory) | `jobs` only | Authenticated `GET` list requests for namespaces, pods, services, workloads, ingresses and network policies; nothing about findings | Only for clusters an administrator added; read-only ClusterRole in `deploy/kubernetes` |
| Container registries (runtime inventory) | `jobs` only | `GET` requests for tag lists, manifests and image configuration of the configured repositories | Only for registries an administrator added |
| Vulnerability database updates | workers, through the egress proxy | Download requests | Enabled unless offline |

With `PATHOS_OFFLINE=true` (air-gapped installations):

- the API never downloads intelligence feeds; they are imported from files, and the UI says so;
- declared endpoint verification and live secret validation are disabled, and keyless signature verification is skipped (key-based verification still runs);
- Trivy, Grype and OSV-Scanner use only the local databases imported from an offline bundle, and fail with an explicit error when one is missing;
- `scripts/offline-bundle.sh import` refuses bundles with links or unsafe paths and verifies the SHA-256 of every file before replacing the databases.

The procedure is in [AIRGAP.md](AIRGAP.md).

## AI review and MCP

- **No subscription credentials:** automated reviews use provider API keys or a self-hosted model only. Claude subscriptions are used solely by a person's own assistant through the MCP server ([ARCHITECTURE.md §6](ARCHITECTURE.md#6-ai-review-architecture)).
- **Data minimization:** evidence is the finding metadata plus at most ±5 lines of code. It passes through redaction three times (worker capture → ingest → prompt), using built-in secret patterns plus organization patterns. Secret findings never include code in reviews (AI-proposed fixes are the exception, described below). The SHA-256 of every transmitted request is stored. The same applies to the AI Security Analyst, AI reports and Human Eye assistance.
- **Prompt injection:** evidence is JSON-encoded inside a delimiter carrying a random per-request nonce, and the system prompt forbids following embedded instructions. Provider output must match a strict schema, and unknown fields are rejected, so a model cannot introduce actions.
- **Guardrails:** AI never closes a Critical finding and never overrides a human decision. The approval policy is per configuration, with four eyes for interactive reviews and a written justification for closing Critical findings. Human Eye AI patch proposals are validated (one file, well-formed, not whitespace-only), need a person's approval and are never applied by PATHOS. AI-proposed fixes (below) are verified by a worker before a person can open a pull request from them.
- **AI-proposed fixes** ("never trust AI without validation"): a fix request needs `ai.fix`, is off until a provider and a default configuration with `send_code_context` exist, and is rate-limited (10 per user per hour, 200 per organization per day). It sends more code than a review (the whole file up to 200 lines, otherwise ±60 lines, at most 24,000 bytes), redacted with the built-in and organization patterns; for secrets findings the code is sent with the secret's value (and every copy of it) replaced by `[REDACTED]`, and a diff that writes the marker back is refused. The returned diff is untrusted: it is parsed strictly, confined to the finding's file and at most two files in the same directory (3 files, 20,000 bytes, 200 changed lines), and may not create, delete, rename or change the mode of files or change CI/CD definitions, build scripts, dependency manifests, lockfiles or repository control files other than the finding's own file. The worker checks the policy again, applies hunks only where their context matches, refuses symbolic links and binary files, and re-runs the finding's scanner on the changed files before and after; a fix is verified only when the finding is gone and nothing new appears. The repository's tests run only when an administrator chose a test runner for the repository (`repos.manage`, audited), only in the sandbox runner of worker-fuzz (see [Scanning](#scanning)), never elsewhere. Only a verified fix can become a pull request, opened by a person with `ai.fix`, `findings.triage` and `repos.manage` through the fix pull request machinery (`pathos/fix/` branches only); nothing is merged, and the finding is resolved only by a later scan. Every request, proposal, verdict and pull request is audited (`ai_fix.*`).
- **Self-hosted providers:** the provider type `self_hosted` accepts plain `http` and private addresses, since model servers usually run on the local network. Cloud providers keep the `https`-only rule and the public-address SSRF policy. Loopback, link-local and cloud metadata addresses stay blocked for every provider. The API key is optional and encrypted when given.
- **Self-approval** of interactive reviews (`allow_self_approval`) is a property of the versioned AI configuration and off by default. Enabling it creates a new configuration version and an audit entry. Each self-approved review is recorded with `self_approved: true`, and Critical false positives still require a written note.

## Secret push protection

Push-event scanning is opt-in per repository (`repos.manage`). It runs in the jobs role, never on the request path: for a verified push webhook it reads the pushed commits' diffs through the provider API with the connection's credential (no clone; no repository code is executed) and matches only the lines the commits add against a curated set of high-confidence patterns. PATHOS stores the rule, file, line, commit and the first 16 hex characters of SHA-256 of the match (for de-duplication); the secret value is never stored, logged, sent in notifications or returned by the API. Diffs are bounded (50 commits read one by one, otherwise the combined diff; 1 MiB per file; 16 MiB per push). The client-side and pre-receive hooks in `integrations/` run Gitleaks with `--redact` and make no network connections to PATHOS.

## Fix pull requests

Fix pull requests are opt-in per repository (`repos.manage`) and requesting one needs both `findings.triage` and `repos.manage` on the repository, because PATHOS then writes to the repository with the connection's credential. The worker only clones (hardened as for scans) and edits manifests as text in Go: no package manager, build tool, lifecycle script, hook or other repository code runs, and the worker never pushes. The API creates the branch, commit and pull request itself; every SCM write method refuses any branch outside `pathos/fix/`, so PATHOS cannot push to a default or protected branch, and branch updates are fast-forward only (GitHub `force: false`, Bitbucket `parents`, Azure DevOps `oldObjectId`). Worker results are validated (relative paths without `..` or `.git`, at most 20 files and 20 MiB, a full base commit) before anything is written. A merged pull request never changes a finding: only a later scan resolves it. PR titles and bodies escape scanner-provided text. Requests, results, pull requests and state changes are audited (`fix_pr.*`).

## VEX and application versions

Imported VEX statements (OpenVEX, CycloneDX) never change a finding on import: matching `not_affected` and `fixed` statements become pending suggestions, and only a person other than the importer, holding `findings.accept_risk` on the repository, can approve one (enforced in the service and by a CHECK constraint). Approving `not_affected` closes the finding as a false positive through the normal lifecycle (history reason names the statement, importer and approver); approving `fixed` only records the statement, because findings are resolved by scans. Imported documents are parsed as data (at most 10 MB, 20 000 statements), not stored (only their SHA-256), and every import, decision and export is audited. Exports and the portfolio view are filtered by the caller's scoped `findings.export` / `sbom.read`; version snapshots show components and findings only for repositories the caller may read.

## Vulnerability management

- **Tamper-evident lifecycle:** status history is written by a database trigger, not application code. The app role has no `UPDATE`, `DELETE` or `TRUNCATE` on `finding_status_history`.
- **Separation of duties:** risk acceptances need an approver other than the requester, enforced both in the service and by a CHECK constraint. Acceptances are capped at 365 days and expire automatically. Closing a Critical finding as a false positive requires `findings.accept_risk`. Suppression rules need a second person's approval (API and CHECK constraint) and expire within a year.
- **Scope:** every triage, bulk and SBOM query is filtered by the caller's scoped permissions. A bulk action fails as a whole if any finding is out of scope.
- **Human Eye:** decisions, approvals, comments, AI suggestions and history are append-only for the app role; a trigger rejects approval by the decision's author. See [HUMAN_REVIEW.md](HUMAN_REVIEW.md).

## Notifications and scheduling

- **Connectors hub:** the registry stores no copy of a legacy connection's settings or credentials (only its table and key). Health checks are read-only and never post a message, send an e-mail or create a ticket; stored check messages are redacted (URLs reduced to scheme and host, e-mail addresses and token-shaped strings removed). AI troubleshooting of a connector receives only server-built, non-secret metadata. The GitLab webhook signing token (kind `webhook`) and the Teams trigger client secret (kind `integration`) are write-only.
- **E-mail transport:** `starttls` mode refuses to send if the server does not offer STARTTLS; there is no silent clear-text fallback. Credentials are never sent without TLS, and the relay password is encrypted (kind `smtp`) and write-only. The SMTP dialer refuses loopback, link-local and metadata addresses. Private relays are allowed.
- **Header injection:** recipient and sender addresses are validated as bare addresses. Subjects are collapsed to one sanitized line and MIME-encoded, and bodies are quoted-printable. Untrusted text (finding titles, scanner errors) can reach only the body. Messages carry `Auto-Submitted: auto-generated`.
- **Templates:** administrators edit Go `text/template` (no code execution, no file or network access). Templates are validated against sample data on save, rendering is capped at 64 KiB, and a broken template falls back to the default rather than dropping the notification.
- **Recipients:** role-based recipients only include users whose assignment scope covers the event's repository. Approval requests go to users who may accept risk there, never to the requester. Explicit addresses are an administrator decision (`notifications.manage` is organization-only). Each e-mail has a single recipient, so recipient lists are never disclosed. Scheduled reports are delivered as a link; each reader sees only their own scope.
- **Scheduling:** schedules need `schedules.manage` at the target's scope, and scoped users see only schedules in their scope. A schedule may run at most once per hour, and priority 100 is reserved for emergency scans.

## Outbound webhooks and ticketing

- **Off until configured.** Nothing is sent anywhere until an administrator (`notifications.manage` for webhooks, `settings.manage` for ticket connections, both organization-wide) adds an endpoint or connection. Every change is audited.
- **URLs are credentials.** Webhook URLs must be `https` without user information and are stored encrypted (Slack and Teams URLs grant posting rights); only the host is shown. Signing secrets and ticket-system credentials are encrypted (kinds `webhook`, `integration`) and write-only.
- **Signing.** Generic JSON deliveries with a signing secret carry `X-PATHOS-Signature: sha256=<hex>`, an HMAC-SHA256 over `<timestamp>.<body>`, with the timestamp in `X-PATHOS-Timestamp` and a unique `X-PATHOS-Delivery` ID. Receivers should verify the signature, reject stale timestamps and de-duplicate by delivery ID.
- **SSRF policy.** Webhook and ticket-system addresses go through the same connect-time policy as SCM connections: loopback, link-local and cloud metadata addresses are always refused; private addresses only when the endpoint has **Allow private network** set.
- **Retries** are bounded: five retries with back-off (1 minute to 6 hours, about 9 hours in all). A 4xx response other than 408 and 429 is not retried. Each attempt is in the delivery log.
- **Ticket content.** Issues created in Jira or ServiceNow carry the finding's facts, redacted, and never code snippets. Errors returned by the ticket system are redacted before they are stored or shown. Creating a ticket needs `findings.triage` on the finding.

## Security testing

- **Self-tests:** `make security` gates on gosec, govulncheck, npm audit, fixable HIGH or CRITICAL image vulnerabilities (Trivy) and ZAP baseline failures. Accepted ZAP warnings are documented in `deploy/security/zap-baseline.conf`.
- **Authenticated DAST:** `scripts/dast.sh` signs in as an administrator and runs OWASP ZAP's active API scan against every endpoint in `backend/api/openapi.yaml`, sending the session cookie, CSRF token and `Origin`. CI runs it on a disposable stack for every push to `main`, before every release and weekly. Any High alert that isn't in the reviewed list (`deploy/security/zap-api.conf`) fails the run.

How to run both: [OPERATIONS.md](OPERATIONS.md#security-self-tests).

## Known gaps

- **Accepted residual risk:** vulnerabilities with no upstream fix are reported but not gated. As last measured (platform phase P8):
  - Debian base packages in the worker image (the worker is sandboxed; see "Scanning").
  - `ecdsa` CVE-2024-23342, a timing side channel the maintainers will not fix; it is unused in PATHOS code paths.
  - go-jose v3 inside Caddy's ACME stack.

  Re-run `make security` with each release.
- Capabilities that are not built yet are tracked in the [ASPM register](aspm/PATHOS_FEATURE_GAP_ANALYSIS.md#remaining-gaps).
