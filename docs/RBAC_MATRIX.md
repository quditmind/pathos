# RBAC Matrix

PATHOS authorization is **scoped RBAC**. A role assignment is `user × role × scope`, where the scope is one of:

| Scope | Covers |
|---|---|
| `organization` | Everything in the organization |
| `region` | Resources in that region (repositories through their country) |
| `business_unit` | That business unit **and all of its descendants** |
| `repository` | One repository |

Rules enforced by the API (`backend/internal/authz`):

- **Org-only permissions** (marked below) take effect only through an organization-scope assignment. A Security Manager scoped to one business unit cannot list the organization's users.
- **No privilege escalation.** Granting or revoking a role requires `roles.assign` at the target scope and **every permission of that role** at the target scope.
- `super_admin` can only be granted at organization scope. The last active super administrator cannot be deactivated or have that role removed.
- Users cannot deactivate themselves. Deactivation revokes all PATHOS sessions immediately and disables the Keycloak account.
- List endpoints filter by the caller's scopes **in SQL** (`authz.FilterFor`). The UI hides menus only as a courtesy.
- Denied requests are written to the audit log (`authz.denied`). Resources outside the caller's scope return 404.
- Personal API tokens and the MCP server act with the token owner's **current** assignments; a token never adds permissions ([SECURITY.md](SECURITY.md#api-tokens-and-mcp)).

## System roles

| Role | Purpose |
|---|---|
| `super_admin` | Full control of the platform. Granted automatically to the bootstrap administrator on first verified login, only while no super admin exists |
| `platform_admin` | Operates the platform (users, SCM, scanners, settings). Separation of duties: cannot triage findings or accept risk |
| `security_manager` | Owns the security program for a scope: risk acceptance, scheduling, reporting |
| `security_analyst` | Triages findings, runs scans and AI reviews |
| `appsec_engineer` | Tunes scanners and profiles, onboards repositories, triages |
| `application_owner` | Accountable for applications in scope |
| `developer` | Views and remediates findings on assigned repositories |
| `auditor` | Read-only, including users and the audit log |
| `independent_reviewer` | Second-level Human Eye: validates other analysts' decisions (approve, reject, request information) |
| `repository_contributor` | Onboards and maintains repositories and runs scans in scope; otherwise read-only |
| `viewer` | Read-only posture data in scope |

## Matrix

Generated from `backend/internal/authz/catalog.go` with `make rbac-matrix` (`scripts/go.sh run ./cmd/pathosctl rbac-matrix`). A unit test fails if this table drifts from the code.

| Permission | Org-only | super_admin | platform_admin | security_manager | security_analyst | appsec_engineer | independent_reviewer | repository_contributor | application_owner | developer | auditor | viewer |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `dashboard.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `insights.people` | yes | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `users.read` | yes | ✓ | ✓ | ✓ |  |  |  |  |  |  | ✓ |  |
| `users.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `teams.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `roles.read` | yes | ✓ | ✓ | ✓ |  |  |  |  |  |  | ✓ |  |
| `roles.assign` |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |  |  |
| `roles.manage` | yes | ✓ |  |  |  |  |  |  |  |  |  |  |
| `org.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `org.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `audit.read` | yes | ✓ | ✓ | ✓ |  |  |  |  |  |  | ✓ |  |
| `settings.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `notifications.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `repos.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `repos.manage` |  | ✓ | ✓ | ✓ |  | ✓ |  | ✓ |  |  |  |  |
| `scm.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `tags.manage` | yes | ✓ | ✓ | ✓ |  | ✓ |  |  |  |  |  |  |
| `assets.configure` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `scanners.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `scanners.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `profiles.manage` | yes | ✓ | ✓ | ✓ |  | ✓ |  |  |  |  |  |  |
| `scans.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `scans.run` |  | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ | ✓ |  |  |  |
| `scans.compare` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `schedules.manage` |  | ✓ | ✓ | ✓ |  | ✓ |  |  |  |  |  |  |
| `findings.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `findings.triage` |  | ✓ |  | ✓ | ✓ | ✓ |  |  | ✓ | ✓ |  |  |
| `findings.accept_risk` |  | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `findings.export` |  | ✓ |  | ✓ | ✓ | ✓ | ✓ |  | ✓ |  | ✓ |  |
| `sbom.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `threats.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `threats.manage` |  | ✓ |  | ✓ | ✓ | ✓ |  |  | ✓ |  |  |  |
| `threats.approve` |  | ✓ |  | ✓ |  |  | ✓ |  |  |  |  |  |
| `reviews.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `reviews.assess` |  | ✓ |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |
| `reviews.assign` |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |  |  |
| `reviews.approve` |  | ✓ |  | ✓ |  |  | ✓ |  |  |  |  |  |
| `reviews.configure` | yes | ✓ | ✓ | ✓ |  |  |  |  |  |  |  |  |
| `ai.review` |  | ✓ |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |
| `ai.configure` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `ai.fix` |  | ✓ |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |
| `ai.evidence_read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `mcp.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `remediation.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `remediation.manage` |  | ✓ |  | ✓ | ✓ | ✓ |  |  | ✓ | ✓ |  |  |
| `gates.manage` | yes | ✓ | ✓ | ✓ |  |  |  |  |  |  |  |  |
| `gates.approve_exception` |  | ✓ |  | ✓ |  |  | ✓ |  |  |  |  |  |

### AI-proposed fixes (`ai.fix`)

`ai.fix` lets a user ask the configured AI provider for a code fix of a SAST, secrets or IaC finding on a repository in scope (**Propose fix** in the finding drawer). It is granted to `super_admin`, `security_manager`, `security_analyst` and `appsec_engineer` by default. The fix is only a proposal until a worker verifies it, and the feature is off until an administrator with `ai.configure` adds a provider and a default AI configuration that allows sending code. Opening a pull request from a **verified** fix additionally needs `findings.triage` and `repos.manage` on the repository (the same rights as a dependency fix pull request), and the repository must allow fix pull requests. Choosing a test runner that executes the repository's tests during verification needs `repos.manage`. See [Findings: AI-proposed fixes](user-guide/findings.md#ai-proposed-fixes).

### Developer attribution (`insights.people`)

`insights.people` shows who introduced and who fixed findings, per git author name, per linked user and per team. It is **organization-only** because data about people is not divided by repository scope, and it is granted only to `super_admin` and `security_manager` by default; grant it through a custom role otherwise. Attribution itself is **off by default**: an administrator with `settings.manage` must enable it (Administration → Developer attribution), and linking git author names to users needs `users.manage`. See [the user guide](user-guide/developer-insights.md).

### Verifying a fix (`remediation.manage`, `scans.run`, item owner)

"Verify fix" on a remediation item queues a targeted rescan (the findings' own scanners on the item's affected files only). It needs `remediation.manage` and `scans.run` on the item's repository, **except for the item's assigned owner**, who may verify their own item with `remediation.read` alone. A developer can therefore prove the fix of an item assigned to them; other developers cannot queue rescans. The item page shows the button from the server's `can_request_verification`.

### AI evidence records (`ai.evidence_read`)

`ai.evidence_read` (PATHOS 3.0 M7, `ai_intelligence` flag) lets a user read AI evidence records: model, prompt and response (redacted), reasoning steps, conclusion, reviewer. It is in the read-only set, so every built-in role has it, and a record is shown only with read access to its subject: `findings.read` on the finding's repository, `threats.read` on the threat model, or for troubleshooting, chat and report records being the requester or holding `ai.configure` organization-wide. Accepting, rejecting and replaying need `ai.review` on the finding's repository (an AI review awaiting approval also `findings.triage`) or `threats.manage` for threat suggestions; model per task and evidence retention need `ai.configure`. See [AI security intelligence](user-guide/ai-security-intelligence.md#permissions).

## Organizations and installation administrators (multi-tenancy)

Every role assignment above belongs to **one organization**. With multi-tenancy enabled ([MULTI_TENANCY.md](MULTI_TENANCY.md)), a person who belongs to several organizations has a separate user record, separate role assignments and separate API tokens in each; the session acts in one organization at a time (the organization switcher starts a new session). No role, scope or token of one organization reaches another: authorization resolves every repository, business unit and region inside the request's organization, and the database enforces row-level security on every tenant table.

**Installation administrator** is not a role in this matrix. It is an attribute of a person (their identity-provider subject), granted with `PATHOS_INSTALLATION_ADMIN_EMAIL` or `pathosctl installation-admin grant`, and it allows exactly this:

| Action | Installation administrator | Any organization role (including `super_admin` and `platform_admin`) |
|---|:-:|:-:|
| List organizations (name, slug, status, user and repository counts) | ✓ | |
| Create an organization and invite its first super administrator | ✓ | |
| Suspend, resume and delete an organization (not the default one) | ✓ | |
| Read the installation audit log | ✓ | |
| Read or change any organization's data | | only its own organization, per the matrix |

An installation administrator who should also work inside an organization needs an ordinary membership and roles there. The organization role `platform_admin` (Platform Administrator) operates one organization's settings and has no installation-level rights.
