# RBAC Matrix

PATHOS authorization is **scoped RBAC**. A role assignment is `user × role × scope`, where the scope is one of:

| Scope | Covers |
|---|---|
| `organization` | Everything in the organization |
| `region` | Resources in that region (repositories via their country, from Phase 3) |
| `business_unit` | That business unit **and all of its descendants** |
| `repository` | One repository (from Phase 3) |

Rules enforced by the API (`backend/internal/authz`):

- **Org-only permissions** (marked below) take effect only through an organization-scope assignment. A Security Manager scoped to one business unit cannot list the organization's users.
- **No privilege escalation.** Granting or revoking a role requires `roles.assign` at the target scope and **every permission of that role** at the target scope.
- `super_admin` can only be granted at organization scope. The last active super administrator cannot be deactivated or have that role removed.
- Users cannot deactivate themselves. Deactivation revokes all PATHOS sessions immediately and disables the Keycloak account.
- List endpoints filter by the caller's scopes **in SQL** (`authz.FilterFor`). The UI hides menus only as a courtesy.
- Denied requests are written to the audit log (`authz.denied`).

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
| `independent_reviewer` | Second-level Human Review: validates other analysts' decisions (approve, reject, request information) |
| `viewer` | Read-only posture data in scope |

## Matrix

Generated from `backend/internal/authz/catalog.go` with `scripts/go.sh run ./cmd/pathosctl rbac-matrix`. A unit test fails if this table drifts from the code.

| Permission | Org-only | super_admin | platform_admin | security_manager | security_analyst | appsec_engineer | independent_reviewer | repository_contributor | application_owner | developer | auditor | viewer |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `dashboard.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
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
| `reviews.read` |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `reviews.assess` |  | ✓ |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |
| `reviews.assign` |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |  |  |
| `reviews.approve` |  | ✓ |  | ✓ |  |  | ✓ |  |  |  |  |  |
| `reviews.configure` | yes | ✓ | ✓ | ✓ |  |  |  |  |  |  |  |  |
| `ai.review` |  | ✓ |  | ✓ | ✓ | ✓ |  |  |  |  |  |  |
| `ai.configure` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `mcp.manage` | yes | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
