---
title: Administration
section: user-guide
order: 26
version: "1.0"
updated: 2026-11-19
summary: Users and roles, organization structure, notifications (rules, e-mail, templates, in-app), scanners and workers, the audit log, and where every other administration page is described.
---
# Administration

The **Administration** and **Configurations** groups of the navigation hold the platform settings. A menu entry is shown only when you hold its permission; organization-only permissions (see `docs/RBAC_MATRIX.md` in the PATHOS repository) work only through a role granted for the **Entire organization**.

| Page | Permission | Described in |
|---|---|---|
| **Administration → Users** | `users.read` (view), `users.manage`, `roles.assign` | [Users and roles](#users-and-roles) |
| **Administration → Organization** | `org.read` (view), `org.manage` | [Organization structure](#organization-structure) |
| **Administration → SCM connections** | `scm.manage` | [Provider integrations](provider-integrations.md) |
| **Administration → Tags** | `repos.read` (view), `tags.manage` | [Asset registration](asset-registration.md#mandatory-optional-and-configurable-fields) |
| **Administration → Asset settings** | `assets.configure` | [Asset registration](asset-registration.md#step-by-step-configure-required-fields-and-the-repository-id-prefix) |
| **Administration → Policies** (SLAs, license policy, security policies) | `settings.manage` | [Security policies and compliance](policies-and-compliance.md) |
| **Administration → Integrations** (Jira, ServiceNow) | `settings.manage` | [Integrations and API tokens](reporting-and-integrations.md#jira-and-servicenow) |
| **Assets → Runtime** (Kubernetes clusters, container registries, application mappings) | `findings.read` organization-wide (view), `settings.manage` organization-wide | [Runtime context](runtime.md#connect-a-cluster) |
| **Administration → Risk & intelligence** | `settings.manage` | [Contextual risk and vulnerability intelligence](vulnerability-intelligence.md#for-administrators-feeds-and-the-risk-model) |
| **Administration → Notifications** | `notifications.manage` | [Notifications](#notifications) |
| **Administration → Audit log** | `audit.read` | [Audit log](#audit-log) |
| **Configurations → Scan profiles**, **Custom rules** | `scans.read` / `scanners.read` (view), `profiles.manage` | [Security scanning](security-scanning.md#scan-profiles) |
| **Configurations → Scanners & workers** | `scanners.read` (view), `scanners.manage` | [Scanners and workers](#scanners-and-workers) |
| **AI & MCP → AI settings**, **AI usage**, **MCP registry** | `ai.configure`, `mcp.manage` | [AI features](ai-analyst.md) |
| **Human Eye → Review Configurations** | `reviews.configure` | [Human Eye](human-review.md) |

## Users and roles

**Administration → Users** lists the people with access, with their status (*Active*, *Invited*, *Deactivated*), e-mail, when they were added and their last sign-in. Search by name or e-mail.

### Invite a user

1. Select **Invite user**, enter the **Email** and optionally an **Initial role** with its scope.
2. PATHOS creates the user and a Keycloak account; the person receives an e-mail to set a password. The status is *Invited* until the first sign-in.

People who sign in through [single sign-on](sign-in-and-sso.md#single-sign-on-with-your-identity-provider) are created on their first sign-in **without roles**; inviting them beforehand gives them their role at once.

### Roles and scopes

Select a user to open their details. **Role assignments** lists each role with its scope; **Grant a role** adds one, the bin icon removes one. A user with no roles can sign in but sees no data.

| Scope | Covers |
|---|---|
| Entire organization | Everything |
| Region | Repositories placed in that region (through their country) |
| Business unit | That business unit and all units below it |
| Repository | One repository |

| Role | Purpose |
|---|---|
| Super Administrator (`super_admin`) | Full control; organization scope only. The last active super administrator cannot be deactivated or lose the role |
| Platform Administrator (`platform_admin`) | Operates the platform (users, SCM, scanners, settings); cannot triage findings or accept risk |
| Security Manager (`security_manager`) | Owns the security program for a scope: policy, risk acceptance, scheduling, reporting |
| Security Analyst (`security_analyst`) | Triages findings, runs scans and AI reviews |
| AppSec Engineer (`appsec_engineer`) | Tunes scanners and profiles, onboards repositories, triages |
| Independent Reviewer (`independent_reviewer`) | Second-level Human Eye review |
| Repository Contributor (`repository_contributor`) | Imports and maintains repositories in scope and runs scans |
| Application Owner (`application_owner`) | Accountable for applications in scope: views posture, assigns and triages findings |
| Developer (`developer`) | Views and remediates findings on assigned repositories |
| Auditor (`auditor`) | Read-only, including users and the audit log |
| Viewer (`viewer`) | Read-only posture data in scope |

You can grant a role only if you hold `roles.assign` **and every permission of that role** at the target scope, so nobody can give more than they have.

### MFA, recovery codes and deactivation

In the user's details:

- **Require MFA**: the user enrols an authenticator app at the next sign-in. To require it for everyone, the operator sets `PATHOS_REQUIRE_MFA=true`.
- **Recovery codes**: **Require recovery codes** or **Issue new codes**; see [Sign-in, MFA and single sign-on](sign-in-and-sso.md#recovery-codes).
- **Deactivate user** signs the user out everywhere immediately and disables their Keycloak account and API tokens. **Reactivate user** restores access. You cannot deactivate yourself.

## Organization structure

**Administration → Organization** holds the **Regions & countries** and the **Business units** used to place repositories and scope access and reporting. With `org.manage`, add a business unit with a **Name** and an optional parent (*None (top level)* for a top-level unit). Repositories are placed in a business unit and a country when they are [registered](asset-registration.md#business-ownership).

## Notifications

**Administration → Notifications** decides who hears about what. It has five tabs.

**Rules.** A rule matches an **Event** to recipients. **New rule** with a **Name**, the **Event**, an optional **Minimum severity**, a **Scope** (*Whole organization*, *Region*, *Business unit* or *Repository*), recipients — **Roles** (users holding the role at a scope that covers the repository), **Specific users**, **External addresses** and **Dynamic recipients** such as the assignee, the requester, eligible approvers or application owners — and the channels **Email** and **In-app**. *built-in* rules come with PATHOS; they can be edited or disabled, but not deleted, and their event cannot change.

| Event | When |
|---|---|
| New findings | A scan found new findings |
| Security-material change | A branch scan found security-material changes since the previous scanned commit ([details](developer-insights.md#notifications-and-webhooks)) |
| Scan failed | A scan job failed after its retries |
| SLA breached | Open findings passed their remediation deadline |
| Security policy violated | Open findings newly violate a notifying security policy |
| Scheduled report | A [report](dashboards.md#reports) was delivered |
| Finding assigned | A finding was assigned to someone |
| Risk acceptance requested / decided | A [risk acceptance](findings.md#risk-acceptance) needs a decision or was decided |
| Schedule missed runs, Scheduled scans completed, Scheduled scans failed | [Scan schedules](scanning.md#scan-schedules) |
| Repository sync failed, Repository import failed | Sync or [import](import-history.md) problems |
| Scan worker offline | A worker stopped reporting |
| Human Eye review assigned, Independent review requested, Independent review decided, Human Eye review overdue | [Human Eye](human-review.md) workflow |

**Email (SMTP).** **Send email notifications**, **SMTP host**, **Port**, **Security** (*STARTTLS (port 587)*, *Implicit TLS (port 465)* or *None (internal relay or development only)*), **Username**, **Password**, **From address** and **From name**. **Send a test email** queues a message like any other notification, so it tests the real path. Without e-mail configured, e-mail deliveries are marked *Suppressed*.

**Templates.** The subject and body of each event's message, in Go `text/template` syntax, with a **Preview (sample data)**. Templates are validated on save; **Reset to default** restores the built-in text.

**Webhooks.** Send events to Slack, Microsoft Teams or a SIEM; see [Webhooks](reporting-and-integrations.md#webhooks-slack-microsoft-teams-siem).

**Delivery history.** Every message with its status (*Sent*, *Pending*, *Failed*, *Suppressed*); **Retry** resends a failed one.

**In-app notifications.** The bell beside **Help** in the top bar shows your unread notifications; **Mark all read** clears them. In-app notifications go to PATHOS users only, never to external addresses.

## Developer attribution

**Administration → Developer attribution** turns the opt-in attribution of findings to git authors on or off (`settings.manage`) and links git author names to users (`users.manage`). It is off by default, and turning it off erases all stored author data. See [Material changes and developer insights](developer-insights.md#developer-insights-attribution).

## Secret validation

**Administration → Secret validation** (`settings.manage`, organization-wide) enables [live secret validation](secret-validation.md) provider by provider. It is off by default: nothing is sent to any provider until you enable one.

1. Tick the providers whose credentials workers may check. PyPI is listed but cannot be enabled (no read-only check exists).
2. Add each enabled provider's host to `deploy/egress/allowlist.txt` and restart the `egress` service; the page lists the lines to add. Until a host is allowed, its checks fail closed with *Check failed: the egress proxy denied …* and the secret is not sent anywhere.
3. Optionally change **Checks per second** (1–10, default 1) and **Checks per scan** (1–500, default 50; further secrets are reported as not checked).
4. **Save**. The next repository scans validate; to validate existing findings, rescan or use **Re-check** on a finding.

| Provider | Allowlist line |
|---|---|
| AWS access key | `sts.amazonaws.com` |
| GitHub token | none: `api.github.com` is covered by the default `.github.com` |
| GitLab token | `gitlab.com` |
| Slack token | `slack.com` |
| Stripe key | `api.stripe.com` |
| OpenAI API key | `api.openai.com` |
| Anthropic API key | `api.anthropic.com` |
| SendGrid API key | `api.sendgrid.com` |
| Twilio credentials | `api.twilio.com` |
| npm token | `registry.npmjs.org` |
| Google API key | `generativelanguage.googleapis.com` |
| Azure Storage key | `.blob.core.windows.net` |

Every change of these settings (`secret_validation.settings.update`), every validation batch uploaded by a worker (`secret_validation.batch`, with the number of verdicts per provider and status, never a secret or identity) and every re-check (`secret_validation.recheck`) is in the audit log. With `PATHOS_OFFLINE=true` the page says so and nothing is validated.

## Scanners and workers

**Configurations → Scanners & workers** shows:

- **Workers**: each registered worker with its status (*Online* with the number of running jobs, *Last seen*, or *Revoked*), family, agent version and the scanner versions it provides. With `scanners.manage` you can **Revoke** a worker (its token stops working and it cannot re-register until its record is deleted) or delete its record. If no worker is registered, start one with `docker compose up -d worker-core`. Workers never receive platform secrets or a Docker socket.
- **Scanner catalog**: every scanner with category, license, availability and policy; see [Scanners](security-scanning.md#scanners) and [Scanner plugins](security-scanning.md#family-workers-and-scanner-plugins).

Offline (air-gapped) operation is described in [Security scanning](security-scanning.md#offline-air-gapped-operation) and, for operators, in `docs/AIRGAP.md` in the PATHOS repository.

## Audit log

**Administration → Audit log** is the append-only record of sign-ins, administrative changes and denied actions: time, actor, action, target, outcome (*Success*, *Denied*, *Failure*), IP address, request ID and details. Filter by action (for example `user` or `role_assignment.create`) and outcome. Changes made with an API token record the token's id; denied requests are recorded as `authz.denied`.

## Organizations (multi-tenant installations)

An installation can host several organizations that are completely separate: each has its own users, roles, repositories, findings, settings, integrations, secrets, AI configuration, risk model, workers and audit log, and nobody in one organization can see or change anything of another. Multi-tenancy is off unless your operator enabled it (`docs/MULTI_TENANCY.md` and `docs/OPERATIONS.md` in the PATHOS repository); on a single-organization installation nothing in this section appears.

**Belonging to several organizations.** You can be a member of more than one organization, with different roles in each. The organization switcher in the header shows the active organization; choose another one to switch. Switching starts a new session in that organization and reloads the page. API tokens and MCP tokens belong to the organization they were created in.

**How people join an organization:**

- an administrator of the organization invites them (**Administration → Users → Invite user**); the invitation is linked when they sign in with that email address, if the identity provider confirms the address;
- or the identity provider puts them in the organization's group (Keycloak: group `/pathos/<slug>`); they become a member without roles at their next sign-in, and an administrator grants roles as usual.

Removing someone from the identity-provider group does **not** remove their membership: deactivate the user in **Administration → Users** of that organization.

**Installation administrators** (the people the operator named) see **Installation → Organizations**:

- **New organization**: name, slug (lowercase letters, digits and hyphens; also used for the identity-provider group and for workers) and, optionally, the email of its first administrator, who is invited with the *Super Administrator* role. The organization starts with the default regions, scan profile, policies and notification rules.
- **Suspend**: its members can no longer sign in to it, its API tokens, MCP tokens and workers stop working and its scheduled scans pause. Nothing is deleted. **Resume** undoes it.
- **Delete** (suspended organizations only): type the slug to confirm. Every record of the organization, including its audit log, stored scan artifacts and source snapshots, is removed permanently.
- The **installation audit log** below the list records who created, suspended, resumed or deleted which organization.

The default organization (the first one) can be neither suspended nor deleted. Being an installation administrator gives no access to any organization's data: to work in an organization you need a membership and roles there like everyone else. Do not confuse it with the organization role **Platform Administrator**, which manages the settings of one organization.

**Workers.** Each organization needs its own scan workers; the operator starts them for the organization's slug. **Configurations → Scanners & workers** lists only your organization's workers.

**Related APIs.** [Administration](../api-reference/administration.md), [Notifications](../api-reference/notifications.md), [Scan configuration](../api-reference/scan-configuration.md), [Worker protocol](../api-reference/worker-protocol.md).
