---
title: Troubleshooting and FAQ
section: user-guide
group: home
order: 27
version: "1.0"
updated: 2026-11-20
summary: Answers to common questions and problems with sign-in, repository import, connections, metadata, scanning, findings and notifications.
---

# Troubleshooting and FAQ

When you contact your PATHOS administrator, include the **Repository ID** (for example `QD-REPO-000042`), the **import job ID** (last part of the Import progress address) and the exact **error code** shown. Never include tokens or secrets.

## Error codes (PTH-…)

Every error PATHOS reports has a code of the form `PTH-<AREA>-<NNNN>` (for example `PTH-CONN-1007`, "Provider rejected the credential") and a **request ID**. The code leads to a page that explains the cause, the impact, the fix and how to check it; the pages are listed in [Troubleshooting codes](../troubleshooting/index.md) and are part of the in-app help, so they work without internet access. Quote both the code and the request ID when you ask for help: an administrator finds the matching server log lines by them (`request_id` and `error_code`).

When the cause is proven by the check that failed (for example an expired API token), PATHOS shows it as **confirmed**; otherwise it lists **probable causes**, most likely first. For codes that offer it, **Troubleshoot with AI** asks the organization's AI model (a local model when one is configured) for steps; it sends only the code, the redacted message and non-secret context, never secrets or source code, and the catalogue steps remain available when AI is off. AI answers are suggestions, never confirmed causes.

## A repository does not appear in the list

1. Check the filters: the default list shows only **Active** repositories. Set **Status** to *Active and archived* and select **Reset** (or clear the filters).
2. Search by name or exact **Repository ID** (**More filters → Repository ID (exact)**).
3. Check **Import history**: the import may still be running, have failed, or need attention.
4. Check your scope: you only see repositories in the business units, regions or repositories your role is assigned to. Ask an administrator if the repository is placed in another business unit.

## Authentication failed

The connection shows **Error** with *scm: authentication failed (check the token and its scopes)*, or imports fail with `authentication_failed`.

1. Select **Test** on the connection in **Administration → SCM connections**.
2. Create a new credential and use **Rotate credential**, or **Reconnect** for OAuth connections.

Every status message and the full checklist are in [Connection statuses and messages](provider-integrations.md#connection-statuses-and-messages); method-specific causes are in [Authentication methods](authentication.md).

## I can't see an organization, group, workspace or project

- **GitHub App**: install the app on that organization, and include the repositories in the installation.
- **GitHub PAT**: the token's owner must belong to the organization; authorise the token for SAML SSO; fine-grained tokens need the organization as resource owner.
- **GitLab group or project token**: it only sees its own group or project.
- **Bitbucket access token**: cannot list workspaces; set **Workspace** on the connection.
- **Azure DevOps service principal**: cannot list organizations; enter them in **Organizations**, and add the service principal to each organization with Basic access.
- **Azure DevOps PAT**: the token may be limited to other organizations, or the connection's **Organizations** field limits discovery.
- The connection's owner scope (**Organization or user**, **Group**, **Workspace**, **Project**) restricts discovery to that scope.

## The import is failing

Open the job in **Import history** and read the item's error code. [Import history → Error codes](import-history.md#error-codes) lists every code with its fix. Temporary errors are retried automatically up to three times; permanent errors need a fix and a manual **Retry** or a new import.

## The repository was marked as a duplicate

The same repository through the same connection completes as *already imported* and links to the existing record; nothing to do. The same clone URL through another connection, or the same archive, needs a decision: **Import anyway** creates a second record. An asset name that is already used (`name_clash`) must be changed. Details: [What happens to duplicates](repository-import.md#what-happens-to-duplicates).

## The production URL is missing

The Production URL is optional unless your administrator made it required. Add it with **Edit metadata → General → Production URL**. Use the **Missing production URL** card or checkbox to find all repositories without one. The URL is metadata only; PATHOS never contacts it.

## What does "Unknown" exposure mean?

*Unknown* means "not assessed yet". It is a deliberate answer to the mandatory question *Is this application or asset publicly exposed to the internet?*. Repositories registered before the question existed also show Unknown. Unknown repositories are counted on the **Unknown exposure** card so they can be followed up. Change the answer to **Yes** (with at least one public URL, domain or IP) or **No** when it is known.

## The scan is not starting

The most common causes: importing does not scan unless **Scan on import** is on; the repository is archived or has scanning disabled; no worker is online; a scan is already queued; or an uploaded repository has no snapshot yet. The full list with fixes is in [Why a scan does not start or fails](scanning.md#why-a-scan-does-not-start-or-fails).

## How do I reconnect an expired integration?

Open **Administration → SCM connections** (permission `scm.manage`). For an OAuth connection select **Reconnect** and approve access at the provider; for a token, app or service principal select **Rotate credential**. Then **Test**, and retry imports that stopped with `token_expired`. See [Reconnect](provider-integrations.md#reconnect-oauth-connections) and [Rotate a credential](provider-integrations.md#rotate-a-credential-token-github-app-service-principal).

## How do I retry a failed import?

Open the job in **Import history** and select **Retry** on the item or **Retry all failed (n)**. Fix the cause first. See [Retry a failed import](import-history.md#retry-a-failed-import).

## How do I change repository ownership?

Open the repository, select **Edit metadata**, change **Business owner**, **Technical owner**, **Application owner** or the teams in **Business ownership**, and **Save changes**. You need to be a current owner or have `repos.manage`. Moving the repository to another **business unit**, **department** or **country** requires `repos.manage`, because it changes who can access it. See [Repository management](repository-management.md#step-by-step-view-and-edit-a-repository).

## How do I link multiple repositories to an application?

- New repositories: select all of them in one import and choose the application in **General → Application**; every repository of that import is linked.
- Existing repositories: edit each repository and set **Application**. There is no bulk application assignment.

See [Applications](applications.md#step-by-step-create-an-application-and-link-repositories).

## The upload is rejected or stuck

Errors shown in the wizard (unsupported type, `too_large`, `too_many_uploads`, paused uploads, *Waiting for n uploads to finish…*) are explained in [Common upload errors](repository-import.md#common-upload-errors). If the import job fails, for example with `archive_rejected`, open it in **Import history** and look up the code in [Error codes](import-history.md#local-uploads).

## "You do not have permission" (HTTP 403)

The API answers `forbidden` (*you do not have permission to perform this action*) and the attempt is recorded in the audit log as `authz.denied`.

| Task | Permission |
|---|---|
| View repositories, applications, import history | `repos.read` |
| Import, archive, delete, change placement, create applications | `repos.manage` at the business unit |
| Edit descriptive metadata | Owner of the repository, or `repos.manage` |
| Manage SCM connections and OAuth applications | `scm.manage` (organization-wide) |
| Create and edit tags | `tags.manage` |
| Asset settings (required fields, catalogs, Repository ID prefix) | `assets.configure` |
| Run scans, import results | `scans.run` |
| Change finding status, assign | `findings.triage` |
| Approve risk acceptances and suppression rules | `findings.accept_risk` |
| Manage policies, integrations, risk & intelligence | `settings.manage` |
| Manage notifications | `notifications.manage` |

The full list of roles is in [Users and roles](administration.md#users-and-roles).

`csrf_failed` (*missing or invalid CSRF token*) usually means your session expired: reload the page and sign in again.

## "Too many requests" (HTTP 429)

- `rate_limited` (*too many requests; retry later*): PATHOS limits requests per user. Wait a moment and try again.
- *scm: rate limited by the provider, try again later*: the provider's API limit was reached. Import items retry automatically; GitHub search within an organization has a lower limit and returns at most 1,000 results, so narrow the search.

## Sync status shows "Sync failed", "Missing upstream" or "No access"

The latest sync could not read the repository: *Missing upstream* means it was deleted, renamed or moved at the provider; *No access* means the credential lost permission; *Sync failed* covers other errors (the **Source** tab shows *Last sync: `<error>`*). Fix access, then select **Sync now**. *Archived upstream* means the repository is archived at the provider; consider archiving it in PATHOS.

## Can I change a Repository ID?

No. Repository IDs are permanent and never reused. An administrator can change the **prefix** for future repositories only.

## I signed in but see nothing

A new user, including one created by single sign-on, has no roles until an administrator grants one in **Administration → Users** ([Users and roles](administration.md#users-and-roles)). Inviting the e-mail address beforehand gives the role at the first sign-in.

## A finding I fixed is still open

Findings are closed by scans, not by tickets: the next **successful** scan that no longer detects the finding sets it to Fixed. Scans that failed, were cancelled or ran without the scanner that reported it never close it. Run **Scan now** after the fix is on the scan branch (or upload a new version), or set the status to *Fixed* with a reason. See [Status and lifecycle](findings.md#status-and-lifecycle).

## Notification e-mails do not arrive

Check **Administration → Notifications → Delivery history**. *Suppressed* means e-mail is not configured or switched off (**Email (SMTP)** tab); *Failed* shows the SMTP error and can be retried. Use **Send a test email** to test the configuration. A rule must exist and be enabled for the event, and the recipient must match its scope. See [Notifications](administration.md#notifications).
