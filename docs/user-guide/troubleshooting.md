---
title: Troubleshooting and FAQ
section: user-guide
order: 11
version: "1.0"
updated: 2026-11-17
summary: Answers to common questions and problems with repository import, connections, metadata and scanning.
---

# Troubleshooting and FAQ

When you contact your PATHOS administrator, include the **Repository ID** (for example `QD-REPO-000042`), the **import job ID** (last part of the Import progress address) and the exact **error code** shown. Never include tokens or secrets.

## A repository does not appear in the list

1. Check the filters: the default list shows only **Active** repositories. Set **Status** to *Active and archived* and select **Reset** (or clear the filters).
2. Search by name or exact **Repository ID** (**More filters → Repository ID (exact)**).
3. Check **Import history**: the import may still be running, have failed, or need attention.
4. Check your scope: you only see repositories in the business units, regions or repositories your role is assigned to. Ask an administrator if the repository is placed in another business unit.

## Authentication failed

The connection shows **Error** with *scm: authentication failed (check the token and its scopes)*, or imports fail with `authentication_failed`.

1. Select **Test** on the connection in **Administration → SCM connections**.
2. Check the credential at the provider: expired, revoked, wrong scopes, or wrong IDs (App ID, Installation ID, Tenant ID, Client ID).
3. Create a new credential and use **Rotate credential**, or **Reconnect** for OAuth connections.

See [Authentication methods](authentication.md#troubleshooting-authentication-failures).

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

- **Same repository, same connection**: the item completes as *already imported* and links to the existing repository. Nothing to do.
- **Same clone URL through another connection** or **same archive (SHA-256)**: the item **Needs attention** (`duplicate`) or the review shows the problem. Open the existing repository with the link. If you really need a second record, select **Import anyway** (job page) or tick **Import anyway** (review step).
- **Asset name already used** (`name_clash`): choose another asset name.

## The production URL is missing

The Production URL is optional unless your administrator made it required. Add it with **Edit metadata → General → Production URL**. Use the **Missing production URL** card or checkbox to find all repositories without one. The URL is metadata only; PATHOS never contacts it.

## What does "Unknown" exposure mean?

*Unknown* means "not assessed yet". It is a deliberate answer to the mandatory question *Is this application or asset publicly exposed to the internet?*. Repositories registered before the question existed also show Unknown. Unknown repositories are counted on the **Unknown exposure** card so they can be followed up. Change the answer to **Yes** (with at least one public URL, domain or IP) or **No** when it is known.

## The scan is not starting

| Check | Fix |
|---|---|
| Was a scan requested at all? | Importing does not scan unless **Scan on import** is enabled and *Start onboarding scan* was ticked. Use **Scan now** |
| Is the repository archived? | Unarchive it |
| Is a worker online? | **Scanning → Scans** shows the number of workers online; **Configurations → Scanners & workers** lists them |
| Is a scan already queued? | **Scan now** shows *Already queued*; only one queued scan per repository |
| Uploaded repository without a snapshot | Wait until the import completes (*repository has no source snapshot yet*) |
| Webhook push did not scan | Only pushes and merges to the **scan branch** trigger a scan, the webhook secret must match, and the repository must be registered through that connection |
| Scheduled scan skipped the repository | The repository is *Excluded* from scheduled scans |

See [Security scanning](security-scanning.md).

## How do I reconnect an expired integration?

1. Open **Administration → SCM connections** (permission `scm.manage`). The card shows **Expired** and *The credential expired and could not be refreshed.*
2. **OAuth connection**: select **Reconnect** and approve access at the provider. **Token / app / service principal**: select **Rotate credential** and enter a new credential.
3. Select **Test**; the status becomes **Connected**.
4. Retry imports that stopped with `token_expired`.

## How do I retry a failed import?

Open the job in **Import history** and select **Retry** on the item or **Retry all failed (n)**. Fix the cause first. See [Retry a failed import](import-history.md#retry-a-failed-import).

## How do I change repository ownership?

Open the repository, select **Edit metadata**, change **Business owner**, **Technical owner**, **Application owner** or the teams in **Business ownership**, and **Save changes**. You need to be a current owner or have `repos.manage`. Moving the repository to another **business unit**, **department** or **country** requires `repos.manage`, because it changes who can access it. See [Repository management](repository-management.md#step-by-step-view-and-edit-a-repository).

## How do I link multiple repositories to an application?

- New repositories: select all of them in one import and choose the application in **General → Application**; every repository of that import is linked.
- Existing repositories: edit each repository and set **Application**. There is no bulk application assignment.

See [Applications](applications.md#step-by-step-create-an-application-and-link-repositories).

## The upload is rejected or stuck

| Symptom | Fix |
|---|---|
| *only .zip, .tar, .tar.gz and .tgz archives are accepted* | Re-pack the code |
| `too_large` | The archive exceeds the maximum size shown in the drop zone (default 2 GiB). Remove dependencies and build output |
| `too_many_uploads` | Finish, import or remove your open uploads |
| Upload paused or failed mid-way | Select **Resume** or **Retry**; only missing parts are sent |
| *Waiting for n uploads to finish before checking the import.* | Wait until all uploads show **Uploaded** |
| Import fails with `archive_rejected` | The archive contains a forbidden path or exceeds a limit; the message names it |

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
| Run scans | `scans.run` |

`csrf_failed` (*missing or invalid CSRF token*) usually means your session expired: reload the page and sign in again.

## "Too many requests" (HTTP 429)

- `rate_limited` (*too many requests; retry later*): PATHOS limits requests per user. Wait a moment and try again.
- *scm: rate limited by the provider, try again later*: the provider's API limit was reached. Import items retry automatically; GitHub search within an organization has a lower limit and returns at most 1,000 results, so narrow the search.

## Sync status shows "Sync failed", "Missing upstream" or "No access"

The latest sync could not read the repository: *Missing upstream* means it was deleted, renamed or moved at the provider; *No access* means the credential lost permission; *Sync failed* covers other errors (the **Source** tab shows *Last sync: `<error>`*). Fix access, then select **Sync now**. *Archived upstream* means the repository is archived at the provider; consider archiving it in PATHOS.

## Can I change a Repository ID?

No. Repository IDs are permanent and never reused. An administrator can change the **prefix** for future repositories only.
