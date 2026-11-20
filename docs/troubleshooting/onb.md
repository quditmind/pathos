---
title: Troubleshooting: Onboarding and imports
section: troubleshooting
order: 105
version: "1.0"
updated: 2026-11-20
summary: Repository import jobs, source uploads and asset registration (18 codes, PTH-ONB-*)
---

# Troubleshooting: Onboarding and imports

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Repository import jobs, source uploads and asset registration.

| Code | Title | Severity |
|---|---|---|
| [PTH-ONB-1001](#PTH-ONB-1001) | Uploaded archive rejected | error |
| [PTH-ONB-1002](#PTH-ONB-1002) | Repository not found for import | warning |
| [PTH-ONB-1003](#PTH-ONB-1003) | Import not permitted | warning |
| [PTH-ONB-1004](#PTH-ONB-1004) | Repository already registered | info |
| [PTH-ONB-1005](#PTH-ONB-1005) | Import worker stopped during the item | warning |
| [PTH-ONB-1006](#PTH-ONB-1006) | Mandatory tags missing | warning |
| [PTH-ONB-1007](#PTH-ONB-1007) | Import item metadata no longer valid | warning |
| [PTH-ONB-1008](#PTH-ONB-1008) | Repository already being onboarded | info |
| [PTH-ONB-1009](#PTH-ONB-1009) | Mandatory application fields missing | warning |
| [PTH-ONB-1010](#PTH-ONB-1010) | Mandatory application tags missing | warning |
| [PTH-ONB-1011](#PTH-ONB-1011) | Application name already exists | info |
| [PTH-ONB-1012](#PTH-ONB-1012) | Repository belongs to another application | info |
| [PTH-ONB-1101](#PTH-ONB-1101) | Repository URL not accepted for anonymous import | warning |
| [PTH-ONB-1102](#PTH-ONB-1102) | Repository is not public | warning |
| [PTH-ONB-1103](#PTH-ONB-1103) | Provider rate limit for anonymous requests reached | warning |
| [PTH-ONB-1104](#PTH-ONB-1104) | Provider not reachable for anonymous import | error |
| [PTH-ONB-1105](#PTH-ONB-1105) | Repository already imported anonymously | info |
| [PTH-ONB-1106](#PTH-ONB-1106) | Repository host address not allowed | warning |

<a id="PTH-ONB-1001"></a>

## PTH-ONB-1001: Uploaded archive rejected

| | |
|---|---|
| Severity | error |
| Category | integrity |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `import:archive_rejected`, `import:upload_corrupt` |
| Raised in | internal/repos/import_worker.go, internal/repos/uploads.go |

**What it means.** The source archive failed safety checks (path traversal, links, size or file count limits) during import.

**Confirmed cause.** The archive contains entries PATHOS refuses (see the item's message). Confirmed automatically when this code is raised.

**Probable causes**

1. Absolute paths or ".." entries
2. Symbolic links pointing outside the archive
3. Too many files or too large when extracted

**Impact.** The item was not imported.

**How to fix**

1. Create the archive from inside the project folder (for example `git archive`).
2. Upload it again as a new item.

**Verify**

1. The new item completes.


<a id="PTH-ONB-1002"></a>

## PTH-ONB-1002: Repository not found for import

| | |
|---|---|
| Severity | warning |
| Category | not-found |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `import:repository_not_found`, `import:invalid_branch` |
| Raised in | internal/repos/import_worker.go |

**What it means.** The repository to import does not exist or the connection cannot see it.

**Confirmed cause.** The provider does not return the repository for this connection. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The repository was renamed or deleted after selection
2. The credential cannot see it

**Impact.** The item failed; other items continue.

**How to fix**

1. Refresh the inventory and select the repository again.

**Verify**

1. The new import item completes.


<a id="PTH-ONB-1003"></a>

## PTH-ONB-1003: Import not permitted

| | |
|---|---|
| Severity | warning |
| Category | authorization |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `import:permission_denied`, `import:requester_unavailable` |
| Raised in | internal/repos/import_worker.go |

**What it means.** Either the connection's credential lacks read permission on the repository, or the requesting user no longer holds repos.manage for the selected placement.

**Confirmed cause.** A permission needed for the import is missing (see the item's message). Confirmed automatically when this code is raised.

**Probable causes**

1. The token cannot read this repository
2. The requester's role changed or the user left

**Impact.** The item needs attention; it is retried after the fix.

**How to fix**

1. Grant the credential read access, or ask an administrator with repos.manage to retry.

**Verify**

1. Retry the item; it completes.


<a id="PTH-ONB-1004"></a>

## PTH-ONB-1004: Repository already registered

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `import:duplicate`, `import:name_clash`, `import:upload_consumed`, `already_registered` |
| Raised in | internal/repos/import_worker.go, internal/repos/imports.go |

**What it means.** The repository is already registered (through this or another connection), or the asset name is taken.

**Confirmed cause.** A registered asset already matches this repository or name. Confirmed automatically when this code is raised.

**Probable causes**

1. The repository was imported before
2. Another connection reaches the same repository

**Impact.** The item waits for a decision; nothing is duplicated.

**How to fix**

1. Open the existing asset, or retry with "import anyway" to register it twice on purpose.
2. Choose another asset name if the name clashes.

**Verify**

1. The item completes or is skipped as intended.


<a id="PTH-ONB-1005"></a>

## PTH-ONB-1005: Import worker stopped during the item

| | |
|---|---|
| Severity | warning |
| Category | availability |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Short codes | `import:worker_lost`, `import:internal_error` |
| Raised in | internal/repos/import_worker.go |

**What it means.** The API instance working on the import item stopped (restart or crash) and the item used all its attempts.

**Confirmed cause.** The import lease expired on the last attempt. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The api container restarted during a long import
2. Out of memory on a very large repository

**Impact.** The item failed; it can be retried.

**How to fix**

1. Retry the item.
2. Check the api container's memory and restarts.

**Verify**

1. The retried item completes.


<a id="PTH-ONB-1006"></a>

## PTH-ONB-1006: Mandatory tags missing

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `mandatory_tags_missing` |
| Raised in | internal/repos/repositories.go |

**What it means.** The organization requires tags of some categories on every asset, and the registration lacks them.

**Confirmed cause.** Tags of mandatory categories are missing (listed in the message). Confirmed automatically when this code is raised.

**Probable causes**

1. A new mandatory tag category was added

**Impact.** The asset was not saved.

**How to fix**

1. Add a tag from each mandatory category.

**Verify**

1. Save again; the asset is registered.


<a id="PTH-ONB-1007"></a>

## PTH-ONB-1007: Import item metadata no longer valid

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Short codes | `import:validation_failed`, `import:invalid_item`, `import:connection_unavailable`, `import:upload_missing`, `import:upload_incomplete` |
| Raised in | internal/repos/import_worker.go |

**What it means.** Between validation and import, a referenced owner, team, business unit, region or tag was deleted, or the item has no connection or upload.

**Confirmed cause.** The item's metadata references something that no longer exists. Confirmed automatically when this code is raised.

**Probable causes**

1. An administrator deleted a business unit, team or tag
2. The SCM connection or upload was deleted

**Impact.** The item needs attention.

**How to fix**

1. Edit the item's metadata and import again.

**Verify**

1. The item completes.


<a id="PTH-ONB-1008"></a>

## PTH-ONB-1008: Repository already being onboarded

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `already_onboarding` |
| Raised in | internal/inventory/onboarding.go (register) |

**What it means.** The onboarding flow found that the repository is already being onboarded or was onboarded into an application. Each repository is onboarded once; the database refuses a second onboarding, also when two people start it at the same time.

**Confirmed cause.** An onboarding record for the same repository (same connection and external ID, or the same normalised URL) already exists. Confirmed automatically when this code is raised.

**Probable causes**

1. Someone else onboarded the repository a moment earlier
2. The repository was onboarded before under another application

**Impact.** Nothing was created: no application, repository or onboarding record.

**How to fix**

1. Open the application named in the message and continue its onboarding there.
2. If the repository belongs elsewhere, finish or archive that application first.

**Verify**

1. The repository appears once, in the Repositories tab of its application.


<a id="PTH-ONB-1009"></a>

## PTH-ONB-1009: Mandatory application fields missing

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `mandatory_fields_missing`, `onboarding_incomplete` |
| Raised in | internal/inventory/onboarding.go (completeOnboarding, startDiscovery) |

**What it means.** Save to inventory requires every mandatory application field (Configurations › Asset settings › Application fields). Drafts can be saved incomplete; completing them cannot.

**Confirmed cause.** Mandatory fields are empty (listed in the message and next to the fields). Confirmed automatically when this code is raised.

**Probable causes**

1. The draft was saved before every field was known
2. An administrator made another field mandatory

**Impact.** The application stays a draft ("Onboarding: N of M fields") in the inventory.

**How to fix**

1. Fill the fields marked as required in Tag & classify, then save to the inventory again.

**Verify**

1. The application shows as Registered in the inventory.


<a id="PTH-ONB-1010"></a>

## PTH-ONB-1010: Mandatory application tags missing

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Raised in | internal/inventory/onboarding.go (completeOnboarding) |

**What it means.** Tag categories can be mandatory for some application types (Inventory › Tags). The application lacks a tag in such a category.

**Confirmed cause.** Tags of categories mandatory for this application type are missing (listed in the message). Confirmed automatically when this code is raised.

**Probable causes**

1. The application type was set to a type with mandatory categories
2. A category was made mandatory recently

**Impact.** The application stays a draft.

**How to fix**

1. Add a tag from each listed category in Tag & classify.

**Verify**

1. Save to inventory succeeds.


<a id="PTH-ONB-1011"></a>

## PTH-ONB-1011: Application name already exists

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `application_exists` |
| Raised in | internal/inventory/onboarding.go (register) |

**What it means.** Register as new was chosen with the name of an existing application. Application names are unique within an organization.

**Confirmed cause.** An active application with the same name (ignoring case) exists. Confirmed automatically when this code is raised.

**Probable causes**

1. The application already exists and the repositories belong to it
2. Someone registered the same application at the same time

**Impact.** Nothing was created.

**How to fix**

1. Choose Link to existing for that application, or register under another name.

**Verify**

1. Registration succeeds and the application appears once in the inventory.


<a id="PTH-ONB-1012"></a>

## PTH-ONB-1012: Repository belongs to another application

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `repository_in_other_application` |
| Raised in | internal/inventory/onboarding.go (completeOnboarding) |

**What it means.** Save to inventory found repositories of the onboarding that already belong to another application. PATHOS never moves a repository between applications silently: each one must be listed explicitly as moved or kept.

**Confirmed cause.** A repository being onboarded is linked to another application (listed in the message and in error.details.conflicts). Confirmed automatically when this code is raised.

**Probable causes**

1. The repository was linked to another application before onboarding started
2. Someone linked it to another application while the draft was open

**Impact.** Nothing was saved; the application stays a draft and no repository moved.

**How to fix**

1. In Save to inventory, tick "Move it to this application" for repositories that belong here, or leave it unticked to keep them where they are.
2. API: list each repository in move_repositories or keep_repositories.

**Verify**

1. Save to inventory succeeds; moved repositories appear in the audit log as repository.application_move.


<a id="PTH-ONB-1101"></a>

## PTH-ONB-1101: Repository URL not accepted for anonymous import

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/repos/anonymous.go |

**What it means.** Import repositories → Public repository by URL (POST /api/v1/repositories/import-url) accepts only an https:// repository URL without credentials, query or fragment.

**Confirmed cause.** The URL is not an https:// repository URL, or it contains a user name, password or token, a query string or a fragment. Confirmed automatically when this code is raised.

**Probable causes**

1. An ssh:// or git@host: clone URL was pasted
2. A clone URL with an embedded token (https://user:token@host/...)
3. A browser URL with ?tab=... or #readme

**Impact.** Nothing was imported.

**How to fix**

1. Paste the repository's HTTPS address, for example https://github.com/owner/repo.
2. Never put a credential in the URL: private repositories are imported through an SCM connection with a token (Connectors → SCM).

**Verify**

1. The import is accepted and the repository is listed with the anonymous badge.


<a id="PTH-ONB-1102"></a>

## PTH-ONB-1102: Repository is not public

| | |
|---|---|
| Severity | warning |
| Category | authorization |
| HTTP status | 422 |
| AI help | not offered |
| Raised in | internal/repos/anonymous.go, internal/repos/anonymous_import.go, internal/worker/tools.go, internal/scans/jobs.go |

**What it means.** The provider answered the anonymous request as for a private, internal or missing repository (providers answer these the same way to an anonymous caller). Raised at import, by a sync of an anonymous repository that turned private (sync status permission_denied) and by a worker whose anonymous clone was refused.

**Confirmed cause.** The provider refuses anonymous access to the repository. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The repository is private or internal
2. The URL has a typo or the repository was renamed, moved or deleted
3. The repository was made private after it was imported

**Impact.** The repository is not imported, or an anonymous repository that turned private is no longer scanned.

**How to fix**

1. Open the URL in a private browser window: if it asks to sign in, the repository is not public.
2. Import private repositories through an SCM connection with a token (Connectors → SCM, then Import repositories).
3. Correct the URL if the repository was renamed or moved.

**Verify**

1. Sync of the repository succeeds, or the import through the SCM connection completes.


<a id="PTH-ONB-1103"></a>

## PTH-ONB-1103: Provider rate limit for anonymous requests reached

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | 429 |
| AI help | not offered |
| Raised in | internal/repos/anonymous.go |

**What it means.** The provider's rate limit for anonymous API requests was reached (GitHub: 60 requests per hour per IP address). error.details.retry_after_seconds says when to retry, when the provider tells.

**Confirmed cause.** The provider answered with its rate-limit response to an anonymous request. Confirmed automatically when this code is raised.

**Probable causes**

1. Many anonymous imports or syncs from the same egress IP address
2. Other clients behind the same NAT or proxy use the provider anonymously

**Impact.** The import or sync was not done; nothing else is affected.

**How to fix**

1. Wait the time in retry_after_seconds and try again.
2. For regular use, create an SCM connection with a token: authenticated requests have a much higher limit.

**Verify**

1. The import or sync succeeds after the wait.


<a id="PTH-ONB-1104"></a>

## PTH-ONB-1104: Provider not reachable for anonymous import

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/repos/anonymous.go |

**What it means.** The provider API or the git server (git smart HTTP) could not be reached to check that the repository is public.

**Confirmed cause.** The request to the provider failed (DNS, connection, TLS or timeout; named in the message). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The API container has no route to the provider (egress proxy or firewall)
2. The git host is not on the egress allowlist
3. A provider outage
4. A git server whose certificate is issued by a private CA

**Impact.** Nothing was imported.

**How to fix**

1. Check that the API can reach the host (egress proxy and allowlist: deploy/egress/allowlist.txt).
2. Retry later if the provider reports an outage.
3. For a self-hosted git server with a private CA, use a Generic Git SCM connection with its CA bundle instead.

**Verify**

1. The import succeeds.


<a id="PTH-ONB-1105"></a>

## PTH-ONB-1105: Repository already imported anonymously

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Raised in | internal/repos/anonymous_import.go |

**What it means.** An active anonymous repository with the same clone URL already exists in the organization (error.details.repository_id names it).

**Confirmed cause.** The organization already has an active anonymous repository with this clone URL. Confirmed automatically when this code is raised.

**Probable causes**

1. The repository was imported before, possibly by someone else
2. The same URL was submitted twice

**Impact.** No second repository was created.

**How to fix**

1. Open the existing repository (error.details.repository_id) and scan or sync it.
2. Archive the existing one first if a fresh import is really needed.

**Verify**

1. The repository list shows one anonymous repository for the URL.


<a id="PTH-ONB-1106"></a>

## PTH-ONB-1106: Repository host address not allowed

| | |
|---|---|
| Severity | warning |
| Category | security |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/repos/anonymous.go, internal/scm/safehttp.go |

**What it means.** The repository host is, or resolves to, a loopback, link-local or reserved address, or a private address while private networks are not allowed for SCM requests.

**Confirmed cause.** The host's address is blocked by the outbound network policy. Confirmed automatically when this code is raised.

**Probable causes**

1. A self-hosted git server on an internal network
2. DNS returns an internal address for the host name

**Impact.** No request was sent to the host; nothing was imported.

**How to fix**

1. Import repositories of internal git servers through an SCM connection (Generic Git) with "Allow private network".
2. An administrator can allow private networks for SCM requests installation-wide (PATHOS_SCM_ALLOW_PRIVATE_NETWORKS=true); loopback and link-local addresses stay blocked.

**Verify**

1. The import is accepted.

