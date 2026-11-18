---
title: Application versions, VEX and component policies
section: api-reference
order: 27
version: "1.1"
updated: 2026-11-19
summary: Application versions (releases) with frozen SBOM and findings snapshots, the component portfolio, OpenVEX and CycloneDX VEX export and import with reviewed suggestions, and operational component policies.
---
# Application versions, VEX and component policies

## Application versions

An application version (release) freezes, for each repository of an [application](applications.md#the-application-object), the scan it was built from: the commit, the component inventory and the findings that scan saw. Later scans do not change a version.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/applications/{id}/versions` | `repos.read` on the application's scope or on one of its repositories | `{ "items": [Version], "application": { "id", "name" }, "can_manage" }`, newest first |
| `POST` | `/api/v1/applications/{id}/versions` | `repos.manage` on the application's scope (business unit, else organization) | Creates a version → `201 { "version": Version, "warnings": [string] }`. Audited (`application_version.create`) |
| `GET` | `/api/v1/applications/{id}/versions/{vid}` | as for the list | `{ "version", "application", "repositories", "components", "findings", "can_manage" }` |
| `DELETE` | `/api/v1/applications/{id}/versions/{vid}` | `repos.manage` | Deletes the version and its snapshot → `204`. Findings are not changed. Audited (`application_version.delete`) |

Create body:

| Field | Description |
|---|---|
| `version` | Required, 1–100 characters, unique per application (`409` otherwise) |
| `description` | Optional, at most 2000 characters |
| `released_at` | Optional RFC 3339 timestamp |
| `repositories` | Optional `[{ "repository_id", "scan_job_id" }]`. Default: every non-archived repository of the application with its latest successful scan of the scan branch (not pull request or target scans). A `scan_job_id` must be a successful scan of that repository (`400` otherwise) |

The component inventory holds only each repository's latest components; when an older scan is chosen its components are copied only if they are still the current ones, otherwise the response carries a warning. A repository without a successful scan is included without components or findings, with a warning.

`Version`: `id`, `application_id`, `version`, `description`, `released_at`, `created_by`, `created_at`, `repository_count`, `component_count`, `open_findings` (frozen findings whose current status is open, in progress or needs review).

In the detail, `repositories` (`repository_id`, `full_name`, `ref`, `commit_sha`, `scan_job_id`) lists the repositories the caller may read; `components` (`repository_id`, `name`, `version`, `purl`, `type`, `licenses`) only those of repositories with `sbom.read`; `findings` (`finding_id`, `repository_id`, `category`, `title`, `severity`, `cve`, `package_name`, `package_version`, `fixed_version`, `status_at_release`, `status`) only those with `findings.read`. `status` is the finding's current decision.

## Component portfolio

`GET /api/v1/portfolio/component-versions` (`sbom.read` at any scope) answers "which released versions, and which repositories today, contain this component or vulnerability?" within the caller's scope. Give at least one of:

| Parameter | Description |
|---|---|
| `name` | Component name (case-insensitive, exact) |
| `version` | Optional exact component version (with `name` or `purl`) |
| `purl` | Package URL; the version and qualifiers are ignored (prefix match on the base purl) |
| `cve` | Vulnerability identifier, matched against frozen findings (versions) and open, in-progress, needs-review or accepted-risk findings (repositories) |

Response: `{ "versions": [{ "application_id", "application_name", "version_id", "version", "repository", "component", "component_version", "purl", "matched_by" }], "repositories": [{ "repository_id", "repository", "component", "component_version", "purl", "matched_by" }] }`, at most 1000 each. `matched_by` is `component` or `vulnerability`.

## VEX export

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/repositories/{id}/vex?format=openvex\|cyclonedx` | `findings.export` on the repository | Statements for the repository's findings that have a CVE |
| `GET` | `/api/v1/applications/{id}/versions/{vid}/vex?format=openvex\|cyclonedx` | `findings.export` on at least one of the version's repositories | Statements for the version's frozen findings (repositories without `findings.export` are left out) |

`format` defaults to `openvex` (OpenVEX v0.2.0, `application/json`); `cyclonedx` produces a CycloneDX 1.6 BOM with `vulnerabilities[].analysis` (`application/vnd.cyclonedx+json`). Both are downloads. Every export is audited (`vex.export`).

Each statement covers one vulnerability and one component (the purl from the inventory, else `pkg:generic/<name>@<version>`). When the same component and vulnerability appear more than once, the most conservative status wins. A frozen finding uses its current decision; one whose finding was deleted keeps its status at release.

| PATHOS status | OpenVEX | CycloneDX `analysis` |
|---|---|---|
| False positive | `not_affected`; `justification: vulnerable_code_not_in_execute_path` when reachability analysis says not reachable; `impact_statement` from the decision reason | `state: not_affected`, `justification: code_not_reachable` (when known), `detail` |
| Accepted risk | `affected`, `action_statement` "Risk accepted; no fix planned until <date>: <justification>" | `state: exploitable`, `response: [will_not_fix]` |
| Fixed | `fixed` | `state: resolved` |
| Open, in progress | `affected`, `action_statement` "Update <package> to <fixed version>" when a fixed version is known | `state: exploitable`, `response: [update]` when a fix is known |
| Needs review | `under_investigation` | `state: in_triage` |

## VEX import

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/repositories/{id}/vex?filename=` | `findings.triage` on the repository | Body: the VEX document (JSON, at most 10 MB) → `201` ImportResult |
| `POST` | `/api/v1/applications/{id}/versions/{vid}/vex?filename=` | `findings.triage` on at least one of the version's repositories | Same; only findings of repositories with `findings.triage` are matched |
| `GET` | `/api/v1/vex-imports` | `findings.read` at any scope | Imports in scope: `id`, `repository_id`, `repository`, `application_version_id`, `application`, `version`, `format`, `filename`, `document_sha256`, `author`, `statements`, `matched`, `pending`, `imported_by`, `created_at` (at most 200) |

The format is detected: OpenVEX (v0.2.0 and the older string `vulnerability` form; `subcomponents` are the components) or a CycloneDX BOM with `vulnerabilities`. The document itself is not stored, only its SHA-256, author, filename and counts.

A statement matches a finding when its vulnerability (or an alias) equals the finding's CVE or advisory ID and, when the statement names products, one of them is the finding's component: by purl (version and qualifiers ignored, but a version in the purl must equal the finding's package version) or, when the inventory has no purl, by package name.

**An import never changes a finding.** Matching `not_affected` and `fixed` statements become pending suggestions (one pending suggestion per finding and status; none when the finding already has that status). `affected` and `under_investigation` statements are counted as informational: PATHOS already tracks those findings.

ImportResult: `import_id`, `format`, `statements`, `matched` (statement–finding matches), `suggestions` (created), `informational`, `unmatched` (statements that matched no finding). Audited (`vex.import`).

## VEX suggestions

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/vex-suggestions?status=&import_id=` | `findings.read` at any scope | Suggestions of repositories in scope (at most 500). `status`: `pending`, `approved`, `rejected` or empty for all |
| `POST` | `/api/v1/vex-suggestions/{id}/approve` | `findings.accept_risk` on the repository | Body (optional): `{ "note" }` (at most 2000 characters) |
| `POST` | `/api/v1/vex-suggestions/{id}/reject` | `findings.accept_risk` on the repository | Same body |

Each item: `id`, `import_id`, `finding_id`, `finding_title`, `finding_status`, `severity`, `package_name`, `package_version`, `repository_id`, `repository`, `vulnerability`, `vex_status` (`not_affected` or `fixed`), `justification`, `impact_statement`, `status`, `requested_by_id`, `requested_by`, `decided_by`, `decided_at`, `decision_note`, `created_at`, `can_decide` and, when the caller cannot decide, `cannot_decide_reason`.

Four eyes: the person who imported a statement cannot decide it (`403 four_eyes`; also enforced by a database constraint). A decided suggestion answers `409`.

- Approving `not_affected` closes the finding as a **false positive** through the normal lifecycle: a status-history entry whose reason quotes the statement, importer and approver, and a `finding.status` audit entry. A finding that is accepted risk or fixed answers `409` (reject the suggestion, or reopen the finding first).
- Approving `fixed` only records the statement. A finding is resolved only when a scan no longer detects it.

Decisions are audited (`vex_suggestion.approve`, `vex_suggestion.reject`).

## Component policies

Operational policies over the component inventory (all non-archived repositories).

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/component-policies` | `sbom.read` at any scope | `{ "items": [Policy], "can_manage" }` |
| `POST` | `/api/v1/component-policies` | `settings.manage` (organization-wide) | Creates → `201` Policy; evaluated immediately when enabled. Audited |
| `PUT` | `/api/v1/component-policies/{id}` | `settings.manage` | Replaces the definition; its violations are recomputed. Audited |
| `DELETE` | `/api/v1/component-policies/{id}` | `settings.manage` | `204`; violations are deleted with it. Audited |
| `POST` | `/api/v1/component-policies/evaluate` | `settings.manage` | Evaluates every enabled policy now → `{ "policies", "components", "violations", "not_evaluated" }`. Audited |
| `GET` | `/api/v1/component-policy-violations?policy_id=&repository_id=&state=open\|resolved` | `sbom.read` at any scope | Violations of repositories in scope (at most 1000): `id`, `policy_id`, `policy_name`, `violation_state`, `repository_id`, `repository`, `component`, `component_version`, `purl`, `detail`, `first_seen_at`, `last_seen_at`, `resolved_at` |

Policy: `name` (1–200, unique), `description`, `enabled` (default `true`), `violation_state` (`fail`, `warn` (default) or `info`), `condition_kind` and `params`:

| `condition_kind` | `params` | Violates when |
|---|---|---|
| `component_age` | `{ "max_days": 1–36500 }` | The package's latest release is older than `max_days` (possibly unmaintained) |
| `outdated` | `{ "versions_behind": "any" \| "major" }` | A newer version (or a newer major version) than the one in use exists |
| `license` | `{ "licenses": [SPDX], "include_unknown": bool }` | The component declares one of the licences (case-insensitive), or declares none when `include_unknown` |
| `vulnerability_severity` | `{ "min_severity": "critical" \| "high" \| "medium" \| "low" \| "info" }` | An open, in-progress or needs-review SCA or container finding on this component and version is at or above the severity |

Package age and the latest version come from [package health](supply-chain.md) (the deps.dev feed, off by default). Components without that data are not evaluated for `component_age` and `outdated` (counted in `not_evaluated`), never reported as violations. Versions are compared numerically (`1.10.0` is newer than `1.9.0`); versions that are not dotted numbers are not evaluated.

Policies are re-evaluated hourly by the jobs process. A violation is resolved when the component no longer matches (or leaves the inventory) and reopens if it matches again.
