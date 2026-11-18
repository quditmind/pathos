---
title: Scanners, scan profiles and custom rules
section: api-reference
order: 23
version: "1.0"
updated: 2026-11-19
summary: The scanner catalog, versioned scan profiles (scanners, thresholds, exclusions, timeouts, SBOM) and custom Opengrep detection rules.
---
# Scanners, scan profiles and custom rules

A **scan profile** decides which scanners run and how. Every [scan execution](scans.md) uses one profile version and stores a read-only snapshot of it. Repositories use their own profile or the organization default ([set the scan profile of a repository](repositories.md#set-the-scan-profile-of-a-repository)).

All endpoints are under `/api/v1`, need a browser session, and mutations need `X-CSRF-Token` (see [API reference overview](index.md)).

## Scanner catalog

`GET /api/v1/scanners` — permission `scanners.read` at any scope. Returns `{ "items": [scanner…] }`: every catalogued scanner, the Syft SBOM utility, and declarative plugin scanners that an online, non-revoked worker currently provides.

| Field | Description |
|---|---|
| `key`, `name` | Scanner key (used in profiles, findings and results) and display name |
| `category` | `secrets`, `sast`, `sca`, `iac`, `container`, `license`, `dast`, `supply-chain` (`sbom` for Syft) |
| `license_spdx`, `decision` | The scanner's licence and PATHOS's decision: `use`, `optional` or `restricted` (cannot be enabled) |
| `worker_family` | Worker image that runs it (`core`, …) |
| `adapter_available` | A worker can run it; others are catalogued only |
| `default_enabled` | Enabled in the seeded **Default** profile |
| `mandatory` | Always on (Gitleaks); added to every profile automatically |
| `target_only` | Runs only for [scan targets](scan-targets.md) (Trivy image, Nuclei) and is refused in profiles |
| `requires_build`, `output_format`, `homepage`, `notes` | Information |

## Scan profiles

### The profile object

```json
{
  "id": "0190c0de-0000-7000-8000-000000000201",
  "name": "Secrets and dependencies",
  "description": "Fast checks for every push",
  "is_default": false,
  "repository_count": 14,
  "current": {
    "id": "0190c0de-0000-7000-8000-000000000211",
    "version": 3,
    "change_note": "Add OSV-Scanner",
    "created_by": "Dana Owner",
    "created_at": "2026-11-17T09:00:00Z",
    "severity_threshold": "low",
    "exclusions": ["node_modules/**", "vendor/**"],
    "timeout_seconds": 1800,
    "sbom": true,
    "fail_on_critical": false,
    "retention_days": 90,
    "scanners": [ { "key": "gitleaks", "config": {} }, { "key": "osv-scanner", "config": {} } ]
  }
}
```

`GET /api/v1/scan-profiles/{id}` and the create and update responses add `history` (the 50 latest versions, newest first). Versions are immutable: every update creates a new version, and executions keep the version they used.

### Endpoints

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/scan-profiles` | `scans.read` or `repos.read` at any scope | Profiles that are not archived, default first |
| `GET` | `/api/v1/scan-profiles/{id}` | `scans.read` or `repos.read` at any scope | One profile with `history` |
| `POST` | `/api/v1/scan-profiles` | `profiles.manage` (organization-wide) | Create → `201` profile (version 1) |
| `PUT` | `/api/v1/scan-profiles/{id}` | `profiles.manage` (organization-wide) | New version with the given settings → `200` profile |
| `POST` | `/api/v1/scan-profiles/{id}/default` | `profiles.manage` (organization-wide) | Make it the organization default → `204` |
| `DELETE` | `/api/v1/scan-profiles/{id}` | `profiles.manage` (organization-wide) | Archive → `204`. Repositories using it fall back to the default profile. `409` for the default profile |

Audit actions: `scan_profile.create`, `scan_profile.update`, `scan_profile.set_default`, `scan_profile.archive`.

### Request body

`POST` and `PUT` take the settings below. `PUT` replaces the settings completely (omitted settings get their defaults); `name` and `description` are optional on `PUT`.

| Field | Default | Rules |
|---|---|---|
| `name` | — | Required on create; 1–200 characters; unique among active profiles (`409`) |
| `description` | `""` | |
| `change_note` | `Initial version` on create | Stored with the version |
| `severity_threshold` | `info` | `critical`, `high`, `medium`, `low`, `info`: lower-severity results are dropped |
| `exclusions` | `[]` | At most 100 relative glob patterns, each at most 200 characters, no `..` and no leading `/` |
| `timeout_seconds` | `1800` | 60–14400 |
| `sbom` | `false` | Generate an SBOM with Syft |
| `fail_on_critical` | `false` | Mark the execution `gate_failed` when it finds a new Critical finding |
| `retention_days` | `90` | 7–3650 |
| `scanners` | `[]` | `[{ "key", "config" }]`; `config` is a JSON object up to 4 KB |

Scanner rules (`400 invalid_request` otherwise):

- The key must be in the catalog (or a registered plugin), have an adapter, not be `target_only` and not be licence-restricted.
- Mandatory scanners are added automatically; duplicates are ignored.
- Grype scans the SBOM: it needs `sbom: true`, and Syft is then added automatically.

```json
{
  "name": "Secrets and dependencies",
  "severity_threshold": "low",
  "exclusions": ["node_modules/**"],
  "sbom": true,
  "scanners": [ { "key": "osv-scanner" }, { "key": "grype" } ]
}
```

## Custom rules

Opengrep (Semgrep-compatible) rule files.

**How they run:**

- Enabled files run in every new scan alongside the PATHOS baseline rules.
- Each scan's configuration snapshot records the rule file versions (`custom_rules: [{id, name, version}]`).
- The worker receives exactly those versions.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/custom-rules` | `scanners.read` | Rule files (without content) |
| `GET` | `/api/v1/custom-rules/{id}` | `scanners.read` | With content |
| `GET` | `/api/v1/custom-rules/{id}/versions` | `scanners.read` | Saved versions |
| `POST` | `/api/v1/custom-rules/validate` | `profiles.manage` | `{ content }` → `{ valid, rule_ids }` or `422 invalid_rules` |
| `POST` | `/api/v1/custom-rules` | `profiles.manage` | `{ name, description, content, enabled }` |
| `PUT` | `/api/v1/custom-rules/{id}` | `profiles.manage` | Any of the fields plus `change_note`; content or enabled changes create a new version |
| `DELETE` | `/api/v1/custom-rules/{id}` | `profiles.manage` | New scans stop using the file |

`scanners.read` is needed at any scope; `profiles.manage` organization-wide.

Validation runs without executing anything. It requires:

- a `rules:` list (at most 200 rules)
- for each rule: an `id` (unique across enabled files, not starting with the reserved `pathos.`), a `message`, a `severity` (ERROR, WARNING or INFO), non-empty `languages`, and a pattern (`pattern`, `patterns`, `pattern-either`, `pattern-regex`, or taint mode with `pattern-sources` and `pattern-sinks`)
