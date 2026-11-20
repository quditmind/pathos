---
title: Reverse engineering
section: api-reference
order: 10
version: "3.0"
updated: 2026-11-20
summary: Static reverse engineering of build artifacts from your own builds — input policy and authorisations, analyses in the sandboxed worker-rea lane, functions, strings, imports, sections, the binary call graph, the source ↔ binary diff and finding proposals. Behind the reverse_engineering feature flag.
---
# Reverse engineering

Reverse engineering (static tier) analyses an uploaded **build artifact** (a [scan target](scan-targets.md) of kind `artifact` or `mobile-app`) without executing it, stores the facts as a binary graph in the [CodeGraph](codegraph.md) store and compares them with the CodeGraph snapshot of the commit the artifact was built from. The design is in [PATHOS_REVERSE_ENGINEERING.md](../aspm/PATHOS_REVERSE_ENGINEERING.md); the [user guide](../user-guide/reverse-engineering.md) explains the screens.

Every endpoint answers `404` with `PTH-PLAT-1007` (`feature_disabled`) while the organization's `reverse_engineering` feature flag is off (Administration → Feature flags). Changes write audit log entries (`rea.*`).

## Input policy

By default PATHOS analyses only artifacts it can tie to the organization's own builds:

| Trust | Basis | Evidence PATHOS checks |
|---|---|---|
| `trusted` | `provenance` | The target's newest signature verification (`signature_verifications`, written by the cosign check of a target scan) has `attestation_status = verified` for an SLSA provenance attestation uploaded with the artifact, and the attested subject is the artifact's SHA-256. The source commit comes from the statement. |
| `trusted` | `signature` | The newest verification has `status = verified` with a key or keyless policy. |
| `authorized` | `authorization` | No verified evidence, but an active "analyse untrusted artifact" authorisation for this artifact's SHA-256 (with a reason, audited), and the input policy allows authorisations. |
| `untrusted` | — | Anything else: `POST /rea/analyses` answers `403 PTH-REA-1001`, nothing is queued, the refusal is audited. |

Verifications are recorded by the existing target scan: set the artifact target's signature policy (`config.signature`: key or keyless; `attestation: "slsaprovenance1"` for provenance), upload the signature (`signature` field) and/or the provenance bundle (`provenance` field) with the artifact, and scan the target once.

## Permissions

| Operation | Permission |
|---|---|
| Artifacts, analyses, facts, graph, diff, drafts | `findings.read` on the artifact's repository |
| Start an analysis | `scans.run` **and** `rea.run` on the repository |
| Recompute the diff against a chosen snapshot | `rea.run` |
| Authorise or revoke an untrusted artifact | `rea.authorize` |
| Create a finding from a draft, dismiss a draft | `findings.triage` |
| Read settings and tools | `scanners.read` or `findings.read` |
| Change settings | `scanners.manage` (organization-wide) |

Callers without any access to the repository get `404`.

## Settings

`GET /api/v1/rea/settings` · `PUT /api/v1/rea/settings`

```json
{ "enabled_tools": ["radare2", "binwalk"], "memory_mb": 4096, "timeout_minutes": 30,
  "input_policy": "own_builds_or_authorized", "decompiled_code_ai": "none",
  "ai_send_code_allowed": false, "updated_at": "2026-11-20T10:00:00Z" }
```

- `enabled_tools`: `radare2`, `binwalk`, `ghidra`, `jadx`, `ilspy` (at least one). Tools not installed in the worker image are skipped.
- `memory_mb` 512–16384 (passed to the tools; the sandbox container limit `PATHOS_REA_MEMORY` is the hard cap), `timeout_minutes` 5–230 (one execution is limited to 4 hours).
- `input_policy`: `own_builds_or_authorized` (default: own builds, other artifacts only with an authorisation) or `own_builds_only` (authorisations are refused and ignored).
- `decompiled_code_ai`: which AI model may see decompiled code — `none` (default), `local` (self-hosted providers only) or `cloud` (only while the default AI configuration allows sending code; otherwise `422 PTH-REA-1010`). `ai_send_code_allowed` is read-only. No M10 endpoint sends decompiled code to a model.

Errors: `422` invalid values, `422 PTH-REA-1010`.

## Tools

`GET /api/v1/rea/tools` → `{ "tools": [{ "key", "name", "license", "purpose", "optional", "installed", "version", "enabled" }], "worker_online": true, "analyser_version": "…" }`

`installed` and `version` come from the newest online worker-rea worker.

## Artifacts

`GET /api/v1/rea/artifacts?repository_id=&q=&limit=` (limit 1–500, default 100)

```json
{ "input_policy": "own_builds_or_authorized",
  "artifacts": [{ "target_id": "0196…", "name": "server", "file_name": "server", "sha256": "…", "size": 7340032, "kind": "artifact",
    "repository_id": "0196…", "repository_name": "acme/svc", "application_id": "0196…", "created_at": "…",
    "trust": { "status": "trusted", "basis": "provenance", "reason": "SLSA provenance verified for this artifact",
               "signature": { "status": "unsigned", "mode": "key", "verified_at": "…" },
               "provenance": { "status": "verified", "commit": "…", "builder": "https://…", "source_repository": "…", "verified_at": "…" },
               "authorization": null, "authorization_allowed": true },
    "last_analysis": { "…": "Analysis" } }] }
```

`provenance.status`: `verified`, `mismatch` (the statement names another file), `unverified`, `missing`, `invalid`, `error`.

### Authorise an untrusted artifact

`POST /api/v1/rea/artifacts/{target_id}/authorizations` `{ "reason": "Vendor agent we must review before rollout" }` → `201`

```json
{ "id": "0196…", "reason": "…", "authorized_by": "ana@example.com", "authorized_by_email": "ana@example.com",
  "created_at": "…", "artifact_sha256": "…" }
```

One active authorisation per artifact (a new one replaces the previous one), bound to the artifact's SHA-256. Errors: `422` reason shorter than 10 or longer than 1000 characters, `409 PTH-REA-1007` input policy `own_builds_only`, `422 PTH-REA-1006` not an artifact target.

`DELETE /api/v1/rea/artifacts/{target_id}/authorizations/{id}` → `204` (revoked, audited).

## Analyses

### Start

`POST /api/v1/rea/analyses` `{ "target_id": "0196…", "commit_sha": "optional" }` → `202 { "analysis": Analysis, "trust": Trust }`

Queues a scan execution with trigger `rea` that only a worker-rea worker leases (its own lane; it neither waits for nor blocks the repository's scans). The commit is the verified provenance commit; otherwise `commit_sha` (labelled `user`); otherwise the Go build information embedded in the binary (`binary`) once the analysis is stored. A second request while one is queued returns the queued analysis.

Errors: `403 PTH-REA-1001` untrusted artifact, `409 PTH-REA-1012` the provenance or authorisation names another file, `409 PTH-REA-1002` no worker-rea online, `422 PTH-REA-1006` not an artifact, target disabled or repository archived, `422` invalid `commit_sha`.

### Analysis

```json
{ "id": "0196…", "target_id": "0196…", "artifact_name": "server", "artifact_sha256": "…", "repository_id": "0196…",
  "repository_name": "acme/svc", "application_id": "0196…", "scan_job_id": "0196…",
  "status": "ready", "trust_basis": "provenance", "commit_sha": "…", "commit_source": "provenance",
  "snapshot_id": "0196…", "source_snapshot_id": "0196…", "diff_status": "ready",
  "format": "elf", "arch": "x86", "language": "go",
  "tools": { "radare2": { "version": "6.2.6", "status": "succeeded", "detail": "", "duration_ms": 4200 } },
  "stats": { "functions": 4812, "strings": 9000, "go": { "go_version": "go1.27.4", "main_module": "example.com/svc" },
             "firmware": { "entries": [], "files": [] } },
  "error_code": "", "error": "", "requested_by": "Ana", "created_at": "…", "started_at": "…", "finished_at": "…" }
```

`status`: `queued`, `running`, `ready`, `partial` (a tool failed or the analyser hit its limits), `failed` (`error_code` `PTH-REA-1003` sandbox failure, `1004` timeout, `1005` invalid document, `1009` store failure). `diff_status`: `pending`, `ready`, `no_commit`, `no_source_snapshot`.

- `GET /api/v1/rea/analyses?target_id=&repository_id=&status=&limit=` → `{ "analyses": [Analysis] }` (newest first; History).
- `GET /api/v1/rea/analyses/{id}` → `{ "analysis", "counts": { "functions", "imports", "strings", "sections", "calls" }, "trust" }`

The endpoints below need a `ready` or `partial` analysis (`409 PTH-REA-1011` otherwise).

### Functions

`GET /api/v1/rea/analyses/{id}/functions?q=&match=&limit=&offset=` (`match`: `matched`, `binary_only`, `library`, `unmatched`, `sensitive`; limit 1–500) → `{ "items": [Function], "total" }`

```json
{ "node_id": "0196…", "key": "fn:0x6a3f20", "name": "net/http/pprof.Index", "addr": "0x6a3f20", "offset": 6963000, "size": 412,
  "section": ".text", "tool": "radare2", "library": true, "match": "library", "sensitive": true, "source": null, "has_code": true }
```

`GET /api/v1/rea/analyses/{id}/functions/{node_id}` → `{ "function", "code": { "tool", "kind": "pseudo_c|disassembly|java|csharp", "text" } | null, "code_withheld"?, "callers", "callees", "imports", "strings", "evidence" }`. Code is shown to people with `findings.read`; secrets are redacted.

### Strings, imports, sections

- `GET …/strings?q=&kind=&limit=&offset=` (`kind`: `text`, `url`, `path`, `route`, `secret`, `format`) → `{ "items": [{ "node_id", "value", "offset", "vaddr", "section", "kind", "redacted", "tool" }], "total" }`. Secrets are redacted by the analyser and again by the API (`value` `[REDACTED]`); a redacted value is never returned and never matched by `q`.
- `GET …/imports?q=&limit=&offset=` → `{ "items": [{ "node_id", "name", "library", "kind", "tool", "sensitive" }], "total" }`
- `GET …/sections` → `{ "items": [{ "node_id", "name", "offset", "vaddr", "size", "perm", "entropy", "tool" }] }`

### Binary graph

`GET /api/v1/rea/analyses/{id}/graph?view=&focus=&depth=&filters=&limit=` — the same parameters and response shape as the [CodeGraph graph endpoint](codegraph.md#views), on the analysis's binary snapshot. Views: `binary_call_graph` (default), `binary_imports`, `binary_layout`, `binary_strings`. Node types `binary`, `binary_function`, `import`, `string_ref`, `section`; edge types `defines`, `calls`, `imports`, `references`. Every edge is `verified` with evidence of kind `binary`: `ref` is the file offset (`0x…`), `detail` names the tool. Source views answer `400 PTH-GRAPH-1003`.

`GET /api/v1/rea/analyses/{id}/graph/nodes/{node_id}` — the CodeGraph node inspector shape (no findings or source links for binary nodes).

Binary snapshots are never listed with an application's CodeGraph snapshots and never used by threat models.

### Source ↔ binary diff

`GET /api/v1/rea/analyses/{id}/diff?side=&kind=&sensitive=true&limit=&offset=`

```json
{ "status": "ready", "commit_sha": "…", "commit_source": "provenance", "source_snapshot_id": "0196…",
  "counts": { "binary_only": 7, "source_only": 12, "matched": 310 }, "total": 7,
  "items": [{ "id": "0196…", "side": "binary_only", "kind": "route", "name": "/debug/pprof/", "sensitive": true,
    "sensitive_reason": "net/http/pprof registers /debug/pprof/ profiling handlers … (route not in the API inventory)",
    "binary": { "node_id": "0196…", "key": "str:0x7a1010", "offset": 8000016, "tool": "radare2" },
    "source": null,
    "evidence": [{ "evidence": "verified", "kind": "binary", "ref": "0x7a1010", "detail": "radare2: string \"/debug/pprof/\"" },
                 { "evidence": "verified", "kind": "file_line", "ref": "cmd/server/main.go:7", "detail": "CodeGraph: registered by import \"net/http/pprof\"" }] }] }
```

`side`: `binary_only`, `source_only`, `matched`; `kind`: `function` (the artifact's own functions; library code is not compared), `package` (Go packages and sensitive native imports), `route` (HTTP paths in the binary against the source routes), `string` (URLs referenced by the artifact's own code against external services).

`POST /api/v1/rea/analyses/{id}/diff` `{ "source_snapshot_id": "0196…" }` compares with a CodeGraph snapshot a person chose (ready, same repository; `commit_source` becomes `user`) and returns the diff. Errors: `409 PTH-REA-1008` not a ready snapshot of the artifact's repository, `409` drafts of the analysis were already decided.

### Finding drafts

`GET /api/v1/rea/analyses/{id}/drafts` → `{ "drafts": [Draft] }`

```json
{ "id": "0196…", "title": "Profiling endpoints (/debug/pprof) shipped in the binary", "description": "…", "severity": "high",
  "rule_id": "rea/go-pprof", "cwe": ["CWE-215"], "status": "proposed", "label": "proposal", "evidence": [Ref],
  "diff_item_id": "0196…", "finding_id": null, "application_id": "0196…", "analysis_id": "0196…", "created_at": "…" }
```

Drafts are proposals derived from sensitive items only in the binary; they never become findings by themselves.

- `POST /api/v1/rea/drafts/{id}/create-finding` → `201 { "finding_id", "status": "needs_review" }` — a finding of category `binary`, status `needs_review`, attributed to the analysis execution and the artifact target, with the evidence in its description. `409` when the draft was already decided.
- `POST /api/v1/rea/drafts/{id}/dismiss` `{ "reason": "…" }` → `200 Draft` (`status: dismissed`).
- **Add to threat model** uses the [threat model API](threat-models.md) (`POST /api/v1/threat-models/{id}/threats`).

## Errors

| Code | Status | When |
|---|---|---|
| `PTH-REA-1001` | 403 | Artifact not from your own builds and not authorised |
| `PTH-REA-1002` | 409 | No worker-rea online |
| `PTH-REA-1003` | — | The analysis failed in the sandbox (on the analysis) |
| `PTH-REA-1004` | — | The analysis timed out (on the analysis) |
| `PTH-REA-1005` | — | Invalid analysis document (on the analysis) |
| `PTH-REA-1006` | 422 | Not an artifact target, disabled target or archived repository |
| `PTH-REA-1007` | 409 | Authorisations disabled by the input policy |
| `PTH-REA-1008` | 409 | No ready source snapshot for the diff |
| `PTH-REA-1009` | — | Store failure (on the analysis) |
| `PTH-REA-1010` | 422 | Decompiled-code AI policy refuses the setting |
| `PTH-REA-1011` | 409 | Analysis not ready |
| `PTH-REA-1012` | 409 | Provenance or authorisation names another file |

Details and fixes: [troubleshooting](../troubleshooting/rea.md).
