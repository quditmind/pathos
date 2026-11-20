Quditmind PATHOS · applies to v2.2.0 · status: Proposed

# PATHOS Application Security Lifecycle

This document describes the nine-phase Application Security Lifecycle that the **lifecycle release** builds on PATHOS 2.2.0. It shows which parts exist today and which are planned. Every item is marked:

- **Existing**: in the code today, with the path cited.
- **Partial**: some of it exists; the gap is stated.
- **Planned**: in an approved milestone (M1 to M11), not yet built.
- **Proposed**: suggested in this document, not yet approved.

Nothing marked Planned or Proposed exists in the code. The capability-by-capability evidence is in [PATHOS_FEATURE_GAP_ANALYSIS.md › Lifecycle release capability matrix (M0)](PATHOS_FEATURE_GAP_ANALYSIS.md#lifecycle-release-capability-matrix-m0). The audit of the current code is in [PATHOS_ARCHITECTURE_ASSESSMENT.md §8](PATHOS_ARCHITECTURE_ASSESSMENT.md#8-lifecycle-release-audit-m0).

The owner's build prompt names this work "PATHOS 2.0" from a 1.1.1 base. PATHOS 2.0.0 is already released, and the code is 2.2.0. This document uses "the lifecycle release" and assigns no version.

Paths are relative to `backend/internal/` for Go and to `frontend/src/` for TypeScript unless they start with another top-level folder.

## Purpose

PATHOS today covers each security activity as a separate module: onboarding, scanning, findings, AI review, Human Eye, posture and reporting. The lifecycle organises these modules into one ordered flow per application, from connecting a source to monitoring it in production. Results from later phases feed back into earlier ones.

The lifecycle gives three things:

- **one place per application** that shows how far the application has come through the phases (the application profile hub, Planned M3)
- **a menu ordered by phase** (Planned M1), so a user can follow the work from left to right
- **explicit feedback loops**, so that a change or a decision in one phase triggers the right work in another

## Scope

In scope:

- The nine phases, the shared application context and the feedback loops.
- For each phase, the existing modules (packages, routes, tables, pages) and the planned modules (milestone).

Out of scope:

- Implementation detail of new modules. That belongs in the per-module documents named in prompt §8: `PATHOS_INTEGRATION_TECHNICAL_SPEC.md`, `PATHOS_CODEGRAPH_ARCHITECTURE.md`, `PATHOS_THREAT_MODELLING.md`, `PATHOS_REVERSE_ENGINEERING.md`, `PATHOS_AI_SECURITY_INTELLIGENCE.md`, `PATHOS_UI_UX_WIREFRAMES.md` and `PATHOS_ARCHITECTURE_DECISION_RECORDS.md`.
- Multi-tenancy. 2.2.0 supports it as an option that is off by default ([MULTI_TENANCY.md](../MULTI_TENANCY.md)). The lifecycle keeps it working and adds nothing for it.

## Architecture

The lifecycle is a **view over the existing architecture**, not a new runtime. It does not change these parts:

- the single Go binary with roles `api`, `jobs` and `scheduler`
- the PostgreSQL job queues
- the sandboxed worker images
- the `/api/v1` contract

The phases map onto existing packages, and new modules are added in the same style:

- a Go package under `backend/internal/`
- additive goose migrations
- routes under `/api/v1`
- a feature folder under `frontend/src/features`
- a worker pack where a module runs tools

```
          ┌──────────────────────── shared application context ────────────────────────┐
          │ application · repositories · targets · versions · SBOM · findings · runtime │
          │ classification & tags · owners · policies · (CodeGraph, threat model: new)  │
          └────────────────────────────────────────────────────────────────────────────┘
   1 Connect → 2 Inventory → 3 Discover → 4 Threat model → 5 Reverse engineering
        → 6 Assess → 7 Validate & intelligence → 8 Remediate & gate → 9 Report & monitor
                         ▲                                                    │
                         └──────────── feedback loops 1–7 (below) ────────────┘
```

Phases are an **order of work, not a state machine**. An application can be in several phases at once: for example, re-assessed after every commit while its threat model is still in draft. The "lifecycle progress strip" (Planned M3) shows what each phase has produced for the application. It does not show a single current phase.

### The nine phases

| # | Phase | Question it answers | Existing modules (2.2.0) | Planned modules |
|---|---|---|---|---|
| 1 | **Connect** | Where does the code, the build and the runtime live, and can PATHOS reach them? | SCM connections for GitHub, GitHub Enterprise Server, GitLab, Bitbucket Cloud, Azure DevOps Services and Server (`scm/providers.go`, `repos/connections.go`, `/admin/scm`). OAuth apps (`repos/oauth.go`). Ticketing for Jira and ServiceNow (`tickets/connectors.go`, `/admin/integrations`). Outbound webhooks for Slack, Teams and JSON (`notify/webhooks.go`). Container registries and Kubernetes clusters (`runtimectx/registry.go`, `runtimectx/k8s.go`). CLI, VS Code, JetBrains, CI templates, pre-commit and pre-receive hooks (`backend/cmd/pathos-cli`, `ide/`, `integrations/`) | Connectors hub `/connectors` with Health (M2). Bitbucket Data Center, generic Git, cloud accounts, secret managers, SIEM (M2). Custom CA per connection (M2) |
| 2 | **Inventory** | Which applications, repositories and other assets exist, who owns them, and how important are they? | Applications (`repos/applications.go`, `/applications`). Repositories with classification, exposure and owners (`repos/repositories.go`, `/repositories`). Import jobs with drafts (`repos/imports.go`). Unmanaged assets from SCM inventory (`posture/unmanaged.go`). Coverage (`posture/coverage.go`). Tags with mandatory categories (`repos/tags.go`). Asset settings (`repos/assets.go`). Scan targets: image, URL, API, SBOM, mobile, LLM endpoint (`scans/targets.go`). Runtime workloads (`runtimectx`, `/runtime`) | One guided onboarding flow, extended classification, and the application profile hub `/applications/$id` (M3) |
| 3 | **Discover** | What is inside the application: components, routes, data stores, calls, and how do they connect? | SBOM inventory and dependency edges (`vuln/sbom.go`, `sbom_dependencies`). Component portfolio (`/portfolio`). Context graph, built on request (`posture/graph.go`, `/posture/graph`). Package- and function-level reachability (`reach`, `reachscan`). Endpoint and authentication changes found as material changes (`material/rules.go`). Declared public endpoints (`scans/endpoints.go`) | CodeGraph: discovery worker, graph store with an evidence label per edge, graph API, shared graph component, views, snapshots and diff (M4). API & endpoints inventory (M4) |
| 4 | **Threat model** | What can go wrong, along which path, and what stops it? | Attack paths from the internet to findings (`posture/attack.go`, `/posture/attack-paths`). Blast radius (`/posture/blast-radius`). CWE on findings | STRIDE engine on CodeGraph, ATT&CK / CAPEC / CWE / D3FEND mapping, an editable and approvable model, import and export (M5) |
| 5 | **Reverse engineering** | Does the shipped binary match the source, and what does an unknown binary do? | Binary hardening checks (checksec-style), CVE Binary Tool, capa and YARA-X (`workers/binary`, `scanners/catalog_binary.go`). Jadx, Androguard and mobsfscan (`workers/mobile`). Build-artifact targets and cosign signature verification (`signature_verifications`) | `workers/rea` static tier, source-vs-binary diff, workspace (M10). VM sandbox tier, never on the PATHOS host (M11, separate approval) |
| 6 | **Assess** | Which weaknesses does the application have now? | 25 scan types and 98 catalogued integrations (`scanners/scantypes.go`, `scanners/catalog*.go`). 9 worker images (`workers/`). Versioned scan profiles (`scans/profiles.go`). Scans, schedules and comparison (`scans`, `schedule`). Result import in 232 formats (`scanners/import_*.go`). Findings with fingerprints and cross-tool de-duplication (`scans/ingest.go`, `scans/findings.go`) | Quick / Standard / Comprehensive / Custom profiles, the kind of check shown instead of tool names, "confirmed by N engines" (M6) |
| 7 | **Validate & intelligence** | Is each finding real and how much does it matter? | AI review with approval policy (`ai`, `/ai`). AI Security Analyst and reports (`analyst`, `/ai/analyst`). Human Eye with independent review (`review`, `/human-review/*`). Risk scoring with EPSS, KEV and OSV (`risk`, `intel`). Secret validation (`scans/secretvalidation.go`). Runtime context per finding (`GET /api/v1/findings/{id}/runtime`) | Cross-phase correlation; reproducible AI evidence records with stored prompt and response; model per task; evidence labels on AI conclusions (M7) |
| 8 | **Remediate & gate** | Who fixes what by when, and what may ship? | SLA policies and assignees. Fix pull requests on four SCMs (`depfix`, `scans/fixprs.go`). Verified AI fixes (`aifix`, `scans/aifixes.go`). Tickets (`tickets`). Security policies with block, review, SLA and notify actions (`policy`). PR checks (`scans/prchecks.go`). CI gate and CLI (`scans/gate.go`, `pathos gate`). Secret push protection (`pushprotect`, `integrations/pre-*`). Risk acceptance, suppression rules, VEX, component policies | Remediation workspace; gates at IDE, pre-commit, PR, CI, release and deploy with block, warn, exception and approval outcomes; fix verification with before-and-after evidence for every fix type (M8) |
| 9 | **Report & monitor** | What is the posture now, how is it changing, and what changed since last time? | Dashboard, executive overview, reports with CSV and schedules (`dashboard`, `reporting`). Application posture and benchmarking (`posture`, `bench`). Compliance mapping to 5 frameworks (`compliance/catalog.go`). Developer insights (`insights`). Notifications (`notify`). Material changes per scan (`material`) | Continuous monitoring feed, architecture drift against a CodeGraph snapshot, lifecycle overview, version-stamped exports (M9; stamping starts in M1) |

Two groups sit outside the phases, as in prompt §5:

- **Configurations**: scan profiles, scanners and workers, scan coverage, custom rules, asset settings, risk and intelligence, review configurations and AI settings. Reverse engineering tools are planned (M10).
- **Administration**: users, organization, developer attribution, notifications, AI usage, MCP registry and the audit log.

The M0 menu check found that Runtime, Secret validation and the multi-tenant Organizations page are not placed in the prompt's table ([assessment §8.3](PATHOS_ARCHITECTURE_ASSESSMENT.md#83-menu-mapping-check-prompt-5-against-the-code)).

## Components

### Shared application context

Every phase reads and writes one context per application. Today that context exists in the schema, linked through `application_id`:

| Context element | Existing table or source | Link to the application | Status |
|---|---|---|---|
| Application (name, key, owners, criticality, business unit) | `applications` (`backend/migrations/00002_repositories.sql:32-42`, `00013_finding_intelligence.sql:154-166`) | — | Existing |
| Repositories with classification, exposure, owners, compliance scopes | `repositories`, `repository_compliance_scopes` (`00009_asset_onboarding.sql`, `00010_repository_identity_exposure.sql`) | `repositories.application_id` (`00002_repositories.sql:64,79`) | Existing |
| Tags and mandatory tag categories | `repos/tags.go` | through repositories | Existing |
| Scan targets (image, URL, API, SBOM, mobile, LLM endpoint) | `scan_targets` (`00015_scan_targets.sql`, `00031_mobile_llm_targets.sql`) | through `scan_targets.repository_id` | Existing |
| Versions (frozen release snapshots of repositories, components, findings) | `application_versions` and three link tables (`00027_remediation_vex_push.sql:62-102`) | direct | Existing |
| SBOM components and dependency edges | `sbom_components`, `sbom_dependencies` (`00016_aspm_inventory.sql:11`) | through repositories | Existing |
| Findings and occurrences, with risk score, reachability, AI and human verdicts | `findings`, `finding_occurrences`, `ai_reviews`, `human_reviews` | through repositories; risk re-scored when the application changes (`00013_finding_intelligence.sql:59-73`) | Existing |
| Runtime workloads and mappings | `runtime_workloads.application_id`, `runtime_app_mappings` (`00035_runtime_context.sql:120,164-171`) | direct | Existing |
| Policies, violations, risk acceptances, VEX | `security_policies`, `policy_violations` (`00021_governance.sql`), `vex_*` | organization-wide, evaluated per repository | Existing |
| Material changes between scans | `material_changes` (`00028_developer_context.sql:28`) | through repositories | Existing |
| CodeGraph nodes, edges, evidence, snapshots | — | per repository and application | Planned (M4) |
| Threat model, threats, mitigations, approvals | — | per application | Planned (M5) |
| Reverse-engineering artifacts and diffs | — | per application version | Planned (M10) |
| Lifecycle progress per phase | — (computed from the rows above) | per application | Proposed: a read-only API that counts what each phase produced, with no new state table, so the strip cannot drift from the data |

### Cross-cutting components

| Component | Status | Where |
|---|---|---|
| Brand header, version chip, About, help menu, help drawer | Planned (M1) | `components/layout/AppShell.tsx`, `Logo.tsx`, `features/help` |
| `GET /api/v1/meta` with version, commit and build date | Planned (M1) | `server` (today: `GET /healthz` returns `version` only) |
| Diagnostic catalogue `PTH-<AREA>-<NNNN>` and `<ErrorPanel>` | Planned (M1) | `platform/diag` (new); today: `platform/httpx` slugs |
| Feature-flag framework | Planned (M1) | none today; modules use separate per-organization and per-repository switches |
| Shared graph component | Planned (M4) | today: custom SVG in `posture/ContextGraphPage.tsx` |
| Evidence labels (verified / observed / AI-inferred) | Planned (M4, M5, M7) | none today |

## Data flow

1. **Connect** stores a connection. Credentials go to the encrypted secret store (`secrets`), and the rest goes to the connection table (`scm_connections`, `ticket_connections`, `runtime_clusters`, `registry_connections`).
2. **Inventory** creates applications, repositories and targets from imports, SCM inventory runs or manual entry. Classification and tags are set at registration.
3. **Discover** runs on every scan today:
   - the SBOM (Syft) and the dependency graph
   - reachability (`reach.Update` at ingest, `scans/ingest.go:478`)
   - material changes against the previous scanned commit

   CodeGraph discovery (Planned M4) will run in a worker in the same lease protocol.
4. **Threat model** (Planned M5) reads the CodeGraph and the attack paths and writes a versioned model for a person to approve.
5. **Reverse engineering** (Planned M10) runs on build artifacts from the organization's own builds, in a worker with no network.
6. **Assess** follows the existing pipeline. The scheduler, a webhook or a person queues a job; a worker leases it and runs the tools; ingest normalises, fingerprints and de-duplicates the results into findings. Approved suppression rules and security policies are applied in the same transaction (`scans/ingest.go:482-490`).
7. **Validate** follows the existing queues. AI review runs first, then Human Eye picks up findings that need a person (`server/server.go`, "After a scan"). Risk is re-scored when intelligence or context changes (`risk_dirty`, `risk/service.go:244-247`).
8. **Remediate & gate** follows the existing paths:
   - fix PRs and AI fixes produce pull requests
   - PR checks and the CI gate return a verdict to the SCM or pipeline
   - a finding is closed only when a later scan no longer detects it (`scans/fixprs.go:856`)
9. **Report & monitor** reads all of the above for dashboards, reports and notifications. The planned monitoring feed (M9) combines the change events into one stream.

## Dependencies

| Phase | Depends on | Status |
|---|---|---|
| 3 Discover (CodeGraph) | a parser stack such as tree-sitter or Joern in a worker image | Planned (M4); tool choice in the tool catalogue and an ADR |
| 4 Threat model | CodeGraph (M4); offline copies of ATT&CK, CAPEC, CWE and D3FEND data | Planned (M5); licences to verify before bundling |
| 5 Reverse engineering | a new worker pack (`workers/rea`); for M11 a separate VM host | Planned (M10, M11) |
| 7 Validate | an AI provider (local model by default for code) | Existing provider abstraction (`ai`); per-task routing Planned (M7) |
| All | the shared graph component and its ADR (React Flow + ELK or Cytoscape) | Planned (M4) |
| All | feature flags, so each module stays off until approved (rule 9) | Planned (M1) |

## APIs

There is no lifecycle-specific API today. Each phase uses the existing routes of its modules (388 `/api/v1` routes, [assessment §8.1](PATHOS_ARCHITECTURE_ASSESSMENT.md#api-routes)). Planned and proposed additions:

- `GET /api/v1/meta` (Planned M1)
- connector APIs (Planned M2)
- graph APIs (Planned M4)
- threat model APIs (Planned M5)
- RE APIs (Planned M10)
- `GET /api/v1/applications/{id}/lifecycle`, a read-only per-phase summary for the progress strip and the lifecycle overview (Proposed)

The API design belongs in [PATHOS_API_DESIGN.md](PATHOS_API_DESIGN.md).

## Protocols

No new protocol is introduced by the lifecycle itself. The existing ones stay:

- REST/JSON over HTTPS through Caddy
- the internal worker API on `:8081` (lease, heartbeat, results), which must not break (§7 of the assessment)
- SCM webhooks with signature checks (`scm/webhook.go`)
- MCP at `/mcp`
- OTLP for telemetry

Connector protocols (Planned M2) are specified per vendor in `PATHOS_INTEGRATION_TECHNICAL_SPEC.md`.

## Authentication

Unchanged:

- Keycloak OIDC with PKCE for people
- personal API tokens for the CLI, IDE plugins, CI and MCP (`mcp/tokens.go`)
- bootstrap and per-worker tokens for workers

Every phase uses the existing scoped RBAC: organization, region, business unit and repository. New modules add permission keys and do not change existing ones ([RBAC_MATRIX.md](../RBAC_MATRIX.md)).

## Security requirements

These apply to every phase. Each is Existing for today's modules and must be kept by new ones:

- **Secrets** are write-only, encrypted at rest (AES-256-GCM), never logged, never shown and never sent to an AI model (`secrets`, `platform/logging/logging.go:48-55`, AI redaction `ai/generate.go:17-30`). The AI never asks a user to paste a secret.
- **No code execution on the API host.** Tools run in sandboxed worker images. Repository code runs only in the network-less sandbox (`worker/sandbox.go`). Reverse-engineering detonation needs a separate VM host (M11).
- **Nothing fake.** Status shown is measured status only. Example data appears only in tests and fixtures.
- **Evidence labels** on graph edges, threats and AI conclusions: *verified (static)*, *observed (runtime)* or *AI-inferred*. Planned (M4, M5, M7); none exist today.
- **No blocking without policy.** Today, PR checks block on a repository severity threshold and the CLI on `--fail-on` ([assessment C6](PATHOS_ARCHITECTURE_ASSESSMENT.md#84-conflicts-between-the-prompt-and-the-code-the-code-wins-for-what-exists)). The owner must decide whether these count as explicit policies.
- **Tool names hidden** outside Scan profiles and Scanners & workers. Planned (M6); today several pages show them ([matrix L130](PATHOS_FEATURE_GAP_ANALYSIS.md#m6-scan-profiles-and-tool-catalogue)).

## Error handling (with error codes)

Today errors use the `httpx` envelope `{"error":{"code","message","details?","fields?"},"request_id"}` with snake_case codes (`platform/httpx/httpx.go:22-70`). Phase-relevant codes that exist today:

| Phase | Existing codes (examples) |
|---|---|
| 1 Connect | `scm_error`, `idp_error`, `ticket_failed` |
| 2 Inventory | `validation_failed`, `mandatory_tags_missing`, `too_large`, `uploads_unavailable`, `source_required` |
| 3 Discover | `no_sbom`, `no_snapshot` |
| 6 Assess | `lease_lost`, `worker_revoked`, `malware_detected`, `malware_scanner_unavailable`, `object_storage_error` |
| 7 Validate | `ai_not_configured`, `ai_failed`, `ai_refused`, `not_verified`, `not_scored` |
| 8 Remediate & gate | `fix_pr_not_available`, `no_target_file`, `no_candidates` |
| 9 Report & monitor | `attribution_disabled` |

Planned (M1): a catalogue with codes `PTH-<AREA>-<NNNN>` in 16 areas. They map to the phases as follows:

| Areas | Phase |
|---|---|
| `CONN`, `SYNC` | 1 Connect |
| `ONB` | 2 Inventory |
| `DISC`, `GRAPH` | 3 Discover |
| `TM` | 4 Threat model |
| `REA` | 5 Reverse engineering |
| `SCAN`, `WORK` | 6 Assess |
| `AI` | 7 Validate & intelligence |
| `GATE`, `REM` | 8 Remediate & gate |
| `REP`, `MON` | 9 Report & monitor |
| `PLAT`, `AUTH` | every phase |

How the new codes sit beside the existing slugs is an open ADR ([assessment C4](PATHOS_ARCHITECTURE_ASSESSMENT.md#84-conflicts-between-the-prompt-and-the-code-the-code-wins-for-what-exists)). No `PTH-` code exists yet.

## Operations

- The lifecycle adds no new service in M1 to M3. M4 (discovery) and M10 (reverse engineering) add worker packs, deployed as opt-in Compose profiles like the eight family images. M11 needs a separate host.
- Each new module is behind a feature flag and off by default until its milestone is approved (Planned M1; there is no flag framework today).
- Backup, restore and upgrade scripts keep working because migrations stay additive.

## Implementation status

| Phase | Status | Main gap |
|---|---|---|
| 1 Connect | Partial | One hub with health; more vendors; custom CA per connection |
| 2 Inventory | Partial | Guided flow; application profile hub |
| 3 Discover | Partial | CodeGraph (store, evidence, views, snapshots) |
| 4 Threat model | Partial (attack paths and blast radius only) | STRIDE model, framework mapping, approval |
| 5 Reverse engineering | Partial (binary hardening, capa, YARA-X, mobile decompilation) | Static RE worker, source-vs-binary diff, workspace; sandbox tier |
| 6 Assess | Existing | Profile templates, category-only UI |
| 7 Validate & intelligence | Partial | Reproducible evidence records, model per task, evidence labels |
| 8 Remediate & gate | Partial | Workspace; release and deploy gates; warn outcome; policy-only blocking |
| 9 Report & monitor | Partial | Monitoring feed, drift, lifecycle overview, stamped exports |

### Feedback loops

The flow design defines seven feedback loops. The M9 milestone is done when all seven are wired and tested.

**Implemented in M9** (flag `continuous_monitoring`; [user guide](../user-guide/monitoring.md), [API](../api-reference/monitoring.md)). The M9 brief numbered the loops differently from the table below; the wiring follows the brief, and each loop has an integration test in `backend/test/integration/m9_monitoring_test.go`:

| Brief loop | Wired in | Target effect | Test |
|---|---|---|---|
| 1 New commit → rediscovery | push/merge webhook → scan → `codegraph.OnScanFinished` (rate-limited) | rediscovery queued, `rediscovery.queued` | `TestM9LoopsArchitecture` |
| 2 Dependency change → SBOM reassessment | `feedback.Loops.OnSnapshotReady` on component changes between snapshots | component policies re-evaluated, dependency findings re-scored, `dependency.changed` | `TestM9LoopsArchitecture` |
| 3 Architecture change → threat model | drift per snapshot; `threatmodel.AutoUpdate` | new draft version (approved untouched) or `threat_model.review_needed` | `TestM9LoopsArchitecture` |
| 4 New CVE → risk reassessment | intelligence sync marks findings dirty; `risk.Recompute` compares before and after | re-scored findings, `risk.rescored` | `TestM9LoopRiskRescore` |
| 5 Fix merged → targeted rescan | M8 merged-fix loop; item marked `fix_submitted` | targeted verification, `fix.verification_queued` / `fix.verified` | `TestM9LoopFixVerification` |
| 6 Gate failure → developer feedback | `gates.Evaluate` (only decisions with a policy) | PR check (existing), `gate.failed` notification (in-app, e-mail, webhooks), feed | `TestM9LoopGateFeedback` |
| 7 New findings → AI intelligence | `ai.OnScanFinished` queue → the automated AI review, which writes an M7 AI evidence record (prompt, response, model) linked from the review | queued for AI triage (`ai.triage_queued`); the conclusion is an AI-inferred evidence record pending a person's decision (`ai.triage_concluded`); never auto-approved, a false-positive verdict always waits for a person | `TestM9LoopAITriage` |

Loop 7 of the table below ("verdict → tune rules") is not part of the brief and stays a proposal.

| # | Loop | What exists today | Status | Missing |
|---|---|---|---|---|
| 1 | **Gate failed → developer** | PR checks set a commit status and comment on the four SCMs (`scans/prchecks.go`, `scm/status.go:31-35`); blocking policies name themselves in the summary (`prchecks.go:162`); the CLI gate exits 1 (`backend/cmd/pathos-cli/main.go:55`); `policy.violated` and `scan.failed` notifications (`notify/events.go`) | Existing | Gate verdict in the IDE plugins (`ide/vscode`, `ide/jetbrains` show findings only); release and deploy gates (M8) |
| 2 | **New commit → rediscovery** | A push or merge webhook on the scan branch queues a scan (`scans/jobs.go:236-262`); each branch scan computes material changes against the previous scanned commit (`scans/changes_worker.go`, `material`) and re-runs reachability (`scans/ingest.go:478`) | Partial | CodeGraph rediscovery and snapshot diff (M4). Today the whole scan re-runs, not only discovery |
| 3 | **Dependency change → SBOM** | Every scan with Syft stores a new SBOM and rebuilds the component inventory and dependency edges (`scans/ingest.go:137-172`); the material-change category `dependency` compares with a baseline (`material_dependency_baselines`, `00028_developer_context.sql:59`); component policies are evaluated (`component-policies/evaluate`) | Existing | No event-driven SBOM refresh between scans; a dependency change is seen at the next scan |
| 4 | **Architecture change → threat model** | Material changes detect authentication, endpoint, crypto, IaC-exposure, CI/CD, secrets and sensitive-data changes (`material/rules.go:11-27`). They raise the `change.material` notification (`notify/events.go:37-40`) and can be a policy condition (`policy/policy.go:40-43`) | Partial (signal only) | No threat model to update (M5). Proposed: a material change in these categories marks the application's threat model "needs review" |
| 5 | **New CVE → re-prioritise** | Intelligence feeds (EPSS, KEV, OSV) mark affected findings `risk_dirty` (`intel/feeds.go:232,260`, `intel/osv.go:353`), and the jobs role re-scores them (`risk.Recompute`, `risk/service.go:244-247`) | Existing | A new CVE for a component that has no finding yet appears only at the next scan, because there is no SBOM re-match without a scan. Re-prioritisation of threats (M5) |
| 6 | **Fix merged → targeted rescan** | Merging to the scan branch triggers a full scan through the webhook (`scans/jobs.go:240-254`); findings close only when a later scan misses them (`scans/fixprs.go:856`); fix PR state refresh (`POST /api/v1/fix-prs/{id}/refresh`); AI fixes are verified before and after in the sandbox (`00033_verified_ai_fixes.sql`) | Partial | The rescan is not targeted at the fixed findings' scanners and files; no before-and-after evidence for dependency fix PRs (M8) |
| 7 | **Verdict → tune rules** | A false-positive or accepted verdict survives re-detection (only `fixed` re-opens, `scans/ingest.go:309-310`); approved suppression rules apply at ingest (`scans/ingest.go:482-484`); the dashboard reports the AI false-positive rate (`dashboard/catalog.go:73`); custom rules can be edited (`/configurations/custom-rules`) | Partial | No per-rule precision from human and AI verdicts, and no proposal to disable or change a noisy rule or profile. Proposed: per-rule verdict statistics feeding scan-profile and custom-rule suggestions, applied only by a person (no silent suppression) |

## Known limitations

- The prompt's menu table was drawn from 1.1.1. Four current menu items have no place in it, and the "55 pages" count is 58 in 2.2.0 ([assessment §8.3](PATHOS_ARCHITECTURE_ASSESSMENT.md#83-menu-mapping-check-prompt-5-against-the-code)).
- The context graph is computed on request and not stored. Graph snapshots and drift cannot be built until M4 adds a store.
- Phase 5 static tooling is partial (no radare2, Ghidra, angr, ILSpy or binwalk). The existing sandbox is a container on the worker host, not a VM.
- The 20 "kinds of check" in prompt §7 do not match the 25 existing scan types one to one. M6 must map them, not replace them.
- Three e2e tests pin today's menu and Help link ([assessment C11](PATHOS_ARCHITECTURE_ASSESSMENT.md#84-conflicts-between-the-prompt-and-the-code-the-code-wins-for-what-exists)).

## Future improvements

- **Proposed:** `GET /api/v1/applications/{id}/lifecycle`, computed from existing tables, for the progress strip and the lifecycle overview.
- **Proposed:** loop 4: a material change in the authentication, endpoint, IaC or data categories marks the application's threat model "needs review".
- **Proposed:** loop 6: a targeted rescan that runs only the scanners that reported the fixed findings, on the merge commit.
- **Proposed:** loop 7: per-rule verdict statistics shown on Custom rules and Scan profiles, with suggestions a person must apply.
- **Planned (M9):** one continuous monitoring feed that combines commit, dependency, API, CVE and gate events.
