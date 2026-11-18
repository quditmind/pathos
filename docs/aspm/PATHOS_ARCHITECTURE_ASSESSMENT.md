# PATHOS architecture assessment (phase 0 baseline)

> **Status: historical snapshot.** Written in phase 0 of the ASPM programme (2026-11-17) and not updated since. It describes PATHOS as it was before the ASPM phases, as the baseline for [PATHOS_FEATURE_GAP_ANALYSIS.md](PATHOS_FEATURE_GAP_ANALYSIS.md). The gaps listed under "does not yet have" below were addressed in ASPM phases 1 to 10 (see [PATHOS_IMPLEMENTATION_ROADMAP.md](PATHOS_IMPLEMENTATION_ROADMAP.md)); what is still open is listed in the register. For the current architecture read [ARCHITECTURE.md](../ARCHITECTURE.md); for the current schema, [DATABASE.md](../DATABASE.md).

It was based on the code on `main`, plus the Human Review module in PR #29, which was complete with CI green but not yet merged.

## 1. Summary

PATHOS is already a working, self-hosted ASPM foundation:

- multi-provider repository onboarding
- a sandboxed, distributed scanning pipeline that runs 7 engines and normalises their output
- a de-duplicated finding store with lifecycle and SLA tracking
- AI review that can use a local model (Ollama)
- manual review with four-eyes approval
- scheduling, notifications, scoped RBAC, MFA, audit logging, backup and restore, and observability

What it does **not** yet have:

- **External intelligence**: EPSS, CISA KEV, CVE details.
- **Contextual risk**: application-level scoring, reachability, a dependency or context graph.
- **More engines**: DAST, API, container image, IaC breadth. Most of the ~50 catalogued scanners have no adapter.
- **Ingestion from outside**: SARIF and JSON import, SBOM import.
- **Developer-workflow integration**: pull-request checks, outbound webhooks, Jira, ServiceNow.
- **Governance**: a general policy engine, compliance control mapping, executive and custom reporting.

The architecture can absorb all of these without a rewrite. None of the 100 capabilities needs a framework change.

## 2. Technology

| Layer | Technology | Notes |
|---|---|---|
| Backend | Go 1.27, `net/http` ServeMux, pgx v5, goose migrations | One binary with roles `api`, `jobs`, `scheduler`. 21 internal packages (22 with `review`) |
| Database | PostgreSQL 18 | 67 tables on `main` (+9 in PR #29), 11 migrations (+1). Least-privilege app role; append-only audit and history tables enforced by grants |
| Queue / cache | Valkey | Rate limiting, leader election. Job queues are in PostgreSQL (`SKIP LOCKED`) |
| Frontend | React 19, TypeScript 6, Vite 8, TanStack Router and Query, Tailwind 4, Radix, Recharts | Feature folders under `src/features`, a shared design system, dark and light themes |
| Identity | Keycloak (OIDC with PKCE) | Local accounts, TOTP MFA, password policy, enforced MFA, admin API limited to private networks |
| Scan workers | `worker-core` image (Go agent and pinned tools) | Non-root, read-only filesystem, `cap_drop: ALL`, tmpfs, no Docker socket, egress through an allow-listing Squid proxy |
| AI | Provider abstraction: Anthropic, OpenAI, xAI, self-hosted OpenAI-compatible (Ollama, vLLM) | Strict JSON schema, redaction, fenced untrusted evidence, approval policy |
| Storage | PostgreSQL inline or S3-compatible (SeaweedFS profile) for scan artifacts; encrypted file store for source snapshots and evidence | AES-256-GCM with per-object keys |
| Proxy | Caddy | TLS, security headers, `/internal` blocked |
| Observability | slog JSON, OpenTelemetry traces and metrics, optional Grafana LGTM | |
| Deployment | Docker Compose (single host), production override, backup, restore and upgrade scripts | |

Full detail: [ARCHITECTURE.md](../ARCHITECTURE.md), [DATABASE.md](../DATABASE.md), [SECURITY.md](../SECURITY.md), [OPERATIONS.md](../OPERATIONS.md).

## 3. Modules (backend packages and UI)

| Area | Package(s) | UI | State |
|---|---|---|---|
| Identity, sessions, users, teams, roles | `auth`, `identity`, `authz`, `org` | Users, Organization | Scoped RBAC (organization, region, business unit, repository), 10 system roles (+ Independent Reviewer), custom roles, no privilege escalation |
| Assets | `repos`, `scm` | Repositories, Imports, Applications, Asset settings, Tags, SCM connections | GitHub, GitLab, Bitbucket, Azure DevOps (PAT, OAuth, App, service principal), uploads, discovery, sync, webhooks, Repository IDs, ownership and exposure metadata |
| Scanning | `scans`, `scanners`, `schedule`, `worker` | Scan Overview, Scans, Schedules, Comparison, Scan profiles, Scanners and workers | Versioned profiles, leases, retries, stages and logs, config snapshots, schedules with windows and plans |
| Findings | `scans` (ingest, findings), `vuln` | Findings, Risk acceptances, SBOM, Policies | Fingerprinting, cross-tool SCA de-duplication, lifecycle trigger and history, SLA, risk acceptance with expiry, SBOM inventory, licence policy |
| AI and MCP | `ai`, `mcp` | AI reviews, AI settings, MCP registry, API tokens | Automated review queue, approval, local models, MCP server with personal tokens |
| Human Review (PR #29) | `review` | 6 pages and the assessment workspace | Queue, 8-tab workspace, decisions, independent review, evidence, AI assistance, reports |
| Notifications | `notify` | Notifications admin, inbox | Outbox, rules, templates, SMTP, in-app |
| Dashboard and search | `dashboard`, `search` | Dashboard, Ctrl-K | KPIs from live data, trends |
| Platform | `platform/*`, `audit`, `secrets` | Audit log | Rate limits, telemetry, object storage, encryption keyring |

About 180 REST endpoints on `main` (about 215 with PR #29), all under `/api/v1`, plus an internal worker API on `:8081` and MCP at `/mcp`.

## 4. Scanning architecture

```
scheduler/webhook/manual ─▶ scan_jobs (queued) ─lease─▶ worker (sandbox)
   clone/snapshot ─▶ tools ─▶ SARIF/JSON ─▶ POST results ─▶ ingest (normalise, fingerprint, de-duplicate) ─▶ findings
                                                                 └▶ raw artifacts (retention) ─▶ AI review queue ─▶ Human Review queue
```

- Engines with adapters (`worker-core`): **Gitleaks** (mandatory), **Opengrep** (12 PATHOS baseline rules plus mounted rule packs), **Trivy fs**, **Syft** (CycloneDX SBOM), **Grype**, **OSV-Scanner**, **Checkov**.
- Catalogued with a licence decision but **no adapter** (about 45): TruffleHog, Semgrep CE, CodeQL, Bandit, Gosec, …, ZAP, Nuclei, Schemathesis, Trivy image, KICS, Kubescape, Scorecard, ScanCode, …
- Adding an engine means four things:
  - a catalogue entry in `scanners/catalog.go`
  - an invocation in `worker/tools.go`
  - a parser (SARIF, so usually none)
  - adding the tool to a worker image

  This is a workable plugin seam, but it is compiled in.
- **Targets are repositories only.** DAST, API and image scanning need new target types (URL, API spec, image reference).
- Not present: incremental scanning, PR-diff scanning, and external SARIF/JSON or SBOM import.

## 5. Data model highlights

- `findings`:
  - one row per (repository, fingerprint), with `scanner_keys[]` as provenance and `finding_occurrences` holding commit, file and line per sighting
  - category, rule, CWE[], CVE, CVSS (score only), package coordinates, location, snippet
  - status, SLA, assignee, recurrence, AI status
  - `human_*` columns (PR #29)
- Status values: `open`, `in_progress`, `needs_review`, `fixed`, `false_positive`, `accepted_risk`. Every change is recorded by a trigger in `finding_status_history`.
- `applications` (name, description, business unit, owner, security owner, criticality) ↔ `repositories` (many to one), which carry most of the context: environment, criticality, exposure, data classification, lifecycle, owners, compliance scopes.
- `sbom_components` is a **flat** list per repository (name, version, purl, type, licences). It has no dependency edges and no direct/transitive flag.
- Multi-tenancy is ready in the schema: `organization_id` is on every table, with composite foreign keys. At runtime there is one organization per deployment (`PATHOS_ORG_SLUG`).

## 6. Security posture of the platform

These strengths must be kept:

- the worker sandbox and egress allow-list
- secret redaction in reports, AI prompts and logs
- encryption at rest for secrets, source and evidence
- append-only audit, enforced by database grants
- CSRF and same-site sessions
- rate limiting
- gosec, govulncheck, Trivy and ZAP gates in CI
- MFA enforcement
- the Keycloak admin surface limited to private networks

Every new feature must preserve them: no external calls without configuration, no code execution on the API host, redaction before AI.

## 7. Must not break

- the `/api/v1` contracts used by the UI, MCP tools and webhooks
- the finding status values (stored in history and used by triggers, SLA and AI policy)
- fingerprints (changing them would re-open every finding)
- the worker API protocol
- Repository and Scan IDs
- the RBAC permission keys
- the backup format
- the least-privilege grant function `pathos_apply_app_grants`, which every migration must keep updating
