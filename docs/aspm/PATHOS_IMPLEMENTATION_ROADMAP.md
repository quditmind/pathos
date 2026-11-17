# PATHOS ASPM implementation roadmap

From the gap analysis (`PATHOS_FEATURE_GAP_ANALYSIS.md`). Each phase ships as its own pull request (or several) with migrations, backend, UI, tests, docs and an updated register. Nothing is marked Completed without backend logic, UI, persistence and tests.

## 1. Target architecture

Same stack and deployment, with these additions:

```
             ┌───────────── ingestion ──────────────┐
 scanners ──▶│ worker results │ SARIF/JSON import │ SBOM import │──▶ normalise ─▶ findings (+ provenance)
             └──────────────────────────────────────┘                        │
 intel feeds (EPSS, KEV, CVE; online or offline files) ──▶ intel tables ─────┤
 context (applications, repositories, exposure, criticality, components,     ▼
          dependency edges, reachability, reviews) ─────────────▶ risk engine (configurable, explainable)
                                                                             │
        policies ─▶ gates, PR checks, SLAs, required review ◀────────────────┤
        outbound: webhooks, Jira, ServiceNow, notifications ◀───────────────┘
```

- **Intelligence layer** = relational context, not a separate graph database. Applications, repositories, components, dependency edges, findings, owners, endpoints and reviews are joined by foreign keys. Graph questions (blast radius, attack paths) are recursive SQL views behind one service, `internal/intel`.
- **Connectors** (`internal/connectors`): one interface for outbound integrations (webhook, Jira, ServiceNow, chat). All are optional and disabled by default.
- **New target types** for workers: `repository` (today), `url`, `api_spec`, `image`, `artifact`, `sbom`, handled by additional worker families (`dast`, `container`) with the same sandbox and egress rules.

## 2. Phases

| Phase | Scope (feature numbers) | Main deliverables | Depends on |
|---|---|---|---|
| **0** | Assessment | These documents and the register | — |
| **1** | Unified data model (32, 35, 37, data for 38–40, 43) | Finding fields: CVSS version and vector, confidence, exploit signals, KEV and EPSS columns, risk score and factors; application IDs and fields (16, 26); intel tables; status presentation (D2) | — |
| **2** | Ingestion and engines (4, 13, 62, 7, 8, 3, 67, 15) | SARIF/JSON and SBOM import API and UI; image and URL targets; Trivy image, Dockle, ZAP, Nuclei, Schemathesis, zizmor and actionlint adapters; custom rule management | 1 |
| **3** | ASPM inventory (16–30) | Application posture page, coverage matrix, shadow and unmanaged report, dependency edges, context graph views, benchmarking | 1 |
| **4** | Vulnerability intelligence (36–43, 33, 34) | EPSS, KEV and CVE feeds (online and offline), risk engine (§4), reachability (govulncheck, import usage), attack paths, cross-tool correlation, suppression rules | 1, 3 |
| **5** | Manual validation (51, 56–58) | Optional N-level approval, AI patch proposals with approval, AI correlation | 4 |
| **6** | AI Security Analyst (E) | Analyst workspace, usage dashboard, dependency analysis, risk explanation, technical and executive AI reports | 4 |
| **7** | Supply chain (61–75) | SPDX, SBOM import, package health (outdated, end of life, Scorecard), malicious-package classification, PR checks (72), commit attribution (73), artifacts (74), provenance verification (75) | 2, 4 |
| **8** | Governance (77, 78, 82, 83, 95) | Recovery codes, SAML and OIDC brokering guide and tests, policy engine, compliance mapping, multi-tenancy (if D3 = yes) | 4 |
| **9** | Reporting and integrations (84, 85, 90–94) | Executive dashboard, saved and scheduled reports, outbound webhooks, Jira, ServiceNow, Slack and Teams, REST API tokens | 8 |
| **10** | Production readiness (99, 100) | Declarative adapters, offline database bundles, air-gap guide, load and security regression, release | all |

Within a phase, every feature follows the same sequence:

1. design note
2. migration (additive, with a Down migration)
3. backend and tests
4. UI and tests
5. documentation
6. register update
7. completion report in `docs/DEVELOPMENT_ROADMAP.md`

## 3. Decisions needed from the product owner

| # | Decision | Recommendation |
|---|---|---|
| D1 | Rename "Human Review" to **"Human Eye"** and regroup the navigation into the 10 proposed sections | Keep the routes, change the labels only; regroup when phases 3, 6 and 9 add their pages, so no empty sections are created |
| D2 | Finding statuses New, Open, In Progress, Under Review, Confirmed, False Positive, Accepted Risk, Resolved, Reopened | **Present** them without migrating the stored values: New = open and not yet triaged (first seen in the last scan); Under Review = `needs_review` or a review in progress; Confirmed = human disposition confirmed; Resolved = `fixed`; Reopened = recurrence > 0 and open. Keeps the API, history, SLA and AI contracts intact |
| D3 | Real multi-tenancy (several organizations in one deployment) | Only if you host PATHOS for several customers. The schema is ready; runtime work is moderate (tenant resolution, administration, isolation tests). Otherwise defer |
| D4 | External feeds (EPSS, KEV, NVD) need outbound access | Off by default; enable per feed with an egress allow-list entry, or import files offline |
| D5 | Jira and ServiceNow | Optional connectors in phase 9. Generic outbound webhooks come first |

## 4. Contextual risk engine (design)

The risk score is in the range 0–100 per finding. It is **explainable**: every factor and its contribution is stored with the score. It is **configurable**: weights per organization, versioned like the scan profiles.

```
base        = severity score (critical 9.5, high 7.5, medium 5, low 2.5, info 0) or the CVSS base score when present
likelihood  = max(EPSS percentile factor, KEV ? 1.0 : 0, public exploit ? 0.8 : 0)   (unknown ⇒ neutral 0.5, never 0)
context     = criticality (critical 1.3 … low 0.8) × exposure (internet 1.3, internal 1.0, none 0.8, unknown 1.1)
reachability= reachable 1.2, unknown 1.0, not reachable 0.6     (not reachable never hides a finding)
confidence  = scanner confidence (high 1.0, medium 0.9, low 0.75); human-confirmed 1.1
controls    = compensating controls recorded in a review 0.7
fixability  = fix available 1.05 (prioritises quick wins slightly)
score       = clamp(10 × base × (0.5 + likelihood) × context × reachability × confidence × controls × fixability / 1.75, 0, 100)
bands       = critical ≥ 75, high ≥ 50, medium ≥ 25, low > 0
```

- False positives, accepted risks and resolved findings get a score of 0 with the reason recorded.
- The score is recomputed on ingest, when feeds update, on context changes (criticality, exposure) and on review decisions, in a batched background job.
- The application score is the 90th percentile plus a count-weighted tail of its open findings' scores (documented).
- The UI shows the factor breakdown and "why this score".

## 5. Breaking-change risks and how they are avoided

| Risk | Mitigation |
|---|---|
| Status renames | D2 presentation layer; stored values unchanged |
| Fingerprint changes from new correlation | Correlation **links** findings (`finding_correlations`) and never merges or re-fingerprints |
| Severity changes from risk scoring | Severity stays the scanner's; risk score is a separate column; SLA stays severity-based unless policy opts in |
| New worker families | Same worker API; families are additive images |
| External network access | Every feed or connector is disabled until configured; egress allow-list |
| Multi-tenancy | Only behind D3; the default single-organization mode is unchanged |

## 6. Phase 1 completion report (2026-11-17)

**Decisions taken:** D1 rename to Human Eye (labels only); D2 lifecycle statuses derived, stored values unchanged; D3 single organization; D4 EPSS and KEV online daily by default, with offline import.

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00013 | Finding intelligence columns, triggers that mark findings for re-scoring, intel tables, feed configuration and runs, versioned risk models, application IDs and fields, confidence backfill, full Down migration |
| `internal/risk` | Explainable model, validation, versioning API, background recomputation |
| `internal/intel` | EPSS and KEV parsers (gzip aware), atomic loaders, daily online updates with failure back-off, offline import, CVE lookup |
| Ingest | Confidence (category-based, with explicit tool metadata) and CVSS vectors (Trivy, Grype) |
| Findings API | Lifecycle status, intel fields, application; filters `lifecycle`, `kev`, `epss_min`, `risk_min`, `confidence`, `reachability`, `application_id`; risk ordering with keyset pagination |
| UI | Risk and lifecycle columns and filters, KEV badge, risk explanation in the finding drawer, **Risk & intelligence** administration page, application fields |
| Docs | API reference, user guide (Help Center), DATABASE.md, CHANGELOG, register update |

**Verified on the local stack:**

- live feeds loaded 407,165 EPSS scores and 1,781 KEV entries
- all 337 findings were scored: 30 critical, 114 high, 174 medium, 19 low
- the top findings are critical CVEs in the 94th–98th EPSS percentile

**Tests:**

- unit tests for the risk model (ordering, calibration, validation), the feed parsers, and confidence and vector parsing
- an integration test covering offline import, online download over TLS, scoring, explanation, re-scoring when context changes, model versioning and permissions, lifecycle filters, risk ordering and application IDs
- Vitest for the risk panel, the feeds page and the findings columns

**Register:** 52 completed, 29 in progress, 19 not started (from 47, 32 and 21).

**Next:** phase 2, ingestion (SARIF/JSON and SBOM import) and new engines and targets.

## 7. Phase 2a completion report (2026-11-17)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00014 | `dast` category, `import` trigger, `pathos_register_import_tool()`, `import_jobs`, imported SBOM inventories, `custom_rules` and versions, full Down migration |
| Result imports | SARIF 2.1, Grype JSON and PATHOS findings JSON (documented). Per-tool scanner keys `import-<category>-<tool>` keep provenance and stable fingerprints. Each import is a scan execution through the normal pipeline; partial imports never resolve findings |
| SBOM import | CycloneDX and SPDX 2.x JSON into the component inventory |
| Custom rules | Opengrep rule files with server-side validation (no execution), versions, unique IDs, enable/disable; snapshots pin versions; the worker writes them to a private temporary directory |
| UI | **Scanning → Import Results** (results, SBOM, history), **Configurations → Custom rules** (editor, validate, versions) |

**Verified on the local stack:**

- a SARIF import created 5 findings, recorded as execution `QD-SCAN-000007`
- a custom rule ran in a real worker scan of `nodejs-goof` and produced 2 findings

**Tests:**

- unit: import keys and formats, the generic JSON format, SPDX, rule validation, worker rule files
- integration: imports (permissions, partial and complete, DAST, invalid files), SBOM, rules, version pinning
- Vitest: 132

**Register:** 56 completed, 28 in progress, 16 not started.

**Next:** phase 2b, scan targets for container images, URLs (DAST) and API specs on workers; vulnerability matching of imported SBOMs; CI/CD pipeline scanning.

## 8. Phase 2b completion report (2026-11-17)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00015 | `scan_targets` (image, url, api, sbom; encrypted credentials; authorization statement), `scan_jobs.target_id/target_kind`, `findings.scan_target_id`, `scan_target` secret kind, full Down migration |
| Scan targets API | CRUD, SBOM upload, scan, filters on findings (`scan_target_id`, `target_kind`) and scans (`asset_type`, `target_id`); retries of target scans |
| Workers | Target jobs without a clone; `trivy image` with registry credentials; Nuclei for URL and OpenAPI targets (reviewed template subset, no intrusive/brute-force/DoS, no interactsh, rate-limited); Grype on downloaded, SHA-256-verified SBOMs; zizmor for GitHub Actions; egress reachability preflight; target credentials redacted from logs |
| Worker image | zizmor 1.32.0 and the Nuclei templates 10.5.1 pinned by SHA-256; Nuclei 3.11.1 built from its Go module (checksum database) with Go 1.27.4 and patched dependencies, like Gitleaks |
| Pipeline | Target-namespaced fingerprints; auto-resolve scoped to the same target; profiles cannot include target scanners |
| UI | **Scanning → Scan targets** (add, edit, authorize, scan, findings and last scan); Findings **Asset** filter and target names; Scans asset types |

**Verified on the local stack:**

- an image target (`ghcr.io/containerd/alpine:3.14.0`) produced 48 container findings with packages and risk scores
- an SBOM target produced 5 Grype findings
- web and API targets against a throwaway local application: blocked by the egress proxy, the scan failed with the allowlist explanation (the first run, before the preflight existed, showed the proxy's error page producing false findings, which is why the preflight was added); allowed, about 10,500 requests went through the proxy and the scan completed
- zizmor found 18 issues in `nodejs-goof`'s workflows; a profile with Nuclei was rejected
- test targets and their findings were removed afterwards

**Tests:**

- unit: Nuclei JSONL, zizmor and Trivy image parsing, target scanners, image/URL/OpenAPI validation, Nuclei arguments, workflow detection, preflight, credential redaction
- integration: targets (authorization, validation, coalescing, lease payload with decrypted credential, SBOM download checksum, per-target resolution, delete/disable, audit)
- Vitest: 135

**Register:** 60 completed, 27 in progress, 13 not started.

**Next:** phase 3, ASPM inventory: application posture rollup, coverage matrix, unmanaged repository report, dependency edges and the context graph.

## 9. Phase 3 completion report (2026-11-17)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00016 | `sbom_components.bom_ref` and `depth`, `sbom_dependencies`, `scm_remote_repositories`, `scm_inventory_runs`; full Down migration |
| Dependency graph | CycloneDX `dependencies` and SPDX `DEPENDS_ON` / `*DEPENDENCY_OF` parsed for scanned and imported SBOMs (duplicate refs aliased); depth by breadth-first search from the roots; repository dependencies and "how it gets in" paths; dependency paths on findings |
| SCM inventory | Daily listing of every connection's repositories (jobs service), on-demand refresh, run history; truncated listings never remove entries |
| Posture API | Application posture with an explainable rollup (riskiest finding + ≤ 15), aggregation by application, business unit, team, owner and region, benchmarking, coverage matrix (target scans count while the target exists), unmanaged assets and shadow repositories, blast radius by CVE/GHSA or package, context graph |
| UI | **Posture** section (Application posture, Coverage, Unmanaged assets, Benchmarking, Blast radius, Context graph), repository **Dependencies** tab, finding "How the package gets in"; Human Eye source tab explains findings without a line |

**Verified on the local stack:**

- the inventory of the real GitHub connection found `quditmind/pathos` as a shadow repository
- a fresh scan of `nodejs-goof` stored 572 components and 1,479 edges (49 direct, 511 transitive, 94 vulnerable of which 69 transitive); a path `goof › mongoose › async`
- blast radius for `minimist` found four transitive versions with 7 open findings
- coverage, benchmark and aggregates returned live figures
- the context graph rendered correctly (screenshot checked)

**Tests:**

- unit: graph parsing and depths (CycloneDX, SPDX, aliases, cycles), rollup, paths, relation and CVE validation
- integration: posture end to end (rollup, aggregation, benchmark, coverage, unmanaged, inventory with a fake SCM, dependency graph and finding paths, blast radius by CVE and package, context graph, scope isolation)
- Vitest: 143
- Playwright: 62, including the posture pages and context graph; two existing tests made independent of the data in the stack

**Register:** 68 completed, 22 in progress, 10 not started. Module B (ASPM and application intelligence) is complete.

**Next:** phase 4, vulnerability intelligence: CVE detail pages, reachability, attack paths, correlation across tools, suppression rules.

## 10. Phase 4 completion report (2026-11-18)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00017 | `intel_vulns` and the `osv` feed, `repository_code_imports`, `repositories.imports_scanned_at/imports_files`, `findings.reachability_basis`, `suppression_rules` and `findings.suppression_rule_id`; full Down migration (decided findings reopen) |
| CVE intelligence | OSV lookups for open findings' CVE/GHSA identifiers (weekly refresh, unknown identifiers remembered), offline JSON/zip import, vulnerability page; vendor CVSS fills findings without a vector; EVIDENCE references count as exploits in the risk score |
| Reachability | Worker code inventory (JS/TS, Python, Go imports; package names in strings; browser assets in templates) uploaded per scan; package-level decision over the dependency graph; "not reachable" only for npm and Go with complete evidence; explained per finding; recomputed on inventory, SBOM import and scan completion |
| Attack paths | Internet → tested application or exposed asset → code finding, image, or reachable vulnerable package, ranked by risk, with reasons |
| Correlation | Related findings: same location from another tool (±3 lines, common CWE), same CVE elsewhere, other repositories with the CVE |
| Suppression rules | Proposal with preview, four-eyes approval (API and CHECK), expiry ≤ 1 year, application to new findings at scan completion, reopening at expiry or revocation, full status history and audit |
| UI | Vulnerability page, Attack paths, Suppression rules, reachability and related findings in the finding drawer, OSV feed import |

**Verified on the local stack:**

- the OSV feed fetched 229 records for `nodejs-goof`'s vulnerabilities in 19 s (32 with exploit references); 297 of 301 CVE findings have a CVSS vector
- a real scan inventoried 17 files: 218 dependency findings reachable, 33 not reachable (build tooling, `jquery` declared but never used), 85 unknown; `ejs`, loaded by name as the Express view engine, is reachable
- with the repository temporarily marked internet-exposed, 100 attack paths were listed, ranked by risk with exploit evidence (the exposure was restored)

**Tests:**

- unit: OSV parsing (record, array, zip), vector choice, code inventory (imports, strings, assets), reachability decisions
- integration: OSV import, worker inventory and reachability, attack paths, correlation, suppression rules (validation, preview, four eyes, history, later findings, revocation, expiry)
- Vitest: 147; Playwright: 65; smoke 92/92

**Register:** 72 completed, 20 in progress, 8 not started. Module C (vulnerability intelligence) is complete.

**Next:** phase 5, Human Eye extras: multi-level approval, AI patch proposals with human approval, AI risk explanation and correlation suggestions.

## 11. Phase 5 completion report (2026-11-18)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00018 | Final-approval settings, approval levels (unique per decision and level, and per person), three new AI kinds, patch decision columns; the app role may update only those columns of AI suggestions; full Down migration |
| Multi-level approval | Optional third level: decisions needing independent review that match the configured severities or dispositions also need a final approval by a third person; capabilities, banner and history |
| AI patch proposals | Unified diffs of the reviewed file, validated (one file, well-formed hunks, not whitespace-only, ≤ 16 KB); approved or rejected by a person with history and audit; approved patches downloadable; never applied |
| AI risk explanation | The contextual risk score and its factors explained, with what would lower it |
| AI duplicate suggestions | Comparison with nearby, same-rule and same-CVE findings of the repository; the analyst decides |
| Fix | AI requests wait for model responses as long as the request timeout (the 30-second header timeout cut off local CPU inference) |

**Verified on the local stack (Ollama, qwen2.5-coder:3b):**

- a risk explanation built from the finding's real factors (CVSS 9.2, EPSS percentile, criticality)
- duplicate candidates and a patch proposal returned and stored; the small model's whitespace-only "patch" led to the no-op check

**Tests:** unit (patch validation); integration (three levels with capabilities, patch decision, history and download, settings validation, migration rollback); Vitest 150; Playwright 65; smoke 92/92; gosec 0 issues.

**Register:** 76 completed, 17 in progress, 7 not started. Module D is complete.

**Next:** phase 6, AI Security Analyst workspace (conversation over the security data), AI usage and AI-written technical and executive reports.

## 12. Phase 6 completion report (2026-11-18)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00019 | `ai_conversations`, `ai_messages`, `ai_reports`; full Down migration |
| AI generation | One structured request path (`ai.Service.Generate`): default configuration, redaction, fenced untrusted payload, organization guidance, SHA-256 of what is sent |
| AI Security Analyst | Private conversations; context scoped to the user (figures, riskiest applications, matching or riskiest findings, OSV records); exploit questions get exactly the exploited findings; citations kept only for findings in the context; follow-ups; rate limit; audit |
| AI reports | Technical and executive reports for the organization, an application or a repository: PATHOS-computed facts, optional AI narrative from those facts, Markdown export; visible to the author and organization-wide readers |
| AI usage | Requests and tokens by feature, model, person and day |
| UI | AI Security Analyst (conversations, cited findings, follow-ups, safe Markdown), AI reports, AI usage |

**Verified on the local stack (Ollama, qwen2.5-coder:3b):**

- an answer in 46 s grounded in 25 findings with 9 valid citations; the small model over-stated KEV findings, so exploit questions now get exactly the exploited findings: the repeat answered with the single open KEV finding, matching the database
- an executive report with narrative in 40 s over the real figures (49 critical, 167 high open; coverage 100 %)
- usage by feature recorded every AI request

**Tests:** unit (keywords, narrative validation, Markdown); integration (fake provider: citations filtered, redaction, privacy, empty answers refused, reports with and without narrative, report visibility, usage); Vitest 152; Playwright 68; smoke 92/92; gosec 0 issues.

**Register:** module E requirements are all met (no numbered features).

### Phase 7 — Supply chain and DevSecOps (done)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00020 | `findings.malicious`; `package_health`; artifact targets; `repositories.pr_checks_enabled` / `pr_gate_severity`; `scan_jobs.pull_request`; `pr_checks`, `pr_findings`; full Down migration |
| SBOM export | `GET /repositories/{id}/sbom?format=spdx` (SPDX 2.3) and CycloneDX 1.5 from the inventory with its dependency graph; the scan's own CycloneDX file stays the default |
| Malicious packages | OSV `MAL-*` advisories and malware reports flagged on findings; KEV-level likelihood, always reachable; badge, filter, remediation guidance |
| Package health | deps.dev feed (off by default: it sends package names): latest version, deprecated versions, OpenSSF Scorecard and verified SLSA provenance of direct dependencies; outdated compared by version, not by inequality |
| CI/CD | actionlint 1.7.12 (built from source) on GitHub Actions workflows; Checkov now also checks Bitbucket Pipelines |
| Build artifacts | Upload (≤ 200 MiB) as a scan target; archives validated and extracted on the worker with the snapshot extractor (no links, traversal, bombs); Java archives and binaries scanned whole; Trivy |
| PR checks | Opt-in per repository; PR head scanned with the repository's profile; results in `pr_findings`, never in `findings`; new = not already known on the scan branch (open, accepted or false positive); gate by severity; commit status `PATHOS / security` on GitHub, GitLab, Bitbucket and Azure DevOps; re-post |
| Commit attribution | Commit of the first detecting scan on every finding |
| UI | Pull request checks page and repository settings; SPDX download; package health column, filter and counts; artifact targets; malicious badge and filter |

**Verified on the local stack:** SPDX export of nodejs-goof (572 packages, 1,479 dependency relationships); deps.dev refresh of 437 packages in 13 s (458 outdated, 43 deprecated versions, Scorecards; the root package no longer matches an unrelated public package); an uploaded release zip with lodash 4.17.20 extracted and scanned (4 CVEs); actionlint 1.7.12 found 7 genuine workflow problems in nodejs-goof. PR checks were not run against the provider: the connected repositories belong to third parties, so the integration test drives the full flow with a fake status writer.

**Tests:** unit (SPDX/CycloneDX round trip through PATHOS's own parsers, purl mapping, deps.dev client, version order, actionlint parser, artifact extraction incl. traversal and checksum, commit statuses on four providers, PR outcome); integration (PR checks: opt-in, isolation from findings, new vs known, gate, statuses, permissions; migration down and up); Vitest 154; gosec 0 issues.

**Register:** module F 12 completed, 3 in progress (end-of-life dates, exact introducing commit, image and artifact signature verification).

### Phase 8 — Governance (done)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00021 | `security_policies`, `policy_violations`; `pr_findings.cwe` and `policy_ids`; full Down migration |
| MFA recovery codes | Recovery code sign-in enabled by an idempotent `keycloak-setup` job (bootstrap administrator; PATHOS's service account keeps user-management rights only); status, self-service (**Sign-in security**) and administrator requests; audited |
| SSO | SAML 2.0 and OIDC brokering guide; `scripts/test-sso-brokering.py` signs in through a temporary external OIDC and SAML provider and checks provisioning |
| Policy engine | Conditions on findings and context, actions block / require review / SLA / notify; evaluated after every scan (gate), in PR checks (new findings), every 10 minutes and on change; SLA restored when a policy stops applying; dry-run preview; violations; `policy.violated` notification |
| Compliance mapping | Five frameworks; controls mapped by category, CWE and malicious packages; views over repositories in each framework's compliance scope; findings filter `control=` |
| UI | Security policies (editor with live preview, violations), Compliance, Sign-in security, recovery codes in the user drawer, policies on findings and PR checks |

**Verified on the local stack:** recovery codes enrolled at sign-in (12 codes), a code accepted once and refused when reused; OIDC and SAML brokering end to end (both signatures validated, new users without access), cleaned up; a KEV policy matched the one exploited finding, tightened its deadline to 7 days, notified and queued a Human Eye review, and deleting it restored the 90-day SLA; OWASP Top 10 view on real data (A03, A05, A06 failing).

**Tests:** unit (policy validation and parameterised SQL, compliance catalog, recovery codes against a fake Keycloak); integration (policies: permissions, violations, gate, SLA and restoration, notification once, Human Eye queue, PR block, disable and delete, audit; compliance views, scope and control filter; recovery codes); Vitest 160.

**Register:** module G 17 completed, 5 in progress (executive dashboard, outbound webhooks, multi-tenant, plugin architecture, offline bundles), 3 not started (custom reporting, Jira, ServiceNow).

### Phase 9 — Reporting and integrations (done)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00022 | `outbound_webhooks`, `outbound_webhook_deliveries`, `ticket_connections`, `finding_tickets`, `saved_reports`; secret kind `integration`; full Down migration |
| REST API tokens | Scopes `api:read` / `api:write` on personal tokens; bearer authentication in the API middleware (no CSRF exposure); owner's current permissions; never for tokens, sign-in or MFA endpoints; token id on audit entries |
| Outbound webhooks | Every notification event, as signed JSON (HMAC-SHA256 over timestamp and body), Slack or Microsoft Teams (Adaptive Card); queued with the event, retried with back-off (5 retries over ~9 h), 4xx not retried; URLs encrypted, only the host shown; SSRF policy (no loopback, metadata or private addresses unless allowed); test message; delivery log |
| Jira, ServiceNow | Connections (encrypted credentials, connection test), a ticket per finding and connection with the finding's facts (redacted, no code), status sync every 10 minutes |
| Executive overview | Open critical/high, KEV, SLA compliance, past-SLA, new vs fixed, weekly trend and backlog, MTTR by severity, riskiest applications and business units; printable |
| Custom reports | Saved definitions over the Findings filters, grouping or columns; preview; shared; CSV (formula-safe); scheduled delivery as a link (`report.scheduled`), each reader sees only their own scope |
| UI | Executive overview, Reports, Integrations, Webhooks tab, token scopes, finding tickets |

**Tests:** integration (REST tokens: read-only, deny-list, deactivation; webhooks: SSRF, encryption, signature verification, Slack format, retry vs give-up, delivery log, test, secrets removed on delete; Jira and ServiceNow against mock servers: auth, redacted content, duplicates, permissions, sync; executive and reports: scope, CSV protection, grouping, sharing, scheduling); Vitest 165.

**Register:** module G 22 completed, 3 in progress (multi-tenant, plugin architecture, offline bundles); 89 completed, 10 in progress, 1 not started overall.

### Phase 10 — Production readiness (done)

**Implemented:**

| Area | What was built |
|---|---|
| Migration 00023 | `pathos_register_plugin_scanner` (SECURITY DEFINER, plugin keys only, category bound to the key); Down migration |
| Declarative scanner adapters | YAML/JSON definitions in `deploy/scanners.d` (mounted read-only into `worker-core`): absolute, non-writable executable, templated arguments without a shell, SARIF output, restricted environment; registered by the worker, selectable in profiles, findings of the declared category |
| Connector interface | `tickets.Connector` (`Check`, `Create`, `Status`) with a registry; Jira and ServiceNow implement it |
| Offline mode | `PATHOS_OFFLINE=true`: Trivy (`--skip-db-update --skip-java-db-update --offline-scan`), Grype (no auto-update), OSV-Scanner (`--offline-vulnerabilities`) use local databases only, with a clear error when one is missing; the API never downloads feeds (file import only; the UI says so) |
| Offline bundles | `scripts/offline-bundle.sh create / import / status`: Trivy, Grype and OSV databases plus EPSS and KEV, SHA-256 manifest, refuses links and unsafe paths, verifies every checksum, optional feed import with a REST token |
| Malware scanning | ClamAV scans uploaded build artifacts (reject and audit on detection; `PATHOS_CLAMAV_REQUIRED` behaviour as for source uploads) |
| Docs | Air-gap guide (`docs/AIRGAP.md`), declarative adapters (`docs/SCANNER_CATALOG.md`) |

**Verified on this machine:** a real bundle (6.6 GB, npm OSV) created in about 5 minutes, imported with every checksum verified; with `--network none`, Trivy, Grype and OSV-Scanner each found the lodash vulnerabilities from the bundle alone. Test data removed.

**Tests:** unit (offline flags and database checks, plugin validation: placeholders, environment, relative or writable commands, unknown fields, duplicates; a plugin run end to end); integration (plugin registration, catalog, profile, unregistered keys refused, results as findings; the registration function refuses non-plugin keys and mismatched categories; artifact malware scan with a fake clamd: infected, clean, scanner required or optional).

**Register:** 91 completed, 9 in progress, 0 not started.
