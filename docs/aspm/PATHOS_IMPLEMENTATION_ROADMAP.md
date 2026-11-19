Quditmind PATHOS · applies to v2.2.0 · status: Proposed

# PATHOS ASPM implementation roadmap

Sections 1 to 16 are the completed ASPM programme (status: Existing). Section 17 is the proposed plan for the lifecycle release (status: Proposed; nothing in it is built).

**Status of the ASPM programme: complete.** All ASPM phases (1 to 10) are merged: phase 1 in #31, 2a in #32, 2b in #33, 3 to 10 in #35 to #42. The register in [PATHOS_FEATURE_GAP_ANALYSIS.md](PATHOS_FEATURE_GAP_ANALYSIS.md) stands at 91 completed, 9 in progress, 0 not started.

**Phase numbers.** "Phase N" in this document and in the `docs/aspm/` folder means an **ASPM phase**. The platform was first built in eight earlier phases (foundation to enterprise hardening), which [DEVELOPMENT_ROADMAP.md](../DEVELOPMENT_ROADMAP.md) calls *platform phases P1 to P8*. The two numberings are unrelated: ASPM phase 7 (supply chain) is not platform phase P7 (scheduling and notifications).

From the gap analysis ([PATHOS_FEATURE_GAP_ANALYSIS.md](PATHOS_FEATURE_GAP_ANALYSIS.md)). Each phase ships as its own pull request (or several) with migrations, backend, UI, tests, docs and an updated register. Nothing is marked Completed without backend logic, UI, persistence and tests.

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

As built, the design changed in three places:

- Graph questions are answered by the posture service (`internal/posture`: blast radius, attack paths, context graph, dependency paths), while `internal/intel` holds the feeds (EPSS, KEV, OSV, deps.dev).
- Outbound integrations are split by kind. Outbound webhooks (JSON, Slack, Teams) live in `internal/notify`. Jira and ServiceNow implement the `tickets.Connector` interface in `internal/tickets`.
- All target kinds (`image`, `url`, `api`, `sbom`, `artifact`) run on the single `worker-core` image; no extra worker families were needed.

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
7. completion report in this document (sections 6 onwards)

## 3. Decisions needed from the product owner

The decisions were taken in phase 1 (see section 6): D1 renamed the module to Human Eye (labels only), D2 derives the lifecycle statuses, D3 kept one organization per deployment (revised for 2.2: multi-tenancy is an option an operator enables), and D4 enabled EPSS and KEV online by default, with offline import. D5 was delivered in phase 9.

| # | Decision | Recommendation |
|---|---|---|
| D1 | Rename "Human Review" to **"Human Eye"** and regroup the navigation into the 10 proposed sections | Keep the routes, change the labels only; regroup when phases 3, 6 and 9 add their pages, so no empty sections are created |
| D2 | Finding statuses New, Open, In Progress, Under Review, Confirmed, False Positive, Accepted Risk, Resolved, Reopened | **Present** them without migrating the stored values: New = open and not yet triaged (first seen in the last scan); Under Review = `needs_review` or a review in progress; Confirmed = human disposition confirmed; Resolved = `fixed`; Reopened = recurrence > 0 and open. Keeps the API, history, SLA and AI contracts intact |
| D3 | Real multi-tenancy (several organizations in one deployment) | Only if you host PATHOS for several customers. The schema is ready; runtime work is moderate (tenant resolution, administration, isolation tests). Otherwise defer. **Revised for 2.2:** supported as an option (`pathosctl multi-tenancy enable`); single-organization stays the default ([MULTI_TENANCY.md](../MULTI_TENANCY.md)) |
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

**Decisions taken:** D1 rename to Human Eye (labels only); D2 lifecycle statuses derived, stored values unchanged; D3 single organization (revised for 2.2: multi-tenancy is an option an operator enables, with row-level security, installation administrators and an isolation test suite; single organization stays the default); D4 EPSS and KEV online daily by default, with offline import.

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

## 13. Phase 7 completion report (supply chain and DevSecOps)

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

## 14. Phase 8 completion report (governance)

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

## 15. Phase 9 completion report (reporting and integrations)

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

## 16. Phase 10 completion report (production readiness)

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

## 17. Lifecycle release plan (M0–M11, proposed)

**Status: Proposed.** This section plans the work in the owner's build prompt (milestones M0 to M11), adjusted for what PATHOS 2.2.0 already contains. Nothing here is built. The version that ships it is not decided ([ADR-013](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-013-naming-and-versioning-of-the-lifecycle-release)); this document calls it "the lifecycle release". Data model: [PATHOS_DATABASE_DESIGN.md](PATHOS_DATABASE_DESIGN.md#lifecycle-release-data-model-m0-proposed). Endpoints: [PATHOS_API_DESIGN.md](PATHOS_API_DESIGN.md#lifecycle-release-endpoints-m0-proposed). Decisions: [PATHOS_ARCHITECTURE_DECISION_RECORDS.md](PATHOS_ARCHITECTURE_DECISION_RECORDS.md).

### 17.1 Starting point (verified on `main`, commit `f3c5efd`, 2.2.0)

| Prompt assumption | Code today | Effect on the plan |
|---|---|---|
| PATHOS is at 1.1.1 | 2.2.0 is released (2.0.0, 2.1.0 and 2.2.0 on 2026-11-19, `CHANGELOG.md`) | Plan from 2.2.0; never assign a version (ADR-013) |
| Multi-tenant is out of scope (rule 8) | Optional multi-tenancy ships in 2.2.0, off by default ([MULTI_TENANCY.md](../MULTI_TENANCY.md)) | Keep it (rule 1). New tables still follow its isolation rules, because `pathos_apply_app_grants()` adds a policy to every table with `organization_id` and the isolation test probes every route. No new multi-tenant features |
| `make e2e` exists | It does: `Makefile:45` runs `scripts/e2e.sh` (Playwright `v1.65.1` container against the running stack; `e2e/tests/*.spec.ts`). Only `e2e` is missing from the `.PHONY` line (`Makefile:2`) | No new target needed; the M0 brief's note that the target is missing is not correct |
| `e2e/screenshots.config.ts` captures pages | It captures light theme only, 1440×900 (`e2e/screenshots.config.ts:19-20`), into `e2e/screenshots/out/` | Add a dark-theme project (test plan 17.6.7) |
| Tool catalogue to be built (M6) | 25 scan types (`backend/internal/scanners/scantypes.go:30`), catalogue split over `catalog.go` and `catalog_<family>.go`, 9 worker images (core plus `sast`, `iac`, `sca`, `dast`, `mobile`, `binary`, `ai`, `fuzz`), 232 import formats, "confirmed by N engines" data in `findings.scanner_keys` | M6 is mostly mapping and UI; size reduced |
| Connectors are new (M2) | SCM connections (GitHub, GitHub Enterprise, GitLab, Bitbucket, Azure DevOps), Jira and ServiceNow, outbound webhooks (JSON, Slack, Teams), Kubernetes clusters and container registries (2.1), AI providers, SMTP, CLI, VS Code and JetBrains plugins, CI templates (GitHub Action, GitLab, Azure Pipelines, Jenkins, pre-commit, pre-receive) | M2 is a registry and health layer over existing connections plus new kinds |
| Help exists in `features/help` | Yes, bundled offline at build time (`frontend/src/features/help/content.ts:37`) | M1 adds the drawer, the route map and troubleshooting docs |
| Design page lists connector status | The connectors design marks JetBrains IDEs and Kubernetes as "new" and result import as "25 formats". In the code, the JetBrains plugin shipped in 2.2.0, a Kubernetes inventory in 2.1.0, and imports cover 232 formats | The code wins; the connector catalogue must use the code's status |

Partly existing items mapped to milestones:

| Item | Exists today | Milestone that builds on it |
|---|---|---|
| Version on `/healthz`, CLI `--version`, worker version at registration | Yes (ADR-001) | M1 |
| Configurations group (scan profiles, scanners & workers) with old URLs redirecting | Yes (`frontend/src/app/router.tsx:172-177`) | M1 sidebar regroup |
| Context graph, attack paths, blast radius | Yes (`backend/internal/posture`) | M4, M5 |
| Function-level reachability with call paths | Yes, 2.1 (`pathos-reach`, govulncheck) | M4 (call edges), M7 |
| Endpoints declared and verified per repository | Yes (`repository_public_endpoints`, `endpoint_verifications`) | M4 API & endpoints view |
| Runtime context (clusters, registries, workloads) | Yes, 2.1 | M2 (as connectors), M4 (observed edges), M9 |
| Live secret validation | Yes, 2.1, off by default | M2 health, M7 |
| Verified AI fixes, dependency fix pull requests | Yes (2.1, 1.1) | M8 |
| PR checks, scan security gate, CI gate endpoint, security policies with block | Yes | M8 (ADR-010) |
| Material change detection | Yes, 1.1 | M9 drift and feed |
| Application versions, VEX | Yes, 1.1 | M3 hub, M8 release gate |
| Drafts in repository imports, required asset fields, mandatory tag categories | Yes (`00009`) | M3 |
| AI review records with model, configuration version and request hash | Yes | M7 (ADR-008) |
| Binary family worker, artifact targets, signature verification, sandbox runner | Yes | M10 (ADR-009) |

### 17.2 Milestones

Sizes: S ≈ up to 1 week, M ≈ 1–3 weeks, L ≈ 3–6 weeks, XL ≈ more than 6 weeks of one engineer with AI assistance. They are rough and assume the owner's approval turnaround is not on the critical path. Each milestone follows the prompt's sequence: design note → wireframe or screenshot → **owner approval** → implementation → tests → docs → PR, on its own branch, with every new module behind a flag that is off by default.

| # | Scope (adjusted) | Depends on | Size | Main risks | Approval gate (in addition to §9 outputs) |
|---|---|---|---|---|---|
| **M0** | Approval pack: audit, capability gap matrix, ADRs, integration and protocol matrix, DB and API design (this set of documents) | — | M | Documents drift from code if M1 starts late | Owner approves the pack, ADR-001 to ADR-012, and decides or defers ADR-013 and the open questions in 17.5 |
| **M1** | Brand header with live version and pre-release tag; About; Help menu and drawer with the route map; Troubleshooting centre; diagnostic catalogue, `make docs-errors`, extended error envelope (`error_code`), `<ErrorPanel>` and the shared page states; `/api/v1/meta`; Commit and BuildDate ldflags for API, `pathosctl`, worker, CLI and helpers; bundle-version mismatch banner; version-stamped exports; sidebar regroup into the prompt's groups (URLs unchanged, new items with `phase`); feature-flag framework; system status | M0 | L | The regroup touches every page's navigation; envelope change must not break the CLI and IDE plugins; mapping 56 legacy codes; export stamping may break CSV consumers | Every route has help; every API error carries a catalogue code; all existing e2e tests pass unchanged; screenshots in light and dark; CLI and both IDE plugins pass their tests against the new envelope |
| **M2** | `/connectors` (tabs Connectors, Authentication, Configuration, Health; nine categories); registry over existing connections; health checks with catalogue codes and AI troubleshooting; parity for SCM connections and Integrations, then redirects; vendor facts cited in `PATHOS_INTEGRATION_TECHNICAL_SPEC.md`; new kinds in priority order set by the owner (cloud, SIEM, Vault are larger than they look) | M1 | L (plus M per new connector kind) | Parity of the old pages (rule 1); vendor API facts change; new cloud connectors need egress and credentials design; health checks must not call vendors from the API process where the current design avoids it | Parity e2e tests pass for `/admin/scm` and `/admin/integrations`; every connector shows only real status (no fake health, rule 4) |
| **M3** | Connect → find existing asset → register → tag and classify → inventory flow with drafts; application classification fields; tag `applies_to`, application tags and tag history; application profile hub with the prompt's tabs | M1 (M2 for "connect" step from Connectors) | L | Duplicate detection across repositories, applications and targets; hub tabs that depend on later milestones must show the disabled state, not empty data | No duplicate assets in tests; incomplete assets save with a status; hub tabs for M4/M5/M8 show "feature disabled" until those flags are on |
| **M4** | Discovery worker family (`worker-graph`) with tier 1 engines; CodeGraph store, aggregation, expansion, path search, diffs; shared graph component (React Flow + ELK unless measurement says otherwise); the 15 views; snapshots and compare; API & endpoints view; context graph becomes the ownership layer | M1; M3 hub for placement | XL | Graph size and load time; 2 s render budget unproven; engine coverage per language; Joern memory; evidence on every edge | Graph for the PATHOS repository renders and every edge has evidence (test); measurement results for ADR-005 in the PR |
| **M5** | STRIDE (and LINDDUN) engine on CodeGraph; attack-path integration filtered by application; ATT&CK, CAPEC, CWE, D3FEND mappings with notices; editable, versioned, approvable model; Threat Dragon, pytm, Threagile import and export | M4 | L | Threat quality depends on graph coverage; licence of LINDDUN material unclear; imported threats and rule 5 | Each threat has evidence, method, severity, confidence and mitigation (test); approver differs from author (test) |
| **M6** | Map the existing 25 scan types to the prompt's 20 kinds of check; Quick / Standard / Comprehensive / Custom tiers over existing profiles; category-only UI with "confirmed by N engines"; add missing tools per §7 only after licence and maintenance evidence; worker pack updates | M1 (flag, tool-name rule) | M (catalogue mapping and UI); each new tool batch S–M | Prompt's 20 kinds do not match the 25 scan types one-to-one; tool-name hiding conflicts with help, imports and exports (ADR-011); image size growth | Tool names appear only on the two configuration pages (test); every added tool has licence evidence in the PR |
| **M7** | Cross-phase correlation (findings, graph, threats, runtime); AI evidence records with replay; model per task with local default for code; reviewer decisions; no silent suppression | M4 (evidence table), M5 | L | Storage and retention of redacted prompts; hosted-model drift makes replays differ; cost of replays | Every AI decision is reproducible from its record (replay test with a local model fixture) |
| **M8** | Remediation workspace (items, owners, due dates, links to findings and threats); gates at IDE, pre-commit, PR, CI, release, deploy with block / warn / exception / approval; legacy thresholds per ADR-010; fix verification with before-and-after evidence | M5 (threat links), M7 (AI fixes evidence); can start in parallel with M7 for gates | L | Changing gate behaviour that customers rely on; IDE and pre-commit clients need updates (VS Code, JetBrains, hooks) | No gate blocks without a policy (test); legacy thresholds behave identically after migration (parity test) |
| **M9** | Technical and compliance report upgrades; continuous monitoring feed; architecture drift from graph diffs; all exports version-stamped; feedback loops 1–7 of the flow design wired | M4, M5, M8 | M–L | Feed volume and noise; the flow design's loops must be listed precisely in the M9 design note | Loops 1–7 each have an integration test |
| **M10** | `workers/rea` static tier (agent on `worker-api` only, tools in a network-less sandbox runner); own-build artifacts by default; source-versus-binary diff; workspace UI on the shared graph component | M4 (graph component), existing artifact targets | L | Image size (Ghidra JVM, .NET); parser exploits (mitigated by the runner); licences of RE tools | Runs only on artifacts from own builds by default (test); no network in the analysis runner (test) |
| **M11** | Sandbox tier on a throwaway VM, never on the PATHOS host | M10 | XL (not estimated) | Host isolation; VM lifecycle; legal limits on dynamic analysis | Separate approval and its own ADR |

Critical path: M0 → M1 → M4 → M5 → M7/M8 → M9. M2, M3 and M6 can run after M1 in parallel with M4 if more than one engineer works on the release; M10 needs only M4's graph component.

### 17.3 Feature flags per milestone

Proposed keys (ADR-003): `shell.v2` and `diagnostics` (M1), `connectors` (M2), `onboarding.v2` (M3), `codegraph` (M4), `threat_models` (M5), `scan_profiles.v2` (M6), `ai.evidence` (M7), `remediation` and `gates` (M8), `monitoring` (M9), `reverse_engineering` (M10). The flag framework itself and the error envelope are not flagged: the envelope is additive and the framework must exist before any flag. Whether the M1 sidebar regroup is flagged is an owner question (17.5).

### 17.4 Documents per milestone

Every milestone updates in the same PR: [DATABASE.md](../DATABASE.md), [ARCHITECTURE.md](../ARCHITECTURE.md), the matching `docs/aspm/*` file, `docs/user-guide/*` (with a Troubleshooting section listing its error codes), `docs/api-reference/*` (request, response, errors, permission), the generated `docs/troubleshooting/*`, and `CHANGELOG.md` under `## [Unreleased]`. New `docs/aspm` files only where prompt §8 lists them and none exists (for example `PATHOS_CODEGRAPH_ARCHITECTURE.md` in M4).

### 17.5 Open questions for the owner

1. ADR-013: naming and versioning of the lifecycle release.
2. ADR-002: accept `error.error_code` (backward-compatible) instead of replacing `error.code` as written in prompt §3.2.
3. ADR-010: how existing non-policy thresholds (`fail_on_critical`, `pr_gate_severity`, signature-required targets) relate to rule 7.
4. ADR-011: whether help articles, import format selection and exports are exempt from tool-name hiding.
5. ADR-008: retention and default for storing redacted AI prompts and responses.
6. ADR-007: LINDDUN material licence; until confirmed, only category names are used.
7. ADR-005: the reference client hardware for the 2 s graph budget.
8. Whether the M1 sidebar regroup ships behind a flag (safer) or directly (simpler; URLs do not change either way).
9. M2: which new connector kinds come first (cloud, SIEM, Vault, cloud secret managers, API specs), since each is a separate integration with its own credentials and egress.
10. M3: the list of "security" classification fields.
11. Whether imported threats without evidence may exist in a model (stored as "not yet linked", blocked from approval).

### 17.6 Test plans for the new quality gates (prompt §9)

Each plan names where the test lives, what it checks, how it fails, and how it runs today. All run in the existing containers (`scripts/go.sh`, `scripts/npm.sh`, `scripts/e2e.sh`).

#### 17.6.1 Route ↔ help mapping (M1)

- **Unit (Vitest, `make test-web`).** Import the router tree from `frontend/src/app/router.tsx` and collect every route path (including parameterised ones such as `/scans/$id`; redirect-only routes are excluded and listed). Import the `routeHelp` map. Fail when: a route has no entry; an entry's article (`section/slug`) is not in the bundled help (`content.ts`); an entry's anchor is not among the article's headings; an entry names a route that does not exist.
- **E2E (`make e2e`).** For each top-level menu route, press F1 and assert the drawer opens with the mapped article title. One test per group to keep run time low.
- **Negative check:** a fixture route without a mapping makes the unit test fail (meta-test).

#### 17.6.2 Error code ↔ docs mapping (M1)

- **Go unit test (`make test-go`)** in `internal/platform/diag`: every entry has the required fields (title, at least one action and one verification step, docs slug) and a unique, well-formed code `^PTH-(PLAT|AUTH|CONN|SYNC|ONB|DISC|GRAPH|TM|REA|SCAN|WORK|AI|GATE|REM|REP|MON)-[0-9]{4}$`.
- **Generated-docs check (CI job, also run in `make test-go`):** run `make docs-errors` into a temporary directory and compare with `docs/troubleshooting/`; any difference fails ("run make docs-errors"). Then parse the docs: every `PTH-…` anchor exists in the catalogue and every catalogue code has exactly one anchor.
- **Legacy mapping test:** an AST scan of `backend/` collects every `httpx.E(…, "<code>", …)` and helper call; each legacy code must have a default catalogue entry.
- **Help test (Vitest):** every code listed in a user-guide page's Troubleshooting section exists in the bundled catalogue.

#### 17.6.3 Tool names hidden outside the two configuration pages (M1 helper, enforced from M6)

- **Source check (Vitest or ESLint rule):** only files under the scan-profiles and scanners configuration features may import `<ToolName>` or the raw `scanner_catalog.name`; other files must use the check-label helper.
- **E2E crawl (`make e2e`):** with seeded data that includes findings from several engines, visit every non-configuration route reachable from the menu (and detail pages such as `/scans/$id` and a finding drawer) in light and dark themes; extract visible text (`innerText`); fail if it matches any catalogue tool name with word boundaries. Names that are ordinary words are checked by asserting no element carries `data-tool` instead of by text. The two configuration routes and any owner-approved exemptions (ADR-011: help, imports) are allowed and listed in the test.
- **API contract test (Go integration):** finding and scan responses still contain `scanner_key` / `scanner_keys` (rule 3 keeps them for audit).

#### 17.6.4 Old URLs still resolve (every milestone, starting M1)

- **Fixture:** `e2e/fixtures/routes-2.2.0.json`, generated once from the 2.2.0 router (every path, with sample ids for parameterised routes) and the 2.2.0 menu (`AppShell.tsx` `groups`), committed and never edited except by an approved redirect.
- **E2E:** for each URL, navigate and assert: HTTP 200 from the proxy, no error boundary, the page heading expected for that route (as `e2e/tests/navigation.spec.ts` already does for its list), or, for an approved redirect, the final URL and that the replacement page shows the same records (parity check named in the redirect's PR).
- **Unit:** a router test fails if a 2.2.0 path is missing from the route tree and has no approved redirect entry.

#### 17.6.5 Version shown matches `/api/v1/meta` (M1)

- **Go integration:** with the binary built with `-X …Version=9.9.9-test -X …Commit=abc -X …BuildDate=…`, `GET /api/v1/meta` without credentials returns exactly `{product, vendor, version}`, and with a session or token returns the extra fields; an invalid token gets the unauthenticated form; `/healthz` and `/api/v1/meta` report the same version.
- **E2E:** read `/api/v1/meta` with the test session; assert the header chip, the login page, the collapsed sidebar tooltip and the About dialog show the same `version` (and `commit` in About). Mock a different bundle version (Vite `define` in a test build or a route intercept of `/api/v1/meta`) and assert the reload banner appears; with equal versions it does not.
- **CLI unit:** `pathos --version` and `pathosctl version` print the injected values.
- **Export check:** one CSV, one JSON and one SARIF export contain the stamp with the same version.

#### 17.6.6 No gate blocks without a policy (M8)

- **Database (Go integration):** inserting `gate_decisions` with `outcome = 'block'` and empty `policy_ids` fails with a check violation; inserting `security_gates` without `policy_id` fails.
- **Service (Go integration):** with no gates configured, `POST /api/v1/gates/evaluate` returns `pass` for a scan with critical findings at every stage; with a disabled gate, `pass`; with a `warn` gate, `warn`; only a `block` gate whose policy matches returns `block`, and the response names the policy and version.
- **Property test:** randomised combinations of gates, policies and findings; assert `outcome = block ⇒ policies non-empty and each matched`.
- **Legacy parity (depends on ADR-010):** existing scan gate and PR check tests (`backend/internal/scans`) pass unchanged; after migration of legacy thresholds, the same inputs give the same `gate_failed` and PR status, now with a policy reference.
- **Static check:** the only code path that sets a blocking outcome is the evaluator (AST scan for assignments of `gate_failed = true` / `OutcomeBlock` outside allowed functions).

#### 17.6.7 Screenshots in both themes (every milestone with UI)

- **Config:** extend `e2e/screenshots.config.ts` with two Playwright projects, `light` and `dark` (`colorScheme` plus the app's theme setting, so a stored preference cannot override it), 1440×900, plus a 1024×768 project for the "usable down to 1024 px" rule.
- **Spec:** `e2e/screenshots/lifecycle.spec.ts` lists every new page of the milestone, waits for skeletons to disappear, and captures each page state that can be produced with test data (loading, empty, error with `<ErrorPanel>`, permission denied, feature disabled, populated). Example data is created through the API in test setup and labelled as test data (rule 4); no real customer names, hosts or secrets (public repository).
- **Check:** the run fails if any listed page lacks either theme's file; an accessibility pass (axe-core in Playwright) runs on the same pages in both themes and fails on serious or critical violations (WCAG 2.2 AA goal).
- **Run:** `scripts/e2e.sh --reporter=line --config=screenshots.config.ts`, output in `e2e/screenshots/out/`; the PR attaches them.

### 17.7 Completion reports

Each milestone adds a completion report to this document (sections 18 onwards), in the format of sections 6 to 16 and the order of prompt §9: what was built, existing versus new, test output, docs changed, error codes added, known limitations and blockers, proposed next milestone.
