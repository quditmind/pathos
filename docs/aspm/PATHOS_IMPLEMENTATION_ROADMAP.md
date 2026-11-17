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
