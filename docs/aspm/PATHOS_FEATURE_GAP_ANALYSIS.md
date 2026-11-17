# PATHOS feature gap analysis and register

The 100 target capabilities compared with PATHOS as of 2026-11-17 (`main` plus PR #29). This is also the **feature register**. Update it as phases land.

**Status** uses the programme's values:

| Status | Meaning |
|---|---|
| **Completed** | Backend, UI, persistence and tests exist |
| **In Progress** | Partly there; the gap column lists what is missing |
| **Not Started** | |

Columns B / F / D / T are the backend / frontend / database / test state: ✓ done, ◐ partial, — none.

## Summary

| Module | Completed | In Progress | Not Started |
|---|---|---|---|
| A. Code and application scanning (1–15) | 4 | 6 | 5 |
| B. ASPM and application intelligence (16–30) | 6 | 6 | 3 |
| C. Vulnerability intelligence (31–45) | 7 | 4 | 4 |
| D. Manual validation and AI (46–60) | 11 | 3 | 1 |
| F. Supply chain and DevSecOps (61–75) | 6 | 4 | 5 |
| G. Enterprise and governance (76–100) | 13 | 9 | 3 |
| **Total** | **47** | **32** | **21** |

Module E (AI Security Analyst) has no numbered features. Its requirements are assessed in §E.

## A. Code and application security scanning

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 1 | SAST | Completed | ✓ | ✓ | ✓ | ✓ | Opengrep with baseline rules, multi-language | More engines (Bandit, Gosec, …) are catalogued only |
| 2 | SCA / dependencies | Completed | ✓ | ✓ | ✓ | ✓ | Trivy fs, Grype (on the Syft SBOM), OSV-Scanner; cross-tool de-duplication | Reachability (see 41) |
| 3 | DAST | Not Started | — | — | — | — | ZAP and Nuclei catalogued; ZAP only tests PATHOS itself in CI | URL targets, a `dast` worker family, authenticated scan configuration, scope safety |
| 4 | IAST integration | Not Started | — | — | — | — | — | Import IAST results (SARIF/JSON) through the import API (see the SARIF import requirement) |
| 5 | Secrets | Completed | ✓ | ✓ | ✓ | ✓ | Gitleaks mandatory, redaction, optional full history | Secret validity checks (TruffleHog verify, opt-in) |
| 6 | IaC | Completed | ✓ | ✓ | ✓ | ✓ | Checkov | KICS and Kubescape adapters (optional) |
| 7 | Container image | In Progress | ◐ | ◐ | ◐ | ◐ | Trivy fs reads Dockerfiles and lockfiles | Image targets (registry reference), `trivy image`, Dockle, registry credentials |
| 8 | API security | Not Started | — | — | — | — | Schemathesis catalogued | OpenAPI target type, Schemathesis and ZAP API adapters |
| 9 | Malware detection | In Progress | ◐ | ◐ | ◐ | ✓ | ClamAV on uploads; OSV `MAL-*` advisories arrive as SCA findings | Repository and artifact malware scanning, a "malicious package" classification |
| 10 | Licence scanning | In Progress | ✓ | ✓ | ✓ | ◐ | Licences from the SBOM, deny/review policy, SBOM page and KPI | Violations as findings (lifecycle and SLA), ScanCode for file-level licences |
| 11 | Binary analysis | Not Started | — | — | — | — | — | Artifact targets; Syft and Grype on binaries and archives; checksec-style hardening checks |
| 12 | Application configuration scanning | In Progress | ◐ | ◐ | — | ◐ | Checkov and Trivy cover some configuration files | Framework config rules (Spring, Django, Express), a misconfiguration category |
| 13 | Fuzz testing | Not Started | — | — | — | — | — | Import of fuzzing crash results (SARIF) and a CI integration guide. Running fuzzers is the customer's pipeline |
| 14 | Infrastructure exposure | In Progress | ◐ | ✓ | ✓ | ✓ | Internet exposure, public URLs, domains and IPs per repository (declared) | Verification of declared endpoints (Nuclei, TLS checks), opt-in and scope-limited |
| 15 | Custom detection rules | In Progress | ◐ | — | — | ◐ | Administrators mount Opengrep rule packs on the worker | Rule management (upload, validate, version, enable per profile) in the UI and API |

Cross-cutting requirements:

| Requirement | State |
|---|---|
| Multiple languages | ✓ |
| Git and local source | ✓ |
| Configurable profiles, full scans, execution history, worker health, logs, severity thresholds, structured results | ✓ |
| Incremental scanning | **missing**. Diff-aware scans for PRs (see 72) |
| **SARIF/JSON import** | **missing**. This is the key enabler for 4, 13 and third-party tools |
| Adding engines | Compiled in. Documented adapter seam; a declarative adapter (SARIF tools) would make it data-driven |

## B. ASPM and application intelligence

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 16 | Application inventory | In Progress | ✓ | ✓ | ◐ | ✓ | Applications: name, description, business unit, owner, security owner, criticality | Permanent application ID (`QD-APP-…`), technical owner, lifecycle, environment and exposure at application level (aggregated from repositories), last scan, posture |
| 17 | Repository discovery | Completed | ✓ | ✓ | ✓ | ✓ | SCM discovery across organizations and projects | — |
| 18 | Application ↔ repository mapping | Completed | ✓ | ✓ | ✓ | ✓ | `repositories.application_id` | Many-to-many (monorepos serving several applications) is optional |
| 19 | Ownership | Completed | ✓ | ✓ | ✓ | ✓ | Owners on applications and repositories, teams | — |
| 20 | Posture dashboard | Completed | ✓ | ✓ | ✓ | ✓ | Live KPIs and trends | Application-level view (with 21) |
| 21 | Application risk scoring | In Progress | ◐ | ◐ | — | ◐ | Severity-weighted repository score | Contextual score per finding, rolled up per application (see 43 and §4 of the roadmap) |
| 22 | Dependency graph | In Progress | ◐ | ◐ | ◐ | ✓ | Flat SBOM components | Dependency edges from CycloneDX `dependencies`, a direct/transitive flag, graph view |
| 23 | Security context graph | Not Started | — | — | — | — | — | Relational graph (applications, repositories, components, findings, owners, endpoints) with traversal queries and a "blast radius" view |
| 24 | Business criticality | Completed | ✓ | ✓ | ✓ | ✓ | Application and repository criticality | Used in risk scoring (21) |
| 25 | Internet exposure | Completed | ✓ | ✓ | ✓ | ✓ | Exposure yes/no/unknown with endpoints | Used in risk scoring |
| 26 | Lifecycle management | In Progress | ✓ | ✓ | ✓ | ✓ | Repository lifecycle | Application lifecycle |
| 27 | Shadow application discovery | Not Started | — | — | — | — | Discovery lists repositories not yet imported | "Unmanaged" report: SCM repositories with recent activity not in PATHOS, repositories without an application or owner |
| 28 | Coverage mapping | In Progress | ◐ | ◐ | — | ◐ | Scan-coverage KPI | Matrix of applications/repositories × scan categories (SAST, SCA, secrets, IaC, DAST) with last run |
| 29 | Risk aggregation | In Progress | ◐ | ◐ | — | ◐ | Repository counts | Aggregation by application, business unit, team, owner (with 21) |
| 30 | Benchmarking | Not Started | — | — | — | — | — | Compare applications and business units on normalised metrics (risk per KLOC or per repository, mean time to remediate, SLA compliance) |

## C. Vulnerability intelligence and management

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 31 | Central repository | Completed | ✓ | ✓ | ✓ | ✓ | `findings` with occurrences and provenance | — |
| 32 | Normalisation | Completed | ✓ | ✓ | ✓ | ✓ | SARIF and Grype parsers, severity mapping, CWE and CVE extraction | Confidence; CVSS version and vector |
| 33 | Duplicate detection | Completed | ✓ | ✓ | ✓ | ✓ | Line-independent fingerprints, cross-tool SCA merge by package and CVE | **Correlation** (not merging) of SAST findings from different tools at the same location and CWE |
| 34 | False-positive management | Completed | ✓ | ✓ | ✓ | ✓ | Status, AI with approval, Human Review | Suppression rules (fingerprint or path patterns) with expiry |
| 35 | Lifecycle | Completed | ✓ | ✓ | ✓ | ✓ | Trigger-recorded history, recurrence | Requested status names differ (see roadmap decision D2) |
| 36 | CVE intelligence | In Progress | ◐ | ◐ | — | ◐ | CVE ID and links | Local CVE records (description, CVSS vectors, references, published date) from NVD or OSV feeds |
| 37 | CVSS scoring | In Progress | ◐ | ◐ | ◐ | ✓ | Scanner score; CVSS 3.1 and 4.0 in Human Review | Store version and vector per finding; prefer the vendor vector from the CVE feed |
| 38 | EPSS | Not Started | — | — | — | — | — | Daily FIRST EPSS feed (online, or offline file import) |
| 39 | CISA KEV | Not Started | — | — | — | — | — | KEV catalogue feed (online or file) with flag and due date |
| 40 | Exploitability analysis | In Progress | ◐ | ✓ | ✓ | ✓ | Human Review questions, AI verdicts | Automated signals (EPSS, KEV, exploit references) feeding the risk score |
| 41 | Dependency reachability | Not Started | — | — | — | — | — | govulncheck (Go, symbol level), Opengrep import-usage rules for other ecosystems; a reachable / unreachable / unknown flag that never hides findings |
| 42 | Attack path analysis | Not Started | — | — | — | — | — | Paths through the context graph: internet-exposed → application → reachable vulnerable component |
| 43 | Risk prioritisation | In Progress | ◐ | ◐ | — | ◐ | Severity ordering, SLA | Configurable, explainable contextual risk score (roadmap §4) |
| 44 | SLA tracking | Completed | ✓ | ✓ | ✓ | ✓ | Per-severity policies, breach notifications | SLA by risk score (optional) |
| 45 | Trend analysis | Completed | ✓ | ✓ | ✓ | ✓ | Dashboard trends, scan comparison | — |

Unified finding fields: **present**: ID, title, description, category, CWE, CVE, CVSS score, scanner, repository, path, line, application (through the repository), dependency, code evidence, severity, first and last seen, owner, remediation (status and SLA), reviewer status (PR #29). **Missing**: CVSS version and vector, EPSS, KEV, confidence, exploitability (automated), business impact, risk score.

## D. Manual validation (Human Eye = Human Review) and AI assistance

| # | Feature | Status | Evidence | Gap |
|---|---|---|---|---|
| 46 | Review queue | Completed | PR #29 | — |
| 47 | Manual validation | Completed | Workspace and dispositions | — |
| 48 | False-positive confirmation | Completed | Justified disposition, independent review | — |
| 49 | Evidence management | Completed | Encrypted uploads, text, reproduction template | — |
| 50 | Reviewer assignment | Completed | Manual, bulk, round robin, least loaded | — |
| 51 | Multi-level approval | In Progress | Two levels (analyst plus independent reviewer), configurable | More than two levels (optional), if needed |
| 52 | AI explanation | Completed | AI assist `explanation` | — |
| 53 | AI code analysis | Completed | `code_summary`, `code_paths` | — |
| 54 | AI false-positive assistance | Completed | AI review verdicts, `false_positive_indicators` | — |
| 55 | AI remediation | Completed | `remediation`, `secure_code` | — |
| 56 | AI patch generation | In Progress | Secure code examples | Unified-diff patch proposals with human approval; never applied to repositories automatically |
| 57 | AI risk assessment | In Progress | Suggested severity | Explanation of the contextual risk score (with 43) |
| 58 | AI finding correlation | Not Started | — | Suggest related or duplicate findings across tools (with 33) |
| 59 | AI report generation | Completed | `assessment_summary` per review | Report-level summaries (see 84 and 85) |
| 60 | AI review assistant | Completed | AI panel | — |

The required review page sections are covered by the 8 workspace tabs: Overview, Source code, Data flow, Exploitability, Evidence, Risk, Remediation and History. "Technical evidence", "Scanner information" and "AI analysis" are inside Overview, Evidence and the AI panel.

## E. AI Security Analyst (requirements, no numbered features)

| Requirement | State |
|---|---|
| Ollama, local models (Qwen and others), offline inference | ✓ self-hosted provider (`00008_local_ai`, Ollama container) |
| Configurable providers, model configuration | ✓ versioned AI configurations |
| Health | ✓ provider test |
| Token and execution tracking | ✓ per review and suggestion; no usage dashboard |
| Administrator enable/disable | ✓ auto-review, Human Review AI switch |
| No source sent externally without configuration | ✓ `send_code_context`, redaction, secrets never sent |
| Human approval of AI changes | ✓ approval queue |
| Capabilities 1–6 | ✓ (see D) |
| 7 (dependency analysis), 8 (correlation), 9 (risk explanation), 10 (technical and executive reports) | **missing** |
| Dedicated "AI Security Analyst" workspace (conversation over the security data, usage) | **missing**. MCP already exposes the data to external assistants |

## F. Software supply chain and DevSecOps

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 61 | SBOM generation | Completed | ✓ | ✓ | ✓ | ✓ | Syft, CycloneDX, per scan | SPDX export |
| 62 | SBOM import | Not Started | — | — | — | — | — | CycloneDX and SPDX upload; components and vulnerabilities through Grype or OSV on the imported SBOM |
| 63 | Dependency graph analysis | In Progress | ◐ | ◐ | ◐ | ✓ | Flat inventory | Edges, direct and transitive (see 22) |
| 64 | Package risk | In Progress | ◐ | ◐ | — | ◐ | Known vulnerabilities | Outdated and unsupported signals (latest version, end of life, deprecation), OpenSSF Scorecard |
| 65 | Malicious packages | In Progress | ◐ | — | — | — | OSV `MAL-*` via OSV-Scanner | Classify and highlight; KEV-like urgency |
| 66 | Licence compliance | Completed | ✓ | ✓ | ✓ | ✓ | Policy and SBOM view | Findings for violations (see 10) |
| 67 | CI/CD pipeline security | Not Started | — | — | — | — | actionlint and zizmor catalogued | Adapters for GitHub Actions (zizmor, actionlint) and pipeline misconfiguration rules |
| 68 | GitHub | Completed | ✓ | ✓ | ✓ | ✓ | PAT, App, OAuth, webhooks | Checks API (see 72) |
| 69 | GitLab | Completed | ✓ | ✓ | ✓ | ✓ | | MR notes or status (see 72) |
| 70 | Azure DevOps | Completed | ✓ | ✓ | ✓ | ✓ | | PR status (see 72) |
| 71 | Bitbucket | Completed | ✓ | ✓ | ✓ | ✓ | | Commit status (see 72) |
| 72 | Pull-request checks | Not Started | ◐ | — | ◐ | — | PR webhooks parsed, not acted on | Scan the PR head, diff against the base branch, report status or check back to the provider, gate policy |
| 73 | Commit-level analysis | In Progress | ◐ | ◐ | ✓ | ✓ | Commit recorded per scan and occurrence | "Introduced in commit" attribution, push-triggered diff summaries |
| 74 | Build artifact scanning | Not Started | — | — | — | — | — | Artifact and image targets (see 7, 11) |
| 75 | Software provenance | Not Started | — | — | — | — | — | Verify SLSA, in-toto and Sigstore attestations of images and artifacts (cosign) |

Formats: CycloneDX ✓ (generate), SPDX ✗, SARIF ✓ (internal, no import), OCI ✗.

Dependency inventory: vulnerable ✓, licence violations ✓, direct/transitive ✗, outdated ✗, malicious ◐, unsupported ✗.

## G. Enterprise security and governance

| # | Feature | Status | Evidence today | Gap |
|---|---|---|---|---|
| 76 | RBAC | Completed | Scoped roles, custom roles | — |
| 77 | MFA | Completed | Keycloak TOTP, enforcement | Recovery codes: enable Keycloak's recovery-codes authenticator |
| 78 | SSO | In Progress | OIDC through Keycloak | SAML 2.0 and external OIDC identity providers through Keycloak brokering: configuration, guide and tests |
| 79 | User management | Completed | | — |
| 80 | Team management | Completed | Teams and members | — |
| 81 | Audit logging | Completed | Partitioned, append-only | — |
| 82 | Policy engine | In Progress | SLA, licence policy, critical-finding gate | General policies (conditions on finding attributes and context → actions: block gate, require review, SLA, notify) |
| 83 | Compliance mapping | In Progress | Compliance scope per repository | Control mapping (OWASP ASVS, PCI DSS, ISO 27001, SOC 2 ↔ CWE and categories) and compliance views |
| 84 | Executive dashboard | In Progress | Dashboard | Executive view: risk by application or business unit, trend, MTTR, SLA compliance; printable |
| 85 | Custom reporting | Not Started | CSV exports | Saved report definitions (filters, grouping, columns), scheduled delivery, CSV and print layout |
| 86 | Scheduled scanning | Completed | | — |
| 87 | Distributed workers | Completed | Leased jobs, multiple workers | Additional worker families |
| 88 | Orchestration | Completed | | — |
| 89 | Scanner health | Completed | | — |
| 90 | Webhooks | In Progress | Inbound SCM webhooks | Outbound webhooks (signed with HMAC, retries) for findings, scans and reviews |
| 91 | REST API | Completed | `/api/v1`, documented | Personal API tokens for REST (today MCP only) |
| 92 | Jira | Not Started | — | Optional connector: create and link issues, status sync |
| 93 | ServiceNow | Not Started | — | Optional connector: incidents and vulnerability items |
| 94 | Notification engine | Completed | Email, in-app, rules, templates | Chat (Slack and Teams incoming webhooks) via 90 |
| 95 | Multi-tenant | In Progress | `organization_id` everywhere | Several organizations per deployment: tenant resolution, administration and isolation tests (see decision D3) |
| 96 | Custom security rules | In Progress | Same as 15 | Same as 15 |
| 97 | Data encryption | Completed | Keyring, encrypted stores, TLS | — |
| 98 | Backup and recovery | Completed | Scripts, tested restore | — |
| 99 | Plugin architecture | In Progress | Scanner adapter seam | Declarative scanner adapters, connector interface for ticketing and notifications |
| 100 | Offline / air-gapped | In Progress | Egress allow-list, local AI, no mandatory external service | Offline vulnerability database bundles (Trivy, Grype, OSV), offline EPSS and KEV import, air-gap install guide |

Authentication requirements:

| Requirement | State |
|---|---|
| Local accounts, secure hashing (Keycloak's built-in password hashing), TOTP, sessions, logout, revocation, password policy, RBAC, local admin recovery, authentication audit | ✓ |
| Recovery codes | ◐ (configuration) |
| SAML 2.0 and OIDC identity providers | ◐ (Keycloak supports them; not configured or tested) |
| No external SMS, email or domain needed locally | ✓ (Mailpit for development; email optional) |

## Biggest gaps by value

1. **Contextual risk engine** (21, 29, 37–40, 43): EPSS and KEV, CVSS vectors, confidence, explainable scoring, application rollup.
2. **Import pipeline** (SARIF/JSON, CycloneDX/SPDX): unlocks 4, 13, 62 and any third-party tool.
3. **Pull-request checks** (72) and **outbound webhooks** (90): developer workflow.
4. **Application intelligence** (16, 22, 23, 27, 28): application IDs, dependency edges, context graph, coverage, shadow assets.
5. **New target types** (3, 7, 8, 11, 74): DAST, API, images and artifacts on new worker families.
6. **Governance** (82–85): policy engine, compliance mapping, executive and custom reports.
7. **Ticketing** (92, 93), optional.
