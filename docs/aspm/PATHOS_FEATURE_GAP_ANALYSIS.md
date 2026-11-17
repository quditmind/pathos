# PATHOS feature gap analysis and register

The 100 target capabilities compared with PATHOS as of 2026-11-17 (`main` plus PR #29), updated after phase 1. This is also the **feature register**. Update it as phases land.

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
| A. Code and application scanning (1–15) | 10 | 4 | 1 |
| B. ASPM and application intelligence (16–30) | 15 | 0 | 0 |
| C. Vulnerability intelligence (31–45) | 15 | 0 | 0 |
| D. Manual validation and AI (46–60) | 15 | 0 | 0 |
| F. Supply chain and DevSecOps (61–75) | 7 | 5 | 3 |
| G. Enterprise and governance (76–100) | 14 | 8 | 3 |
| **Total** | **76** | **17** | **7** |

Module E (AI Security Analyst) has no numbered features. Its requirements are assessed in §E.

## A. Code and application security scanning

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 1 | SAST | Completed | ✓ | ✓ | ✓ | ✓ | Opengrep with baseline rules, multi-language | More engines (Bandit, Gosec, …) are catalogued only |
| 2 | SCA / dependencies | Completed | ✓ | ✓ | ✓ | ✓ | Trivy fs, Grype (on the Syft SBOM), OSV-Scanner; cross-tool de-duplication | Reachability (see 41) |
| 3 | DAST | Completed | ✓ | ✓ | ✓ | ✓ | Web application targets scanned by Nuclei (reviewed non-intrusive templates), header or basic authentication, recorded authorization, rate limits, egress preflight (phase 2b) | ZAP spidering and scripted login flows |
| 4 | IAST integration | Completed | ✓ | ✓ | ✓ | ✓ | IAST results imported as PATHOS findings JSON or SARIF (phase 2a) | — |
| 5 | Secrets | Completed | ✓ | ✓ | ✓ | ✓ | Gitleaks mandatory, redaction, optional full history | Secret validity checks (TruffleHog verify, opt-in) |
| 6 | IaC | Completed | ✓ | ✓ | ✓ | ✓ | Checkov | KICS and Kubescape adapters (optional) |
| 7 | Container image | Completed | ✓ | ✓ | ✓ | ✓ | Image targets (registry reference or digest) scanned by `trivy image` with registry credentials; findings keep package and fix data (phase 2b) | Dockle image-configuration checks; registry discovery |
| 8 | API security | Completed | ✓ | ✓ | ✓ | ✓ | API targets from OpenAPI 3 / Swagger 2 (servers locked to the authorized host) tested with Nuclei DAST templates (phase 2b) | Schemathesis property-based testing; GraphQL |
| 9 | Malware detection | In Progress | ◐ | ◐ | ◐ | ✓ | ClamAV on uploads; OSV `MAL-*` advisories arrive as SCA findings | Repository and artifact malware scanning, a "malicious package" classification |
| 10 | Licence scanning | In Progress | ✓ | ✓ | ✓ | ◐ | Licences from the SBOM, deny/review policy, SBOM page and KPI | Violations as findings (lifecycle and SLA), ScanCode for file-level licences |
| 11 | Binary analysis | Not Started | — | — | — | — | — | Artifact targets; Syft and Grype on binaries and archives; checksec-style hardening checks |
| 12 | Application configuration scanning | In Progress | ◐ | ◐ | — | ◐ | Checkov and Trivy cover some configuration files | Framework config rules (Spring, Django, Express), a misconfiguration category |
| 13 | Fuzz testing | Completed | ✓ | ✓ | ✓ | ✓ | Fuzzing crash results imported (SARIF or PATHOS JSON) (phase 2a) | Running fuzzers stays in the customer's pipeline |
| 14 | Infrastructure exposure | In Progress | ◐ | ✓ | ✓ | ✓ | Internet exposure, public URLs, domains and IPs per repository (declared) | Verification of declared endpoints (Nuclei, TLS checks), opt-in and scope-limited |
| 15 | Custom detection rules | Completed | ✓ | ✓ | ✓ | ✓ | Custom Opengrep rules: validation, versions, enable/disable; scans pin versions (phase 2a) | — |

Cross-cutting requirements:

| Requirement | State |
|---|---|
| Multiple languages | ✓ |
| Git and local source | ✓ |
| Configurable profiles, full scans, execution history, worker health, logs, severity thresholds, structured results | ✓ |
| Incremental scanning | **missing**. Diff-aware scans for PRs (see 72) |
| **SARIF/JSON import** | ✓ SARIF 2.1, Grype JSON, PATHOS findings JSON (phase 2a) |
| Adding engines | Compiled in. Documented adapter seam; a declarative adapter (SARIF tools) would make it data-driven |

## B. ASPM and application intelligence

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 16 | Application inventory | Completed | ✓ | ✓ | ✓ | ✓ | Applications with permanent IDs, owners, lifecycle, environment (phase 1); last scan, open findings, exposure, coverage and risk per application (phase 3) | — |
| 17 | Repository discovery | Completed | ✓ | ✓ | ✓ | ✓ | SCM discovery across organizations and projects | — |
| 18 | Application ↔ repository mapping | Completed | ✓ | ✓ | ✓ | ✓ | `repositories.application_id` | Many-to-many (monorepos serving several applications) is optional |
| 19 | Ownership | Completed | ✓ | ✓ | ✓ | ✓ | Owners on applications and repositories, teams | — |
| 20 | Posture dashboard | Completed | ✓ | ✓ | ✓ | ✓ | Live KPIs and trends | Application-level view (with 21) |
| 21 | Application risk scoring | Completed | ✓ | ✓ | ✓ | ✓ | Explainable rollup per application: riskiest open finding + up to 15 points for other high-risk findings (phase 3) | — |
| 22 | Dependency graph | Completed | ✓ | ✓ | ✓ | ✓ | CycloneDX and SPDX dependency edges, direct/transitive depth, repository Dependencies tab with paths, finding dependency paths (phase 3) | Graph across repositories (shared internal libraries) |
| 23 | Security context graph | Completed | ✓ | ✓ | ✓ | ✓ | Context graph of an application or repository (owners, teams, business unit, repositories, targets, components, findings) and blast radius for a CVE or package (phase 3), computed from the relational model | Arbitrary graph queries; runtime and cloud nodes |
| 24 | Business criticality | Completed | ✓ | ✓ | ✓ | ✓ | Application and repository criticality | Used in risk scoring (21) |
| 25 | Internet exposure | Completed | ✓ | ✓ | ✓ | ✓ | Exposure yes/no/unknown with endpoints | Used in risk scoring |
| 26 | Lifecycle management | Completed | ✓ | ✓ | ✓ | ✓ | Repository and application lifecycle (phase 1) | — |
| 27 | Shadow application discovery | Completed | ✓ | ✓ | ✓ | ✓ | Daily SCM inventory per connection; unmanaged-assets report (shadow repositories, no application or owner, never or stale scans, failing sync) (phase 3) | Discovery beyond SCM (registries, cloud) |
| 28 | Coverage mapping | Completed | ✓ | ✓ | ✓ | ✓ | Repositories × SAST, secrets, SCA, IaC, CI/CD, container, DAST with last success and covered/stale/never/no-target (phase 3) | — |
| 29 | Risk aggregation | Completed | ✓ | ✓ | ✓ | ✓ | Posture by application, business unit, team, owner and region (phase 3) | — |
| 30 | Benchmarking | Completed | ✓ | ✓ | ✓ | ✓ | Normalised comparison (risk, open and critical/high per repository, KEV, MTTR, SLA compliance, coverage) with best/worst and median (phase 3) | Per-KLOC normalisation; trends over time |

## C. Vulnerability intelligence and management

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 31 | Central repository | Completed | ✓ | ✓ | ✓ | ✓ | `findings` with occurrences and provenance | — |
| 32 | Normalisation | Completed | ✓ | ✓ | ✓ | ✓ | SARIF and Grype parsers, severity mapping, CWE and CVE extraction; confidence and CVSS vectors (phase 1) | — |
| 33 | Duplicate detection | Completed | ✓ | ✓ | ✓ | ✓ | Line-independent fingerprints, cross-tool SCA merge by package and CVE; related findings across tools (same location and CWE, same CVE) without merging (phase 4) | — |
| 34 | False-positive management | Completed | ✓ | ✓ | ✓ | ✓ | Status, AI with approval, Human Review; four-eyes suppression rules with expiry and automatic reopening (phase 4) | — |
| 35 | Lifecycle | Completed | ✓ | ✓ | ✓ | ✓ | Trigger-recorded history, recurrence; unified lifecycle status New, Open, In progress, Under review, Confirmed, False positive, Accepted risk, Resolved, Reopened, derived without changing stored values (phase 1) | — |
| 36 | CVE intelligence | Completed | ✓ | ✓ | ✓ | ✓ | OSV records (online lookups, offline import) with descriptions, references, aliases, affected and fixed versions; vulnerability page with EPSS and KEV (phase 4) | NVD as an additional source |
| 37 | CVSS scoring | Completed | ✓ | ✓ | ✓ | ✓ | Scanner score, version and vector per finding; vendor vectors from OSV when the scanner gives none; CVSS 3.1 and 4.0 in Human Eye (phases 1, 4) | — |
| 38 | EPSS | Completed | ✓ | ✓ | ✓ | ✓ | FIRST EPSS feed: daily download or offline import, per finding (phase 1) | — |
| 39 | CISA KEV | Completed | ✓ | ✓ | ✓ | ✓ | CISA KEV feed: daily download or offline import, flag and due date per finding (phase 1) | — |
| 40 | Exploitability analysis | Completed | ✓ | ✓ | ✓ | ✓ | Human Eye questions, AI verdicts; EPSS, KEV and OSV exploit/proof-of-concept references in the risk score (phases 1, 4) | Exploit databases beyond OSV references |
| 41 | Dependency reachability | Completed | ✓ | ✓ | ✓ | ✓ | Package-level reachability from a code inventory (imports, names, browser assets) and the dependency graph; explained; weights risk only (phase 4) | Function-level reachability (govulncheck call graphs, Java) |
| 42 | Attack path analysis | Completed | ✓ | ✓ | ✓ | ✓ | Paths from the internet through tested applications or exposed assets to code findings, images and reachable vulnerable packages, ranked by risk (phase 4) | Runtime and cloud network topology |
| 43 | Risk prioritisation | Completed | ✓ | ✓ | ✓ | ✓ | Configurable, versioned, explainable contextual risk score; sort and filter by risk (phase 1) | — |
| 44 | SLA tracking | Completed | ✓ | ✓ | ✓ | ✓ | Per-severity policies, breach notifications | SLA by risk score (optional) |
| 45 | Trend analysis | Completed | ✓ | ✓ | ✓ | ✓ | Dashboard trends, scan comparison | — |

Unified finding fields: **present**: ID, title, description, category, CWE, CVE, CVSS score, version and vector, EPSS, KEV, confidence, risk score, lifecycle status, scanner, repository, path, line, application (through the repository), dependency, code evidence, severity, first and last seen, owner, remediation (status and SLA), reviewer status (PR #29). **Missing**: business impact (beyond criticality), automated reachability (phase 4).

## D. Manual validation (Human Eye = Human Review) and AI assistance

| # | Feature | Status | Evidence | Gap |
|---|---|---|---|---|
| 46 | Review queue | Completed | PR #29 | — |
| 47 | Manual validation | Completed | Workspace and dispositions | — |
| 48 | False-positive confirmation | Completed | Justified disposition, independent review | — |
| 49 | Evidence management | Completed | Encrypted uploads, text, reproduction template | — |
| 50 | Reviewer assignment | Completed | Manual, bulk, round robin, least loaded | — |
| 51 | Multi-level approval | Completed | Optional third level: final approval by a third person for chosen severities and dispositions (phase 5) | — |
| 52 | AI explanation | Completed | AI assist `explanation` | — |
| 53 | AI code analysis | Completed | `code_summary`, `code_paths` | — |
| 54 | AI false-positive assistance | Completed | AI review verdicts, `false_positive_indicators` | — |
| 55 | AI remediation | Completed | `remediation`, `secure_code` | — |
| 56 | AI patch generation | Completed | Unified-diff patch proposals, validated, approved or rejected by a person, downloadable; never applied to repositories (phase 5) | — |
| 57 | AI risk assessment | Completed | Suggested severity; AI explanation of the contextual risk score and its factors (phase 5) | — |
| 58 | AI finding correlation | Completed | AI suggestions of possible duplicates among nearby, same-rule and same-CVE findings (phase 5); deterministic related findings (phase 4) | — |
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
| 62 | SBOM import | Completed | ✓ | ✓ | ✓ | ✓ | CycloneDX and SPDX import into the component inventory (phase 2a); SBOM targets matched by Grype on workers (phase 2b) | — |
| 63 | Dependency graph analysis | In Progress | ◐ | ◐ | ◐ | ✓ | Flat inventory | Edges, direct and transitive (see 22) |
| 64 | Package risk | In Progress | ◐ | ◐ | — | ◐ | Known vulnerabilities | Outdated and unsupported signals (latest version, end of life, deprecation), OpenSSF Scorecard |
| 65 | Malicious packages | In Progress | ◐ | — | — | — | OSV `MAL-*` via OSV-Scanner | Classify and highlight; KEV-like urgency |
| 66 | Licence compliance | Completed | ✓ | ✓ | ✓ | ✓ | Policy and SBOM view | Findings for violations (see 10) |
| 67 | CI/CD pipeline security | In Progress | ✓ | ◐ | ✓ | ✓ | zizmor audits GitHub Actions workflows and actions offline (phase 2b) | actionlint; GitLab CI, Azure Pipelines and Bitbucket Pipelines rules |
| 68 | GitHub | Completed | ✓ | ✓ | ✓ | ✓ | PAT, App, OAuth, webhooks | Checks API (see 72) |
| 69 | GitLab | Completed | ✓ | ✓ | ✓ | ✓ | | MR notes or status (see 72) |
| 70 | Azure DevOps | Completed | ✓ | ✓ | ✓ | ✓ | | PR status (see 72) |
| 71 | Bitbucket | Completed | ✓ | ✓ | ✓ | ✓ | | Commit status (see 72) |
| 72 | Pull-request checks | Not Started | ◐ | — | ◐ | — | PR webhooks parsed, not acted on | Scan the PR head, diff against the base branch, report status or check back to the provider, gate policy |
| 73 | Commit-level analysis | In Progress | ◐ | ◐ | ✓ | ✓ | Commit recorded per scan and occurrence | "Introduced in commit" attribution, push-triggered diff summaries |
| 74 | Build artifact scanning | Not Started | — | — | — | — | — | Artifact and image targets (see 7, 11) |
| 75 | Software provenance | Not Started | — | — | — | — | — | Verify SLSA, in-toto and Sigstore attestations of images and artifacts (cosign) |

Formats: CycloneDX ✓ (generate and import), SPDX ✓ (import), SARIF ✓ (internal and import), OCI ✗.

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
| 96 | Custom security rules | Completed | Same as 15 (phase 2a) | — |
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
