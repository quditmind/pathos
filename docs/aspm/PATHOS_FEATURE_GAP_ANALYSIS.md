# PATHOS feature gap analysis and register

The 100 target capabilities compared with PATHOS. The first assessment was made on 2026-11-17 (`main` plus PR #29); the register has been updated after every ASPM phase and is current as of PATHOS 1.1 (phase 10 plus the 1.1 gap closure). This is also the **feature register**: update it whenever a capability changes. "Phase N" in the evidence column means an ASPM phase ([PATHOS_IMPLEMENTATION_ROADMAP.md](PATHOS_IMPLEMENTATION_ROADMAP.md)).

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
| A. Code and application scanning (1–15) | 15 | 0 | 0 |
| B. ASPM and application intelligence (16–30) | 15 | 0 | 0 |
| C. Vulnerability intelligence (31–45) | 15 | 0 | 0 |
| D. Manual validation and AI (46–60) | 15 | 0 | 0 |
| F. Supply chain and DevSecOps (61–75) | 15 | 0 | 0 |
| G. Enterprise and governance (76–100) | 24 | 1 | 0 |
| **Total** | **99** | **1** | **0** |

Module E (AI Security Analyst) has no numbered features. Its requirements are assessed in §E.

## A. Code and application security scanning

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 1 | SAST | Completed | ✓ | ✓ | ✓ | ✓ | Opengrep with baseline rules, multi-language | More engines (Bandit, Gosec, …) are catalogued only |
| 2 | SCA / dependencies | Completed | ✓ | ✓ | ✓ | ✓ | Trivy fs, Grype (on the Syft SBOM), OSV-Scanner; cross-tool de-duplication; automatic fix pull requests for vulnerable dependencies on GitHub, GitLab, Bitbucket and Azure DevOps (1.1) | Reachability (see 41) |
| 3 | DAST | Completed | ✓ | ✓ | ✓ | ✓ | Web application targets scanned by Nuclei (reviewed non-intrusive templates), header or basic authentication, recorded authorization, rate limits, egress preflight (phase 2b) | ZAP spidering and scripted login flows |
| 4 | IAST integration | Completed | ✓ | ✓ | ✓ | ✓ | IAST results imported as PATHOS findings JSON or SARIF (phase 2a) | — |
| 5 | Secrets | Completed | ✓ | ✓ | ✓ | ✓ | Gitleaks mandatory, redaction, optional full history; secret push protection: pre-commit and pre-receive Gitleaks hooks and push-event diff scanning with redacted alerts (1.1) | Secret validity checks (TruffleHog verify, opt-in) |
| 6 | IaC | Completed | ✓ | ✓ | ✓ | ✓ | Checkov | KICS and Kubescape adapters (optional) |
| 7 | Container image | Completed | ✓ | ✓ | ✓ | ✓ | Image targets (registry reference or digest) scanned by `trivy image` with registry credentials; findings keep package and fix data (phase 2b) | Dockle image-configuration checks; registry discovery |
| 8 | API security | Completed | ✓ | ✓ | ✓ | ✓ | API targets from OpenAPI 3 / Swagger 2 (servers locked to the authorized host) tested with Nuclei DAST templates (phase 2b) | Schemathesis property-based testing; GraphQL |
| 9 | Malware detection | Completed | ✓ | ✓ | ✓ | ✓ | ClamAV on source uploads and build artifacts (phase 10); the `clamav` scanner streams repository content to clamd over an isolated `malware` network: critical findings with signature, SHA-256 and engine version, unscannable files reported, skipped with a clear reason when not configured; OSV `MAL-*` malicious packages (phase 7) (1.1) | — |
| 10 | Licence scanning | Completed | ✓ | ✓ | ✓ | ✓ | Licence policy violations from the SBOM and from file-level licences (built-in `licensecheck`: google/licensecheck plus SPDX tags) are `license` findings with lifecycle and SLA, re-evaluated on policy change, resolved and never deleted (1.1) | Pull request scans create no licence findings; ScanCode not adopted (image size) |
| 11 | Binary analysis | Completed | ✓ | ✓ | ✓ | ✓ | Built-in `binary-hardening` checks ELF, PE and Mach-O (PIE, RELRO, NX, canaries, FORTIFY, RPATH; ASLR, HIGH_ENTROPY_VA, DEP, CFG, SafeSEH, /GS) with remediation flags; always on for build artifacts, optional for repositories; Trivy for vulnerable components (1.1) | — |
| 12 | Application configuration scanning | Completed | ✓ | ✓ | ✓ | ✓ | 27 Opengrep framework configuration rules (Spring Boot, Django, Express) with CWE, references and tested fixtures; `misconfiguration` finding category; Checkov and Trivy for other configuration files (1.1) | More frameworks (Rails, Laravel, ASP.NET) |
| 13 | Fuzz testing | Completed | ✓ | ✓ | ✓ | ✓ | Fuzzing crash results imported (SARIF or PATHOS JSON) (phase 2a) | Running fuzzers stays in the customer's pipeline |
| 14 | Infrastructure exposure | Completed | ✓ | ✓ | ✓ | ✓ | Declared public URLs, domains and IPs per repository; opt-in, authorization-gated, rate-limited worker verification through the egress proxy (DNS, reachability, TLS, HSTS, security headers, optional Nuclei exposure templates); per-endpoint status and findings; disabled offline (1.1) | Ports other than 80/443 through the default egress proxy |
| 15 | Custom detection rules | Completed | ✓ | ✓ | ✓ | ✓ | Custom Opengrep rules: validation, versions, enable/disable; scans pin versions (phase 2a) | — |

Cross-cutting requirements:

| Requirement | State |
|---|---|
| Multiple languages | ✓ |
| Git and local source | ✓ |
| Configurable profiles, full scans, execution history, worker health, logs, severity thresholds, structured results | ✓ |
| Incremental scanning | **missing**. Diff-aware scans for PRs (see 72) |
| **SARIF/JSON import** | ✓ 25 formats: SARIF 2.1, 21 native tool formats (JSON, JSON lines, XML), generic CSV and PATHOS findings JSON; explicit or detected format (phase 2a, 1.1) |
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
| Token and execution tracking | ✓ per review, suggestion, analyst answer and report; AI usage dashboard by feature, model, person and day (phase 6) |
| Administrator enable/disable | ✓ auto-review, Human Review AI switch |
| No source sent externally without configuration | ✓ `send_code_context`, redaction, secrets never sent |
| Human approval of AI changes | ✓ approval queue |
| Capabilities 1–6 | ✓ (see D) |
| 7 (dependency analysis), 8 (correlation), 9 (risk explanation), 10 (technical and executive reports) | ✓ dependency paths and reachability (phases 3–4), related findings and AI duplicate suggestions (phases 4–5), AI risk explanation (phase 5), AI technical and executive reports over PATHOS-computed figures (phase 6) |
| Dedicated "AI Security Analyst" workspace (conversation over the security data, usage) | ✓ private, scoped, cited conversations; usage dashboard (phase 6). MCP also exposes the data to external assistants |

## F. Software supply chain and DevSecOps

| # | Feature | Status | B | F | D | T | Evidence today | Gap |
|---|---|---|---|---|---|---|---|---|
| 61 | SBOM generation | Completed | ✓ | ✓ | ✓ | ✓ | Syft CycloneDX per scan; CycloneDX 1.5 and SPDX 2.3 export of the inventory with its dependency graph (phase 7); VEX export (OpenVEX, CycloneDX) per repository or application version (1.1) | — |
| 62 | SBOM import | Completed | ✓ | ✓ | ✓ | ✓ | CycloneDX and SPDX import into the component inventory (phase 2a); SBOM targets matched by Grype on workers (phase 2b); VEX import as reviewable suggestions with four-eyes approval; application versions with frozen SBOM and findings snapshots and portfolio search (1.1) | — |
| 63 | Dependency graph analysis | Completed | ✓ | ✓ | ✓ | ✓ | Dependency edges, direct and transitive depth, paths (phase 3, see 22) | — |
| 64 | Package risk | Completed | ✓ | ✓ | ✓ | ✓ | Known vulnerabilities; latest, outdated, deprecated versions and OpenSSF Scorecard from deps.dev (phase 7); end-of-life dates from endoflife.date (opt-in feed, offline import) for SBOM components, declared runtimes, Dockerfile base images and image targets, with `eol` findings and SLA (1.1) | End of life of image targets from the reference only, not the image contents |
| 65 | Malicious packages | Completed | ✓ | ✓ | ✓ | ✓ | OSV `MAL-*` advisories and malware reports classified as malicious; KEV-level likelihood, always reachable; badge, filter and remediation guidance (phase 7) | — |
| 66 | Licence compliance | Completed | ✓ | ✓ | ✓ | ✓ | Policy and SBOM view | Findings for violations (see 10) |
| 67 | CI/CD pipeline security | Completed | ✓ | ✓ | ✓ | ✓ | zizmor (phase 2b) and actionlint (phase 7) for GitHub Actions; Checkov for GitLab CI, Azure Pipelines and Bitbucket Pipelines; CI integration: `pathos` CLI, GitHub Action, GitLab, Azure Pipelines and Jenkins templates with a security gate (1.1) | — |
| 68 | GitHub | Completed | ✓ | ✓ | ✓ | ✓ | PAT, App, OAuth, webhooks, commit statuses (phase 7) | — |
| 69 | GitLab | Completed | ✓ | ✓ | ✓ | ✓ | Commit statuses on merge requests (phase 7) | — |
| 70 | Azure DevOps | Completed | ✓ | ✓ | ✓ | ✓ | Commit statuses on pull requests (phase 7) | — |
| 71 | Bitbucket | Completed | ✓ | ✓ | ✓ | ✓ | Build statuses on pull requests (phase 7) | — |
| 72 | Pull-request checks | Completed | ✓ | ✓ | ✓ | ✓ | Opt-in per repository: PR head scanned with the repository's profile, results kept apart from the scan branch's findings, new vs already known, gate by severity, commit status on all four providers (phase 7); CI templates with a security gate exit code (1.1) | Pull requests from forks (the head branch must be in the repository) |
| 73 | Commit-level analysis | Completed | ✓ | ✓ | ✓ | ✓ | Commit per scan and occurrence; introducing commit and date from git blame on code findings (author name only while developer attribution is on; "unknown (shallow clone)" without history); push and merge change summaries on the scan, in notifications and webhooks; security-material change detection between scans (1.1) | Shallow clones are not deepened for blame |
| 74 | Build artifact scanning | Completed | ✓ | ✓ | ✓ | ✓ | Container image targets (phase 2b); uploaded artifacts (zip, tar, Java archives, binaries) extracted safely on workers and scanned by Trivy (phase 7) | — |
| 75 | Software provenance | Completed | ✓ | ✓ | ✓ | ✓ | SLSA provenance of direct dependencies from deps.dev (phase 7); pinned cosign verifies image and artifact signatures (key or keyless) and in-toto/SLSA attestations, evidence per scan, optional "require signature" finding and gate failure; key-only offline (1.1) | Keyless verification offline (no bundled Sigstore trust root) |

Formats: CycloneDX ✓ (generate, import, export), SPDX ✓ (import and export), SARIF ✓ (internal and import), OCI ✗.

Dependency inventory: vulnerable ✓, licence violations ✓, direct/transitive ✓, outdated ✓, malicious ✓, deprecated ✓, end of life ✗.

## G. Enterprise security and governance

| # | Feature | Status | Evidence today | Gap |
|---|---|---|---|---|
| 76 | RBAC | Completed | Scoped roles, custom roles | — |
| 77 | MFA | Completed | Keycloak TOTP, enforcement; recovery codes (self-service and administrators, sign-in with a code; phase 8) | — |
| 78 | SSO | Completed | OIDC through Keycloak; SAML 2.0 and external OIDC identity providers brokered by Keycloak: guide and end-to-end test of both (phase 8) | — |
| 79 | User management | Completed | | — |
| 80 | Team management | Completed | Teams and members | — |
| 81 | Audit logging | Completed | Partitioned, append-only | — |
| 82 | Policy engine | Completed | Security policies: conditions on findings (severity, type, CWE, risk, KEV, malicious, reachability, age) and context (criticality, exposure, environment, data, compliance scope, repositories) → block scan and PR gates, require a Human Eye review, tighten the SLA, notify; dry-run preview, violations, versions, audit (phase 8) | — |
| 83 | Compliance mapping | Completed | OWASP Top 10 2021, OWASP ASVS 4.0.3, PCI DSS 4.0.1, ISO/IEC 27001:2022 Annex A, SOC 2 controls mapped by category, CWE and malicious packages; per-framework views over the repositories in scope; findings filter by control (phase 8). Indicative evidence, not a verdict | — |
| 84 | Executive dashboard | Completed | Executive overview: open critical/high, KEV, SLA compliance, new vs fixed, weekly trend and backlog, MTTR by severity, riskiest applications and business units; printable (phase 9) | — |
| 85 | Custom reporting | Completed | Saved reports (Findings filters, grouping, columns), shared, scheduled delivery as a link, CSV with formula protection, print; each reader sees only their scope (phase 9) | — |
| 86 | Scheduled scanning | Completed | | — |
| 87 | Distributed workers | Completed | Leased jobs, multiple workers | Additional worker families |
| 88 | Orchestration | Completed | | — |
| 89 | Scanner health | Completed | | — |
| 90 | Webhooks | Completed | Inbound SCM webhooks; outbound webhooks for every notification event: signed JSON (HMAC-SHA256), Slack, Microsoft Teams; retries with back-off, delivery log, SSRF protection, encrypted URLs (phase 9) | — |
| 91 | REST API | Completed | `/api/v1`, documented; personal API tokens for REST (read or read-write, owner's permissions, audited) (phase 9); `pathos` CLI and the scan gate endpoint (1.1) | — |
| 92 | Jira | Completed | Optional connector (Cloud and Data Center): create an issue for a finding, link, status sync (phase 9) | Automatic ticket creation by policy |
| 93 | ServiceNow | Completed | Optional connector: incidents (any table), link, status sync (phase 9) | Vulnerability Response items |
| 94 | Notification engine | Completed | Email, in-app, rules, templates; Slack and Microsoft Teams through webhooks (phase 9) | — |
| 95 | Multi-tenant | In Progress | `organization_id` everywhere | Several organizations per deployment: tenant resolution, administration and isolation tests (see decision D3) |
| 96 | Custom security rules | Completed | Same as 15 (phase 2a) | — |
| 97 | Data encryption | Completed | Keyring, encrypted stores, TLS | — |
| 98 | Backup and recovery | Completed | Scripts, tested restore | — |
| 99 | Plugin architecture | Completed | Declarative scanner adapters defined on workers (SARIF, no code; phase 10); connector interface for issue trackers (phase 10); import adapters for any SARIF tool; import adapters for 25 formats (1.1) | — |
| 100 | Offline / air-gapped | Completed | `PATHOS_OFFLINE` mode; offline bundles of the Trivy, Grype and OSV databases and the EPSS and KEV feeds with checksum verification (`scripts/offline-bundle.sh`); air-gap guide; local AI; egress allow-list (phase 10) | — |

Authentication requirements:

| Requirement | State |
|---|---|
| Local accounts, secure hashing (Keycloak's built-in password hashing), TOTP, sessions, logout, revocation, password policy, RBAC, local admin recovery, authentication audit | ✓ |
| Recovery codes | ✓ (phase 8) |
| SAML 2.0 and OIDC identity providers | ✓ (Keycloak brokering; guide and end-to-end test, phase 8) |
| No external SMS, email or domain needed locally | ✓ (Mailpit for development; email optional) |

## Remaining gaps

The original "biggest gaps by value" were closed in ASPM phases 1 to 9; PATHOS 1.1 completed the eight remaining capabilities (9, 10, 11, 12, 14, 64, 73, 75). One capability is still **In Progress**, by decision:

| # | Capability | What is missing |
|---|---|---|
| 95 | Multi-tenant | Several organizations per deployment (decision D3: single organization) |

Smaller limits are listed in each row's Gap column.

## Beyond the register (1.1)

Capabilities added in 1.1 to match other application security tools; they have no numbered row:

- **Import breadth:** 25 import formats (21 native tool formats, generic CSV, SARIF, Grype, PATHOS JSON).
- **CI/CD:** the `pathos` CLI (import, scan, gate, findings, SBOM export) and GitHub Action, GitLab, Azure Pipelines and Jenkins templates.
- **Automatic fix pull requests** for vulnerable dependencies on four SCMs, with honest per-ecosystem support; findings are resolved only by a later scan.
- **VEX, application versions and component policies:** OpenVEX and CycloneDX VEX export and reviewed import, frozen release snapshots, portfolio search, operational SBOM policies.
- **Secret push protection:** pre-commit and pre-receive hooks and push-event diff scanning with redacted alerts.
- **Material change detection:** explainable rules for authentication, endpoints, crypto, IaC exposure, CI/CD, secrets handling and PII changes between scans; a notification event and a policy condition.
- **Developer attribution:** who introduces and fixes findings, off by default, with identity linking and erasure.
- **VS Code extension:** findings in the editor, triage from VS Code.
