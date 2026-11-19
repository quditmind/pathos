Quditmind PATHOS · applies to v2.2.0 · status: Existing

# PATHOS feature gap analysis and register

The 100 target capabilities compared with PATHOS. The first assessment was made on 2026-11-17 (`main` plus PR #29); the register has been updated after every ASPM phase and is current as of PATHOS 1.1 (phase 10 plus the 1.1 gap closure). This is also the **feature register**: update it whenever a capability changes. The lifecycle release (the owner's nine-phase build prompt) is assessed separately in [Lifecycle release capability matrix (M0)](#lifecycle-release-capability-matrix-m0) at the end; the 100-row register above it is unchanged. "Phase N" in the evidence column means an ASPM phase ([PATHOS_IMPLEMENTATION_ROADMAP.md](PATHOS_IMPLEMENTATION_ROADMAP.md)).

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
| G. Enterprise and governance (76–100) | 25 | 0 | 0 |
| **Total** | **100** | **0** | **0** |

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
| 95 | Multi-tenant | Completed | Optional multi-tenancy (2.2; decision D3 revised): several isolated organizations per installation, enabled with `pathosctl multi-tenancy enable`. Organization from the authenticated session, token or worker only; PostgreSQL row-level security on every tenant table with the scope set on every connection checkout; same-organization foreign keys; installation administrators create, suspend and delete organizations; memberships of one person in several organizations with an organization switcher; Keycloak group or OIDC claim mapping; one organization per worker; cross-tenant isolation suite over every API route, MCP, worker API and webhooks, with and without row-level security ([MULTI_TENANCY.md](../MULTI_TENANCY.md)) | No shared workers; claim mapping adds but never removes memberships; row-level security can make lookups by `lower(...)` slower (not measured at scale); readable keys come from installation-wide sequences |
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

The original "biggest gaps by value" were closed in ASPM phases 1 to 9; PATHOS 1.1 completed the eight remaining capabilities (9, 10, 11, 12, 14, 64, 73, 75). The last one, 95 (multi-tenant), was kept out by decision D3 (single organization) until the owner revised it for PATHOS 2.2: multi-tenancy is now supported as an option that an operator enables, and single-organization installs are unchanged ([MULTI_TENANCY.md](../MULTI_TENANCY.md)). No capability is In Progress.

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

## Lifecycle release capability matrix (M0)

This matrix compares every capability in the owner's lifecycle build prompt with PATHOS **2.2.0** (commit `f3c5efd`, checked 2026-11-20). It covers §2 to §5 and the scope of every milestone from M1 to M11. The prompt calls the work "PATHOS 2.0" from a 1.1.1 base. Both are out of date (see [PATHOS_ARCHITECTURE_ASSESSMENT.md §8.4](PATHOS_ARCHITECTURE_ASSESSMENT.md#84-conflicts-between-the-prompt-and-the-code-the-code-wins-for-what-exists)), so this document says "the lifecycle release" and assigns no version.

**Status** values for this matrix (separate from the register's Completed / In Progress / Not Started):

| Status | Meaning |
|---|---|
| **Implemented** | Exists in code with UI and tests and meets the prompt's requirement |
| **Partial** | Some of it exists; the notes say what is missing |
| **Missing** | Nothing in the code |
| **Needs improvement** | Exists, but must change to meet the prompt (behaviour, copy, coverage) |
| **Needs architecture change** | Needs a new component, a contract change, or a decision recorded in an ADR |

Paths are relative to `backend/internal/` for Go and to `frontend/src/` for TypeScript unless they start with another top-level folder. Rows for §2 to §5 also belong to M1 unless the milestone column says otherwise. The matrix has more rows than the prompt's estimate (80 to 150) because the shell and help items are listed one by one. A few rows (L024 to L026, L104, L154, L163) record capabilities that already exist and only move in the menu, so that nothing is lost.

What the counts mean in practice:

- Most of the **new modules** are Missing: CodeGraph, threat modelling, reverse engineering, the diagnostic catalogue and feature flags.
- Most of **M2, M3, M6, M7 and M8** is Partial or Implemented. Those milestones should map and extend the existing code, not rebuild it.

### Summary

| Area | Rows | Implemented | Partial | Missing | Needs improvement | Needs architecture change |
|---|---|---|---|---|---|---|
| §2 Enterprise shell | 27 | 5 | 4 | 17 | 1 | 0 |
| §3 Diagnostics | 14 | 0 | 3 | 9 | 0 | 2 |
| §4 UI standards | 17 | 2 | 8 | 4 | 1 | 2 |
| §5 Information architecture and hub | 18 | 6 | 4 | 7 | 1 | 0 |
| M1 extra (feature flags, tests) | 4 | 0 | 1 | 2 | 0 | 1 |
| M2 Connectors | 15 | 3 | 6 | 5 | 0 | 1 |
| M3 Onboarding and inventory | 9 | 4 | 5 | 0 | 0 | 0 |
| M4 CodeGraph | 12 | 0 | 5 | 6 | 0 | 1 |
| M5 Threat modelling | 8 | 0 | 3 | 5 | 0 | 0 |
| M6 Scan profiles and tools | 9 | 2 | 4 | 1 | 2 | 0 |
| M7 AI intelligence | 9 | 1 | 6 | 1 | 1 | 0 |
| M8 Remediation and gates | 13 | 5 | 5 | 2 | 1 | 0 |
| M9 Reporting and monitoring | 8 | 3 | 3 | 2 | 0 | 0 |
| M10 Reverse engineering, static | 6 | 0 | 2 | 4 | 0 | 0 |
| M11 Reverse engineering, sandbox | 3 | 0 | 0 | 2 | 0 | 1 |
| **Total** | **172** | **31** | **59** | **67** | **7** | **8** |

### §2 Global enterprise shell

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L001 Logo mark in the top-left brand block | §2.1 | Implemented | `components/layout/Logo.tsx` `LogoMark`; `AppShell.tsx:230` | M1 | Reuse as is |
| L002 Wordmark "Quditmind \| PATHOS" | §2.1 | Missing | `Logo.tsx` `Wordmark` renders "PATHOS" only | M1 | Text change; keep tokens |
| L003 Version chip from the backend version | §2.1 | Missing | Only `GET /healthz` returns `version` (`server/server.go:104-106`); nothing in the UI reads it | M1 | Read from `/api/v1/meta` (L010) |
| L004 About PATHOS dialog | §2.1, §2.3 | Missing | No About in `AppShell.tsx` or any feature | M1 | Licence Apache-2.0 (`LICENSE`), `NOTICE` exist to link |
| L005 Bundle/backend version mismatch banner with Reload | §2.1 | Missing | `vite.config.ts` has no `define`; no version in the bundle | M1 | Needs L011 |
| L006 Pre-release / dev tag | §2.1 | Missing | Version defaults to `"dev"` (`server.go:52`, `cmd/pathos-cli/main.go:20`) but is not shown | M1 | Release tags `v*-*` are already accepted (`release.yml:22`) |
| L007 Top-bar right side: search, notifications, Help, theme, user menu | §2.1 | Partial | `AppShell.tsx:283-340`: palette, `NotificationCentre`, Help link, theme toggle, user menu exist | M1 | Help is a link, not the §2.3 menu; organization switcher sits here on multi-tenant installs |
| L008 Brand block on login page, collapsed sidebar tooltip, exports, email | §2.1 | Missing | Collapsed sidebar shows `LogoMark` without tooltip (`AppShell.tsx:230`); notification templates use "[PATHOS]" subject prefix (`notify/events.go:40`) | M1 | Email templates in `notify/defaults.go`, `render.go` |
| L009 `Commit` and `BuildDate` ldflags (API, CLI, workers) | §2.2 | Missing | Only `-X …server.Version` (`backend/Dockerfile:10`), `-X main.version` (`workers/core/Dockerfile:17`, `release.yml:223`); `pathosctl` has none (`backend/Dockerfile:11`) | M1 | Pass `${{ github.sha }}` and the build date as build arguments; release workflow already sets the OCI revision label |
| L010 `GET /api/v1/meta` (public: product, vendor, version; signed in: commit, build date, API version, flags, worker and pack versions) | §2.2 | Missing | No such route among the 388 `/api/v1` routes | M1 | Worker versions are in `workers.version` and `workers.scanners` (`00003_scanning.sql:98-100`) |
| L011 Bundle version injected with Vite `define` | §2.2 | Missing | `frontend/vite.config.ts` | M1 | `frontend/package.json` already has `"version": "2.2.0"` |
| L012 Version-stamped exports (PDF, CSV, JSON, SARIF, SBOM) | §2.2, §4 | Missing | CSV: `components/data/DataTable.tsx:39-136`, `reporting/reports.go:556-580`, `review/reports.go:454-475`; SBOM: `vuln/export.go:146,196` (tool "PATHOS", no version); VEX: `releases/vex.go:175,283` | M1, M9 | PATHOS does not **export** SARIF today; PDF is browser print (`reporting/ExecutivePage.tsx:83`). Decide if SARIF export is in scope |
| L013 `pathos --version` shows the brand block | §2.1 | Partial | Prints `pathos <version>` (`cmd/pathos-cli/main.go:131,143`) | M1 | Add vendor, commit, build date |
| L014 Help menu (?) with nine entries | §2.3 | Missing | Help is a single `<Link to="/help">` (`AppShell.tsx`) | M1 | |
| L015 Help drawer for the current route (F1 / `?`) | §2.3 | Missing | No drawer, no route→article map in `features/help` | M1 | `content.ts` already loads every article, so the drawer can reuse it |
| L016 Unit test: every route has a help article | §2.3 | Missing | `features/help/help.test.tsx` tests parsing and search only | M1 | 74 routes in `app/router.tsx` to map |
| L017 Help centre organised by the nine phases plus Configurations and Administration | §2.3 | Partial | `/help` and `/help/$section/$slug` exist (`router.tsx:236-237`); sections are "User guide" and "API reference" (`content.ts:30-33`) | M1 | Add a `phase` front-matter key to the 32 user-guide articles |
| L018 Troubleshooting centre `/help/troubleshooting` | §2.3, §3.1 | Missing | Hand-written FAQ `docs/user-guide/troubleshooting.md` (rendered at `/help/user-guide/troubleshooting`) | M1 | The new route must not clash with `/help/$section/$slug` (it has two segments, so it does not) |
| L019 Keyboard shortcuts dialog | §2.3 | Missing | Only Ctrl/⌘ K exists (`CommandPalette.tsx:43`) | M1 | |
| L020 "What's new in v{version}" from `CHANGELOG.md` | §2.3 | Missing | `CHANGELOG.md` is not bundled | M1 | Bundle with `import.meta.glob` like `content.ts:37` (offline) |
| L021 System status (API, DB, queue, object storage, worker packs, connectors, AI providers) | §2.3 | Partial | `/readyz` checks PostgreSQL + migrations and Valkey (`server.go:254-278`); `GET /api/v1/workers`; `GET /api/v1/scheduler/status`; connection tests (`POST /api/v1/scm-connections/{id}/test`, `ticket-connections/{id}/test`, `ai/providers/{id}/test`) | M1 | No aggregated page; object storage not checked by `/readyz` |
| L022 Report a problem: redacted diagnostic bundle | §2.3 | Missing | `ApiError` keeps `requestId` (`api/client.ts:4-52`) but nothing collects the last 50 | M1 | Must never include secrets, tokens, source or finding contents |
| L023 Help works offline | §2.3 | Implemented | Markdown bundled at build time (`features/help/content.ts:37-47`) | M1 | Keep for new help content |
| L024 Theme toggle | §2.1 | Implemented | `AppShell.tsx:181-200`; `localStorage["pathos-theme"]` | — | |
| L025 Global search (command palette) | §2.1 | Implemented | `components/layout/CommandPalette.tsx` | — | |
| L026 Notifications in the top bar | §2.1 | Implemented | `components/layout/NotificationCentre.tsx` | — | |
| L027 Licence and third-party notices in About | §2.3 | Needs improvement | `NOTICE` and `LICENSE` exist at the repository root; not bundled or shown | M1 | |

### §3 Unified diagnostics and troubleshooting

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L028 Error catalogue `PTH-<AREA>-<NNNN>` in Go (`platform/diag`) | §3.1 | Missing | No `PTH-` anywhere; `platform/` has no `diag` | M1 | 16 areas |
| L029 Catalogue entry fields (cause, probable causes, impact, actions, verify, docs slug, AI help) | §3.1 | Missing | — | M1 | |
| L030 `docs/troubleshooting/<area>.md` generated by `make docs-errors` | §3.1 | Missing | No `docs/troubleshooting/`; no Makefile target | M1 | Keep the FAQ (`docs/user-guide/troubleshooting.md`) |
| L031 Two-way test: code ↔ doc | §3.1 | Missing | — | M1 | |
| L032 Error envelope keeps backward compatibility | §3.2 | Needs architecture change | `platform/httpx/httpx.go:22-70`: `{"error":{"code","message","details?","fields?"},"request_id"}`; `code` is a snake_case slug (61 distinct) | M1 | `error.code` is matched by the UI, CLI, IDE plugins and MCP. Prompt puts the `PTH-` code in `code` and `request_id` inside `error`. Proposal: keep `code`, add `diag_code` + the new fields, and repeat `request_id` inside `error`. ADR |
| L033 Envelope fields: title, cause (confirmed), probable causes, impact, actions, verify, docs_url | §3.2 | Missing | `httpx.Error` has `Details any` only | M1 | |
| L034 Map every existing slug to a catalogue code | §3.2, M1 done-when | Needs architecture change | `httpx.E(...)` called with 61 distinct codes across packages; unknown errors → `internal` (`httpx.go:57-70`) | M1 | "Every API error returns a catalogue code" needs a slug→code table and a test that no `httpx.E` slug is unmapped |
| L035 `request_id` on every log line | §3.2 | Partial | Access log has `request_id`, `trace_id` (`httpx.go:153-196`); handler logs add it by hand (for example `httpx.go:62,66`) | M1 | Use a context-aware slog handler |
| L036 `error_code` on every log line | §3.2 | Missing | — | M1 | |
| L037 `<ErrorPanel>` component | §3.3 | Missing | `components/ui/primitives.tsx` has `Alert`, `EmptyState` | M1 | |
| L038 Verify button re-runs the failed check | §3.3 | Partial | Re-test endpoints exist for SCM, ticket, AI provider, webhook and SMTP connections; secret validation recheck (`POST /api/v1/findings/{id}/secret-validation/recheck`) | M1, M2 | No generic "verify" contract |
| L039 Troubleshoot with AI (redacted context, local model by default, same structure) | §3.3 | Missing | Redaction exists (`ai/generate.go:17-30`, `platform/logging/logging.go:48`) | M1 | Must work without AI; never ask for secrets (rule 6) |
| L040 Seven page states with shared components (loading skeleton, empty, error, partial, permission denied, feature disabled, success toast) | §3.3 | Missing | `Skeleton`, `EmptyState`, `Alert` exist and are used on some pages (for example `posture/CoveragePage.tsx`, `BlastRadiusPage.tsx`); no permission-denied, feature-disabled or toast component | M1 | Audit every page |
| L041 Coverage of failure areas (repo auth, API, webhook, scopes, IDE, CLI, CI, sync, discovery, deps, binary, scan, worker, AI, report) | §3.3 | Partial | Slugs exist for some areas: `scm_error`, `lease_lost`, `worker_revoked`, `ai_failed`, `ai_not_configured`, `object_storage_error`; sync errors stored in `repositories.sync_error`; worker offline event `worker.offline` (`notify/events.go`) | M1 | |

### §4 Enterprise UI standards

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L042 Existing tokens and primitives only; dark and light on every screen | §4 | Implemented | `index.css` `:root` and `.dark`; `components/ui/*` | all | Severity colours have no dark override (`index.css`); check contrast |
| L043 WCAG 2.2 AA, keyboard, visible focus | §4 | Partial | Radix primitives; `--ring` token; ~450 `aria-` attributes in `src` | M1 | No audit or axe test in `e2e/` |
| L044 `prefers-reduced-motion` | §4 | Missing | No rule in `src` | M1 | Sidebar width transition (`AppShell.tsx`) |
| L045 Page anatomy: breadcrumb → header → filters → content → pagination | §4 | Partial | `PageHeader` (`primitives.tsx`), `FilterBar` (`components/data/FilterBar.tsx`) | M1 | No breadcrumb component |
| L046 Server-side sort, filter, pagination | §4 | Partial | Cursor pagination and `sort=severity\|risk` on findings (`scans/findings.go:419-485`); filters on the API | M1+ | Sort is limited; most tables sort the loaded rows |
| L047 Column chooser | §4 | Implemented | `DataTable.tsx:23-36,111-150` | — | |
| L048 Saved views | §4 | Partial | Saved report definitions (`GET/POST /api/v1/reports`, `reporting/ReportsPage.tsx`) | M1+ | No saved views on tables |
| L049 Bulk actions with confirmation | §4 | Partial | `features/repos/BulkActions.tsx`, `components/ui/confirm.tsx` | M1+ | Not on every table |
| L050 CSV export, version-stamped | §4 | Needs improvement | Browser CSV of the **loaded rows** only (`DataTable.tsx:47-56,136`) | M1 | Server-side export for 10k rows; stamp (L012) |
| L051 Sticky header, density toggle | §4 | Missing | — | M1 | |
| L052 Shared graph component (zoom, pan, search, filters, layers, expand/collapse, inspector) | §4 | Needs architecture change | `posture/ContextGraphPage.tsx` draws custom SVG; no graph library in `package.json` | M4 | Used by CodeGraph, threat model, RE and context graph |
| L053 Graph path tracing, evidence links, PNG/SVG/JSON export, snapshots, version compare | §4 | Missing | — | M4 | |
| L054 React Flow + ELK vs Cytoscape, decided in an ADR | §4 | Needs architecture change | No ADR file exists in `docs/` | M0/M4 | New dependency; licences MIT / EPL-2.0 (ELK) to verify |
| L055 Server-side aggregation and lazy expansion of large graphs | §4 | Partial | `GET /api/v1/posture/aggregate`, `posture/aggregate.go`; context graph is built server-side (`posture/graph.go`) | M4 | |
| L056 Responsive 1280–1920 px, usable at 1024, read-only on tablets | §4 | Partial | `max-w-7xl` main area, collapsible sidebar (`AppShell.tsx`) | M1 | Not tested below 1440 px (`e2e/playwright.config.ts`) |
| L057 Copy rules (active voice, cause and fix, no blame) | §4 | Partial | Many messages already state cause (for example `analyst/service.go:62`) | M1 | Review with the catalogue |
| L058 Performance budgets (FCP < 2 s, 10k-row p95 < 500 ms, 2,000-node graph < 2 s) | §4 | Missing | k6 load test exists (`scripts/load/run.sh`, `docs/PERFORMANCE.md`) but no frontend or graph budget test | M1, M4 | |

### §5 Information architecture and application hub

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L059 Regroup `groups` into the 12 groups of §5 | §5 | Missing | `AppShell.tsx:75-178` has 9 groups | M1 | One-line moves per item |
| L060 Keep every current menu page (rule 1) | §1.1, §5 | Needs improvement | 58 items (+1 multi-tenant) today; the §5 table lists 55 | M1 | Runtime, Scan coverage, Secret validation and Installation › Organizations are not in the table; see [architecture assessment §8.3](PATHOS_ARCHITECTURE_ASSESSMENT.md#83-menu-mapping-check-prompt-5-against-the-code) |
| L061 New items show disabled with "arrives in roadmap phase N" | §5 | Implemented | `NavItem.phase` and rendering (`AppShell.tsx:72,253-265`) | M1 | Unused today |
| L062 Home › Lifecycle overview | §5 | Missing | — | M9 | Route to define |
| L063 Connect › Add repositories (`/repositories/import`) as a menu entry | §5 | Implemented | Page exists (`router.tsx:148`); reached from Repositories today | M1 | New menu entry only |
| L064 Configurations group (scan profiles, scanners, custom rules, asset settings, risk & intelligence, review configurations, AI settings) | §5 | Partial | Group exists with 4 items (`AppShell.tsx` "Configurations") | M1 | 4 items move in; Scan coverage stays |
| L065 Old URLs keep working | §1.1, M1 | Implemented | URLs unchanged by the move; existing redirects `/scans/profiles`, `/admin/scanners` (`router.tsx:174,177`) | M1 | Add a test that every old URL resolves |
| L066 Redirect `/admin/scm` and `/admin/integrations` to Connectors after parity | §5 | Missing | — | M2 | Only after parity + e2e (rule 1) |
| L067 Application profile hub `/applications/$id` | §5 | Missing | No route; `/applications?app=` opens an edit dialog (`features/repos/ApplicationsPage.tsx:59-104`) | M3 | Must not break `/applications/$id/versions` (`router.tsx:206`) |
| L068 Hub tab: Overview with lifecycle progress strip | §5 | Partial | Posture data per application: `GET /api/v1/posture/aggregate`, `posture/PosturePage.tsx` | M3 | Progress strip is new |
| L069 Hub tab: Repositories | §5 | Implemented | `repositories.application_id`; Repositories list filters by application | M3 | |
| L070 Hub tab: Classification & tags | §5 | Partial | Application fields (`00002_repositories.sql:32-42`, `00013_finding_intelligence.sql:154-166`); tag framework (`repos/tags.go`) | M3 | Extended fields (L099) |
| L071 Hub tab: Versions | §5 | Implemented | `/applications/$id/versions`; `releases/service.go`; `application_versions` (`00027_remediation_vex_push.sql:62`) | M3 | |
| L072 Hub tab: CodeGraph (context graph becomes its ownership layer) | §5 | Missing | — | M4 | |
| L073 Hub tab: Threat model + attack paths filtered to the application | §5 | Missing | Attack paths are not filtered by application today (`posture/attack.go`) | M5 | |
| L074 Hub tab: Findings (filtered) | §5 | Implemented | `GET /api/v1/findings?application_id=` (`scans/findings.go:333-338`) | M3 | |
| L075 Hub tab: SBOM & components (filtered) | §5 | Partial | `GET /api/v1/sbom/components`; application version components (`00027_remediation_vex_push.sql:87`) | M3 | Verify an application filter on the live inventory |
| L076 Hub tabs: Remediation; Activity & audit | §5 | Missing | Audit log is organization-wide (`GET /api/v1/audit-logs`) | M3, M8 | |

### M1 additional scope

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L077 Feature-flag framework, every new module off by default | §1.9, M1 | Needs architecture change | No framework. Ad-hoc switches: `developer_insight_settings.attribution_enabled` (`00028_developer_context.sql:71`), per-repository `pr_checks_enabled` (`00020_supply_chain.sql:49`), multi-tenancy DB switch (`platform/config/config.go:92-94`), Compose profiles for worker families | M1 | Flags listed in `/api/v1/meta` (L010); "feature disabled" state (L040) |
| L078 All existing e2e tests pass unchanged | M1 | Partial | `make e2e` → `scripts/e2e.sh` (Playwright `v1.65.1-noble`); 68 test cases from 22 declarations in 6 specs (`e2e/tests/`) | M1 | `help.spec.ts:3-13` (Help is a link after Notifications), `human-review.spec.ts:23-32` (a "Human Eye" section and its labels) and `scanning.spec.ts:23-39` ("Scan Overview" and other labels) assert today's shell. They will fail after §2.3 and §5: owner decision ([assessment C11](PATHOS_ARCHITECTURE_ASSESSMENT.md#84-conflicts-between-the-prompt-and-the-code-the-code-wins-for-what-exists)) |
| L079 Light and dark screenshots of every new page | §9, M1 | Missing | `e2e/screenshots.config.ts` captures light only (`colorScheme: "light"`) | M1+ | Add a dark project |
| L080 Version shown equals `/api/v1/meta` (test) | §9 | Missing | — | M1 | |

### M2 Connectors

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L081 `/connectors` hub with tabs Connectors · Authentication · Configuration · Health | M2 | Missing | — | M2 | |
| L082 Nine connector categories | M2 | Missing | SCM providers carry `Category: "git"\|"devops"` only (`scm/providers.go:47-129`) | M2 | |
| L083 SCM: GitHub, GitHub Enterprise Server, GitLab (cloud and self-managed), Bitbucket Cloud, Azure DevOps Services and Server | M2 | Implemented | `scm/providers.go:47,53,59,74,98,129`; `scm/github.go`, `gitlab.go`, `bitbucket.go`, `azure.go`; base URL per connection (`00002_repositories.sql:11`, `repos/connections.go:103,255-260`) | M2 | Design page marks GitHub Enterprise Server "new": it exists |
| L084 SCM: Bitbucket Data Center, generic Git (HTTPS/SSH) | M2 | Missing | Not in `scm/providers.go` | M2 | |
| L085 Custom CA certificate per connection | M2 | Partial | Kubernetes connections accept a CA (`runtimectx/kubeconfig.go`, `runtimectx/api.go`) | M2 | Not for SCM or ticket connections |
| L086 Auth methods: GitHub App, OAuth, PAT, API token, service principal | M2 | Implemented | `scm/providers.go:12-134`; `repos/oauth.go`; OAuth apps (`settings/OAuthAppsSection.tsx`) | M2 | Verify scopes and API versions against vendor docs in `PATHOS_INTEGRATION_TECHNICAL_SPEC.md` |
| L087 Credentials write-only, encrypted, never logged or sent to AI | §1.6, M2 | Implemented | `secrets` package (AES-256-GCM keyring); `secret_id` references (for example `00035_runtime_context.sql:51`); log redaction `platform/logging/logging.go:48-55` | all | Keep for every new connector |
| L088 Webhook registration and signature checks | M2 | Partial | `POST /api/webhooks/{github,gitlab,bitbucket,azure-devops}/{id}`; `scm/webhook.go:15-40` | M2 | Health tab must show webhook delivery status |
| L089 Ticketing: Jira, ServiceNow | M2 | Partial | `tickets/connectors.go:94-95`; `POST /api/v1/ticket-connections/{id}/test` | M2 | Moves into Connectors › Monitoring |
| L090 Alerts: Slack, Teams, generic webhooks, SMTP | M2 | Partial | `notify/webhooks.go:38` (`json`, `slack`, `teams`), HMAC; `notify/smtp.go` | M2 | Shown as connectors; settings stay in Notifications |
| L091 Containers: registries, Kubernetes | M2 | Partial | `runtimectx/registry.go` (OCI distribution API, `none\|basic\|bearer`, `00035_runtime_context.sql:41-60`); `runtimectx/k8s.go`; image scan credentials on scan targets | M2 | Design page marks Kubernetes "new": it exists (2.1). Cloud-specific registry auth (ECR/ACR/GAR IAM) is missing |
| L092 Cloud: AWS, Azure, Google Cloud | M2 | Missing | Only S3-compatible object storage for PATHOS itself (`platform/objstore`) | M2 | Cloud posture tools (Prowler etc.) are catalogued in `catalog_iac.go` but need a cloud connector |
| L093 IAM & Secrets: Vault, cloud secret managers | M2 | Missing | Keycloak and SAML/OIDC brokering exist for sign-in (`identity`) | M2 | |
| L094 APIs: OpenAPI (exists), Postman, GraphQL, gateways | M2 | Partial | API targets from OpenAPI 3 / Swagger 2 (`scans/targets.go`, `00015_scan_targets.sql`) | M2, M4 | |
| L095 Health with AI troubleshooting; real status only | M2 | Needs architecture change | Per-connection test endpoints exist (L038); sync status on `scm_connections`, `runtime_sync_runs` (`00035_runtime_context.sql:70`) | M2 | Needs one connection-health model across tables; rule 4 (nothing fake) |

### M3 Onboarding and inventory

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L096 Connect → find existing asset → register → tag → inventory flow | M3 | Partial | Import landing and per-source wizards (`/repositories/import/$source`, `features/repos/onboarding`); SCM inventory and unmanaged assets (`scm_remote_repositories`, `00016_aspm_inventory.sql:23`, `posture/unmanaged.go`) | M3 | Not one guided flow |
| L097 Drafts allowed, incomplete assets save with status | M3 | Partial | Import jobs and items have status `draft` (`00009_asset_onboarding.sql:262,290`); repository `lifecycle_status` (`00009_asset_onboarding.sql:197`) | M3 | No "incomplete" status for an application |
| L098 No duplicate assets | M3 | Implemented | Import detects `duplicate` and `duplicate_item` (`repos/imports.go:204-231`); unique keys per organization | M3 | Test to extend to applications and targets |
| L099 Classification: business, technical, security, geography, environment | M3 | Partial | Repository fields: environment, data classification, internet exposure, business region, data residency region, hosting region, lifecycle, owners, cost centre, compliance scopes (`00009_asset_onboarding.sql`, `00010_repository_identity_exposure.sql`, `00013_finding_intelligence.sql`) | M3 | Mostly on repositories; applications have fewer fields |
| L100 Tag framework with mandatory categories | M3 | Implemented | `repos/tags.go:40-46` (`is_mandatory`); `mandatory_tags_missing` error | M3 | |
| L101 Asset settings (mandatory metadata) | M3 | Implemented | `repos/assets.go:154`; `/admin/assets` | M3 | |
| L102 Application register with owners and criticality | M3 | Partial | `applications` table (`00002_repositories.sql:32-42`), application key (`00013_finding_intelligence.sql:154-166`) | M3 | Hub (L067) |
| L103 Non-repository assets (images, URLs, APIs, mobile, LLM endpoints) in inventory | M3 | Partial | Scan targets (`00015_scan_targets.sql`, `00031_mobile_llm_targets.sql`); `/scans/targets` | M3 | Not linked to applications everywhere |
| L104 Runtime inventory (clusters, workloads, images) linked to applications | M3 | Implemented | `runtimectx` (20 routes), `runtime_app_mappings` (`00035_runtime_context.sql:164`), `/runtime` | M3 | Not asked for by the prompt, but it exists and must keep its menu place (rule 1). Map it into Inventory |

### M4 CodeGraph

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L105 Discovery worker (parsers, flow analysis) | M4 | Missing | No tree-sitter or Joern use (tree-sitter is only a build dependency in `workers/sast/Dockerfile`) | M4 | New worker or a pack on `workers/sast` |
| L106 Route / endpoint discovery | M4 | Partial | Material-change rules detect endpoints in Express, Flask/FastAPI/Django, Spring, Go and ASP.NET (`material/rules.go:109-129`); declared public endpoints (`scans/endpoints.go`) | M4 | Detected as diffs, not stored as an inventory |
| L107 Database access discovery | M4 | Missing | — | M4 | |
| L108 Function-level reachability / call edges | M4 | Partial | `reachscan` (Go, Java, JS, Python: `reachscan/golang.go`, `java.go`, `js.go`, `python.go`); `repository_reach_reports` (`00032_function_reachability.sql:26`); `reach/reach.go` | M4 | Reuse as CodeGraph call edges with evidence "verified (static)" |
| L109 Dependency graph (SBOM edges, direct/transitive) | M4 | Partial | `sbom_dependencies` (`00016_aspm_inventory.sql:11`); `vuln/graph.go` (CycloneDX, SPDX); dependency paths `GET /api/v1/findings/{id}/dependency-paths` | M4 | |
| L110 Graph store with evidence type per edge (verified / observed / AI-inferred) | M4, §1.5 | Needs architecture change | Context graph is computed on request (`posture/graph.go`); no persisted graph or evidence label | M4 | DB design: nodes, edges, evidence, snapshot |
| L111 Graph API | M4 | Partial | `GET /api/v1/posture/context-graph`, `/posture/blast-radius`, `/posture/attack-paths` | M4 | |
| L112 Shared graph component | M4, §4 | Missing | See L052 | M4 | |
| L113 15 views | M4 | Missing | One context-graph view | M4 | Views are listed in the design, not in the prompt |
| L114 Snapshots and diff | M4 | Missing | Material change baselines exist (`material_dependency_baselines`, `00028_developer_context.sql:59`) | M4 | |
| L115 Context graph becomes the ownership layer | §5, M4 | Partial | `posture/graph.go`, `/posture/graph` | M4 | |
| L116 Graph of the PATHOS repository renders with evidence on every edge | M4 done-when | Missing | — | M4 | |

### M5 Threat modelling

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L117 STRIDE engine on CodeGraph | M5 | Missing | No "stride" or "threat model" in code | M5 | |
| L118 Attack-path integration | M5 | Partial | `posture/attack.go` (internet → exposed repository or target → finding / reachable dependency) | M5 | Filter per application |
| L119 Blast radius | M5 | Partial | `GET /api/v1/posture/blast-radius`, `/posture/blast-radius` | M5 | |
| L120 CWE mapping | M5 | Partial | `findings.cwe[]`; compliance mapping (`compliance/catalog.go:91-157`: 5 frameworks) | M5 | Threat-level mapping is new |
| L121 ATT&CK, CAPEC, D3FEND mapping | M5 | Missing | ATT&CK/CAPEC appear only in import parsers (`scanners/import_tracee.go`, `import_falco.go`, `import_kubescape.go`, `import_invicti.go`) | M5 | Bundle data offline; licences to check |
| L122 Editable, approvable model (four-eyes) | M5 | Missing | Approval pattern to reuse: Human Eye independent review (`review`) | M5 | |
| L123 Import/export (Threat Dragon, pytm, Threagile formats) | M5 | Missing | — | M5 | |
| L124 Each threat has evidence, method, severity, confidence, mitigation | M5 done-when | Missing | — | M5 | |

### M6 Scan profiles and tool catalogue

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L125 Catalogue with licence and pack per tool | M6, §7 | Implemented | 98 entries: `scanners/catalog.go:103-190`, `catalog_{sast,sca,iac,dast,mobile,binary,ai,fuzz,reach}.go`; `docs/SCANNER_CATALOG.md` | M6 | Map, do not re-plan |
| L126 Kinds of check | M6, §7 | Needs improvement | 25 scan types (`scanners/scantypes.go:30-125`) vs the prompt's 20 kinds | M6 | Different split. Map the 20 onto the 25 (for example prompt "Secrets" = `secrets`; "CVE & vulnerability intelligence" = `intel` feeds, not a scan type) |
| L127 10 tools per kind | M6, §7 | Partial | 81 of 98 run in a PATHOS image (`docs/SCANNER_CATALOG.md:168`) | M6 | Per-kind gap list belongs in the tool catalogue doc |
| L128 Worker packs, pinned versions and digests | M6 | Implemented | 9 images; pinned digests in every `workers/*/Dockerfile`; signed release (`release.yml`) | M6 | |
| L129 Quick / Standard / Comprehensive / Custom profiles | M6 | Partial | Versioned profiles, one seeded "Default" (`scans/profiles.go:374-395`) | M6 | Seed three templates |
| L130 Category-only UI, tool names only on Scan profiles and Scanners & workers | §1.3, M6 | Needs improvement | Tool names show on Findings "Detected by" (`features/findings/FindingsPage.tsx`), scan details engines (`scans/details/OverviewTab.tsx:146`), Human Eye workspace (`review/workspace/OverviewTab.tsx`), related findings (`vuln/RelatedFindings.tsx`), Import results | M6 | Import results needs tool names to pick a format: owner decision |
| L131 "Confirmed by N engines" | M6 | Partial | `findings.scanner_keys[]` keeps every engine; cross-tool de-duplication adds each detecting engine to `scanner_keys` (`scans/ingest.go:281-293`) | M6 | Count not shown as such |
| L132 Test that tool names appear only on the two pages | M6 done-when | Missing | — | M6 | |
| L133 Intrusive DAST only with recorded authorisation | §7 | Partial | Authorization statements for web/API targets and endpoint verification (`scans/endpoints.go:1-5`); `intrusive` catalogue flag (`catalog.go:128`) | M6 | Already enforced for Nuclei fuzzing (CHANGELOG 2.0.0); extend to new tools |

### M7 AI intelligence

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L134 Cross-phase correlation | M7 | Partial | Related findings (`GET /api/v1/findings/{id}/related`, `posture/related.go`); AI Security Analyst context (`analyst/context.go`) | M7 | No correlation with graph or threat data (do not exist yet) |
| L135 Validation record: finding, verdict, confidence, model, provider, config version, reviewer | M7 | Partial | `ai_reviews` (`00004_ai_mcp.sql:67-96`): provider, model, config version, verdict, confidence, rationale, output, `transmitted_sha`, decided_by | M7 | |
| L136 Record keeps prompt and response, nodes and steps | M7 | Needs improvement | Only a hash of what was sent (`transmitted_sha`) and the output are stored; AI fixes store steps and before/after evidence (`ai_fix_proposals`, `00033_verified_ai_fixes.sql:13`) | M7 | "Reproducible from its record" needs the redacted prompt stored (size, retention, redaction) |
| L137 Model per task | M7 | Partial | Versioned AI configurations with one default (`ai_configurations`, `00004_ai_mcp.sql:27-64`); providers Anthropic, OpenAI, xAI, OpenAI-compatible | M7 | No per-task routing found |
| L138 Local model default for code | M7 | Partial | Local providers (Ollama, vLLM; `ai/openai.go`); `send_code_context` per configuration version | M7 | Default is whatever the admin sets |
| L139 No silent suppression | M7 | Implemented | Approval policy per configuration (`approval_policy`, `allow_self_approval` `00008_local_ai.sql:14`); status history trigger | M7 | Add a test |
| L140 Evidence labels on AI conclusions (AI-inferred) | §1.5 | Missing | — | M7 | |
| L141 Verified AI fixes with before/after evidence | M7, M8 | Partial | `aifix` package; `POST /api/v1/findings/{id}/ai-fixes`; sandbox runs (`worker/sandbox.go`) | M7 | Exists; map into the remediation workspace |
| L142 AI usage accounting | M7 | Partial | `/admin/ai-usage`; token counts on reviews and fixes | M7 | |

### M8 Remediation and gates

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L143 Remediation workspace | M8 | Missing | Building blocks: assignee and SLA (`GET/PUT /api/v1/sla-policies`), fix PRs, AI fixes, tickets | M8 | New page |
| L144 Owner and deadline per finding | M8 | Implemented | Finding assignee, SLA, `finding.sla_breached` event (`notify/events.go`) | M8 | |
| L145 Fix pull requests | M8 | Implemented | `depfix`; `scans/fixprs.go`; `fix_pull_requests` (`00027_remediation_vex_push.sql:17`); four SCMs | M8 | |
| L146 Fix verification with before/after evidence | M8 | Partial | AI fixes keep before/after reports (`00033_verified_ai_fixes.sql`); a finding is fixed only when a later scan misses it (`scans/fixprs.go:856`) | M8 | Not for dependency fix PRs |
| L147 Gate: IDE | M8 | Partial | VS Code (`ide/vscode`, 0.1.0) and JetBrains (`ide/jetbrains`) show findings | M8 | No gate verdict in the IDE |
| L148 Gate: pre-commit / pre-receive | M8 | Partial | `integrations/pre-commit`, `integrations/pre-receive` (Gitleaks; secrets only) | M8 | |
| L149 Gate: PR | M8 | Implemented | `scans/prchecks.go`; `pr_checks` (`00020_supply_chain.sql:57`); policy block (`prchecks.go:162`) | M8 | See L153 |
| L150 Gate: CI | M8 | Implemented | `GET /api/v1/scans/{id}/gate` (`scans/gate.go`); CLI `pathos gate` (exit 1); GitHub Action, GitLab, Azure Pipelines, Jenkins templates (`integrations/`) | M8 | |
| L151 Gate: release, deploy | M8 | Missing | Application versions are frozen snapshots without a gate (`releases`) | M8 | |
| L152 Gate outcomes block / warn / exception / approval | M8 | Partial | Policy actions `block`, `require_review`, `sla_days`, `notify` (`policy/policy.go:47-58`); risk acceptance with expiry (`/risk`) | M8 | No "warn" outcome; exceptions are risk acceptances |
| L153 No gate blocks without an explicit policy (test) | §1.7, M8 | Needs improvement | PR checks block at `pr_gate_severity` (default `high` when enabled; `00020_supply_chain.sql:49-51`, `prchecks.go:184-205`); CLI blocks on the caller's `--fail-on` (`scans/gate.go:45-52`) | M8 | Owner decision: is a repository threshold or CI flag an "explicit policy"? |
| L154 Suppression rules, VEX, risk acceptance | M8 | Implemented | `vuln/suppression.go`; `releases/vex*.go`; `risk` | — | Move in the menu only |
| L155 Component (SBOM) policies | M8 | Partial | `component_policies` (`00027_remediation_vex_push.sql:165`); `POST /api/v1/component-policies/evaluate` | M8 | Not a gate today |

### M9 Reporting and monitoring

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L156 Technical and compliance reports | M9 | Implemented | `reporting/reports.go` (definitions, preview, run, CSV); `compliance/catalog.go` (5 frameworks: OWASP Top 10 2021, OWASP ASVS 4.0.3, PCI DSS 4.0.1, ISO/IEC 27001:2022 Annex A, SOC 2) | M9 | Upgrade, stamp |
| L157 Scheduled reports | M9 | Implemented | `report.scheduled` event (`notify/events.go`) | M9 | |
| L158 Continuous monitoring feed (commits, dependencies, APIs, CVEs, gate failures) | M9 | Partial | Notification inbox; material changes per scan (`GET /api/v1/repositories/{id}/material-changes`); intel feeds (`intel/feeds.go`) | M9 | No combined feed page |
| L159 Architecture drift | M9 | Partial | Material-change categories auth, endpoint, dependency, crypto, IaC, secrets, CI/CD, data (`material/rules.go:11-27`) | M9 | Drift against a CodeGraph snapshot needs M4 |
| L160 All exports version-stamped | M9 | Missing | See L012 | M9 | |
| L161 Feedback loops 1–7 wired and tested | M9 done-when | Partial | See [PATHOS_APPLICATION_SECURITY_LIFECYCLE.md › Feedback loops](PATHOS_APPLICATION_SECURITY_LIFECYCLE.md#feedback-loops) | M9 | 3 exist (loops 1, 3, 5), 4 are partial (2, 4, 6, 7) |
| L162 Lifecycle overview (portfolio by phase) | M9 | Missing | — | M9 | |
| L163 Executive overview, benchmarking, developer insights | M9 | Implemented | `/executive`, `/posture/benchmark`, `/insights/developers` exist | — | Move in the menu only |

### M10 Reverse engineering, static tier

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L164 `workers/rea` (no network, read-only, all capabilities dropped) | M10 | Missing | Hardening pattern exists in Compose for workers (`cap_drop: ALL`, read-only, tmpfs) | M10 | |
| L165 Binary analysis tools | M10 | Partial | `workers/binary`: binary hardening (checksec-style, `catalog.go:189`), CVE Binary Tool, capa, YARA-X (`catalog_binary.go`); `workers/mobile`: Jadx, Androguard, mobsfscan | M10 | No radare2, Ghidra, angr, ILSpy, binwalk |
| L166 Source-vs-binary diff | M10 | Missing | — | M10 | |
| L167 RE workspace UI | M10 | Missing | — | M10 | |
| L168 Runs only on artifacts from our own builds by default | M10 done-when | Missing | Build artifact targets exist (`target_kind=artifact`, `features/findings/FindingsPage.tsx:135`); signature verification (`signature_verifications`, `00025_endpoints_eol_provenance.sql:159`) | M10 | Provenance check can reuse cosign verification |
| L169 Reverse engineering tools settings page | §5 | Partial | Scanners & workers page manages tool settings (`/configurations/scanners`) | M10 | New page under Configurations |

### M11 Reverse engineering, sandbox tier

| Capability | Prompt ref | Status | Evidence (code paths) | Milestone | Notes |
|---|---|---|---|---|---|
| L170 Throwaway VM sandbox | M11 | Needs architecture change | The existing sandbox is a sibling container on the worker host (`worker/sandbox.go:25-45`) | M11 | Separate approval |
| L171 Never on the PATHOS host | M11 | Missing | — | M11 | |
| L172 Dynamic tools (Frida, Tracee, Qiling) | M11 | Missing | Tracee and Falco results can be imported (`scanners/import_tracee.go`, `import_falco.go`) | M11 | |
