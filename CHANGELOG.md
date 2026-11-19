# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, minor versions may contain breaking changes.

## [Unreleased]

### Added
- **25 scan types**: a scan-type registry (SAST, DAST, SCA, secrets, IaC, container, API security, IAST, mobile, fuzzing, licence, SBOM, malware, code-quality security, supply chain, cryptography, configuration, CI/CD pipeline, binary, AI/LLM, runtime, compliance, licence policy, database security, manual review), `GET /api/v1/scan-types` with the tools, import formats and online workers of each type, and a **Scan coverage** page under Configurations.
- New finding categories `api`, `iast`, `mobile`, `fuzz`, `crypto`, `cicd`, `ai`, `runtime`, `compliance`, `database` and `code-quality` (migration 00029), accepted in findings, Human Eye auto-queue settings, imports and plugins. ShellCheck findings use `code-quality`, mobsfscan `mobile`, Schemathesis `api`.
- **Tool manifests (v2)**: scan types, SPDX licence, family, targets (repository, image, url, api, mobile-app, binary, model), placeholders `{target_url}`, `{openapi}`, `{image}`, `{artifact}`, per-tool timeout, `network` and `intrusive` declarations, and the parsers `sarif`, `import:<format>` (the result import parsers) and `jsonmap` (a declarative JSON or JSON Lines mapping). Version 1 plugin files keep working.
- First-party manifests shipped read-only in family images (`/opt/pathos/tools.d`, up to 500); operator plugins stay in `PATHOS_SCANNER_PLUGINS_DIR` (up to 50, was 20). Workers advertise their manifests when they register; jobs that use manifest tools go to the workers that advertise them.
- The original output of manifest tools is stored with its parser, so findings can be located in it later.
- **worker-sast family image** (Compose profile `sast`): Bandit 1.9.4, njsscan 1.0.2 and ShellCheck 0.11.0, defined only by manifests; built in CI, scanned by the Trivy gate, published and signed by the release workflow.
- **Intrusive testing authorization**: a per-target flag (who, when, reference; audited as `scan_target.intrusive_authorize` and `scan_target.intrusive_revoke`) required for intrusive tools in addition to the target's authorization statement; scan targets can select family and plugin tools (`config.tools`).
- **128 more result import formats (153 in total, from 145 tools)**, detected from the content or named explicitly:
  - SAST and code quality: Fortify FVDL/FPR, Veracode detailed XML, Coverity, AppScan Source, Klocwork, Horusec, Bearer, Brakeman, SpotBugs/FindSecBugs, PMD, Cppcheck, Flawfinder, PHPStan, Psalm, njsscan, mobsfscan, Sobelow, ShellCheck, Ruff, Pylint, golangci-lint, Codacy and SonarQube Cloud.
  - Secrets: detect-secrets, Kingfisher, Nosey Parker, ggshield, Whispers and Talisman. Secret values are removed before the report is stored.
  - SCA: Mend, Black Duck, JFrog Xray, Nexus IQ, Dependency-Track FPF, Dependabot alerts, Retire.js, yarn and pnpm audit, Composer audit, govulncheck (with call-path reachability), Safety, `dotnet list package --vulnerable`, bundler-audit, cargo-audit and dep-scan.
  - GitLab security reports (SAST, secret detection, dependency scanning, container scanning, DAST, coverage fuzzing) through one parser.
  - IaC and CI/CD: KICS, tfsec, Terrascan, KubeLinter, Kubescape, cfn-lint, cfn_nag, Hadolint, TFLint, Conftest, Polaris, kube-bench, poutine, Legitify and OpenSSF Scorecard.
  - Formats of commercial products, and a few that need an account or a deployed target, are built from the published format and marked as not yet verified against a real export.
  - DAST, API, infrastructure, TLS, cloud posture, container, mobile, IAST, runtime, AI/LLM, pentest and fuzzing tools: Nikto, Wapiti, Arachni, sqlmap, Dalfox, ffuf, Wfuzz, w3af, Schemathesis, RESTler, Acunetix, Invicti/Netsparker, AppSpider, Qualys WAS, InsightAppSec, HCL AppScan, Burp Suite DAST/Enterprise, StackHawk, 42Crunch, Nmap, Qualys VM, Tenable CSV, Nexpose, testssl.sh, SSLyze, sslscan, Wazuh, Prowler, ScoutSuite, AWS Security Hub (ASFF), Amazon Inspector, Defender for Cloud, Security Command Center, CloudSploit, Dockle, Clair, Harbor, Trivy Kubernetes, Anchore, Prisma Cloud/Twistlock, Sysdig, Docker Scout, MobSF, APKLeaks, NowSecure, Contrast Assess, Falco, Tetragon, Tracee, garak, promptfoo, ModelScan, HackerOne, Bugcrowd, Intigriti, ClusterFuzzLite and libFuzzer/Jazzer. Formats built only from published documentation are marked as not yet verified against a real export.
- **worker-mobile, worker-binary, worker-ai and worker-fuzz family images** (Compose profiles `mobile`, `binary`, `ai`, `fuzz`; built in CI, scanned by the Trivy gate, published and signed by the release workflow), 12 new catalog tools defined only by manifests:
  - Mobile: mobsfscan 1.2.0 (on sources decompiled with jadx 1.5.7), APKLeaks 2.6.3, Quark-Engine 26.11.1 with PATHOS' own rules, and the PATHOS mobile app checks (androguard 4.1.4): Android debuggable, allowBackup, cleartext traffic, exported components without a permission, minSdkVersion, v1-only and debug signing; iOS App Transport Security exceptions, URL schemes, minimum iOS version and entitlements. Binary hardening (ELF, Mach-O) also runs on mobile packages.
  - Binary: CVE Binary Tool 3.4.1 (main-branch commit; offline, on a database the operator installs with `pathos-binary cve-db-update` or imports in air-gapped installations), capa 10.0.0 with capa-rules 10.0.0, YARA-X 1.23.0 with the ReversingLabs YARA rules (MIT) and a PATHOS rule. Rule directories for more Quark and YARA rules can be mounted.
  - AI: ModelScan 0.8.8 (repositories and model artifacts), garak 0.17.1 and promptfoo 0.126.0 (with a PATHOS red-team suite) for LLM endpoint targets; intrusive, tested against a local stub LLM server.
  - Fuzzing: Go native fuzzing (`go test -fuzz`, Go 1.27.4) and Atheris 3.1.0 run the repository's own fuzz harnesses, only when a profile selects them, without network access and under CPU, memory, file size and time limits; crashes are `fuzz` findings with the reproducer input (at most 4 KiB) kept in the report. Jazzer is catalogued but not shipped.
- **Mobile app targets** (`POST /api/v1/scan-targets/mobile-app`: APK, AAB or IPA, stored like build artifacts) and **LLM endpoint targets** (chat completions URL, model name, credential encrypted like other target credentials; authorization statement required, intrusive testing can be authorized). Migration 00031 adds both kinds. Manifests can target `llm-endpoint` and read the endpoint from `{llm_target}`, a file, so credentials never appear on a command line.
- **AI-BOM** (`ai-bom`, built into every worker, opt-in per profile): AI and ML frameworks, LLM SDKs, model files, Hugging Face model references, hosted model names and LLM APIs in a repository, recorded as SBOM components of type `framework`, `library`, `machine-learning-model` and `service` (component source `aibom`, kept when an SBOM scan replaces the other components).
- Imported HTTP evidence is redacted: `Authorization`, `Cookie`, `Set-Cookie` and other credential headers, credential-like parameters and tokens are removed from stored reports and findings.

### Changed
- Manifest tools with `network: none` run without the egress proxy variables.
- Scanner and import keys may be up to 60 characters (`plugin-code-quality-<name>`).
- PATHOS findings JSON is detected only when a document has no fields other than `tool` and `findings`, which its parser already required (reports of Kingfisher, Sobelow, poutine and Dependency-Track also have `findings`). npm audit detection no longer accepts pnpm audit reports.
- Import detection tries tool-specific formats before the generic CSV format, and `{"findings": [...]}` reports are taken as PATHOS findings JSON only when they have no other fields, so Amazon Inspector and Dalfox reports, which also have a `findings` array, are recognised.

## [1.1.1] — 2026-11-19

First published 1.1 release; contains everything listed under 1.1.0. The v1.1.0 tag exists but no release was published from it, because its release gate found a new vulnerability.

### Security
- Trivy, Syft, Grype and OSV-Scanner in the worker image are now built from source with Go 1.27.4. The upstream release binaries were built with Go 1.27.3, which is affected by CVE-2026-97054 (high, standard library).

## [1.1.0] — 2026-11-19

Closes the remaining register capabilities (99 of 100 completed; multi-tenant stays out by decision) and adds the features other application security tools are known for.

### Added
- **Malware scanning of repository content**: the `clamav` scanner streams repository files to clamd over an isolated `malware` network (opt-in profile). Detections are critical `malware` findings with signature, SHA-256 and engine version; files clamd cannot scan are reported, never dropped.
- **Licence findings**: licence policy violations from the SBOM and from file-level licences (built-in `licensecheck`) are `license` findings with lifecycle and SLA, re-evaluated when the policy changes, resolved and never deleted.
- **Binary hardening** (`binary-hardening`): ELF, PE and Mach-O checks (PIE, RELRO, NX, stack canaries, FORTIFY_SOURCE, RPATH; ASLR, HIGH_ENTROPY_VA, DEP, CFG, SafeSEH, /GS) with compiler and linker remediation; always on for build artifacts.
- **Framework configuration rules**: 27 Opengrep rules for Spring Boot, Django and Express in a new `misconfiguration` category.
- **Declared endpoint verification**: opt-in, authorization-gated, rate-limited checks of a repository's public URLs, domains and IPs (DNS, reachability, TLS, HSTS, security headers, optional Nuclei exposure templates).
- **End-of-life dates**: opt-in endoflife.date feed (offline file import) matched to SBOM components, declared runtimes, Dockerfile base images and image targets; `eol` findings with SLA.
- **Introducing commit**: git blame of code findings records the commit and date (and the author name while developer attribution is on); push and merge scans store a change summary shown on the scan and sent with `findings.new`.
- **Sigstore verification**: cosign verifies image and artifact signatures (key or keyless) and in-toto/SLSA attestations; "require signature" creates a `supply-chain` finding and fails the gate.
- **25 import formats**: Semgrep, Snyk, SonarQube, ZAP, Burp, Trivy, Gitleaks, TruffleHog, Checkov, Bandit, gosec, ESLint, npm audit, pip-audit, OSV-Scanner, Dependency-Check, Nessus, OpenVAS, Nuclei, Checkmarx, generic CSV, plus SARIF, Grype and PATHOS JSON; explicit `format` or detection.
- **`pathos` CLI and CI templates**: `import`, `scan`, `gate`, `findings` and `sbom export`, released for Linux, macOS and Windows with signed checksums; GitHub Action, GitLab, Azure Pipelines and Jenkins templates; `GET /api/v1/scans/{id}/gate`.
- **Automatic fix pull requests** for vulnerable dependencies (pip requirements, Maven, Gradle, NuGet, npm without a lockfile) on GitHub, GitLab, Bitbucket and Azure DevOps, opt-in per repository; branches under `pathos/fix/` only; findings are resolved only by a later scan.
- **VEX and application versions**: OpenVEX and CycloneDX VEX export; VEX import as suggestions that a second person approves; frozen application versions with portfolio search; component (SBOM) policies on age, outdated versions, licences and severity.
- **Secret push protection**: pre-commit and pre-receive Gitleaks hooks, and push-event diff scanning for GitHub and GitLab with redacted `secret.pushed` alerts.
- **Material change detection**: explainable rules for authentication and authorization, new endpoints, crypto, IaC exposure, CI/CD, secrets handling and PII fields between scans; `change.material` notifications and a security-policy condition.
- **Developer insights**: who introduces and fixes findings, per developer and team, **off by default**; identity linking; turning it off erases the data. New permission `insights.people`.
- **VS Code extension** (`ide/vscode`): findings as diagnostics and in a tree view, details, open in PATHOS, request review, change status; token kept in VS Code SecretStorage.
- New finding categories: `malware`, `misconfiguration`, `binary`, `eol`, `supply-chain`.

### Security
- Repository-wide `.gitleaks.toml` allowlists only the files that hold fake test credentials; the pre-commit Docker hook pins Gitleaks by digest.
- Fix pull requests never run repository code or package managers, and never write outside `pathos/fix/` branches.
- Commit author names are stored only while developer attribution is on; e-mail addresses are never stored.

### Known limits
- Fix pull requests do not support Go, Cargo, Composer, Bundler or npm/yarn/pnpm projects with a lockfile, or transitive dependencies.
- Push-event secret scanning alerts after the push (blocking needs the hooks) and supports GitHub and GitLab only.
- Material changes and licence findings are computed for branch scans, not pull request scans; no AI summary of material changes.
- Keyless signature verification is skipped offline; shallow clones record the introducing commit as unknown.
- The VS Code extension, CI templates and pre-receive hook are tested in isolation, not yet against live services.

## [1.0.0] — 2026-11-19

First stable release: the platform phases P1–P8 of 0.9.0 plus the ten ASPM phases (application security posture management), with the full documentation set reviewed against the code.

### Added
- **Supply chain** (ASPM phase 7): SBOM export as SPDX 2.3 or CycloneDX JSON; package health and provenance from deps.dev (off by default, because it sends package names); malicious-package flagging; actionlint for GitHub Actions workflows; **build artifacts** as scan targets (Trivy, optional ClamAV malware check on upload); **pull request checks** posted to GitHub, GitLab, Bitbucket and Azure DevOps, opt-in per repository.
- **Governance** (ASPM phase 8): MFA **recovery codes**; **single sign-on** with your SAML 2.0 or OpenID Connect identity provider brokered by Keycloak; **security policies** (conditions → actions: block the scan gate and pull request checks, require a Human Eye review, tighten the SLA, notify) with preview and violations; **compliance views** for OWASP Top 10, OWASP ASVS, PCI DSS, ISO 27001 and SOC 2.
- **Reporting and integrations** (ASPM phase 9): **REST API tokens** with `api:read` or `api:write` scope (valid for `/api/` only); **outbound webhooks** (signed JSON, Slack, Microsoft Teams) with delivery history and retries; **Jira and ServiceNow** tickets for findings with status sync; **executive overview**; saved and scheduled **reports**.
- **Production readiness** (ASPM phase 10): **declarative scanner plugins** defined by files on the worker (`deploy/scanners.d`); **offline mode** (`PATHOS_OFFLINE=true`) with SHA-256-verified vulnerability-database bundles (`scripts/offline-bundle.sh`) and an air-gap guide (`docs/AIRGAP.md`); a pluggable ticket connector interface.
- **Documentation**: complete API reference (every route documented, including findings, scan configuration, AI and MCP, administration, notifications, dashboard and search, and the internal worker protocol); user guide reorganised without duplication and with new Findings and Administration pages; engineering docs rewritten as built.
- **AI Security Analyst** (AI & MCP): private conversations over your security data, scoped to what you may read, citing the findings used (only findings that were in the context), never sending code or secrets. **AI reports**: technical and executive reports for the organization, an application or a repository, with PATHOS-computed figures and an optional AI narrative, downloadable as Markdown. **AI usage** for administrators.
- **Human Eye**: optional third approval level (final approval by a third person for chosen severities or dispositions); AI patch proposals (validated unified diffs, approved or rejected by a person, downloadable, never applied); AI explanations of the contextual risk score; AI suggestions of possible duplicates.
- AI requests to model servers wait for the response as long as the request timeout allows (slow local CPU inference no longer times out after 30 seconds).
- **Vulnerability intelligence**: OSV records for the CVEs and advisories of findings (online lookups, offline JSON/zip import) with a vulnerability page (description, references, exploit evidence, affected and fixed versions, EPSS, KEV); exploit references raise the risk score; vendor CVSS vectors fill findings without one.
- **Dependency reachability**: workers inventory the packages the code imports or names (JavaScript/TypeScript, Python, Go, templates); dependency findings are reachable, not reachable (npm and Go, with complete evidence) or unknown, with an explanation. It only weights the risk score.
- **Attack paths** (Posture): from the internet through tested applications or exposed assets to weaknesses, their images and the vulnerable packages their code uses.
- **Related findings**: the same weakness reported by another tool at the same place, and the same CVE elsewhere, without merging.
- **Suppression rules** (Vulnerabilities): governed, expiring decisions for every finding matching a rule ID, path, package or CVE; effective only after a second person approves; findings reopen at expiry or revocation.
- **Posture** section: **Application posture** with an explainable risk rollup per application (and by business unit, team, owner or region), **Coverage** matrix of repositories × scan categories, **Unmanaged assets** (governance gaps and shadow repositories from a daily SCM inventory), **Benchmarking** on normalised metrics, **Blast radius** for a CVE or package, and the **Context graph** of an application or repository.
- **Dependency graphs**: SBOM dependency relationships are stored (CycloneDX and SPDX), so components are direct or transitive. Repositories have a **Dependencies** tab with "how it gets in" paths, and dependency findings show their path.
- **Scan targets** (**Scanning → Scan targets**): container images (Trivy), running web applications (Nuclei DAST, non-intrusive templates only), APIs from an OpenAPI document (Nuclei DAST templates) and SBOMs of software you receive (Grype). Targets belong to a repository; web and API targets need a recorded authorization statement; credentials are encrypted and redacted from logs; the worker checks the egress proxy lets it reach a target before scanning. Target findings are kept apart from source findings and filterable by asset. Scans can be filtered by asset type.
- **CI/CD workflow security**: zizmor audits GitHub Actions workflows offline (add it to a scan profile).
- **Result imports** (**Scanning → Import Results**): SARIF 2.1, Grype JSON and the PATHOS findings JSON format from any tool (other SAST and SCA products, DAST, IAST, fuzzers, CI pipelines). Each import is a scan execution whose findings keep the tool's name and go through de-duplication, risk scoring and review. Partial imports never resolve findings; complete imports can.
- **SBOM import**: CycloneDX and SPDX 2.x JSON into the repository's component inventory.
- **Custom rules** (**Configurations → Custom rules**): Opengrep rule files with validation, versions and enable/disable. Each scan pins the versions it used.
- A **DAST** finding category.
- **Contextual risk scoring** (`docs/user-guide/vulnerability-intelligence.md`): every finding gets an explainable 0–100 risk score from CVSS or severity, EPSS, CISA KEV, business criticality, internet exposure, reachability, confidence, Human Eye outcomes, compensating controls and fix availability. The model is configurable and versioned (**Administration → Risk & intelligence**). Findings are re-scored in the background when any input changes. Severity is never altered.
- **Vulnerability intelligence feeds**: FIRST EPSS and the CISA KEV catalog, downloaded daily by default (configurable URL and interval, can be turned off) or imported from files for air-gapped installations. CVE lookup API.
- **Unified finding lifecycle**: New, Open, In progress, Under review, Confirmed, False positive, Accepted risk, Resolved and Reopened, derived from the stored statuses (no breaking change). Findings show CVSS version and vector, confidence, EPSS, KEV, risk and application, and can be filtered and ordered by risk.
- **Applications**: permanent Application IDs (`QD-APP-000001`), technical owner, lifecycle and environment. The former "Application ID" field is now labelled **External ID**.
- **Human Eye**: the manual review module is named Human Eye (routes and API unchanged).
- ASPM programme documents in `docs/aspm/` (assessment, gap analysis and feature register, roadmap, database and API design).
- **Human Eye module** (`docs/HUMAN_REVIEW.md`): standalone navigation section with Overview, Review Queue, Assessments, Assignments, Review Reports and Review Configurations. Findings that automated triage or AI review cannot settle are queued automatically (configurable, never duplicated) or sent from the Findings page. The assessment workspace has eight tabs: overview with the preserved scanner output, source code at the **scanned commit** (GitHub, GitLab, Bitbucket, Azure DevOps or the uploaded snapshot) with highlighting, references and comparison, data flow as reported by the scanner (confirmed / incomplete / inferred), structured exploitability questions, evidence (validated, encrypted uploads and text) with a reproduction template, risk reassessment with CVSS 3.1/4.0 and mandatory justification, remediation guidance and tracking, and an immutable history with comments. Separate review status, final disposition and remediation status; dispositions with required justifications; configurable independent (four-eyes) review; accepted risk through the existing risk acceptance approval; reopen as new rounds; AI suggestions that never decide; CSV export and printable reports. Permanent review IDs (`QD-HR-000001`).
- Permissions `reviews.read`, `reviews.assess`, `reviews.assign`, `reviews.approve`, `reviews.configure` and the **Independent Reviewer** role. Notifications `review.assigned`, `review.independent_requested`, `review.independent_decided` and `review.overdue`.
- Findings show their Human Eye outcome and can be filtered by it.
- **Scanning module** (`docs/SCANNING_MODULE.md`): Scan Overview dashboard, Scans management (start with an existing profile for one or many assets, progress and stages from real execution state, cancel, retry as new executions), Scan Details with Overview, Findings, Execution Logs, Stages, Configuration (immutable snapshot) and History tabs, and Scan Comparison over 360 days (new / fixed / recurring / unchanged / not covered — never "fixed" when the later scan failed or did not cover the finding). Permanent Scan IDs (`QD-SCAN-000001`). Workers report stages and redacted logs.
- **Schedules**: one-time, cron (daily / weekly / monthly) and interval schedules with time zones, approved scan windows, retry policies, concurrency limits, pause and resume, execution plans of assets × existing profiles, activation history, duplicate-safe recovery and completion / failure notifications.
- **Configurations** navigation section holding Scan profiles and Scanners & workers (moved out of Scanning; unchanged).
- Permission `scans.compare` (part of every read-only role).
- **Enterprise repository onboarding** (`docs/REPOSITORY_ONBOARDING.md`): three import methods — **Local PC** (chunked, resumable, SHA-256-verified ZIP/TAR/folder uploads, optional ClamAV, encrypted snapshots), **Git** (GitHub, GitLab, Bitbucket) and **DevOps project** (Azure DevOps organizations, projects, repositories, branches) — sharing one registration wizard and a background import engine with progress, retry, cancel, idempotency and duplicate detection.
- **All provider sign-in methods**: GitHub App, PATs and OAuth Apps; GitLab access tokens and OAuth; Bitbucket access tokens, API tokens and OAuth; Azure DevOps PATs, Microsoft Entra ID OAuth and service principals (secret or certificate). OAuth applications are managed in the UI; tokens refresh automatically and connections can be reconnected or revoked.
- **Enterprise asset metadata**: business, technical and application owners, teams, department, cost centre, business region separate from hosting and data-residency region, data classification, internet exposure, compliance scope, lifecycle and asset colour, with administrator-configurable catalogs, colours and required fields (**Administration → Asset settings**). Asset owners can edit their assets' metadata.
- **Repository synchronization**: manual, nightly and webhook-driven (now also GitLab and Bitbucket webhooks), recording the head commit and detecting deleted, archived and inaccessible repositories, with history and `repository.sync_failed` / `import.failed` notifications.
- **Permanent Repository IDs** (`QD-REPO-000001`): generated by the database at registration, unique, never reused or editable, shown and searchable throughout PATHOS (inventory, details, dashboards, scans, findings, exports, audit log). Staging and production URLs and the mandatory **public internet exposure** answer (yes / no / unknown, with public URLs, domains, IPs and notes) are part of the shared registration for every import method.
- Repository dashboard KPIs and insights by provider, region, business unit, owner, classification, environment, compliance and lifecycle; new list filters and sorting.
- Scans of uploaded repositories run against their recorded snapshot; Git scans record the commit actually scanned; optional full-history secret scanning.
- Permissions `tags.manage` and `assets.configure` (granted to existing roles that could manage tags) and the **Repository Contributor** role.
- `pathosctl migrate-down <version>` for release rollback; backups include the encrypted `sources` volume.
- Authenticated active DAST (`scripts/dast.sh`, `make dast`): an OWASP ZAP API scan of every endpoint with session, CSRF token and Origin. CI runs it on pushes to `main`, releases, weekly and manual runs, and gates on unreviewed High alerts.
- A weekly scheduled CI run, which picks up new advisories in dependencies and images.

- MFA for existing users: `PATHOS_REQUIRE_MFA=true` now also makes every existing account without an authenticator enrol at its next sign-in (hourly, idempotent). The Users page shows each user's two-factor status and has a **Require MFA** action (audited).

### Fixed
- Build-artifact uploads were never malware-scanned in the default stack: `PATHOS_CLAMAV_*` reached only the `jobs` service, but artifacts are scanned by `api`. Both services now get the settings.
- Request IDs are 24 random letters instead of hex, so security scanners no longer mistake one for a payment card number (random DAST "PII Disclosure" failures).
- `POST /api/v1/scm-connections/{id}/resync` returns `404` for an unknown connection instead of `502`.
- Repository technologies are a scan setting and need `repos.manage`; asset owners see the Scanning section read-only instead of controls that failed on save.
- API responses now carry `Cross-Origin-Resource-Policy: same-origin`.
- `GET /api` (without a trailing slash) returned the web app's HTML instead of the API's JSON 404.

## [0.9.0] — 2026-11-15

First public release: roadmap phases 1–8 and the follow-up work below.

### Releases and project hygiene

#### Added
- Release workflow: on a version tag it runs the full CI, then publishes cosign-signed images with SBOM and SLSA provenance attestations to `ghcr.io/quditmind/{pathos,pathos-proxy,pathos-worker-core}` and creates the GitHub release with verification instructions.
- `PATHOS_IMAGE_PREFIX` selects registry images instead of local builds (`upgrade.sh --pull`).
- `SECURITY.md` (private vulnerability reporting), `CONTRIBUTING.md`, the code of conduct, and issue and PR templates. `main` is protected by CI.
- Dependency policy: a 14-day Dependabot cooldown, deliberate major upgrades, and security updates enabled.

#### Fixed
- `upgrade.sh --pull` skipped every PATHOS image: `--ignore-buildable` excludes services that also have a build section.

### Local AI and Claude subscriptions (2026-11-15)

#### Added
- Self-hosted AI provider (any OpenAI-compatible server: Ollama, vLLM, LM Studio, llama.cpp):
  - plain `http` on private networks, with an optional key;
  - `max_tokens` and temperature 0 for deterministic triage;
  - helpful errors when the base URL or model is wrong.
- Optional `ollama` compose profile, `docker-compose.gpu.yml` for NVIDIA GPUs, and a `host.docker.internal` mapping for a model server running natively on the host.
- `allow_self_approval` on AI configurations, so a single person can approve the interactive (MCP) reviews made with their own Claude Code (Pro/Max). Audited.
- Claude Code setup notes, including the local-CA tip, on the API tokens page. AI options guide in OPERATIONS.md.

#### Verified
- A live review of a real command-injection finding by `qwen2.5-coder:3b` on CPU through Ollama: correct verdict and remediation in 30 s, accepted by strict schema validation.

### Continuous integration (2026-11-15)

#### Added
- GitHub Actions CI:
  - Backend: gofmt, vet, race-enabled unit tests, gosec, govulncheck.
  - Integration tests against PostgreSQL 18.
  - Frontend: typecheck, tests, build, npm audit.
  - Full-stack job from a fresh install: smoke test, Playwright, Trivy, ZAP baseline.
- Actions are pinned to commit SHAs. Dependabot updates Go, npm, Docker, Compose and Actions.
- Playwright browser test suite (`e2e/`, `make e2e`): every page renders without page errors or CSP violations, plus the command palette, security headers, schedule lifecycle, notification administration, policies, the finding drawer and the notification centre.

#### Fixed
- `backend/internal/secrets` was never committed: the unanchored `secrets/` pattern in `.gitignore` excluded it, so a fresh clone could not build. The pattern is now `/secrets/`. Found by the fresh-install CI dry run.
- Command palette: typing a page name and pressing Enter right away opened the Dashboard, because page matching used the debounced query. It now uses the live input.
- Integration test files were not gofmt-formatted (`go fmt ./...` skips build-tagged files); CI now checks with `gofmt -l`.

### Phase 8: Enterprise hardening (2026-11-15)

#### Added
- API rate limiting (GCRA in Valkey) with `429` and `Retry-After`; tuned with `PATHOS_RATE_LIMIT_SCALE`.
- Keycloak admin console restricted to `KEYCLOAK_ADMIN_ALLOW`; optional TOTP enrolment for new users (`PATHOS_REQUIRE_MFA`).
- `docker-compose.prod.yml` production override, plus `backup.sh`, `restore.sh` and `upgrade.sh`, and the `docs/OPERATIONS.md` runbook.
- OpenTelemetry traces and metrics (OTLP/HTTP) with route-level spans and platform gauges; optional Grafana LGTM profile.
- S3-compatible object storage for scan artifacts (SeaweedFS profile) and `pathosctl migrate-artifacts`.
- `make security` (gosec, govulncheck, npm audit, Trivy, ZAP baseline) and `make load-test` (k6 with 100k-finding seed data).

#### Fixed
- The worker context reader now resolves symlinked directories (defence in depth).
- Valkey crash-looped after any restart; it now runs unprivileged as its own user.
- 42 fixable HIGH/CRITICAL vulnerabilities in our images: go-jose, plus Caddy and Gitleaks rebuilt with patched dependencies; Debian packages upgraded and pip removed from the worker runtime.
- TLS clients without SNI are served; cross-origin isolation headers were added.
- The dashboard findings trend is 10× faster on large datasets.

### Phase 7: Scheduling & notifications (2026-11-15)

#### Added
- `scheduler` role and compose service. A Postgres advisory lock elects the leader, so replicas are hot standbys. It runs cron schedules (with time zones) targeting the organization, a region, a business unit (including children), a repository or a scan profile, with per-schedule priority. It catches up missed runs once and reports them, recovers expired worker leases and reports offline workers.
- Schedules API and UI: create, edit, pause, run now, delete, cadence presets with a live preview of the next runs and repository count, scheduler and queue health, and a "Last run" link to the schedule's scan jobs.
- Notification engine: a trigger-fed outbox, eight built-in rules, custom rules (event, minimum severity, region, business unit or repository scope, role/user/email/dynamic recipients, email and in-app channels), editable templates with a live preview, SMTP settings with a test email, delivery history with retry, and an in-app notification centre with an unread badge.
- Events: new findings, scan failed, SLA breached, finding assigned, risk acceptance requested and decided, schedule missed, worker offline.
- SCM metadata re-sync: nightly in `jobs`, or **Re-sync metadata** per connection.

#### Fixed
- The `jobs` service was on the internal `data` network only, so automated AI reviews could not reach the provider. It now also joins `edge` (with `HTTPS_PROXY` support), which notification email also needs.
- Assignments now record the acting user, so self-assignment is not notified.

### Phase 6: Vulnerability management (2026-11-15)

#### Added
- Finding lifecycle enforced by a database trigger: append-only status history with actor/source/reason, SLA deadline on detection, recurrence counter when a fixed finding reappears.
- Manual triage API and UI: status changes with required reasons, assignment, atomic bulk status/assign, history timeline, SLA and assignee columns and filters.
- Risk acceptance workflow: time-boxed (≤ 365 days), approved by a different person with `findings.accept_risk`, revocable, findings reopen automatically at expiry (jobs role, every 10 minutes).
- SLA policies per severity (default 7/30/90/180 days) with recomputation; license policy (deny/review by SPDX id).
- SBOM inventory: Syft CycloneDX components stored per scan, component search across repositories with license-policy matches and open vulnerability counts, CycloneDX download per repository.
- UI pages: Risk acceptances, SBOM inventory, Policies. All 24 dashboard KPIs are now live.

#### Fixed
- Client disconnects are no longer logged as internal errors.
- `openapi.yaml` is valid YAML again (an unquoted description broke parsing).

### Phase 5: AI review & MCP (2026-11-15)

#### Added
- AI providers: Anthropic (official Go SDK, default `claude-opus-5-5`, structured output, prompt caching, refusal fallbacks), OpenAI and xAI. Keys are encrypted and tested.
- Versioned AI configurations, a review queue in the jobs role, auto-review after scans, and per-review transmitted-payload hashes.
- Redaction, nonce-fenced untrusted evidence, strict output validation, code context captured by workers.
- Approval queue with a critical-finding guardrail and four-eyes for interactive reviews.
- PATHOS MCP server (`/mcp`) with personal API tokens; MCP server registry with tool allow-lists.

### Phase 4: Scanning engine (2026-11-15)

#### Added
- Scanner catalog (52 integrations), versioned scan profiles with mandatory Gitleaks, scan jobs with priority leasing, retries, cancellation and webhook triggers.
- `worker-core` image (Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov; checksum-pinned) and the `pathos-worker` agent with a hardened clone. Internal worker API with per-worker revocable tokens.
- Squid egress proxy with an allowlist and denial of private and metadata destinations.
- Server-side normalization: SARIF and Grype JSON parsing, cross-tool de-duplication, line-independent fingerprints, auto-resolution and a security gate. Raw report/SBOM storage with retention.
- PATHOS baseline Opengrep rules (Apache-2.0).
- UI: Scans, Findings (read-only), Scan profiles, Scanners & workers, Scan now / bulk scan; live scanning KPIs and charts.

### Phase 3: Repository & asset management (2026-11-15)

#### Added
- SCM connections: GitHub (PAT or GitHub App), GitHub Enterprise Server, Azure DevOps Services and Server. Credentials are encrypted and write-only; outbound calls are SSRF-protected.
- Repository discovery and import (selection with defaults, CSV bulk onboarding with dry run), live branch selection, placement and classification, archive/delete, and bulk tagging.
- Tag categories with mandatory and single-value rules; applications with owners.
- Signature-verified GitHub and Azure DevOps webhook receivers with replay protection.
- Repository-scoped RBAC through the BU → region → organization hierarchy.
- Dashboard KPIs Repositories, Applications and Without owner, plus a criticality chart; repositories and applications in global search.

### Phase 2: Premium UI & dashboard (2026-11-15)

#### Added
- Dashboard API with the 24-KPI catalog and chart panels. KPIs that have no data source yet are reported as "not yet available", never with placeholder numbers. Values are permission-aware, with period and geography filters.
- Global search API and the ⌘K command palette.
- UI components: KpiCard, FilterBar and DataTable (column chooser, CSV export). Also a notification centre shell, a dashboard page with lazy-loaded charts, and deep-linkable filters on the Users and Audit pages.
- Keycloak login theme `pathos`.
- Audit log `outcome` filter.

### Phase 1: Foundation (2026-11-15)

#### Added
- Go backend (`pathos` with `api` and `jobs` roles, `pathosctl`): validated configuration (with `_FILE` secret support), slog JSON logging with secret redaction, and `/healthz` and `/readyz`.
- PostgreSQL schema and goose migrations: organizations, regions, countries, business units, users, teams, roles, permissions, role assignments, encrypted secrets, and an append-only audit log partitioned by month. Runtime role `pathos_app` with least privilege.
- RBAC: 29-permission catalog, 9 system roles, and scoped assignments (organization, region, business unit with descendants, repository). Includes privilege-escalation and last-super-admin protections, and SQL scope filters.
- AES-256-GCM envelope encryption for secrets, with versioned master keys and `pathosctl rotate-master-key`.
- Keycloak `pathos` realm import, BFF OIDC login (PKCE), Valkey sessions, CSRF protection, logout through Keycloak, JIT provisioning and bootstrap super admin.
- User management API: list and search, invite with Keycloak account creation and set-password email, deactivate/reactivate with immediate session revocation, and role grant/revoke. Also organization structure and audit log endpoints. OpenAPI spec in `backend/api/openapi.yaml`.
- React app shell (Vite, TypeScript, Tailwind 4, TanStack Query/Router): login, navigation, light/dark theme, and Users, Organization and Audit log screens.
- `docker-compose.yml` (proxy, migrate, api, jobs, postgres, valkey, keycloak, mailpit[dev]) with health checks, internal networks, hardened containers and digest-pinned images. Also `.env.example` and `deploy/scripts/install.sh`.
- Tests: Go unit tests, Go integration tests against PostgreSQL, Vitest frontend tests, and an end-to-end smoke test (`scripts/smoke-test.py`).
