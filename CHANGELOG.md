# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, minor versions may contain breaking changes.

## [Unreleased]

2.2.2 hardening: the open issues of the end-to-end validation ([docs/VALIDATION_REPORT.md](docs/VALIDATION_REPORT.md) §9). Migrations **00043** (scan concurrency indexes) and **00044** (anonymous repositories, private CA bundles, secret exclusions) are additive. Rebuild the family worker images (sast, iac, sca, fuzz, ai) and the API and worker-core images.

### Added
- **Public repositories without a token** (O1). `POST /api/v1/repositories/import-url` imports a PUBLIC repository by URL: GitHub, GitLab.com, Bitbucket Cloud and Azure DevOps public projects are checked anonymously through their public APIs, any other HTTPS git URL through the git smart-HTTP protocol. The repository is registered without an SCM connection (`source_type` `git`, `anonymous: true`, labelled *anonymous* in the UI) and cloned without credentials. Private, internal or missing repositories are refused with `PTH-ONB-1102`; credentials in the URL with `PTH-ONB-1101`; provider rate limits with `PTH-ONB-1103` (HTTP 429, `retry_after_seconds`). A sync re-checks that the repository is still public; one that turned private is marked `permission_denied` and not scanned. *Import repositories → Public repository by URL*. The egress allowlist now includes GitLab.com and Bitbucket Cloud.
- **Private CA bundles** (O3) for registry connections, outbound webhooks (Slack, Teams, JSON) and ticket connections (Jira, ServiceNow): `ca_bundle_pem` (PEM certificates, added to the system trust store for that connection only; verification never disabled; TLS 1.2 minimum). Responses list each certificate's subject, expiry and SHA-256 fingerprint (`ca_certificates`); a private key or other non-certificate input is refused with `PTH-CONN-1701`; an untrusted server certificate names the fix (`PTH-CONN-1702`). Same approach and code as the 3.0 SCM connections.
- **Secret exclusions per profile** (O6): secret findings in vendored dependencies, test fixtures, lockfiles and minified or source-map files are dropped by default (`secret_default_exclusions`, on for every existing profile version), plus the profile's own `secret_exclusions` patterns. On gitlab-cli: Talisman 3,432 → 2,420 and detect-secrets 145 → 104 findings; a SAST profile without Talisman goes from 3,577 to 104 secret findings.
- `POST /internal/worker/v1/jobs/{id}/release` (worker protocol): a stopping worker hands its job back to the queue.
- Image scan targets: `config.built_from_repository` (*This image is built from the repository's code*).
- API errors may carry `error.error_code` (`PTH-<AREA>-<NNNN>`), as in 3.0.

### Changed
- **Concurrent executions per repository** (O2): result imports and target scans (image, URL, API, artifact, SBOM) run next to a repository scan; CI imports no longer get 409 while a DAST or image scan runs. One running code scan per repository (and per pull request) and one running scan per target remain. Results and finalization of a repository are serialized with an advisory lock.
- **Executions whose profile tools no worker has are partial**, not succeeded (O15): `PTH-SCAN-1101` names the tools (failed when nothing ran).
- **Partial tool reports are kept** (O14, O17): the findings of a tool that failed or timed out but wrote a report are stored (the result stays failed/timed out and nothing it covers is auto-resolved), and the worker uploads a timed-out tool's output, so Nuclei's partial results are no longer discarded. URL and API target scans get at least 90 minutes.
- **Runtime linking** (O10): an image target links its repository's code findings to running workloads only when marked `built_from_repository` (the OCI source label still links without it), and a tag match needs a successful scan of the target. *Behaviour change*: mark existing image targets whose image is built from their repository.
- Talisman can never be part of the seeded default profile (`NotRecommended`).
- OWASP Dependency-Check: an NVD API key is a documented prerequisite (`NVD_API_KEY` in `/etc/pathos/sca.env`).

### Fixed
- **Dependency-Check stalls** (O17): the NVD download inside the scan had no read timeout, so a connection stalled through the egress proxy (or broken by an egress restart) left Java at 0 % CPU holding `odc.update.lock` while the other workers waited on the lock. The NVD update now runs separately with connection/read timeouts and a hard limit (`DEPENDENCY_CHECK_UPDATE_TIMEOUT`, default 1200 s) at most every `NVD_MAX_AGE_HOURS` (6) under a lock in the cache; a stale `odc.update.lock` is removed; the scan runs offline with its own limit (`DEPENDENCY_CHECK_SCAN_TIMEOUT`, 1800 s). A failed update falls back to the cached data with a partial result naming the cause.
- **Worker shutdown** (O9): a worker stopped with SIGTERM during a scan returns the job to the queue (or fails it on its last attempt) instead of leaving it running until the lease expires.
- **Go tools** (O4): fuzz targets that do not build make go-fuzz/Atheris fail (partial execution) instead of a success with no findings; gosec is scanned per module and top-level directory with `GOMEMLIMIT` (it was OOM-killed at 4 GB; on go-toml the old helper was killed at 2 GB, the new one finished).
- **detect-secrets hang** (O7): two processes instead of one per host core (a pool process killed for memory hung the scan), the default secret-exclusion files skipped, 20-minute limit.
- **TFLint** (O8): module load errors are reported (they were inside the JSON on standard output, so the scan showed no message) and the other modules' issues are kept.
- **Kubescape** (O16): a repository without Kubernetes manifests but with unparseable YAML/JSON (comments in `.vscode/launch.json`, duplicate keys, a UTF-8 BOM) is an empty result naming the skipped files, not a failure.
- **garak** (O18): each probe runs separately, so one read timeout of a slow model no longer aborts the run; request timeout `GARAK_REQUEST_TIMEOUT` (180 s).
- **Webhook signing** (O11): creating a Slack or Teams webhook with `sign: true` returns a warning (deliveries are not signed) instead of ignoring the flag; the UI says so.
- **SBOM noise** (O12): workflow files (`$/.github/workflows/ci.yml`, version UNKNOWN) are no longer components; GitHub Actions get the type `github-action`.
- **Stage of expired leases** (O13): no longer left at `scanning:<tool>`.

## [2.2.1] — 2026-11-20

Fixes found by an end-to-end validation on 15 public open-source projects (Go, Java, Python, JavaScript/TypeScript, .NET, PHP, Ruby, Android, Terraform, Kubernetes/Helm and CI/CD repositories) with every worker image, plus open-source test services (kind, Jenkins, LocalStack, Mailpit). The report is in [docs/VALIDATION_REPORT.md](docs/VALIDATION_REPORT.md); a deployment checklist is in [docs/PRODUCTION_CHECKLIST.md](docs/PRODUCTION_CHECKLIST.md). **Upgrade if you run the family worker images**: in 2.2.0 most SAST, IaC and SCA family scans ended partial on real repositories.

### Fixed
- Family worker tools no longer run on repositories without their language or files (new manifest field `requires_files`), which made most SAST, IaC and SCA family scans end partial.
- Trivy: concurrent workers no longer crash on a shared vulnerability database (SIGBUS) or contend for the scan cache lock; the Java database is no longer downloaded into the 1 GB `/tmp`.
- OSV-Scanner no longer fails on Maven projects.
- Nuclei on API targets: runs without the intrusive flag (it found no templates before) and handles OpenAPI documents with required parameters.
- Family wrappers: Psalm report path; Kubescape on repositories without Kubernetes manifests; pip-audit on unpinned requirements; cdxgen on Gradle and Maven projects; govulncheck on modules without packages; yarn registry host; OWASP Dependency-Check uses the egress proxy.
- Egress allowlist: govulncheck needs `storage.googleapis.com`; Docker Hub hosts for image targets.
- The CycloneDX SBOM export returned the AI-BOM instead of the repository SBOM.
- `pathos gate --repo` evaluated image and DAST scans of the repository instead of its repository scans.
- Self-hosted AI reviews had no output limit.
- Enabling S3 object storage on an existing installation broke scans of every existing repository.
- An expired worker lease could block a repository's scan queue forever.
- Imports could stay at 50 %.
- Editing a Kubernetes cluster connection deleted its CA certificate.
- The error for a refused image registry now names the registry host.
- Docs: the import API example and the CVE Binary Tool database memory requirement.
- Image builds retry every download on any error (5 attempts): Maven Central and GitHub release downloads intermittently answer 404 or 500, which `curl --retry` alone did not retry. Every download is still checked against its pinned SHA-256.

### Known issues
Listed with reproduction steps in [docs/VALIDATION_REPORT.md](docs/VALIDATION_REPORT.md) §9, among them: repository import needs a token even for public repositories; one execution per repository at a time (CI imports get 409 while a DAST scan runs); no private-CA setting for registries, webhooks and ticketing; OWASP Dependency-Check can stall during scans (make an NVD API key a prerequisite or leave it out of profiles); secret scanners are noisy (keep Talisman out of default profiles); Nuclei can exceed the 30-minute default timeout on API targets.

## [2.2.0] — 2026-11-19

Proof and scale: optional multi-tenancy, benchmarks, performance fixes and a JetBrains IDE plugin. Migrations 00038 and 00040–00042 are additive; 00038 builds indexes concurrently, which can take minutes on large installations. Single-organization installations are unchanged until `pathosctl multi-tenancy enable`. Dependency findings get fingerprint version 2 and are re-keyed in place on the next scan, keeping their status and history.

### Added
- **JetBrains IDE plugin** (`ide/jetbrains`, IntelliJ Platform 2025.3 to 2026.3: IntelliJ IDEA, GoLand, PyCharm, WebStorm and the other IntelliJ-based IDEs), with the features and rules of the VS Code extension: open findings of the project's repository as editor annotations (critical/high errors, medium warnings, low weak warnings, info information) with *Show details* and *Open in PATHOS* quick fixes, a PATHOS tool window grouped by severity and file or by file, finding details, change status and request a Human Eye review with the account's permissions, repository detection from the git remotes (same matching rules as VS Code), refresh on demand and on an interval. The server URL is an IDE-wide setting (https required, http only for localhost); the API token is kept in the IDE password safe per URL; redirects are never followed and the token is never logged. Built with Gradle 9.9.1 (checksum-verified wrapper and dependency verification), Kotlin 2.4.21 and the IntelliJ Platform Gradle Plugin 2.20.1 in a digest-pinned JDK container (`scripts/gradle-jetbrains.sh`); tests cover the API client against a local HTTP server, mapping and matching, and the annotator in a headless IDE (`BasePlatformTestCase`); the Plugin Verifier checks IntelliJ IDEA 2025.3 and 2026.3. CI job `jetbrains-plugin` uploads the ZIP; releases attach it with its checksum in the signed `checksums.txt`. Guide: [IDE integration (JetBrains)](docs/user-guide/ide-integration-jetbrains.md).
- **Multi-tenancy (optional)**: one installation can host several isolated organizations, for example for a managed service ([MULTI_TENANCY.md](docs/MULTI_TENANCY.md)). Off until an operator runs `pathosctl multi-tenancy enable`; single-organization installs are unchanged and their organization becomes the first (default) organization. Migrations 00040–00042.
  - **Row-level security** on every tenant table: the connection pool sets the request's organization (`app.organization_id`) on every connection checkout, from the authenticated session, API or MCP token, worker or webhook connection; without it tenant tables look empty. The application role is subject to the policies, the migration owner is not. New tables with `organization_id` are isolated automatically. Bulk inserts use multi-row `INSERT` instead of `COPY` while row-level security is on.
  - **Same-organization foreign keys** next to the 86 single-column references between tenant tables, and a trigger that keeps role assignments to system roles or roles of the same organization.
  - **Installation administrators** (`PATHOS_INSTALLATION_ADMIN_EMAIL`, `pathosctl installation-admin grant|revoke|list`) create, suspend, resume and delete organizations under **Installation → Organizations** (`/api/v1/installation/*`, installation audit log). They get no access to any organization's data. Suspension blocks sign-in, tokens, workers and scheduled scans; deletion removes every row and stored object of a suspended organization.
  - **Memberships**: one person (OIDC subject) can belong to several organizations with separate users rows and roles; an **organization switcher** in the header starts a new session in another organization (`GET /api/v1/me/organizations`, `POST /api/v1/me/organization`). Logins map to organizations by existing membership, verified-email invitation, or the `groups` claim (`/pathos/<slug>`; `PATHOS_OIDC_ORGANIZATION_CLAIM`, `PATHOS_OIDC_ORGANIZATION_PREFIX`); the shipped Keycloak realm and `keycloak-setup` add the claim mapper.
  - **Workers** serve one organization each (`PATHOS_WORKER_ORGANIZATION`); shared workers are not supported.
  - **Tests**: a cross-tenant isolation suite calls all 396 API routes as each of the 11 system roles of one organization with another organization's ids (5,534 requests per pass), with row-level security and again with the application layer alone, plus MCP, the worker API, webhooks and row-level security directly; valid-body probes of all 131 write routes that address another organization's resource (130 reach the organization check and answer 403 or 404) and of the 15 creates that take a parent in the body (all reject another organization's parent; 11 accept the same body with the caller's own parent); lifecycle and login-mapping tests; static checks of system-scope use, request fields and unauthenticated routes. The whole integration suite runs with row-level security enforced.
- **Benchmark harness** (`benchmarks/run.sh`, [docs/BENCHMARKS.md](docs/BENCHMARKS.md)): measures detection quality on suites with known answers. It runs the scanners in the worker images through the new `pathos-worker run-local` mode (same tool table, manifests and parsers as a scan job, reports written to a directory). `pathos-bench` then parses the reports with the API's parsers, merges findings by fingerprint like the findings table and computes TP, FP, FN, TN, precision, recall, F1 and the OWASP Benchmark score (TPR − FPR, overall and as the category average) per tool, per category and for the merged result. Suites: OWASP Benchmark for Java and for Python (GPL, downloaded at run time from pinned commits with SHA-256 checks, not stored here), a generated secrets corpus (self-made; no secret-shaped strings in the repository), pinned SCA projects with an answer key from OSV (self-made), and the wave C reachability benchmark. First results (2026-11-19, 20 CPUs, 30.5 GiB): merged score +40.2 on OWASP Java (73.0% recall, 32.8% FPR, almost all from Bearer) and +36.9 on OWASP Python (40.7% recall, 3.9% FPR). Secrets 100% recall at 30.8% FPR without Talisman (84.6% with it). SCA 57/57 with no false positives on the fixed versions. The run found five defects, fixed below; after the fixes pip-audit, npm audit and govulncheck each find 100% of their ecosystem's labelled vulnerabilities (0% before) and the merged SCA findings went from 84 (18 duplicates) to 68 (8, from npm audit, which reports no version or CVE). A manual-dispatch **Benchmarks** workflow runs the smoke subset (no downloads), or every suite on request.
- **Scale test tooling and [performance report](docs/PERFORMANCE.md)**: `backend/cmd/pathos-loadgen` (development only, not built into any image) seeds 10,000 repositories and 1 million findings with realistic distributions (SQL), drives the worker API like real workers (register, lease, SARIF upload, complete) and times risk re-scoring; `scripts/load/scale.sh` runs k6 sweeps, mixed load and concurrent-user scenarios over the main read paths; `scripts/load/docker-compose.load.yml` adds `pg_stat_statements`. The report gives the hardware, commands, before/after numbers, sizing derived from them and what was not measured.

### Changed
- Authorization resolves repository, business unit and region targets inside the caller's organization also for organization-wide grants, so a foreign or unknown id is answered like a missing resource. Several sub-resource endpoints (webhook deliveries, custom rule versions, runtime cluster and registry runs and images, notification retry, runtime sync) now answer `404` for an unknown parent instead of an empty list or `409`.
- `users.keycloak_subject` is unique per organization instead of per installation.
- New organizations (installation API) and `pathosctl migrate` create the default Human Eye settings up front instead of on first use.
- The application database role no longer has direct privileges on audit log partitions; it reads and writes them through the parent table, as it already did.
- **Performance with large datasets** (measured with 1 million findings, [details](docs/PERFORMANCE.md)): keyset and covering indexes for the findings list and its summary (migration 00038, built concurrently): default list 1.9 s → 6 ms; worker *complete* 1.6 s → 0.13 s (scan ingest 4–6 → 22–40 jobs/s with 8–16 workers), because the Human Eye auto-queue no longer reads every open finding after each scan unless the *new findings* trigger is on; risk re-scoring 459 → about 2,900 findings/s (OSV alias lookups use the GIN index, batches come from the `risk_dirty` index, batch size 500 instead of 2,000); dashboard 6.9 s → 2.4 s (shared passes over open findings, hashed distinct counts, four queries at a time); executive report trend in one pass; SBOM inventory no longer quadratic, with an index for its open-vulnerability counts (timed out at 120 s with 1 million and with 10 million findings → about 8 s). PostgreSQL JIT is turned off for PATHOS connections (`jit` in the database URL overrides it). Responses are unchanged.

### Fixed
### Fixed
- The worker API answered `500` instead of `404` for a job id it does not know.
- worker-sca: **pip-audit reported nothing** (and the run counted as succeeded) when two `requirements*.txt` files pinned the same package; it now runs once per requirements file. **npm, yarn, pnpm and Composer audit read only the root lockfile**; they now audit every lockfile outside `node_modules`, `vendor` and the other skipped directories, and each finding is located in its lockfile. The reports of per-file runs are stored in a PATHOS envelope (`{"pathos_reports": [{"file", "report"}]}`) that the import parsers read.
- worker-sca: a tool run that fails (an exit status other than "vulnerabilities found", or no valid report) now fails the tool, with the file and the tool's error, instead of counting as success with fewer or no findings; this applies to every `pathos-sca` tool (also cargo-audit, bundler-audit, GuardDog and govulncheck, which accepted partial failures).
- govulncheck findings are located in their module's `go.mod` (for example `services/api/go.mod`), not in `go.mod`; the worker records each module's directory in govulncheck's config message.
- **Dependency findings merge across tools that name a package differently** (fingerprint version 2): package names are normalized (lower case, `-`, `_` and `.` folded: PEP 503, npm scope case), versions lose a leading `v` (Go), and Grype's Maven findings carry `group:artifact` from the package URL. Stored findings are re-keyed on the next scan, keeping their id, status, triage and history; no migration ([DATABASE.md](docs/DATABASE.md#fingerprinting)).
- Manifest tools' version commands run with the manifest's `env` and a new `version_timeout` (1s–5m, default 20s): Semgrep CE's version was empty on every offline scan and cost 20 s (`semgrep --version` waited about 99 s for a version check its manifest disables).
- Talisman's catalog note says it is high-noise (84.6% false positive rate in the PATHOS secrets benchmark); it is not in the default profile.
- The executive report (`GET /api/v1/executive`) failed with HTTP 500 once any open finding's risk score had decimals (the top applications and business units scanned `max(risk_score)` into an integer).

## [2.1.0] — 2026-11-19

Depth and trust: function-level reachability, verified AI fixes, live secret validation (off by default), runtime context and a sandbox for repository code. Migrations 00032–00035 are additive. With `worker-fuzz`, start the new `worker-fuzz-sandbox` service too (`docker compose --profile fuzz up -d`); without it the fuzzers are skipped with a reason.

### Added
- **Verified AI fixes** (migration 00033): **Propose fix** in the finding drawer of SAST, secrets and IaC findings asks the default AI configuration (any provider, including a self-hosted model) for a unified diff, built from the finding and the redacted code around it. PATHOS rejects diffs outside the finding's file (or two files next to it), over the size limits, or touching CI files, build scripts or dependency manifests unless the finding is in them. A worker applies the diff to a fresh checkout of the scanned commit and re-runs the finding's scanner on the changed files before and after: the finding must be gone and nothing new may appear. When an administrator chooses a test runner for the repository (`go` or `python`, off by default), worker-fuzz also runs the repository's tests without and with the fix in the sandbox runner. Only a verified fix can be opened as a pull request (`pathos/fix/ai-…`, fix pull request machinery), by a person; nothing is merged and the finding is resolved by a later scan. New permission `ai.fix` (security managers, analysts and AppSec engineers); requests are rate-limited and every request and decision is audited (`ai_fix.*`). API: [AI-proposed fixes](docs/api-reference/ai-and-mcp.md#ai-proposed-fixes); guide: [AI-proposed fixes](docs/user-guide/findings.md#ai-proposed-fixes).
- **Runtime context** (optional, off until an administrator adds a connection): a read-only **Kubernetes inventory** (service-account token or kubeconfig with inline credentials, stored encrypted; namespaces, Deployments, StatefulSets, DaemonSets, CronJobs, Jobs, Pods, their images and running digests, Services, Ingresses, NetworkPolicies and the pod security context) and a read-only **container registry inventory** (OCI distribution API: tags, digests, `org.opencontainers.image.source` and `revision` labels). Only the `jobs` service contacts clusters and registries, on a schedule or within a minute of **Sync now**; the API server never does. A minimal ClusterRole (`get`, `list`, `watch`, no Secrets or ConfigMaps) is in `deploy/kubernetes/pathos-reader-clusterrole.yaml`. Migration 00035.
- **Linking findings to what runs**: running digests are matched to image scan targets (exact digest, including the digests Trivy image scans now record; or the same tag when no digest is recorded) and to repositories (the target's repository, or the OCI source label of the registry image with the same digest). Workloads map to applications by namespace or label. Imported Falco, Tetragon and Tracee alerts are matched to the workload that owns the pod. Linked: 10 labelled image/target pairs give precision and recall 1.0 in the unit tests.
- **Runtime risk factors** with evidence (cluster, namespace, workload, image, Ingress host, alert): *Deployed* (× 1.1), *not deployed* (× 0.7, only when PATHOS knows the finding's image and a connected cluster was read in the last 7 days), *Internet-exposed in a cluster* (× 1.3, replaces the declared exposure), *Privileged workload* (× 1.15) and *Runtime alert seen* (× 1.3); configurable in the risk model. Risk factors carry an `evidence` list.
- **Runtime** page (Assets → Runtime): workloads with images, links, exposure, security context, alerts and open finding counts; clusters, registries (images and whether they run) and application mappings; empty states explain how to connect a cluster. The finding drawer shows **Where it runs**; the findings list has **Deployed** and **Internet-exposed** filters (`deployed`, `internet_exposed`) and a Runtime column; attack paths include paths observed in clusters (internet → Ingress host → workload → image → finding). API: `/api/v1/runtime/*` and `GET /api/v1/findings/{id}/runtime`.
- **Live secret validation** (off by default; migration 00034): an administrator enables providers in **Administration → Secret validation** (and adds their hosts to the egress allowlist); the worker then asks each detected credential's provider, with one read-only "who am I" request through the egress proxy, whether it is still active. Providers: AWS (STS GetCallerIdentity, SigV4), GitHub, GitLab (gitlab.com), Slack, Stripe, OpenAI, Anthropic, SendGrid, Twilio, npm, Google API keys (model list) and Azure Storage (Shared Key, service properties); PyPI tokens are recognized but not checkable. The secret never leaves the worker: only the verdict (`active`, `inactive`, `error`, `not_checked`), the request, the HTTP status and a non-secret identity are uploaded. Active secrets become critical (previous severity kept as evidence) with maximal risk likelihood; inactive ones restore the severity. Rate-limited (1–10 per second, 1–500 per scan), 10-second timeouts, no redirects, provider hosts only; a provider whose host the proxy refuses fails closed. Finding drawer panel with **Re-check** (queues a scan), a **Secret check** filter and column, `secret_validation` on findings, `GET`/`PUT /api/v1/settings/secret-validation`, `POST /api/v1/findings/{id}/secret-validation/recheck` and the worker upload `POST /internal/worker/v1/jobs/{id}/secret-validation`; settings changes, every validation batch and every re-check are audited. Checks are tested against local stand-ins of each provider and the AWS Signature Version 4 test vector, not against the live services ([Live secret validation](docs/user-guide/secret-validation.md)).
- **Function-level reachability of dependency vulnerabilities**: besides "does the code import the package?", PATHOS answers "does the code call the vulnerable function?" (reachable, not reachable or unknown) with evidence. Go uses govulncheck's call graph: the depth of each vulnerability (called, imported, required) and its call traces now set `reachability` on the findings of govulncheck and of other scanners for the same module and vulnerability. JavaScript/TypeScript, Python and Java use **pathos-reach**, a new offline worker-sca tool (`network: none`, reads source files only, standard-library Go): it follows imports, aliases, re-exports through the repository's modules, star and static imports and declared Java types, and records each call of a module member with its call site and a chain of callers; dynamic member access, dynamic imports, `getattr`, `eval`, Java reflection and Go `reflect` method lookups make the answer unknown, never "not reachable". It does not see inside dependencies; the docs say what that means.
- Vulnerable functions from OSV records (Go `ecosystem_specific.imports[].symbols`, RustSec `affects.functions`, `vulnerable_functions`/`affected_functions` lists) are stored with the vulnerability intelligence (`affected[].symbols`), from online lookups and offline imports alike; loading records re-decides the reachability of matching findings from stored data.
- Findings: `reachability_method` (`import`, `call_graph`, `symbol_calls`) and, in the finding detail, `reachability_evidence` (tool, scan, vulnerable functions checked, call paths as `file:line` chains, dynamic constructs, limits); list filters `reachability` and `reachability_method`; the finding drawer's **Reachability** section shows the call paths. Migration 00032 adds the columns and `repository_reach_reports`.
- Risk model: `function_reachability` weights (defaults reachable 1.3, unknown 1.0, not reachable 0.5) replace the package-level reachability weights when the answer is function level; the factor reads *Reachability (vulnerable function, call graph | calls in the code)*. Editable under **Risk & intelligence**.
- Reachability benchmark (`backend/internal/reach/bench_test.go`): a sample project per language with a called and an uncalled vulnerable function and a dynamic-dispatch or reflection case; all 12 cases are answered as expected (4 reachable, 4 not reachable, 4 unknown, no false "not reachable"). The npm, PyPI and Maven advisories in it carry hand-written function lists; the Go results are real govulncheck output.

### Changed
- **Security: repository code runs in a network-less sandbox runner.** The fuzzers of `worker-fuzz` (Go native fuzzing, Atheris) no longer run in the worker container, which is on the egress proxy and worker API networks and holds the worker token. The new `worker-fuzz-sandbox` service (same image, `pathos-worker sandbox-runner`) runs them. It has `network_mode: none`, UID 10002, its own PID and IPC namespaces, a read-only root filesystem, no capabilities, no token, and memory, CPU and pids limits (`PATHOS_FUZZ_MEMORY`, `PATHOS_FUZZ_CPUS`, `PATHOS_FUZZ_PIDS`). It shares only a tmpfs volume (`fuzz_sandbox`) with the worker. It kills every process of a run before reporting, and signs results with a one-time key. Manifests opt in with `sandbox: true`. Without a runner these tools are skipped and never run in the worker. `worker-fuzz` loses its CPU limit, its 512 pids limit and its executable `/work`, which only the fuzzers needed. `Sandbox.RunUntrusted` in the worker is the reusable entry point for running repository code ([ARCHITECTURE.md](docs/ARCHITECTURE.md#running-repository-code)). `workers/fuzz/test/sandbox-e2e.sh` tests the isolation in the built image with a malicious harness.

## [2.0.0] — 2026-11-19

PATHOS 2.0 covers 25 scan types with eight opt-in family worker images, tool manifests and 232 import formats from 207 tools. Upgrading from 1.x needs no configuration change: the family images are opt-in Compose profiles and migrations are additive. Behaviour change: Nuclei fuzzes API targets only when intrusive testing of the target is authorized.

### Added
- **25 scan types**: a scan-type registry (SAST, DAST, SCA, secrets, IaC, container, API security, IAST, mobile, fuzzing, licence, SBOM, malware, code-quality security, supply chain, cryptography, configuration, CI/CD pipeline, binary, AI/LLM, runtime, compliance, licence policy, database security, manual review), `GET /api/v1/scan-types` with the tools, import formats and online workers of each type, and a **Scan coverage** page under Configurations.
- New finding categories `api`, `iast`, `mobile`, `fuzz`, `crypto`, `cicd`, `ai`, `runtime`, `compliance`, `database` and `code-quality` (migration 00029), accepted in findings, Human Eye auto-queue settings, imports and plugins. ShellCheck findings use `code-quality`, mobsfscan `mobile`, Schemathesis `api`.
- **Tool manifests (v2)**: scan types, SPDX licence, family, targets (repository, image, url, api, mobile-app, binary, model), placeholders `{target_url}`, `{openapi}`, `{image}`, `{artifact}`, per-tool timeout, `network` and `intrusive` declarations, and the parsers `sarif`, `import:<format>` (the result import parsers) and `jsonmap` (a declarative JSON or JSON Lines mapping). Version 1 plugin files keep working.
- First-party manifests shipped read-only in family images (`/opt/pathos/tools.d`, up to 500); operator plugins stay in `PATHOS_SCANNER_PLUGINS_DIR` (up to 50, was 20). Workers advertise their manifests when they register; jobs that use manifest tools go to the workers that advertise them.
- The original output of manifest tools is stored with its parser, so findings can be located in it later.
- **worker-sast family image** (Compose profile `sast`): Bandit 1.9.4, njsscan 1.0.2 and ShellCheck 0.11.0, defined only by manifests; built in CI, scanned by the Trivy gate, published and signed by the release workflow.
- **SAST pack for the worker-sast image**: gosec 2.30.0, Flawfinder 2.0.20, cppcheck 2.19.0, PHPStan 2.3.6, Psalm 7.11.0 (taint analysis), Ruff 0.17.5 (S rules), ESLint 10.15.0 with eslint-plugin-security 4.2.1, Semgrep CE 1.172.0 (PATHOS rules only, optional), Bearer CLI 2.1.3 (Elastic-2.0, optional), TruffleHog 3.99.9 (verification off), detect-secrets 1.5.0, Kingfisher 2.19.1 (validation off), Talisman 1.37.0, Pylint 4.1.4 and golangci-lint 2.15.0 (security-relevant checks, `code-quality`), all offline, off by default and defined by manifests; fixtures are real output of each tool in the image. Brakeman (licence forbids redistribution), Sobelow, Horusec, DevSkim, Nosey Parker, Whispers and PMD are catalogued as not bundled (import their reports). The image grows from 2.22 GB to 3.37 GB and passes the Trivy gate.
- **Opengrep rule packs** `pathos-crypto`, `pathos-database`, `pathos-ai` and `pathos-cicd` (80 rules for Python, JavaScript/TypeScript, Java, Go, C#, GitLab CI, Azure Pipelines, Bitbucket Pipelines and Jenkinsfiles), each rule with positive and negative test cases; their findings use the `crypto`, `database`, `ai` and `cicd` categories.
- **worker-iac family image** (Compose profile `iac`): KICS 2.2.1, KubeLinter 0.8.3, Kubescape 4.0.21 (offline, frameworks bundled), TFLint 0.66.0 (bundled Terraform ruleset), Conftest 0.71.1 with a PATHOS policy bundle for Kubernetes, Dockerfiles and Terraform, Hadolint 2.15.1, cfn-lint 1.60.1, cfn_nag 0.8.10, Polaris 10.2.6 (security checks), kube-score 1.20.0 (security checks), Trivy 0.76.2 in config mode and OpenSSF Scorecard 5.7.0 in `--local` mode. All run offline and are defined by manifests; built in CI, scanned by the Trivy gate, published and signed by the release workflow. Terrascan (archived) and poutine (cannot be rebuilt without fixable CVEs) are not shipped; their reports can still be imported.
- **worker-sca family image** (Compose profile `sca`): govulncheck 1.10.0 (call-graph reachability), pip-audit 2.10.1, cargo-audit 0.23.0, bundler-audit 0.9.3 and Retire.js 6.1.1 (offline advisory snapshots), npm, yarn and pnpm audit, Composer audit 2.11.2, OWASP Dependency-Check 13.0.0 (NVD API key optional, off by default), GuardDog 3.2.0 (malicious-package heuristics), pathos-depcheck and cdxgen 12.9.2, defined by manifests and pinned by hash; off by default. Registry tools need their hosts enabled in the egress proxy (`deploy/egress/conf.d/sca-registries.conf.disabled`); optional settings go in `/etc/pathos/sca.env`. `dotnet list package --vulnerable` (runs MSBuild on repository files) and OWASP dep-scan (database too large) are not shipped.
- pathos-depcheck: an offline dependency-confusion and typosquatting check of `package.json`, `.npmrc`, `requirements*.txt` and `pyproject.toml`.
- cdxgen SBOMs feed the component inventory like Syft's: scan results of catalog tools of category `sbom` are stored as the SBOM and imported into the inventory, without finding parsing.
- kube-score JSON import format (`kube-score`): failed checks of each object, with security checks as iac findings and reliability checks as other.
- **worker-dast family image** (Compose profile `dast`) for authorized web application and API targets: OWASP ZAP 2.17.0 baseline scan, full scan and API scan (automation framework; add-on libraries netty, Jackson and Guava patched), Wapiti 3.3.2, Dalfox 3.3.0, ffuf 2.3.0 (small built-in wordlist), testssl.sh 3.2.5, SSLyze 6.3.1, Schemathesis 4.33.4 and Arjun 2.2.7, defined only by manifests; sqlmap 1.10.11 (detection only, `--risk=1 --level=1`) and Nikto 2.6.1 only in an opt-in build because of their licence terms. Every tool needs the target's authorization statement; all except the ZAP baseline scan, testssl.sh and SSLyze are intrusive and also need the intrusive testing flag. Tools run through a `dast-run` helper whose local proxy forwards only to the target host, through the egress proxy, at the target's rate limit. Target credentials are not passed to these tools. Built in CI, scanned by the Trivy gate, published and signed by the release workflow ([DAST tools](docs/user-guide/dast.md)).
- Manifest tools with `network: target` receive the target's rate limit in `PATHOS_TARGET_RATE_LIMIT`.
- **Intrusive testing authorization**: a per-target flag (who, when, reference; audited as `scan_target.intrusive_authorize` and `scan_target.intrusive_revoke`) required for intrusive tools in addition to the target's authorization statement; scan targets can select family and plugin tools (`config.tools`).
- **128 more result import formats (153 in total, from 145 tools)**, detected from the content or named explicitly:
  - SAST and code quality: Fortify FVDL/FPR, Veracode detailed XML, Coverity, AppScan Source, Klocwork, Horusec, Bearer, Brakeman, SpotBugs/FindSecBugs, PMD, Cppcheck, Flawfinder, PHPStan, Psalm, njsscan, mobsfscan, Sobelow, ShellCheck, Ruff, Pylint, golangci-lint, Codacy and SonarQube Cloud.
  - Secrets: detect-secrets, Kingfisher, Nosey Parker, ggshield, Whispers and Talisman. Secret values are removed before the report is stored.
  - SCA: Mend, Black Duck, JFrog Xray, Nexus IQ, Dependency-Track FPF, Dependabot alerts, Retire.js, yarn and pnpm audit, Composer audit, govulncheck (with call-path reachability), Safety, `dotnet list package --vulnerable`, bundler-audit, cargo-audit and dep-scan.
  - GitLab security reports (SAST, secret detection, dependency scanning, container scanning, DAST, coverage fuzzing) through one parser.
  - IaC and CI/CD: KICS, tfsec, Terrascan, KubeLinter, Kubescape, cfn-lint, cfn_nag, Hadolint, TFLint, Conftest, Polaris, kube-bench, poutine, Legitify and OpenSSF Scorecard.
  - Formats of commercial products, and a few that need an account or a deployed target, are built from the published format and marked as not yet verified against a real export.
  - DAST, API, infrastructure, TLS, cloud posture, container, mobile, IAST, runtime, AI/LLM, pentest and fuzzing tools: Nikto, Wapiti, Arachni, sqlmap, Dalfox, ffuf, Wfuzz, w3af, Schemathesis, RESTler, Acunetix, Invicti/Netsparker, AppSpider, Qualys WAS, InsightAppSec, HCL AppScan, Burp Suite DAST/Enterprise, StackHawk, 42Crunch, Nmap, Qualys VM, Tenable CSV, Nexpose, testssl.sh, SSLyze, sslscan, Wazuh, Prowler, ScoutSuite, AWS Security Hub (ASFF), Amazon Inspector, Defender for Cloud, Security Command Center, CloudSploit, Dockle, Clair, Harbor, Trivy Kubernetes, Anchore, Prisma Cloud/Twistlock, Sysdig, Docker Scout, MobSF, APKLeaks, NowSecure, Contrast Assess, Falco, Tetragon, Tracee, garak, promptfoo, ModelScan, HackerOne, Bugcrowd, Intigriti, ClusterFuzzLite and libFuzzer/Jazzer. Formats built only from published documentation are marked as not yet verified against a real export.
- **79 more result import formats (232 in total, from 207 tools; 62 tools are new)**, detected from the content or named explicitly:
  - Named SARIF formats: a SARIF log whose driver is a known tool is detected as that tool's format and imported under its own scanner key without a `tool` field (CodeQL, Semgrep, DevSkim, PSScriptAnalyzer, MSVC code analysis, Roslyn analyzers, SonarLint, Infer, Pysa, Mariana Trench, Clang Static Analyzer, ESLint, Brakeman, Fortify, Veracode Pipeline Scan, Mend SAST, Datadog Static Analyzer, detekt, PVS-Studio, BinSkim, Snyk IaC, KICS, tfsec, Checkov, ansible-lint, zizmor, Spectral, Grype, Trivy, OSV-Scanner, Gitleaks; Snyk Code, Docker Scout, NowSecure and ClusterFuzzLite too). Logs of unknown or several tools stay generic SARIF. One SARIF parser handles them all; Gitleaks SARIF snippets are removed before storage.
  - Compliance: OpenSCAP and CIS-CAT XCCDF/ARF results, Chef InSpec JSON, Lynis reports, AWS Config, Azure Policy, Qualys Policy Compliance and Steampipe/Powerpipe benchmarks (category `compliance`).
  - Cloud, CNAPP and EDR: Wiz, Orca Security, Lacework, Aqua, Snyk Container, Snyk IaC JSON, CrowdStrike Falcon Spotlight, Microsoft Defender Vulnerability Management, Qualys Container Security, Trivy Operator and Rapid7 InsightVM (API v4).
  - Commercial SAST, SCA, DAST and pentest services: Kiuwan (code and SCA), Checkmarx One, Checkmarx SCA, Veracode SCA agent, Fortify on Demand, HCL AppScan on Cloud, Tenable WAS, Detectify, Intruder, Probely, Edgescan, Pentest-Tools.com, Appknox and ImmuniWeb.
  - Open-source tools, tested with reports from real runs: kube-score, kubesec, kubeaudit, Datree, Cloud Custodian (c7n-left), Nuclei JSON export, TruffleHog 2, git-secrets, Arjun, Gixy, Regula, ssh-audit (category `crypto`), GuardDog (category `malware`) and Xeol (end-of-life, from its own test snapshot).
  - Formats built only from published documentation are marked as not yet verified against a real export.
- **worker-mobile, worker-binary, worker-ai and worker-fuzz family images** (Compose profiles `mobile`, `binary`, `ai`, `fuzz`; built in CI, scanned by the Trivy gate, published and signed by the release workflow), 12 new catalog tools defined only by manifests:
  - Mobile: mobsfscan 1.2.0 (on sources decompiled with jadx 1.5.7), APKLeaks 2.6.3, Quark-Engine 26.11.1 with PATHOS' own rules, and the PATHOS mobile app checks (androguard 4.1.4): Android debuggable, allowBackup, cleartext traffic, exported components without a permission, minSdkVersion, v1-only and debug signing; iOS App Transport Security exceptions, URL schemes, minimum iOS version and entitlements. Binary hardening (ELF, Mach-O) also runs on mobile packages.
  - Binary: CVE Binary Tool 3.4.1 (main-branch commit; offline, on a database the operator installs with `pathos-binary cve-db-update` or imports in air-gapped installations), capa 10.0.0 with capa-rules 10.0.0, YARA-X 1.23.0 with the ReversingLabs YARA rules (MIT) and a PATHOS rule. Rule directories for more Quark and YARA rules can be mounted.
  - AI: ModelScan 0.8.8 (repositories and model artifacts), garak 0.17.1 and promptfoo 0.126.0 (with a PATHOS red-team suite) for LLM endpoint targets; intrusive, tested against a local stub LLM server.
  - Fuzzing: Go native fuzzing (`go test -fuzz`, Go 1.27.4) and Atheris 3.1.0 run the repository's own fuzz harnesses, only when a profile selects them, without network access and under CPU, memory, file size and time limits; crashes are `fuzz` findings with the reproducer input (at most 4 KiB) kept in the report. Jazzer is catalogued but not shipped.
- **Mobile app targets** (`POST /api/v1/scan-targets/mobile-app`: APK, AAB or IPA, stored like build artifacts) and **LLM endpoint targets** (chat completions URL, model name, credential encrypted like other target credentials; authorization statement required, intrusive testing can be authorized). Migration 00031 adds both kinds. Manifests can target `llm-endpoint` and read the endpoint from `{llm_target}`, a file, so credentials never appear on a command line.
- **AI-BOM** (`ai-bom`, built into every worker, opt-in per profile): AI and ML frameworks, LLM SDKs, model files, Hugging Face model references, hosted model names and LLM APIs in a repository, recorded as SBOM components of type `framework`, `library`, `machine-learning-model` and `service` (component source `aibom`, kept when an SBOM scan replaces the other components).
- Imported HTTP evidence is redacted: `Authorization`, `Cookie`, `Set-Cookie` and other credential headers, credential-like parameters and tokens are removed from stored reports and findings.

### Changed
- **Security:** Nuclei sends its DAST templates (injection payloads) to API targets only when intrusive testing of the target is authorized; without it, API targets get the non-fuzzing exposure, misconfiguration and known-vulnerability checks used for URL targets.
- Import formats use the 2.0 finding categories. Default categories: Schemathesis, RESTler and 42Crunch `api`; MobSF, APKLeaks and NowSecure `mobile`; ClusterFuzzLite, libFuzzer and GitLab coverage fuzzing `fuzz` (GitLab `api_fuzzing` findings `api`); garak, promptfoo and ModelScan `ai` (ModelScan unsafe operators are titled "Possible malicious code in model"); Falco, Tetragon and Tracee `runtime`; Contrast Assess `iast`; Prowler, ScoutSuite, Defender for Cloud, CloudSploit and kube-bench `compliance`; poutine and Legitify `cicd`; OpenSSF Scorecard `supply-chain`; testssl.sh, SSLyze and sslscan `misconfiguration`; PHPStan and ShellCheck `code-quality`. AWS Security Hub (ASFF) and Security Command Center findings keep their own category (posture checks `compliance`, threat detections `runtime`, package vulnerabilities `sca` or `container`). The non-security rules of Psalm, Ruff, Pylint, golangci-lint, Codacy, SpotBugs, PMD, Cppcheck, Coverity, Klocwork, Polaris and SonarQube are `code-quality` (was `other`). Imports of these formats get new scanner keys (for example `import-ai-garak`, was `import-other-garak`); an import that names category `other` keeps the old key.
- The generic CSV format accepts every import category in its `category` column (was only the seven 1.x categories).
- `GET /api/v1/scan-types` lists the import formats of every scan type that has any: formats are matched on the type's first category (API security no longer lists every DAST format, CI/CD no longer every IaC format) plus the formats the type names, including the formats with per-finding categories (GitLab, Trivy Kubernetes, the SAST and code-quality linters), which are no longer listed as generic. Manual review lists the HackerOne, Bugcrowd and Intigriti exports; cryptography the TLS scanners.
- The catalog entries of PMD and PHPStan use the `code-quality` category (neither has security rules); Brakeman is catalogued as restricted (Brakeman Public Use License).
- Paths that tools report relative to their working directory (`../../work/<job>/src/…`, for example TFLint with `--chdir`) are normalised to repository paths.
- Import detection excludes Snyk Container and Snyk IaC reports from Snyk Open Source JSON and Xeol reports from Grype JSON (both have `matches`). Imported Grype, Trivy and OSV-Scanner SARIF logs get their package name and version from the message like native runs, so two packages with the same vulnerability are no longer one finding.
- Manifest tools with `network: none` run without the egress proxy variables.
- Scanner and import keys may be up to 60 characters (`plugin-code-quality-<name>`).
- PATHOS findings JSON is detected only when a document has no fields other than `tool` and `findings`, which its parser already required (reports of Kingfisher, Sobelow, poutine and Dependency-Track also have `findings`). npm audit detection no longer accepts pnpm audit reports.
- Import detection tries tool-specific formats before the generic CSV format, and `{"findings": [...]}` reports are taken as PATHOS findings JSON only when they have no other fields, so Amazon Inspector and Dalfox reports, which also have a `findings` array, are recognised.

### Fixed
- Reports of manifest tools parsed with an import parser are stored without their secret values, like imported reports; TruffleHog's `SecretParts` field is removed as well.

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
