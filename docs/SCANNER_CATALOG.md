# Scanner Catalog

The licensing and maintenance review behind the scanner catalog. The catalog itself is code: `backend/internal/scanners/catalog.go`, synced into `scanner_catalog` by every `migrate`. Each entry was verified again when its adapter was built: licence text, commercial-use terms, release cadence and output formats. "Repo status" was read from the GitHub API on 2026-11-15; entries marked *unverified* were not checked because of an API rate limit.

## Implemented

These run in the `worker-core` image today, pinned by version and SHA-256 (or built from their checksum-verified Go module):

| Tool | Runs on | Output |
|---|---|---|
| Gitleaks (mandatory in every profile) | Repositories | SARIF, secrets redacted |
| Opengrep | Repositories (PATHOS baseline rules, mounted rule sets, custom rules) | SARIF |
| Trivy (filesystem) | Repositories, build artifacts | SARIF |
| Syft | Repositories (SBOM utility for Grype and the inventory) | CycloneDX |
| Grype | Repositories (on the Syft SBOM), SBOM targets | JSON |
| OSV-Scanner | Repositories | SARIF |
| Checkov | Repositories (including Bitbucket Pipelines) | SARIF |
| zizmor | Repositories with GitHub Actions workflows | SARIF |
| actionlint | Repositories with GitHub Actions workflows | JSON |
| Trivy (image) | Container image targets | SARIF |
| Nuclei | Web application and API targets (reviewed template subset) | JSONL |
| File licences (`licensecheck`, built in) | Repositories | PATHOS JSON |
| Binary hardening (`binary-hardening`, built in) | Build artifacts; repositories when a profile selects it | PATHOS JSON |
| ClamAV (`clamav`, client of the optional clamd service) | Repositories when a profile selects it and `PATHOS_CLAMAV_ADDRESS` is set | PATHOS JSON |

The opt-in `worker-sast` family image adds 18 tools defined only by [tool manifests](#adding-a-tool-tool-manifests) (`workers/sast/tools.d`): Bandit, njsscan and ShellCheck, and the [SAST pack](#sast-pack-worker-sast) (gosec, Flawfinder, cppcheck, PHPStan, Psalm, Ruff, ESLint with eslint-plugin-security, Semgrep CE, Bearer CLI, TruffleHog, detect-secrets, Kingfisher, Talisman, Pylint and golangci-lint).

| Tool | Runs on | Output (parser) |
|---|---|---|
| Bandit 1.9.4 | Repositories (Python) | Bandit JSON (`import:bandit`, the result import parser) |
| njsscan 1.0.2 | Repositories (Node.js) | SARIF |
| ShellCheck 0.11.0 | Repositories (shell scripts; findings in the `code-quality` category) | json1 (`jsonmap`) |

The opt-in `worker-iac` family image (Compose profile `iac`) adds twelve infrastructure-as-code and CI/CD tools, defined by manifests in `workers/iac/tools.d`. All of them run offline (`network: none`), never build or execute repository code, and are off by default (selected in scan profiles):

| Tool | Runs on | Output (parser) |
|---|---|---|
| KICS 2.2.1 | Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles, Ansible, OpenAPI and more, with the queries of the release | KICS JSON (`import:kics`) |
| KubeLinter 0.8.3 | Kubernetes YAML and Helm charts | KubeLinter JSON (`import:kube-linter`) |
| Kubescape 4.0.21 | Kubernetes manifests, Helm charts, Kustomize; frameworks bundled in the image (`--use-artifacts-from`), no update check, results never submitted | Kubescape JSON (`import:kubescape`) |
| TFLint 0.66.0 | Terraform, bundled Terraform ruleset (`recommended` preset); the image's configuration replaces a repository's `.tflint.hcl`, so no plugin is downloaded | TFLint JSON (`import:tflint`) |
| Conftest 0.71.1 | Kubernetes manifests, Dockerfiles and Terraform, with the PATHOS policy bundle (`workers/iac/policy`, ids `PATHOS-K8S-*`, `PATHOS-DOCKER-*`, `PATHOS-TF-*`; its Rego unit tests run when the image is built) | Conftest JSON (`import:conftest`) |
| Hadolint 2.15.1 | Dockerfiles and Containerfiles | Hadolint JSON (`import:hadolint`) |
| cfn-lint 1.60.1 | CloudFormation templates | cfn-lint JSON (`import:cfn-lint`) |
| cfn_nag 0.8.10 | CloudFormation templates | cfn_nag JSON (`import:cfn-nag`) |
| Polaris 10.2.6 | Kubernetes manifests (`polaris audit --audit-path`), security checks of Polaris' default configuration only | Polaris JSON (`import:polaris`; no file or line in Polaris' output) |
| kube-score 1.20.0 | Kubernetes manifests, the checks with security impact (security context, image tag and pull policy, resources, network policies, NodePort services, seccomp) | kube-score JSON (`import:kube-score`, new) |
| Trivy 0.76.2, config mode (`trivy-config`) | Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles, with the checks embedded in the core image's Trivy binary (`--skip-check-update`); the core `trivy-fs` scanner runs Trivy for vulnerabilities only | SARIF |
| OpenSSF Scorecard 5.7.0 (`--local`) | The checks that read only the checkout: Binary-Artifacts, Dangerous-Workflow, Dependency-Update-Tool, License, Packaging, Pinned-Dependencies, SAST, Security-Policy, Token-Permissions (findings in `supply-chain`; also listed under CI/CD) | Scorecard JSON (`import:scorecard`) |

Tools that take file names only run through small helpers in `workers/iac/bin` (`hadolint-tree`, `cfn-lint-tree`, `cfn-nag-tree`, `kube-score-tree`, `conftest-tree`) that find the relevant files (Dockerfiles; CloudFormation templates, recognised by `AWSTemplateFormatVersion` or `AWS::` resource types; Kubernetes YAML with `apiVersion` and `kind`, Helm templates excluded) and print one JSON report. Not shipped: **Terrascan** (archived by Tenable in 2025-11; its last release needs dependencies with fixable HIGH and CRITICAL CVEs, so it cannot pass the image gate) and **poutine** 1.1.6 (it requires go-git and go-billy v6 pre-releases with fixable HIGH CVEs, and the fixed versions change the API poutine uses, so it cannot be rebuilt). Reports of both can still be imported (`terrascan`, `poutine` import formats). The Go tools are built from source with Go 1.27.4; KubeLinter, Conftest, kube-score and Polaris with patched dependency versions (listed in `workers/iac/Dockerfile`).

The opt-in `worker-sca` family image (Compose profile `sca`) adds language-specific dependency auditors, malicious-package and dependency-confusion checks and an SBOM generator, each a tool manifest in `workers/sca/tools.d` run by the image's `pathos-sca` helper. The helper finds the files each tool reads, runs the tool on each, combines the reports, and keeps the tools from running repository code: no package-manager plugins, scripts or version switching, and cdxgen runs under the Node.js permission model without child processes. All tools are off by default; a scan profile selects them.

| Tool | Version | Licence | Network | Runs on (parser) |
|---|---|---|---|---|
| govulncheck | 1.10.0 | BSD-3-Clause | registry: proxy.golang.org, sum.golang.org, vuln.go.dev | Every `go.mod`, with call-graph reachability (Go 1.27.4 toolchain in the image, no cgo) (`import:govulncheck`); the depth of each vulnerability (called, imported, required) also sets the findings' function-level reachability |
| pip-audit | 2.10.1 | Apache-2.0 | registry: pypi.org | The pinned requirements of every `requirements*.txt`, one run per file; pip is not run (`import:pip-audit`) |
| cargo-audit | 0.23.0 | Apache-2.0 OR MIT | none | Every `Cargo.lock`, against the RustSec advisory database snapshot in the image (`import:cargo-audit`) |
| bundler-audit | 0.9.3 | GPL-3.0-or-later | none | Every `Gemfile.lock`, against the Ruby advisory database snapshot in the image (`import:bundler-audit`) |
| Retire.js | 6.1.1 | Apache-2.0 | none | JavaScript files, against the Retire.js repository snapshot in the image (`import:retire-js`) |
| npm audit | npm 12.2.3 | Artistic-2.0 | registry: registry.npmjs.org | Every `package-lock.json` or `npm-shrinkwrap.json` (`import:npm-audit`) |
| yarn audit | 1.22.22 | BSD-2-Clause | registry: registry.npmjs.org | Every `yarn.lock` of Yarn 1 (Yarn 2+ lockfiles are skipped) (`import:yarn-audit`) |
| pnpm audit | 11.28.12 | MIT | registry: registry.npmjs.org | Every `pnpm-lock.yaml` (`import:pnpm-audit`) |
| Composer audit | 2.11.2 | MIT | registry: packagist.org, repo.packagist.org | Every `composer.lock`, plugins and scripts off (`import:composer-audit`) |
| OWASP Dependency-Check | 13.0.0 | Apache-2.0 | registry: nvd.nist.gov (data feeds) or services.nvd.nist.gov (with an NVD API key) | NVD data kept in the worker cache; analyzers that run package managers or call other services are off; the API key is optional and off by default (`import:dependency-check`) |
| GuardDog | 3.2.0 | Apache-2.0 | registry: pypi.org, files.pythonhosted.org, registry.npmjs.org | Malware heuristics on the dependencies declared in `requirements*.txt` and `package.json` (downloaded and analysed statically, never installed); findings in `malware`, `capability-*` rules reported as low (SARIF) |
| pathos-depcheck | 1.0.0 (PATHOS) | Apache-2.0 | none | Typosquatting (one edit from the 1000 most popular npm or PyPI names), pip `--extra-index-url` and npm scopes not mapped to a private registry, in `package.json`, `.npmrc`, `requirements*.txt` and `pyproject.toml`; findings in `supply-chain` (`jsonmap`) |
| cdxgen | 12.9.2 | Apache-2.0 | none | CycloneDX 1.6 SBOM (with `--include-crypto`) from manifests and lockfiles; it replaces the repository's component inventory like Syft and produces no findings |
| pathos-reach | 1.0.0 (PATHOS) | Apache-2.0 | none | Function-level reachability: calls of external module members in the repository's JavaScript/TypeScript, Python and Java code with call sites and caller chains, untyped method calls and dynamic constructs; Go packages that call methods through `reflect`. Reads source files only. Its report is stored as reachability evidence and produces no findings ([function-level reachability](api-reference/vulnerability-intelligence.md#function-level-reachability)) |

**Reachability analysis.** For Go, govulncheck already analyses the call graph. For JavaScript/TypeScript, Python and Java the call-graph tools considered were not used: Jelly (BSD-3-Clause, JavaScript/TypeScript) was not integrated in this release (it would be a second analysis to map onto advisories, and needs Node.js with a larger memory budget; a candidate for later), PyCG (Python) is archived, and the Java call-graph libraries (Soot/SootUp, WALA, OPAL) analyse compiled classes, which would mean building repository code. pathos-reach is PATHOS' own conservative analysis instead: imports and calls of the advisory's vulnerable functions through aliases, re-exports and declared types, with "unknown" for anything dynamic. It does not see inside dependencies. Its accuracy on the PATHOS benchmark (one reachable, one unreachable and one dynamic case per language) is tested in `backend/internal/reach/bench_test.go`.

Not shipped: `dotnet list package --vulnerable` (it needs the .NET SDK, about 700 MB, and an MSBuild restore, which evaluates the repository's project files, that is repository code; OSV-Scanner and Trivy in `worker-core` cover NuGet lockfiles) and OWASP dep-scan (its smallest vulnerability database is 395 MB compressed, too large to bundle; dep-scan reports can be imported with the `dep-scan` format). npm, yarn, pnpm and Composer audit and pip-audit run once per lockfile or requirements file found outside `node_modules`, `vendor` and the other skipped directories, and each finding is located in its file (for example `services/web/package-lock.json`): the helper stores the reports in a PATHOS envelope, `{"pathos_reports": [{"file": …, "report": …}]}`, which the import parsers read. govulncheck runs once per Go module, and its findings are located in that module's `go.mod`. A run that fails (an exit status other than the tool's "vulnerabilities found", or no valid report) fails the tool, with the file and the tool's error as the tool's error message; the reports of the other runs are kept with the raw output, but no findings are recorded for a failed tool. The advisory snapshots of cargo-audit, bundler-audit and Retire.js are as recent as the image. The registry hosts are not in the default egress allowlist: `deploy/egress/conf.d/sca-registries.conf.disabled` lists them for the operator to enable ([OPERATIONS.md](OPERATIONS.md#family-worker-images)).

The opt-in `worker-dast` family image (Compose profile `dast`) adds tools for authorized **web application (`url`) and API (`api`) scan targets**, also defined only by manifests (`workers/dast/tools.d`). Every one contacts the target (`network: target`: the target needs an authorization statement); the intrusive ones also need the target's intrusive testing flag. They run through the image's `dast-run` helper, which confines them to the target host, the egress proxy and the target's rate limit ([DAST tools](user-guide/dast.md)). They are never part of a repository scan profile.

| Tool (catalog key) | Runs on | Intrusive | Findings | Output (parser) |
|---|---|---|---|---|
| OWASP ZAP 2.17.0 baseline scan (`zap-baseline`) | URL and API targets | no | dast | ZAP traditional JSON (`import:zap`) |
| OWASP ZAP 2.17.0 full scan (`zap`) | URL and API targets | **yes** | dast | `import:zap` |
| OWASP ZAP 2.17.0 API scan (`zap-api-scan`) | API targets (OpenAPI document) | **yes** | api | `import:zap` |
| Wapiti 3.3.2 (`wapiti`) | URL and API targets | **yes** | dast | Wapiti JSON (`import:wapiti`) |
| Dalfox 3.3.0 (`dalfox`) | URL and API targets | **yes** | dast | Dalfox JSON (`import:dalfox`) |
| ffuf 2.3.0 (`ffuf`) | URL and API targets | **yes** | dast | ffuf JSON (`import:ffuf`) |
| testssl.sh 3.2.5 (`testssl`) | https URL and API targets | no | misconfiguration | testssl.sh JSON (`import:testssl`) |
| SSLyze 6.3.1 (`sslyze`) | https URL and API targets | no | misconfiguration | SSLyze JSON (`import:sslyze`) |
| Schemathesis 4.33.4 (`schemathesis`) | API targets (OpenAPI document) | **yes** | api | Schemathesis JSON report (`import:schemathesis`) |
| Arjun 2.2.7 (`arjun`) | URL and API targets | **yes** | dast | Arjun JSON, turned into one record per parameter by `dast-run` (`jsonmap`) |
| sqlmap 1.10.11 (`sqlmap`), opt-in build | URL and API targets | **yes** | database | sqlmap results CSV (`import:sqlmap`) |
| Nikto 2.6.1 (`nikto`), opt-in build | URL and API targets | **yes** | dast | Nikto JSON (`import:nikto`) |

- **ZAP** is the official 2.17.0 core release with a reviewed set of add-ons at their current versions for 2.17 (`workers/dast/build/zap-addons.txt`; no browser-based, telemetry-only or desktop add-ons). Those add-ons bundle netty, Jackson and Guava versions with fixed HIGH/CRITICAL CVEs; the image replaces them at build time with netty 4.1.141.Final, Jackson 2.22.4 and Guava 33.7.2-jre (`workers/dast/build/patch-zap-addons.py`, jars SHA-256 pinned). ZAP runs on Debian's OpenJDK 21 (headless). It uses the automation framework; the plan is written by `dast-run` (context limited to the target host, ZAP's own rate limit rule, no out-of-band callback service).
- **sqlmap** and **Nikto** are in the image only when it is built with `WITH_SQLMAP=true` or `WITH_NIKTO=true` (Compose: `PATHOS_DAST_WITH_SQLMAP`, `PATHOS_DAST_WITH_NIKTO`). sqlmap's licence (GPL-2.0-or-later with the authors' interpretation) treats software that runs sqlmap and parses its results as a derived work; Nikto's test databases may be distributed only with the full Nikto package and used only with Nikto. Their catalog decision is *restricted*. sqlmap runs in batch mode with `--risk=1 --level=1` (detection only: never `--dump`, file, OS or SQL shell options).
- **Nuclei** DAST templates for APIs are already run by `worker-core` for API targets (all 251 templates of the `dast` directory), so the pack does not add them again.
- Target credentials are **not** passed to these tools (their reports can contain request headers, and raw reports are stored as they are): they scan as an anonymous visitor.

Four more opt-in family images (`worker-mobile`, `worker-binary`, `worker-ai`, `worker-fuzz`) add 12 tools (and the built-in AI-BOM); they are listed in [Family images: mobile, binary, AI and fuzzing](#family-images-mobile-binary-ai-and-fuzzing).

Opengrep runs PATHOS' own Apache-2.0 baseline rules; the community `opengrep-rules` pack carries a Commons Clause restriction and is not bundled. All other catalogue entries have no adapter yet: they can be selected only once a worker provides them, for example as a [declarative plugin](#adding-a-tool-tool-manifests). Versions are listed in [DEPENDENCIES.md](DEPENDENCIES.md#scanners-in-worker-core).

Opengrep also runs the PATHOS framework configuration rules (`workers/rules/pathos-misconfig-*.yml`: Spring Boot, Django, Express), whose findings use the `misconfiguration` category. The rule packs for cryptography, database security, AI/LLM applications and non-GitHub CI/CD pipelines (`workers/rules/pathos-{crypto,database,ai,cicd}.yml`, [below](#opengrep-rule-packs)) use the `crypto`, `database`, `ai` and `cicd` categories. Each rule has a message, CWE, severity and references; the fixtures in `workers/rules-tests/` are run with `scripts/test-opengrep-rules.py`.

**Built-in scanners.** `licensecheck` and `binary-hardening` are part of the worker binary (pure Go: [google/licensecheck](https://github.com/google/licensecheck), BSD-3-Clause, and the Go standard library's `debug/elf`, `debug/pe` and `debug/macho`), so they add no binary to the image. ScanCode Toolkit was evaluated for file-level licences and not adopted: it is a large Python application with its own data set that would roughly double the worker image and its scan times, while licensecheck covers SPDX tags and licence texts in-process. The `clamav` scanner is a client of the ClamAV service (GPL-2.0, optional `clamav` Compose profile, not part of the PATHOS images); it streams repository files to clamd over a dedicated internal network ([OPERATIONS.md](OPERATIONS.md#malware-scanning-clamav)). The same service also scans uploaded source archives and build artifacts before PATHOS accepts them.

Legend: **Use** = include in catalog. **Opt** = optional / restricted. **Excl** = excluded (reason given). Build = requires building the target code (no adapter; see [ARCHITECTURE.md §5](ARCHITECTURE.md#5-scanner-execution-and-isolation)).

## Scanners

| # | Tool | Category | License | Repo status | Decision | Notes |
|---|---|---|---|---|---|---|
| 1 | Gitleaks | Secrets | MIT | active | **Use, mandatory** | **Implemented** |
| 2 | TruffleHog | Secrets | AGPL-3.0 | active | Use | Run unmodified as a separate process; verification mode off by default (it calls third-party APIs) |
| 3 | detect-secrets | Secrets | Apache-2.0 | active (last push 2026-04) | Use | |
| 4 | Kingfisher | Secrets | Apache-2.0 (*unverified*) | *unverified* | Use (verify) | |
| 5 | Opengrep | SAST | LGPL-2.1 | active | **Use (default Semgrep-compatible engine)** | **Implemented**. Rule licensing: ARCHITECTURE D5 |
| 6 | Semgrep CE | SAST | LGPL-2.1 | active | Opt | Registry rules restricted |
| 7 | CodeQL | SAST | GitHub CodeQL Terms | active | **Opt, license-restricted** | Free only for OSS/research. Build for compiled languages |
| 8 | Bandit | SAST (Python) | Apache-2.0 | active | Use | **Implemented** (`worker-sast` manifest) |
| 9 | Gosec | SAST (Go) | Apache-2.0 | active | Use | |
| 10 | Brakeman | SAST (Ruby) | custom (NOASSERTION) | active | Opt (verify license) | License has changed historically |
| 11 | SpotBugs + FindSecBugs | SAST (JVM) | LGPL-2.1 / LGPL-3.0 | active | Opt (Build) | Needs compiled bytecode |
| 12 | PMD | SAST/quality (JVM, Apex…) | BSD-style (NOASSERTION) | active | Use | Source-level, no build |
| 13 | Flawfinder | SAST (C/C++) | GPL-2.0 | maintained (2026-05) | Use | |
| 14 | cppcheck | SAST (C/C++) | GPL-3.0 | active (repo moved) | Use | |
| 15 | Infer | SAST (Java/C/ObjC) | MIT | active (repo moved) | Opt (Build) | |
| 16 | Pysa (Pyre) | SAST taint (Python) | MIT | active (repo moved) | Opt | Heavy; needs type stubs |
| 17 | Psalm | SAST (PHP) | MIT | active | Use | Taint mode |
| 18 | PHPStan | Static analysis (PHP) | MIT | active | Use | |
| 19 | Ruff | Lint incl. `S` (bandit) rules | MIT | active | Use | |
| 20 | ESLint + eslint-plugin-security | SAST (JS/TS) | MIT / Apache-2.0 | active | Use | |
| 21 | njsscan | SAST (Node) | LGPL-3.0-or-later (package metadata of 1.0.2) | active | Use | **Implemented** (`worker-sast` manifest; runs Semgrep CE 1.172.0, LGPL-2.1-or-later, through libsast, LGPL-3.0-or-later) |
| 22 | mobsfscan | SAST (Android/iOS) | LGPL-3.0 (*unverified*) | *unverified* | Use (verify) | |
| 23 | Sobelow | SAST (Elixir/Phoenix) | Apache-2.0 (*unverified*) | *unverified* | Use (verify) | |
| 24 | ShellCheck | Shell script analysis | GPL-3.0 | active | Use | |
| 25 | Trivy (fs) | SCA + secrets + misconfig + license | Apache-2.0 | active | Use | **Implemented** |
| 26 | Grype | SCA | Apache-2.0 | active | Use | **Implemented**; consumes the Syft SBOM |
| 27 | OSV-Scanner | SCA | Apache-2.0 | active | Use | **Implemented** |
| 28 | OWASP Dependency-Check | SCA (JVM/.NET) | Apache-2.0 | original repo archived 2025-09 | Use (verify new home) | Needs NVD API key for good performance |
| 29 | Retire.js | SCA (JS) | Apache-2.0 | active | Use | |
| 30 | govulncheck | SCA, reachability (Go) | BSD-3 | active | Use | |
| 31 | pip-audit | SCA (Python) | Apache-2.0 | active | Use | |
| 32 | cargo-audit (RustSec) | SCA (Rust) | Apache-2.0/MIT | active | Use | |
| 33 | bundler-audit | SCA (Ruby) | GPL-3.0 | active | Use | |
| 34 | OWASP dep-scan | SCA + reachability | MIT | active | Use | |
| 35 | Checkov | IaC | Apache-2.0 | active | Use | **Implemented** |
| 36 | KICS | IaC | Apache-2.0 | active | Use | **Implemented** (`worker-iac` manifest) |
| 37 | KubeLinter | K8s manifests | Apache-2.0 | active | Use | **Implemented** (`worker-iac` manifest) |
| 38 | Kubescape | K8s posture (manifests/Helm) | Apache-2.0 | active | Use | **Implemented** (`worker-iac` manifest, offline frameworks) |
| 39 | TFLint | Terraform | MPL-2.0 | active | Use | **Implemented** (`worker-iac` manifest, bundled Terraform ruleset) |
| 40 | Conftest | Policy-as-code (OPA) | Apache-2.0 | active | Use | **Implemented** (`worker-iac` manifest, PATHOS policy bundle) |
| 41 | Hadolint | Dockerfile | GPL-3.0 | active | Use | **Implemented** (`worker-iac` manifest) |
| 42 | Dockle | Container image | Apache-2.0 | active (2026-08) | Use | Image targets |
| 43 | Trivy (image) | Container image vulns | Apache-2.0 | active | Use | **Implemented** (image targets) |
| 44 | actionlint | CI/CD (GitHub Actions) | MIT | active (1.7.12, 2026-03-30) | Use | **Implemented**: built from source; runs on `.github/workflows` without shellcheck or pyflakes, so no repository script is run |
| 45 | zizmor | CI/CD security (GitHub Actions) | MIT | *unverified* | Use | **Implemented**; runs offline |
| 46 | OpenSSF Scorecard | Supply-chain posture | Apache-2.0 | active | Use | **Implemented** (`worker-iac` manifest, `--local` file-based checks only; the SCM API checks are not run) |
| 47 | ScanCode Toolkit | License compliance | Apache-2.0 + CC-BY (data) | active | Use | Replaces FOSSology for repo scanning |
| 48 | Trivy (license) | License compliance | Apache-2.0 | active | Use | |
| 48a | File licences (licensecheck) | License compliance (file level) | BSD-3-Clause (library) | active | Use | **Implemented** (built into the worker); violations of the licence policy become findings |
| 48b | ClamAV (repository content) | Malware | GPL-2.0 (separate service) | active | Use | **Implemented** (opt-in; needs the clamd service) |
| 48c | Binary hardening (checksec-style) | Binary analysis | Apache-2.0 (PATHOS) | n/a | Use | **Implemented** (built into the worker; ELF, PE, Mach-O) |
| 49 | OWASP ZAP | DAST | Apache-2.0 | active | Use (target URL, not repo) | **Implemented** (`worker-dast` manifests: baseline `zap-baseline`, full scan `zap`, API scan `zap-api-scan`) |
| 50 | Nuclei | DAST / templated checks | MIT | active | Use (target URL) | **Implemented** (URL and API targets) |
| 51 | Schemathesis | API fuzzing (OpenAPI) | MIT | active | Use (target URL) | **Implemented** (`worker-dast` manifest, API targets, intrusive) |
| 52 | kube-bench | K8s CIS (cluster) | Apache-2.0 (*unverified*) | *unverified* | Opt | Cluster target, not repo |

Count: **98 catalogued scanner integrations**, 81 of which a PATHOS worker image runs (worker-core and the family images); the others are optional, licence-restricted or bring-your-own, and their reports can be imported. The family packs add their entries in `backend/internal/scanners/catalog_<family>.go`. Built-in checks (endpoint verification, cosign, endoflife.date, the AI-BOM) and the supporting utilities below come on top. Separately, [result imports](api-reference/result-imports.md) read 232 report formats from 207 tools. Licence policy evaluation (`license-policy` in a finding's *Detected by*) runs on the server against the SBOM inventory; it is a finding source, not a catalogued scanner.

## Supporting utilities (not counted as scanners)

| Tool | Role | License | Status |
|---|---|---|---|
| Syft | SBOM generation | Apache-2.0 | active |
| cdxgen (OWASP) | SBOM generation (CycloneDX) | Apache-2.0 | active (repo moved) |
| CycloneDX CLI | SBOM conversion/validation/merge | Apache-2.0 | active |
| SPDX tools-python | SPDX validation/conversion | Apache-2.0 | maintained (2026-03) |
| Cosign | Signature verification | Apache-2.0 | active; **shipped** in worker-core (catalog key `cosign`): signature and in-toto attestation verification of image and artifact targets |
| in-toto | Attestation verification | Apache-2.0 | active |
| slsa-verifier | SLSA provenance verification | Apache-2.0 | active |
| GUAC | Supply-chain graph (integration, later) | Apache-2.0 | active |

## Built-in checks (not counted as scanners)

The scanner catalog also lists three entries that are not third-party scanner integrations; they exist so their results and findings have a catalog key:

| Key | What it is |
|---|---|
| `pathos-endpoints` | Verification of a repository's declared public endpoints, built into the worker agent (DNS, reachability, TLS, HSTS and security headers); runs only for `endpoints` targets |
| Live secret validation | Built into the worker agent, not a scanner: after the secret scanners ran (their own verification stays off), checks each detected credential against its provider's read-only "who am I" endpoint; off by default, enabled per provider ([Live secret validation](user-guide/secret-validation.md)) |
| `cosign` | The Sigstore cosign utility above, run for image and artifact targets with a signature verification policy |
| `endoflife` | End-of-life findings from the endoflife.date intelligence feed; not run by a worker |

`GET /api/v1/scanners` returns the 52 integrations, Syft and these three entries.

## Import-only integrations (2.0)

These tools are integrated through their own report format: the report is produced outside PATHOS (in CI, or by a commercial product) and uploaded with `POST /api/v1/imports/results` or `pathos import` ([Result imports](api-reference/result-imports.md#supported-formats)). PATHOS does not ship or run them, so their licences place no condition on PATHOS; commercial tools are never required. "Real report" means the import was tested with a report produced by running the tool; "published format" means it was built from the vendor's schema or documentation and is not yet verified against a real export.

| Tool | Format ID | Kind | Licence (SPDX) | Fixture |
|---|---|---|---|---|
| Fortify SCA | `fortify` | SAST | commercial | published format |
| Veracode | `veracode` | SAST, DAST, SCA | commercial (service) | published format |
| Coverity | `coverity` | SAST | commercial | published format |
| HCL AppScan Source | `appscan-source` | SAST | commercial | published format |
| Klocwork | `klocwork` | SAST | commercial | published format |
| Horusec | `horusec` | SAST, secrets | Apache-2.0 | real report |
| Bearer CLI | `bearer` | SAST | Elastic-2.0 | real report |
| Brakeman | `brakeman` | SAST (Ruby) | NOASSERTION (Brakeman Public Use Licence) | real report |
| SpotBugs + FindSecBugs | `spotbugs` | SAST (JVM) | LGPL-2.1 / LGPL-3.0 | real report |
| PMD | `pmd` | SAST, code quality | BSD-4-Clause-style (NOASSERTION) | real report |
| Cppcheck | `cppcheck` | SAST (C/C++) | GPL-3.0 | real report |
| Flawfinder | `flawfinder` | SAST (C/C++) | GPL-2.0 | real report |
| PHPStan | `phpstan` | code quality (PHP) | MIT | real report |
| Psalm | `psalm` | SAST taint (PHP) | MIT | real report |
| njsscan | `njsscan` | SAST (Node.js) | LGPL-3.0 | real report |
| mobsfscan | `mobsfscan` | SAST (mobile) | LGPL-3.0 | real report |
| Sobelow | `sobelow` | SAST (Phoenix) | Apache-2.0 | real report |
| ShellCheck | `shellcheck` | code quality (shell) | GPL-3.0 | real report |
| Ruff | `ruff` | SAST (S rules), code quality | MIT | real report |
| Pylint | `pylint` | code quality | GPL-2.0 | real report |
| golangci-lint | `golangci-lint` | SAST (gosec), code quality | GPL-3.0 | real report |
| Codacy Analysis CLI | `codacy` | SAST, code quality | AGPL-3.0 | real report |
| SonarQube Cloud | `sonarcloud` | SAST, code quality | commercial (service) | published format |
| detect-secrets | `detect-secrets` | Secrets | Apache-2.0 | real report |
| Kingfisher | `kingfisher` | Secrets | Apache-2.0 | real report |
| Nosey Parker | `noseyparker` | Secrets | Apache-2.0 | real report |
| GitGuardian ggshield | `ggshield` | Secrets | MIT (CLI; needs the GitGuardian service) | published format |
| Whispers | `whispers` | Secrets | Apache-2.0 (archived) | real report |
| Talisman | `talisman` | Secrets | MIT | real report |
| Mend (WhiteSource) | `mend` | SCA | commercial | published format |
| Black Duck | `blackduck` | SCA | commercial | published format |
| JFrog Xray | `jfrog-xray` | SCA | commercial | published format |
| Sonatype Nexus IQ | `nexus-iq` | SCA, licence | commercial | published format |
| Dependency-Track | `dependency-track` | SCA | Apache-2.0 | published format |
| GitHub Dependabot alerts | `dependabot` | SCA | GitHub service | published format |
| Retire.js | `retire-js` | SCA (JS) | Apache-2.0 | real report |
| yarn audit | `yarn-audit` | SCA (JS) | BSD-2-Clause | real report |
| pnpm audit | `pnpm-audit` | SCA (JS) | MIT | real report |
| Composer audit | `composer-audit` | SCA (PHP) | MIT | real report |
| govulncheck | `govulncheck` | SCA with reachability (Go) | BSD-3-Clause | real report |
| Safety | `safety` | SCA (Python) | MIT (CLI; database terms apply) | real report |
| dotnet list package | `dotnet-vulnerable` | SCA (.NET) | MIT | real report |
| bundler-audit | `bundler-audit` | SCA (Ruby) | GPL-3.0 | real report |
| cargo-audit | `cargo-audit` | SCA (Rust) | Apache-2.0 OR MIT | real report |
| OWASP dep-scan | `dep-scan` | SCA | MIT | published format |
| GitLab security analyzers | `gl-sast`, `gl-secret-detection`, `gl-dependency-scanning`, `gl-container-scanning`, `gl-dast`, `gl-coverage-fuzzing`, `gitlab` | SAST, secrets, SCA, container, DAST, fuzzing | GitLab (Ultimate feature) | real report (SAST, secrets, dependency, container); published format (DAST, coverage fuzzing) |
| KICS | `kics` | IaC | Apache-2.0 | real report |
| tfsec | `tfsec` | IaC (Terraform) | MIT | real report |
| Terrascan | `terrascan` | IaC | Apache-2.0 (archived) | real report |
| KubeLinter | `kube-linter` | IaC (Kubernetes) | Apache-2.0 | real report |
| Kubescape | `kubescape` | IaC (Kubernetes) | Apache-2.0 | real report |
| cfn-lint | `cfn-lint` | IaC (CloudFormation) | MIT-0 | real report |
| cfn_nag | `cfn-nag` | IaC (CloudFormation) | MIT | real report |
| Hadolint | `hadolint` | IaC (Dockerfile) | GPL-3.0 | real report |
| TFLint | `tflint` | IaC (Terraform) | MPL-2.0 | real report |
| Conftest | `conftest` | Policy as code | Apache-2.0 | real report |
| Polaris | `polaris` | IaC (Kubernetes) | Apache-2.0 | real report |
| kube-bench | `kube-bench` | Kubernetes CIS (cluster) | Apache-2.0 | real report |
| poutine | `poutine` | CI/CD pipelines | Apache-2.0 | real report |
| Legitify | `legitify` | SCM / CI/CD posture | Apache-2.0 | published format |
| OpenSSF Scorecard | `scorecard` | Supply-chain posture | Apache-2.0 | real report |

DeepSource has no documented report export and is not importable. Whispers and Terrascan stay excluded as scanners (archived) but their existing reports can be imported.

## SAST pack (worker-sast)

PATHOS 2.0 adds these tools to the `worker-sast` image. Each is pinned and verified (Go checksum database, `pip --require-hashes`, `npm ci` integrity hashes, or the SHA-256 of a release or source archive), runs offline (`network: none`), is off by default and has a manifest in `workers/sast/tools.d`. Go tools are built with Go 1.27.4; dependencies with fixable HIGH/CRITICAL CVEs are replaced (see [DEPENDENCIES.md](DEPENDENCIES.md#scanners-in-family-worker-images)). The image passes the Trivy gate (0 fixable HIGH/CRITICAL). Its size grows from 2.22 GB to 3.37 GB (uncompressed): the Go toolchain that gosec and golangci-lint need to load packages, Node.js for ESLint, PHP for PHPStan and Psalm, and the Go binaries of TruffleHog, Bearer and gosec are the largest parts.

| Tool (catalog key) | Version | Licence (SPDX) | Category | How it runs | Parser |
|---|---|---|---|---|---|
| gosec (`gosec`) | 2.30.0 | Apache-2.0 | sast | `gosec-tree`: every Go package, with the image's Go toolchain; `GOPROXY=off`, so modules that are not vendored are reported as type-check errors, not downloaded | `import:gosec` |
| Flawfinder (`flawfinder`) | 2.0.20 | GPL-2.0-or-later | sast | C/C++, risk level 1 and above | `import:flawfinder` |
| cppcheck (`cppcheck`) | 2.19.0 | GPL-3.0-or-later | sast | C/C++, `--enable=warning,portability --inconclusive`; one memory leak reported on several return paths is one finding | `import:cppcheck` |
| PHPStan (`phpstan`) | 2.3.6 | MIT | code-quality | Level 5, the image's configuration (a repository's `phpstan.neon` can load extensions); PHPStan has no security rules | `import:phpstan` |
| Psalm (`psalm`) | 7.11.0 | MIT | sast | `psalm-taint`: taint analysis with a generated configuration (a repository's `psalm.xml` can load plugins) | `import:psalm` |
| Ruff (`ruff`) | 0.17.5 | MIT | sast | flake8-bandit rules (`S`) only, `--isolated` (the repository's configuration cannot deselect rules) | `import:ruff` |
| ESLint + eslint-plugin-security (`eslint-security`) | 10.15.0 + 4.2.1 | MIT AND Apache-2.0 | sast | `eslint-tree`: the plugin's recommended rules on JavaScript and TypeScript, the image's configuration only, `--no-inline-config` | `import:eslint` |
| Semgrep CE (`semgrep-ce`) | 1.172.0 | LGPL-2.1-or-later | sast | The PATHOS rules of the core image (`/opt/pathos/rules`) only; no Semgrep Registry rules; metrics and version check off. Optional: Opengrep already runs the same rules | SARIF |
| Bearer CLI (`bearer`) | 2.1.3 | Elastic-2.0 | sast | Bundled rules (Bearer/bearer-rules 0.48.4, Elastic-2.0) as an external rule directory; rule download and version check off. **Optional**: the Elastic License 2.0 is source-available, not open source | `import:bearer` |
| TruffleHog (`trufflehog`) | 3.99.9 | AGPL-3.0-only | secrets | Filesystem mode, **verification off** (`--no-verification`), no update check; run unmodified as a separate process | `import:trufflehog` |
| detect-secrets (`detect-secrets`) | 1.5.0 | Apache-2.0 | secrets | Every file (`--all-files`); no plugin verifies secrets online | `import:detect-secrets` |
| Kingfisher (`kingfisher`) | 2.19.1 | Apache-2.0 | secrets | Current files, **validation off** (`--no-validate`), no update check | `import:kingfisher` |
| Talisman (`talisman`) | 1.37.0 | MIT | secrets | `talisman-tree`: the current files, committed to a throwaway Git repository in the job's temporary directory; Talisman reports files, not lines | `import:talisman` |
| Pylint (`pylint`) | 4.1.4 | GPL-2.0-or-later | code-quality | Security-relevant checks only (eval/exec, dangerous defaults, bare except, lost exceptions, missing timeouts, unclosed resources, subprocess and environment misuse, deprecated modules); the image's `pylintrc` | `import:pylint` |
| golangci-lint (`golangci-lint`) | 2.15.0 | GPL-3.0-only | code-quality | `golangci-lint-tree`: gosec, errcheck, bodyclose, noctx, rowserrcheck, sqlclosecheck, govet, staticcheck, errorlint and nilerr in every Go module, the image's configuration (a repository's `.golangci.yml` can load plugins) | `import:golangci-lint` |

Secret values: reports parsed with an import parser are stored like imported reports, with the secret values removed (TruffleHog `Raw`, `RawV2`, `Redacted` and `SecretParts`; Kingfisher snippets; detect-secrets hashes; Talisman's quoted values). The fixtures in `backend/internal/worker/testdata/manifests` are real output of each manifest command in the image (`docker run --network none`) on `testdata/manifests/sample-pack`, whose credentials are fake.

Evaluated and not bundled:

| Tool | Reason | Instead |
|---|---|---|
| Brakeman | The Brakeman Public Use License forbids distributing it as part of a product and commercial use without a licence (catalogued as restricted) | Import its JSON report (`brakeman`) |
| Sobelow | Needs an Erlang/OTP and Elixir runtime (the `elixir:1.18-slim` image is 477 MB) for one Phoenix-only tool; last release v0.13.0 (2023-08) | Import its JSON report (`sobelow`) |
| Horusec | No release since v2.8.0 (2022-06); it runs its analysers as Docker containers | Import its JSON report (`horusec`) |
| DevSkim | Needs the .NET runtime, which no PATHOS image has yet (candidate for a .NET family image) | Import its SARIF report |
| Nosey Parker | Repository archived; last release v0.24.0 (2025-05) | Import its JSON report (`noseyparker`) |
| Whispers | Repository archived; last release 1.5.3 (2021) | Import its JSON report (`whispers`) |
| PMD | Needs a Java runtime; belongs in a JVM family image (catalogued as `code-quality`, family `jvm`) | Import its XML report (`pmd`) |

### Opengrep rule packs

Four rule packs written for PATHOS (Apache-2.0) run in Opengrep with the baseline rules (worker-core image, `/opt/pathos/rules`), and in Semgrep CE when a profile selects it. Their findings use their own finding categories (rule ids `pathos.<pack>.*`; an administrator's rule with metadata category `crypto`, `database`, `ai` or `cicd` is recorded the same way). Every rule has a CWE, references, a positive and a negative test case in `workers/rules-tests/<pack>/` (`scripts/test-opengrep-rules.py`); cases the baseline rules already report are not repeated.

| Pack (category) | Languages | Rules |
|---|---|---|
| `pathos-crypto.yml` (`crypto`) | Python, JavaScript/TypeScript, Java, Go, C# | Weak hashes (MD5, SHA-1, MD4) and ciphers (DES, 3DES, RC4, RC2, Blowfish), ECB mode, constant IVs and nonces, RSA keys under 2048 bits, non-cryptographic random numbers for tokens, passwords, keys, salts and nonces, disabled TLS certificate or host name verification and TLS 1.0/1.1, hard-coded encryption, MAC and token-signing keys |
| `pathos-database.yml` (`database`) | Python, JavaScript/TypeScript, Java, Go, C#, YAML | SQL built by concatenation or formatting (DB-API, mysql/pg/Sequelize/knex/TypeORM, JDBC Statement, JPA, JdbcTemplate, ADO.NET, EF Core; in Go, request data concatenated into database/sql calls), Django `raw`/`extra`/`RawSQL`, SQLAlchemy `text`, Sequelize `literal`, GORM `Raw`/`Where`/`Order`, NoSQL injection (request objects in MongoDB queries, `$where`), connection strings with plaintext passwords or TLS disabled |
| `pathos-ai.yml` (`ai`) | Python, JavaScript/TypeScript | Non-constant system prompts and instructions (prompt-injection sinks), model and tool-call output reaching eval/exec, shell commands or SQL (taint), unsafe model loading (torch.load without `weights_only=True`, joblib, dill, cloudpickle, `read_pickle`, `numpy.load(allow_pickle=True)`, Keras `safe_mode=False`), `trust_remote_code=True` without a pinned revision, LLM API keys in code |
| `pathos-cicd.yml` (`cicd`) | GitLab CI, Azure Pipelines, Bitbucket Pipelines (YAML), Jenkinsfile (text) | Script injection from commit, branch, merge-request and parameter values (GitLab and Bitbucket variables in eval, `sh -c` or unquoted; Azure `$(...)` macros; Groovy interpolation into `sh`), `curl | sh`, unpinned images, includes, components, template repositories, pipes and shared libraries, secrets echoed to the log, privileged Docker, the Docker socket and Docker-in-Docker without TLS |

## Import-only integrations: SARIF producers, compliance, cloud and commercial services (2.0 wave B)

These tools are integrated through their report format ([Result imports](api-reference/result-imports.md#formats-added-in-20-wave-b)); PATHOS does not ship or run them, so their licences place no condition on PATHOS, and commercial tools are never required. SARIF logs of these tools are detected by the SARIF driver name and imported under the tool's own scanner key. Licences are listed as published by each project (not re-checked against the repositories for this change). "Real run" means the test report was produced by running the pinned tool version against a small local sample; "published format" means the format was built from the published format and is not yet verified against a real export. Where a tool already had an import format (Semgrep, ESLint, Brakeman, Fortify, Veracode, Mend, KICS, tfsec, Checkov, zizmor, Grype, Trivy, OSV-Scanner, Gitleaks, Nuclei, TruffleHog), the new format shares its tool name and scanner key.

| Tool | Format ID | Kind | Licence (SPDX) | Test report |
|---|---|---|---|---|
| CodeQL | `codeql` | SAST | LicenseRef-CodeQL-Terms (GitHub CodeQL Terms and Conditions; free for open-source code) | published format |
| Semgrep (SARIF) | `sarif-semgrep` | SAST | LGPL-2.1 (Semgrep CE) | real run |
| Microsoft DevSkim | `devskim` | SAST | MIT | real run |
| PSScriptAnalyzer | `psscriptanalyzer` | Code quality (PowerShell) | MIT | real run |
| MSVC code analysis (/analyze) | `msvc-analyze` | SAST (C/C++) | Proprietary (Visual Studio) | published format |
| Roslyn analyzers (NetAnalyzers) | `roslyn` | Code quality, security rules (.NET) | MIT | real run |
| SonarLint / SonarQube for IDE | `sonarlint` | Code quality | LGPL-3.0 | published format |
| Infer | `infer` | SAST (C, C++, Java, Objective-C) | MIT | real run |
| Pysa (via SAPP) | `pysa` | SAST taint (Python) | MIT | published format |
| Mariana Trench (via SAPP) | `mariana-trench` | Mobile taint (Android) | MIT | published format |
| Clang Static Analyzer | `clang-analyzer` | SAST (C/C++) | Apache-2.0 WITH LLVM-exception | real run |
| ESLint (SARIF) | `sarif-eslint` | SAST (JavaScript) | MIT | real run |
| Brakeman (SARIF) | `sarif-brakeman` | SAST (Ruby) | NOASSERTION (Brakeman Public Use Licence) | real run |
| Fortify (SARIF) | `sarif-fortify` | SAST | Commercial | published format |
| Veracode Pipeline Scan (SARIF) | `sarif-veracode` | SAST | Commercial (service) | published format |
| Mend SAST (SARIF) | `sarif-mend-sast` | SAST | Commercial | published format |
| Datadog Static Analyzer | `datadog-sast` | SAST | Apache-2.0 | real run |
| detekt | `detekt` | Code quality (Kotlin) | Apache-2.0 | real run |
| PVS-Studio | `pvs-studio` | SAST (C, C++, C#, Java) | Commercial | published format |
| BinSkim | `binskim` | Binary hardening | MIT | published format |
| Snyk IaC | `snyk-iac`, `sarif-snyk-iac` | IaC | Commercial (service; CLI Apache-2.0) | published format |
| KICS (SARIF) | `sarif-kics` | IaC | Apache-2.0 | real run |
| tfsec (SARIF) | `sarif-tfsec` | IaC (Terraform) | MIT | real run |
| Checkov (SARIF) | `sarif-checkov` | IaC | Apache-2.0 | real run |
| ansible-lint | `ansible-lint` | IaC (Ansible) | GPL-3.0-or-later | real run |
| zizmor (SARIF) | `sarif-zizmor` | CI/CD (GitHub Actions) | MIT | real run |
| Spectral | `spectral` | API definitions (OpenAPI, AsyncAPI) | Apache-2.0 | real run |
| Grype (SARIF) | `sarif-grype` | SCA, container | Apache-2.0 | real run |
| Trivy (SARIF) | `sarif-trivy` | SCA, IaC, container | Apache-2.0 | real run |
| OSV-Scanner (SARIF) | `sarif-osv-scanner` | SCA | Apache-2.0 | real run |
| Gitleaks (SARIF) | `sarif-gitleaks` | Secrets | MIT | real run |
| OpenSCAP | `openscap` | Compliance (SCAP / XCCDF) | LGPL-2.1-or-later | real run |
| CIS-CAT Pro Assessor | `cis-cat` | Compliance (CIS benchmarks) | Commercial (CIS SecureSuite) | published format |
| Chef InSpec | `inspec` | Compliance | Apache-2.0 (InSpec 5; later versions are under the Chef EULA) | real run |
| Lynis | `lynis` | Compliance, host hardening | GPL-3.0 | real run |
| AWS Config | `aws-config` | Compliance (cloud) | Cloud service | published format |
| Azure Policy | `azure-policy` | Compliance (cloud) | Cloud service | published format |
| Qualys Policy Compliance | `qualys-pc` | Compliance | Commercial | published format |
| Steampipe / Powerpipe | `steampipe` | Compliance (cloud benchmarks) | AGPL-3.0 (Steampipe CLI), Apache-2.0 (mods) | published format (needs a cloud account) |
| Wiz | `wiz` | CNAPP (issues, vulnerabilities) | Commercial | published format |
| Orca Security | `orca` | CNAPP (alerts) | Commercial | published format |
| Lacework | `lacework` | CNAPP (container and host vulnerabilities) | Commercial | published format |
| Aqua Security | `aqua` | Container image | Commercial | published format |
| Snyk Container | `snyk-container` | Container image | Commercial (service; CLI Apache-2.0) | published format |
| CrowdStrike Falcon Spotlight | `crowdstrike-spotlight` | EDR vulnerability management | Commercial | published format |
| Microsoft Defender Vulnerability Management | `defender-vm` | EDR vulnerability management | Commercial | published format |
| Qualys Container Security | `qualys-cs` | Container image | Commercial | published format |
| Tenable Web App Scanning | `tenable-was` | DAST | Commercial | published format |
| Rapid7 InsightVM (API v4) | `insightvm` | Network / host vulnerabilities | Commercial | published format |
| Kiuwan | `kiuwan`, `kiuwan-sca` | SAST, code quality, SCA | Commercial | published format |
| Checkmarx One | `checkmarx-one` | SAST, SCA, IaC | Commercial | published format |
| Checkmarx SCA | `checkmarx-sca` | SCA | Commercial | published format |
| Veracode SCA (agent) | `srcclr` | SCA | Commercial | published format |
| Fortify on Demand | `fod` | SAST, DAST, SCA, mobile | Commercial (service) | published format |
| HCL AppScan on Cloud | `appscan-cloud` | SAST, DAST, IAST, SCA | Commercial (service) | published format |
| Detectify | `detectify` | DAST | Commercial (service) | published format |
| Intruder | `intruder` | Network / web vulnerabilities | Commercial (service) | published format |
| Probely | `probely` | DAST | Commercial (service) | published format |
| Edgescan | `edgescan` | DAST, network | Commercial (service) | published format |
| Pentest-Tools.com | `pentest-tools` | DAST, network | Commercial (service) | published format |
| Appknox | `appknox` | Mobile | Commercial (service) | published format |
| ImmuniWeb | `immuniweb` | DAST | Commercial (service) | published format |
| Trivy Operator | `trivy-operator` | Kubernetes (images, configuration) | Apache-2.0 | published format (needs a cluster) |
| Xeol | `xeol` | End-of-life software | Apache-2.0 | Xeol's own presenter test snapshot (its database server no longer resolves) |
| kube-score | `kube-score` | IaC (Kubernetes) | MIT | real run |
| kubesec | `kubesec` | IaC (Kubernetes) | Apache-2.0 | real run |
| kubeaudit | `kubeaudit` | IaC (Kubernetes) | MIT | real run |
| Datree | `datree` | IaC (Kubernetes) | Apache-2.0 (archived) | real run |
| Cloud Custodian (c7n-left) | `cloud-custodian` | IaC policy | Apache-2.0 | real run |
| Nuclei (JSON export) | `nuclei-json` | DAST | MIT | real run |
| TruffleHog 2 (legacy) | `trufflehog-v2` | Secrets | GPL (version not stated in the package metadata); unmaintained | real run |
| git-secrets | `git-secrets` | Secrets | Apache-2.0 | real run |
| Arjun | `arjun` | DAST (parameter discovery) | AGPL-3.0 (PyPI metadata also says GPL-3.0) | real run |
| Gixy / gixy-ng | `gixy` | Configuration (nginx) | MPL-2.0 | real run |
| Regula | `regula` | IaC | Apache-2.0 (archived) | real run |
| ssh-audit | `ssh-audit` | Cryptography (SSH configuration) | MIT | real run |
| GuardDog | `guarddog` | Malicious packages | Apache-2.0 | real run |

Not added: Kube-hunter (deprecated); Syft (an SBOM generator: its CycloneDX and SPDX output is imported as an SBOM); the Trivy SBOM scan (`trivy sbom --format json`), OSV-Scanner JSON, Semgrep JSON and Grype JSON, which were already supported.

## Excluded

| Tool | Reason |
|---|---|
| Whispers | Archived (2023) |
| Dredd | Archived (2024). It is also contract testing, not security |
| Terrascan | Archived (2025-11) |
| Tern | No commits since 2024-03 |
| Clair | Registry-integrated server, not a repo scanner. May come back as an integration |
| FOSSology | Full server platform. ScanCode covers repo license scanning |
| tfsec | Merged into Trivy |

## Scan types

PATHOS reports on 25 scan types, grouped for display into the 20 [kinds of check](#kinds-of-check-pathos-30-m6). The registry is code (`backend/internal/scanners/scantypes.go`): each type has an id, a name, the finding categories its findings are recorded under and the catalog tools that cover it. `GET /api/v1/scan-types` ([API](api-reference/scan-types-and-tools.md)) and the **Scan coverage** page add what a deployment provides: the tools an online worker can run, and the import formats.

| Scan type (id) | Finding categories | Tools in the catalog |
|---|---|---|
| SAST (`sast`) | sast | Opengrep, Bandit, njsscan, gosec, Psalm, Bearer, Semgrep CE, CodeQL, … |
| DAST (`dast`) | dast | Nuclei, OWASP ZAP (full, baseline, API), PATHOS endpoint verification, Wapiti, Dalfox, ffuf, Arjun, sqlmap, Nikto |
| SCA (`sca`) | sca, eol | Trivy, Grype, OSV-Scanner, Dependency-Check, govulncheck, pip-audit, cargo-audit, bundler-audit, Retire.js, npm/yarn/pnpm audit, Composer audit, …, endoflife.date |
| Secrets (`secrets`) | secrets | Gitleaks, TruffleHog, detect-secrets, Kingfisher, Talisman |
| IaC (`iac`) | iac | Checkov, KICS, KubeLinter, Kubescape, TFLint, Conftest, Hadolint, cfn-lint, cfn_nag, Polaris, kube-score, Trivy (config) |
| Container (`container`) | container | Trivy (image), Dockle |
| API security (`api`) | api, dast | Nuclei (API targets), Schemathesis, OWASP ZAP API scan |
| IAST (`iast`) | iast | (imports only) |
| Mobile (`mobile`) | mobile | mobsfscan, APKLeaks, Quark-Engine, mobile app checks |
| Fuzzing (`fuzzing`) | fuzz | ffuf, Schemathesis (their findings are recorded as dast and api), Go native fuzzing, Atheris, Jazzer (not shipped) |
| Licence (`license`) | license | licensecheck, ScanCode, Trivy (license) |
| SBOM (`sbom`) | (inventory, no findings) | Syft, cdxgen, AI-BOM |
| Malware (`malware`) | malware | ClamAV, GuardDog, YARA-X, capa, Quark-Engine |
| Code-quality security (`code-quality`) | code-quality | ShellCheck, Pylint, golangci-lint, PHPStan, PMD, Ruff |
| Supply chain (`supply-chain`) | supply-chain | cosign, OpenSSF Scorecard, GuardDog, pathos-depcheck |
| Cryptography (`crypto`) | crypto | Opengrep (PATHOS cryptography rules), testssl.sh, SSLyze (their findings are recorded as misconfiguration) |
| Configuration (`configuration`) | misconfiguration | Opengrep (framework configuration rules), testssl.sh, SSLyze, Nikto |
| CI/CD pipeline (`cicd`) | cicd, iac | zizmor, actionlint (their findings are recorded as iac), Opengrep (PATHOS GitLab CI, Azure Pipelines, Bitbucket and Jenkins rules) |
| Binary (`binary`) | binary | Binary hardening, CVE Binary Tool (its findings are recorded as sca), capa, YARA-X |
| AI / LLM (`ai`) | ai | Opengrep (PATHOS AI/LLM rules), ModelScan, garak, promptfoo, AI-BOM |
| Runtime (`runtime`) | runtime | (imports and plugins) |
| Compliance (`compliance`) | compliance | kube-bench |
| Licence policy (`license-policy`) | license | Licence policy (evaluated by the server) |
| Database security (`database`) | database | Opengrep (PATHOS database rules), sqlmap (opt-in build) |
| Manual review (`manual`) | any | PATHOS findings JSON, CSV and SARIF imports, HackerOne, Bugcrowd and Intigriti exports, Human Eye reviews |


The finding categories added for these types are `api`, `iast`, `mobile`, `fuzz`, `crypto`, `cicd`, `ai`, `runtime`, `compliance`, `database` and `code-quality` (migration 00029). Configuration findings keep `misconfiguration`.

Import formats are listed under a scan type when their default category is the type's first category, or when the type names them (`ImportFormats` in `scantypes.go`) because their findings keep their own categories. For example API security lists Schemathesis, RESTler and 42Crunch (`api`) and also Nuclei, ZAP, Burp and StackHawk (recorded as `dast`); code-quality security lists PHPStan and ShellCheck (`code-quality`) and the linters and SAST tools whose non-security rules are `code-quality` (Psalm, Ruff, Pylint, golangci-lint, Codacy, SpotBugs, PMD, Cppcheck, Coverity, Klocwork, Polaris); cryptography lists the TLS scanners, whose findings are recorded as `misconfiguration`; compliance and runtime list AWS Security Hub and Security Command Center (posture checks `compliance`, threat detections `runtime`); manual review lists the HackerOne, Bugcrowd and Intigriti exports. Licence, SBOM, malware, binary, licence policy and database security have no specific import format; the generic formats (SARIF, PATHOS findings JSON, CSV) apply to every type.

## Kinds of check (PATHOS 3.0 M6)

The build prompt (§7) groups security testing into **20 kinds of check of about 10 tools each**. PATHOS keeps its 25 scan types (decision C8): a kind of check is a display grouping of scan types, defined with the scan-type registry in `backend/internal/scanners/scantypes.go` (`CheckKinds`) and served by `GET /api/v1/scan-types` (`kinds`). Every scan type belongs to exactly one kind; AI / LLM and manual review stay outside the 20 kinds and are shown under their own names. Outside Configurations › Scan profiles, Configurations › Scanners & workers and Import results, the UI shows the kind of check and "confirmed by N engines" instead of tool names (rule 3, decision C5; see [Findings](user-guide/findings.md)).

"Catalogued" counts the §7 tools that are in the scanner catalog; a catalogued tool is runnable when a shipped worker image or manifest runs it and a worker advertising it is online. **No tool was added in this milestone**: the tools on the gap list arrive as worker-pack pull requests, each with its licence evidence re-checked.

| Kind of check | Phase | Scan types | §7 tools in the catalog (N of 10) | Other catalogued tools of its scan types | Gap list |
|---|---|---|---|---|---|
| Discovery & CodeGraph | 3 | — | 1 of 10: Syft | — | 9 |
| SBOM | 3 | `sbom` | 2 of 10: Syft, cdxgen | AI-BOM (AI frameworks, models and LLM APIs) | 8 |
| Threat modelling | 4 | — | 0 of 10: PATHOS STRIDE engine (PATHOS), PATHOS attack paths & blast radius (PATHOS) | — | 8 |
| Reverse engineering | 5 | — | 0 of 10: — | — | 10 |
| SAST: deep engines | 6 | `sast`, `configuration`, `crypto` | 9 of 10: Opengrep, Semgrep CE, CodeQL, Infer, Pysa, SpotBugs + FindSecBugs, PMD, cppcheck, Flawfinder | Bandit, gosec, Brakeman, Psalm (taint analysis), PHPStan, Ruff (S rules), ESLint + eslint-plugin-security, njsscan, Sobelow, Bearer CLI, Horusec, DevSkim, testssl.sh, SSLyze, Nikto | 1 |
| SAST: language checks | 6 | `code-quality` | 10 of 10: Bandit, Gosec, Brakeman, Psalm, PHPStan, Ruff (S rules), ESLint + security plugin, njsscan, Sobelow, ShellCheck | PMD, Pylint (security-relevant checks), golangci-lint (security linters) | 0 |
| Secrets | 6 | `secrets` | 5 of 10: Gitleaks, TruffleHog, detect-secrets, Kingfisher, Talisman | APKLeaks, Nosey Parker, Whispers | 5 |
| Dependency check | 6 | `sca` | 10 of 10: Trivy (filesystem), OSV-Scanner, Grype, OWASP Dependency-Check, govulncheck, pip-audit, Retire.js, cargo-audit, bundler-audit, OWASP dep-scan | endoflife.date, CVE Binary Tool, PATHOS function-level reachability (pathos-reach), npm audit, yarn audit, pnpm audit, Composer audit | 0 |
| CVE & vulnerability intelligence | 7 | — | 1 of 10: endoflife.date; OSV.dev (feed), CISA KEV (feed), FIRST EPSS (feed) | — | 6 |
| Infrastructure as code | 6 | `iac` | 10 of 10: Checkov, KICS, Trivy (config), TFLint, Conftest, Hadolint, KubeLinter, kube-score, cfn-lint, cfn-nag | Kubescape, Polaris | 0 |
| Cloud & Kubernetes posture | 6 | `compliance`, `runtime` | 3 of 10: Kubescape, kube-bench, Polaris | — | 7 |
| CI/CD pipelines | 6 | `cicd` | 3 of 10: actionlint, zizmor, OpenSSF Scorecard (CI checks) | Opengrep | 7 |
| Container images | 6 | `container` | 6 of 10: Trivy (image), Grype, Syft, cosign, Dockle, Hadolint | — | 4 |
| Licence compliance | 6 | `license`, `license-policy` | 3 of 10: licensecheck (built in), ScanCode Toolkit, Trivy (licence) | — | 7 |
| Supply chain & integrity | 6 | `supply-chain` | 3 of 10: cosign, OpenSSF Scorecard, GuardDog; deps.dev (feed) | PATHOS dependency confusion and typosquatting check | 6 |
| Malware | 6 | `malware` | 4 of 10: ClamAV, YARA-X, capa, GuardDog | Quark-Engine | 6 |
| Binary security | 6 | `binary` | 3 of 10: checksec-style checks (built in), Grype, capa | CVE Binary Tool, YARA-X | 7 |
| Mobile apps | 6 | `mobile` | 3 of 10: mobsfscan, APKLeaks, Quark-Engine | Mobile app configuration checks | 7 |
| Web app & API testing | 6 | `dast`, `api`, `iast`, `database` | 7 of 10: Nuclei, OWASP ZAP, Schemathesis, testssl.sh, Wapiti, Nikto, ffuf | PATHOS endpoint verification, OWASP ZAP baseline scan, OWASP ZAP API scan, Dalfox, sqlmap, Arjun, Opengrep | 3 |
| Fuzz testing (after 2.0) | 6 | `fuzzing` | 3 of 10: Go native fuzzing, Atheris, Jazzer | ffuf, Schemathesis | 7 |

Outside the 20 kinds: **AI / LLM** (`ai`: ModelScan, garak, promptfoo, AI-BOM (AI frameworks, models and LLM APIs), Opengrep) and **Manual review** (`manual`, imports and Human Eye). "(feed)" marks vulnerability intelligence feeds the server already reads; "(PATHOS)" marks PATHOS engines (the attack paths and blast radius views exist; the STRIDE engine is planned for M5).

### Gap list

The §7 tools PATHOS does not have yet. Licence and maintenance status were read on **2026-11-20** from each project's official repository (GitHub REST API `license.spdx_id`, `archived`, latest release and default-branch commit) or official page; the evidence column links what was read. Maintenance: *active* = a commit or release within 12 months, *slow* = 12–24 months, *unmaintained* = over 24 months or archived. Anything that could not be confirmed is marked **unverified**. Where the API gives an old SPDX form (GPL-2.0, GPL-3.0, LGPL-3.0, AGPL-3.0) the -only/-or-later variant was not checked. "Import" names an existing PATHOS import format for the tool's reports.

A tool listed under several kinds (Joern, Jadx, binwalk, Frida, Tracee) has one row, under its first kind. Modes of catalogued tools (for example Trivy's SBOM output) are listed separately below.

| Kind | Tool | Licence (SPDX) | Licence evidence | Latest release | Maintenance | Import | Notes |
|---|---|---|---|---|---|---|---|
| Discovery & CodeGraph | [tree-sitter](https://github.com/tree-sitter/tree-sitter) | MIT | [source](https://api.github.com/repos/tree-sitter/tree-sitter) | v0.27.2, 2026-11-07 | active | — |  |
| Discovery & CodeGraph | [Joern](https://github.com/joernio/joern) | Apache-2.0 | [source](https://api.github.com/repos/joernio/joern) | v4.0.687, 2026-11-19 | active | — | also listed under SAST deep (taint) and reverse engineering |
| Discovery & CodeGraph | [go-enry](https://github.com/go-enry/go-enry) | Apache-2.0 | [source](https://api.github.com/repos/go-enry/go-enry) | v2.9.6, 2026-04-04 | active | — |  |
| Discovery & CodeGraph | [scc](https://github.com/boyter/scc) | MIT | [source](https://api.github.com/repos/boyter/scc) | v4.1.0, 2026-09-07 | active | — |  |
| Discovery & CodeGraph | [Microsoft Application Inspector](https://github.com/microsoft/ApplicationInspector) | MIT | [source](https://api.github.com/repos/microsoft/ApplicationInspector) | v1.10.5, 2026-11-13 | active | — |  |
| Discovery & CodeGraph | [Universal Ctags](https://github.com/universal-ctags/ctags) | GPL-2.0 (-only/-or-later unverified) | [source](https://api.github.com/repos/universal-ctags/ctags) | v6.2.1, 2025-10-25 | active | — |  |
| Discovery & CodeGraph | [dependency-cruiser](https://github.com/sverweij/dependency-cruiser) | MIT | [source](https://api.github.com/repos/sverweij/dependency-cruiser) | v18.8.0, 2026-11-16 | active | — |  |
| Discovery & CodeGraph | [kin-openapi](https://github.com/getkin/kin-openapi) | MIT | [source](https://api.github.com/repos/getkin/kin-openapi) | v0.153.0, 2026-11-07 | active | — |  |
| SBOM | [Microsoft sbom-tool](https://github.com/microsoft/sbom-tool) | MIT | [source](https://api.github.com/repos/microsoft/sbom-tool) | v4.1.5, 2025-12-15 | active | — |  |
| SBOM | [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) | Apache-2.0 | [source](https://api.github.com/repos/CycloneDX/cyclonedx-gomod) | v1.12.0, 2026-08-22 | active | — |  |
| SBOM | [cyclonedx-py](https://github.com/CycloneDX/cyclonedx-python) | Apache-2.0 | [source](https://api.github.com/repos/CycloneDX/cyclonedx-python) | v9.0.0, 2026-11-19 | active | — | new major version |
| SBOM | [cyclonedx-npm](https://github.com/CycloneDX/cyclonedx-node-npm) | Apache-2.0 | [source](https://api.github.com/repos/CycloneDX/cyclonedx-node-npm) | v7.0.1, 2026-11-13 | active | — |  |
| SBOM | [CycloneDX Maven plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin) | Apache-2.0 | [source](https://api.github.com/repos/CycloneDX/cyclonedx-maven-plugin) | 2.9.3, 2026-07-31 | active | — |  |
| SBOM | [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) | Apache-2.0 | [source](https://api.github.com/repos/CycloneDX/cyclonedx-cli) | v0.33.1, 2026-07-23 | active | — |  |
| SBOM | [sbomqs](https://github.com/interlynk-io/sbomqs) | Apache-2.0 | [source](https://api.github.com/repos/interlynk-io/sbomqs) | v2.1.3, 2026-10-14 | active | — |  |
| Threat modelling | [OWASP pytm](https://github.com/OWASP/pytm) | MIT | [source](https://github.com/OWASP/pytm/blob/master/LICENSE) | v1.4.1, 2026-11-01 | active | — |  |
| Threat modelling | [OWASP Threat Dragon (format)](https://github.com/OWASP/threat-dragon) | Apache-2.0 | [source](https://api.github.com/repos/OWASP/threat-dragon) | v2.6.2, 2026-05-10 | active | — | format only |
| Threat modelling | [Threagile](https://github.com/Threagile/threagile) | MIT | [source](https://api.github.com/repos/Threagile/threagile) | v0.9.1, 2024-07-30 | active (borderline) | — | pre-1.0, release ~28 months old |
| Threat modelling | [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) | LicenseRef-MITRE-ATTACK-Terms | [source](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt) | v20.1, 2026-11-05 | active | — | royalty-free; reproduce copyright and licence |
| Threat modelling | [MITRE CAPEC](https://capec.mitre.org/) | LicenseRef-CAPEC-Terms | [source](https://capec.mitre.org/about/termsofuse.html) | CAPEC 3.9 (date unverified) | unverified | — |  |
| Threat modelling | [MITRE CWE](https://cwe.mitre.org/) | LicenseRef-CWE-Terms | [source](https://cwe.mitre.org/about/termsofuse.html) | CWE 5.0 (date unverified) | unverified | — |  |
| Threat modelling | [MITRE D3FEND](https://d3fend.mitre.org/) | MIT (ontology code); LicenseRef-D3FEND-Terms (content) | [source](https://d3fend.mitre.org/tou/) | tag 1.6.0 (2026-09-01) | active | — |  |
| Threat modelling | [LINDDUN](https://linddun.org/) | CC-BY-4.0 (LINDDUN GO cards); other material unverified | [source](https://downloads.linddun.org/linddun-go/default/latest/go.pdf) | n/a (methodology) | unverified | — |  |
| Reverse engineering | [radare2](https://github.com/radareorg/radare2) | LGPL-3.0 (some plugins GPL) | [source](https://github.com/radareorg/radare2/blob/master/COPYING.md) | 6.2.6, 2026-11-05 | active | — | build `--without-gpl` |
| Reverse engineering | [Ghidra (headless)](https://github.com/NationalSecurityAgency/ghidra) | Apache-2.0 | [source](https://api.github.com/repos/NationalSecurityAgency/ghidra) | 12.2, 2026-10-22 | active | — |  |
| Reverse engineering | [angr](https://github.com/angr/angr) | BSD-2-Clause | [source](https://api.github.com/repos/angr/angr) | tag v10.0.7 (2026-11-13) | active | — |  |
| Reverse engineering | [Jadx](https://github.com/skylot/jadx) | Apache-2.0 | [source](https://api.github.com/repos/skylot/jadx) | v1.5.7, 2026-11-18 | active | — | also listed under mobile |
| Reverse engineering | [ILSpy (ilspycmd)](https://github.com/icsharpcode/ILSpy) | MIT | [source](https://api.github.com/repos/icsharpcode/ILSpy) | v11.2, 2026-10-27 | active | — |  |
| Reverse engineering | [binwalk](https://github.com/ReFirmLabs/binwalk) | MIT | [source](https://api.github.com/repos/ReFirmLabs/binwalk) | v3.1.0, 2024-10-31 | active (borderline) | — | also listed under binary |
| Reverse engineering | [Frida](https://github.com/frida/frida) (after 2.0) | LGPL-2.0-or-later WITH WxWindows-exception-3.1 | [source](https://github.com/frida/frida/blob/main/COPYING) | 17.27.2, 2026-11-19 | active | — |  |
| Reverse engineering | [Tracee](https://github.com/aquasecurity/tracee) (after 2.0) | Apache-2.0 | [source](https://api.github.com/repos/aquasecurity/tracee) | v0.24.1, 2025-11-19 | active | `tracee` |  |
| Reverse engineering | [Qiling](https://github.com/qilingframework/qiling) (after 2.0) | GPL-2.0 (-only/-or-later unverified) | [source](https://api.github.com/repos/qilingframework/qiling) | v1.4.11, 2026-09-06 | active | — |  |
| Secrets | [git-secrets](https://github.com/awslabs/git-secrets) | Apache-2.0 | [source](https://api.github.com/repos/awslabs/git-secrets) | tag 1.3.0 (2019-02-10) | active (barely) | `git-secrets` | no release in ~7 years |
| Secrets | [secretlint](https://github.com/secretlint/secretlint) | MIT | [source](https://api.github.com/repos/secretlint/secretlint) | v14.0.1, 2026-11-16 | active | — |  |
| Secrets | [ripsecrets](https://github.com/sirwart/ripsecrets) | MIT | [source](https://api.github.com/repos/sirwart/ripsecrets) | v0.1.11, 2025-05-27 | slow | — | borderline |
| CVE & vulnerability intelligence | [GitHub Advisory Database](https://github.com/github/advisory-database) | CC-BY-4.0 | [source](https://api.github.com/repos/github/advisory-database) | data repository | active | — | attribution required |
| CVE & vulnerability intelligence | [NVD](https://nvd.nist.gov/developers/terms-of-use) | unverified | [source](https://nvd.nist.gov/developers/terms-of-use) | service | unverified | — | terms page not readable without JavaScript; NIST general policy: https://www.nist.gov/open/license |
| CVE & vulnerability intelligence | [CVE List](https://github.com/CVEProject/cvelistV5) | LicenseRef-CVE-Terms-of-Use | [source](https://www.cve.org/Legal/TermsOfUse) | daily snapshots (cve_2026-11-19_2000Z) | active | — | copies must reproduce MITRE's copyright designation and licence |
| CVE & vulnerability intelligence | [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) | CC0-1.0 | [source](https://api.github.com/repos/cisagov/vulnrichment) | data repository | active | — |  |
| CVE & vulnerability intelligence | [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | Apache-2.0 | [source](https://api.github.com/repos/ossf/malicious-packages) | data repository | active | — | no separate data licence statement |
| CVE & vulnerability intelligence | [Go vulnerability database](https://github.com/golang/vulndb) | BSD-3-Clause (code), CC-BY-4.0 (entries) | [source](https://github.com/golang/vulndb/blob/master/README.md) | data repository | active | — |  |
| Cloud & Kubernetes posture | [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | [source](https://api.github.com/repos/prowler-cloud/prowler) | 5.51.0, 2026-11-19 | active | `prowler-csv` | import format exists |
| Cloud & Kubernetes posture | [Popeye](https://github.com/derailed/popeye) | Apache-2.0 | [source](https://github.com/derailed/popeye/blob/master/LICENSE) | v0.22.1, 2025-01-28 | slow | — |  |
| Cloud & Kubernetes posture | [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0 (-only/-or-later unverified) | [source](https://api.github.com/repos/nccgroup/ScoutSuite) | 5.14.0, 2024-05-10 | unmaintained | `scoutsuite` | † in §7: replace with an equivalent; import format exists |
| Cloud & Kubernetes posture | [CloudSploit](https://github.com/aquasecurity/cloudsploit) | GPL-3.0 (-only/-or-later unverified) | [source](https://api.github.com/repos/aquasecurity/cloudsploit) | v3.9.0, 2024-09-24 | active | `cloudsploit` | import format exists |
| Cloud & Kubernetes posture | [Steampipe](https://github.com/turbot/steampipe) | AGPL-3.0 | [source](https://api.github.com/repos/turbot/steampipe) | v2.5.1, 2026-11-17 | active | `steampipe` | AGPL: separate process only; import format exists |
| Cloud & Kubernetes posture | [Falco](https://github.com/falcosecurity/falco) (after 2.0) | Apache-2.0 | [source](https://api.github.com/repos/falcosecurity/falco) | 0.45.2, 2026-10-29 | active | `falco` | after 2.0; import format exists |
| CI/CD pipelines | [poutine](https://github.com/boostsecurityio/poutine) | Apache-2.0 | [source](https://api.github.com/repos/boostsecurityio/poutine) | v1.1.6, 2026-05-22 | active | `poutine` | import format exists |
| CI/CD pipelines | [Legitify](https://github.com/Legit-Labs/legitify) | Apache-2.0 | [source](https://api.github.com/repos/Legit-Labs/legitify) | v1.0.11, 2024-07-09 | unmaintained | `legitify` | import format exists |
| CI/CD pipelines | [octoscan](https://github.com/synacktiv/octoscan) | GPL-3.0 (-only/-or-later unverified) | [source](https://api.github.com/repos/synacktiv/octoscan) | v0.1.7, 2026-03-30 | active | — |  |
| CI/CD pipelines | [Raven](https://github.com/CycodeLabs/raven) | Apache-2.0 | [source](https://api.github.com/repos/CycodeLabs/raven) | v1.0.9, 2024-05-01 | slow | — | † in §7 |
| CI/CD pipelines | [ratchet](https://github.com/sethvargo/ratchet) | Apache-2.0 | [source](https://api.github.com/repos/sethvargo/ratchet) | v0.12.0, 2026-07-18 | active | — |  |
| CI/CD pipelines | [frizbee](https://github.com/stacklok/frizbee) | Apache-2.0 | [source](https://api.github.com/repos/stacklok/frizbee) | v0.1.12, 2026-11-17 | active | — |  |
| Container images | [Clair](https://github.com/quay/clair) | Apache-2.0 | [source](https://api.github.com/repos/quay/clair) | v4.9.0, 2025-12-10 | active | `clair` | import format exists |
| Container images | [Docker Bench for Security](https://github.com/docker/docker-bench-security) | Apache-2.0 | [source](https://api.github.com/repos/docker/docker-bench-security) | v1.6.1, 2023-12-20 | active | — | last release 2023 |
| Container images | [container-structure-test](https://github.com/GoogleContainerTools/container-structure-test) | Apache-2.0 | [source](https://api.github.com/repos/GoogleContainerTools/container-structure-test) | v1.22.1, 2025-12-16 | active | — |  |
| Container images | [dive](https://github.com/wagoodman/dive) | MIT | [source](https://api.github.com/repos/wagoodman/dive) | v0.13.1, 2025-03-29 | active | — |  |
| Licence compliance | [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort) | Apache-2.0 | [source](https://api.github.com/repos/oss-review-toolkit/ort) | 99.1.0, 2026-11-19 | active | — |  |
| Licence compliance | [FOSSology](https://github.com/fossology/fossology) | GPL-2.0 (-only/-or-later unverified) | [source](https://github.com/fossology/fossology/blob/master/LICENSE) | 4.7.3, 2026-11-14 | active | — |  |
| Licence compliance | [licensee](https://github.com/licensee/licensee) | MIT | [source](https://api.github.com/repos/licensee/licensee) | v10.1.0, 2026-08-07 | active | — |  |
| Licence compliance | [askalono](https://github.com/jpeddicord/askalono) | Apache-2.0 | [source](https://api.github.com/repos/jpeddicord/askalono) | 0.5.0, 2024-10-22 | unmaintained (archived) | — | archived repository |
| Licence compliance | [go-licenses](https://github.com/google/go-licenses) | Apache-2.0 | [source](https://api.github.com/repos/google/go-licenses) | v2.0.1, 2025-09-08 | slow | — | default-branch commits ~14 months old |
| Licence compliance | [pip-licenses](https://github.com/raimon49/pip-licenses) | MIT | [source](https://api.github.com/repos/raimon49/pip-licenses) | v-5.5.5, 2026-03-28 | active | — |  |
| Licence compliance | [license-checker](https://github.com/davglass/license-checker) | BSD-3-Clause | [source](https://github.com/davglass/license-checker/blob/master/LICENSE) | tag v25.0.1 (2019-01-10) | unmaintained | — | maintained fork: https://github.com/RSeidelsohn/license-checker-rseidelsohn (BSD-3-Clause, v5.0.1 2026-05-27, active) |
| Supply chain & integrity | [Rekor](https://github.com/sigstore/rekor) | Apache-2.0 | [source](https://api.github.com/repos/sigstore/rekor) | v1.6.2, 2026-11-18 | active | — |  |
| Supply chain & integrity | [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) | Apache-2.0 | [source](https://api.github.com/repos/slsa-framework/slsa-verifier) | v2.7.1, 2025-06-27 | active | — | release ~17 months old |
| Supply chain & integrity | [in-toto](https://github.com/in-toto/in-toto) | Apache-2.0 | [source](https://github.com/in-toto/in-toto/blob/develop/LICENSE) | v3.1.0, 2026-05-04 | active | — |  |
| Supply chain & integrity | [witness](https://github.com/in-toto/witness) | Apache-2.0 | [source](https://api.github.com/repos/in-toto/witness) | v0.12.0, 2026-07-10 | active | — |  |
| Supply chain & integrity | [GUAC](https://github.com/guacsec/guac) | Apache-2.0 | [source](https://api.github.com/repos/guacsec/guac) | v1.1.0, 2026-03-13 | active | — |  |
| Supply chain & integrity | [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) | Apache-2.0 | [source](https://api.github.com/repos/ossf/package-analysis) | rel-38, 2026-05-20 | active | — |  |
| Malware | [Malcontent](https://github.com/chainguard-dev/malcontent) | Apache-2.0 | [source](https://api.github.com/repos/chainguard-dev/malcontent) | v1.28.2, 2026-11-18 | active | — |  |
| Malware | [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | MIT | [source](https://api.github.com/repos/horsicq/Detect-It-Easy) | stable release unverified (only pre-releases on GitHub) | active | — |  |
| Malware | [LOKI](https://github.com/Neo23x0/Loki) | GPL-3.0 | [source](https://api.github.com/repos/Neo23x0/Loki) | v0.51.0, 2023-05-18 | unmaintained (deprecated) | — | README: "LOKI (Python) is now officially deprecated", successor Loki-RS |
| Malware | [Manalyze](https://github.com/JusticeRage/Manalyze) | GPL-3.0 | [source](https://api.github.com/repos/JusticeRage/Manalyze) | v1.0.0, 2026-07-21 | active | — |  |
| Malware | [TLSH](https://github.com/trendmicro/tlsh) | Apache-2.0 OR BSD-3-Clause | [source](https://github.com/trendmicro/tlsh/blob/master/LICENSE) | 4.12.1, 2026-01-21 | active | — |  |
| Binary security | [cwe_checker](https://github.com/fkie-cad/cwe_checker) | LGPL-3.0 (-only/-or-later unverified) | [source](https://api.github.com/repos/fkie-cad/cwe_checker) | v0.9, 2024-08-20 | active | — | release ~27 months old |
| Binary security | [BinAbsInspector](https://github.com/KeenSecurityLab/BinAbsInspector) | GPL-3.0 | [source](https://api.github.com/repos/KeenSecurityLab/BinAbsInspector) | v0.1, 2022-04-20 | unmaintained | — | † in §7: replace with an equivalent |
| Binary security | [LIEF](https://github.com/lief-project/LIEF) | Apache-2.0 | [source](https://api.github.com/repos/lief-project/LIEF) | 1.0.0, 2026-07-12 | active | — |  |
| Binary security | [EMBA](https://github.com/e-m-b-a/emba) (after 2.0) | GPL-3.0 | [source](https://api.github.com/repos/e-m-b-a/emba) | v2.0.5-ice-edt, 2026-11-03 | active | — |  |
| Mobile apps | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) (after 2.0) | GPL-3.0 | [source](https://api.github.com/repos/MobSF/Mobile-Security-Framework-MobSF) | v4.6.9, 2026-11-18 | active | `mobsf` |  |
| Mobile apps | [apktool](https://github.com/iBotPeaches/Apktool) (after 2.0) | Apache-2.0 | [source](https://api.github.com/repos/iBotPeaches/Apktool) | v3.0.3, 2026-07-20 | active | — |  |
| Mobile apps | [Androguard](https://github.com/androguard/androguard) (after 2.0) | Apache-2.0 | [source](https://api.github.com/repos/androguard/androguard) | v4.1.4, 2026-06-05 | active | — |  |
| Mobile apps | [FlowDroid](https://github.com/secure-software-engineering/FlowDroid) (after 2.0) | LGPL-2.1 | [source](https://api.github.com/repos/secure-software-engineering/FlowDroid) | v2.15.1, 2026-02-23 | active | — | -only/-or-later not stated by the API |
| Mobile apps | [objection](https://github.com/sensepost/objection) (after 2.0) | GPL-3.0 | [source](https://api.github.com/repos/sensepost/objection) | 1.12.5, 2026-06-02 | active | — |  |
| Web app & API testing | [RESTler](https://github.com/microsoft/restler-fuzzer) | MIT | [source](https://api.github.com/repos/microsoft/restler-fuzzer) | tag v9.3.1 (commit 2025-01-30), no GitHub release | active | `restler` | last tag ~22 months old |
| Web app & API testing | [Katana](https://github.com/projectdiscovery/katana) | MIT | [source](https://api.github.com/repos/projectdiscovery/katana) | v1.8.0, 2026-10-05 | active | — |  |
| Web app & API testing | [GraphQL Cop](https://github.com/dolevf/graphql-cop) | MIT | [source](https://api.github.com/repos/dolevf/graphql-cop) | 1.15, 2025-11-07 | slow | — | borderline (~12 months) |
| Fuzz testing | [ClusterFuzzLite](https://github.com/google/clusterfuzzlite) | Apache-2.0 | [source](https://api.github.com/repos/google/clusterfuzzlite) | moving action tag v1 | active | `clusterfuzzlite` | GitHub Action |
| Fuzz testing | [AFL++](https://github.com/AFLplusplus/AFLplusplus) | unverified (GitHub metadata says AGPL-3.0; historically Apache-2.0) | [source](https://api.github.com/repos/AFLplusplus/AFLplusplus) | v5.03c, 2026-09-02 | active | — | LICENSE file not read: unverified |
| Fuzz testing | [libFuzzer](https://github.com/llvm/llvm-project) | Apache-2.0 WITH LLVM-exception | [source](https://github.com/llvm/llvm-project/blob/main/LICENSE.TXT) | llvmorg-23.1.6, 2026-11-17 | active | `libfuzzer` | part of LLVM compiler-rt |
| Fuzz testing | [Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) | Apache-2.0 | [source](https://api.github.com/repos/CodeIntelligenceTesting/jazzer.js) | v4.0.0, 2026-04-15 | active | — |  |
| Fuzz testing | [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | Apache-2.0 (MIT dual licence unverified) | [source](https://api.github.com/repos/rust-fuzz/cargo-fuzz) | 0.13.2, 2026-06-09 | active | — |  |
| Fuzz testing | [boofuzz](https://github.com/jtpereyda/boofuzz) | GPL-2.0 | [source](https://api.github.com/repos/jtpereyda/boofuzz) | v0.4.2, 2023-10-06 | active | — | last release >3 years old |
| Fuzz testing | [Radamsa](https://gitlab.com/akihe/radamsa) | MIT | [source](https://gitlab.com/akihe/radamsa/-/raw/develop/LICENCE) | v0.7 (2023-11-02) | active | — | last release ~3 years old |

**Modes of catalogued tools** (the tool is catalogued with its licence; the mode the kind needs is not wired yet):

| Kind | Entry | Catalogued as | Mode needed |
|---|---|---|---|
| Discovery & CodeGraph | Opengrep (route & DB rules) | Opengrep (`opengrep`, LGPL-2.1) | route and database rules |
| SBOM | Trivy (SBOM) | Trivy (filesystem) (`trivy-fs`, Apache-2.0) | SBOM output |
| Secrets | Trivy (secret) | Trivy (filesystem) (`trivy-fs`, Apache-2.0) | secret scanner |
| Secrets | Opengrep (secret rules) | Opengrep (`opengrep`, LGPL-2.1) | secret rule pack |
| Cloud & Kubernetes posture | Trivy (Kubernetes) | Trivy (filesystem) (`trivy-fs`, Apache-2.0) | Kubernetes cluster scan |
| CI/CD pipelines | Checkov (CI policies) | Checkov (`checkov`, Apache-2.0) | CI pipeline policies |
| Binary security | Trivy (binary) | Trivy (filesystem) (`trivy-fs`, Apache-2.0) | binary scan |
| Binary security | Syft (binary) | Syft (`syft`, Apache-2.0) | binary cataloguing |

**Licence notes on catalogued tools of the §7 table** (re-checked 2026-11-20): CodeQL — the CLI is under the GitHub CodeQL Terms (free only for OSI-licensed code and research; private code needs GitHub Advanced Security), evidence https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md, catalog decision *restricted*; Brakeman — Brakeman Public Use License (commercial use, including SaaS and value-added services, needs a commercial licence), evidence https://github.com/presidentbeef/brakeman/blob/main/LICENSE.md, *restricted*; TruffleHog — AGPL-3.0 (https://api.github.com/repos/trufflesecurity/trufflehog), runs as a separate process only; YARA-X — BSD-3-Clause (https://api.github.com/repos/VirusTotal/yara-x), each rule set carries its own licence.

**† entries of §7 that fail the check** and need an equivalent before enabling: ScoutSuite (no release or default-branch commit for about 30 months), BinAbsInspector (no commit since 2024-05), Raven (default-branch commit about 21 months old), LOKI (deprecated by its author in favour of Loki-RS), askalono (archived), license-checker (no commit since 2019; the maintained fork is license-checker-rseidelsohn, BSD-3-Clause, active), Legitify (default-branch commit about 26 months old). Steampipe and TruffleHog are AGPL (separate process only). AFL++'s licence could not be confirmed from its LICENSE file (GitHub metadata reports AGPL-3.0; it has historically been Apache-2.0): unverified. Clair and FOSSology were excluded earlier as server platforms (see [Excluded](#excluded)); they stay on the gap list because §7 names them.


## Adding a tool (tool manifests)

A tool is added to PATHOS with a **manifest**: a YAML (or JSON) file that says how to run the tool and how to read its output. No Go code is needed unless the output format has no parser yet. There are two kinds of manifest:

| | First-party manifests | Operator plugins |
|---|---|---|
| Where | In a family worker image, read-only at `/opt/pathos/tools.d` (`PATHOS_TOOLS_DIR`); source: `workers/<family>/tools.d/` | On the worker host in `deploy/scanners.d/`, mounted at `/etc/pathos/scanners.d` (`PATHOS_SCANNER_PLUGINS_DIR`) |
| Trust | Trusted: shipped and reviewed with PATHOS | Operator-defined; same safety checks as before |
| Scanner key | The manifest `name`, which must be a catalog key of a tool that is not built into the core image (for example `bandit`) | `plugin-<category>-<name>` |
| Limit | 500 per image | 50 per worker |

To ship a new first-party tool: add (or update) its catalog entry in `catalog.go` (licence, family, `available`), add it to the scan types it covers in `scantypes.go`, install it in `workers/<family>/Dockerfile` pinned by version and SHA-256 (or pip hashes), add `workers/<family>/tools.d/<name>.yaml`, and add a Go test that parses real output of the tool (generated by running it on a small sample in the image) with the manifest's parser, as in `backend/internal/worker/manifests_test.go`.

### Manifest fields

Version 1 files (the plugin format of PATHOS 1.x: `name`, `display_name`, `category`, `homepage`, `command`, `version_args`, `args`, `ok_exit_codes`, `env`, `output`) keep working unchanged. Unknown fields are rejected.

| Field | Meaning |
|---|---|
| `name` | First-party: the catalog key. Plugins: lowercase letters, digits, dashes (≤ 23); key `plugin-<category>-<name>` |
| `display_name`, `homepage` | Shown in the catalog (homepage must be https) |
| `category` | The findings' category: one of the finding categories except `eol` (for first-party manifests, the catalog's category) |
| `scan_types` | Scan type ids the tool covers (at most 10), e.g. `[sast]`, `[dast, fuzzing]` |
| `license_spdx` | SPDX licence expression of the tool |
| `family` | The worker family that ships it (informational) |
| `targets` | What the tool scans: `repository` (default), `image`, `url`, `api`, `mobile-app`, `binary`, `model`, `llm-endpoint` |
| `command` | Absolute path of an existing executable that is not writable by group or others |
| `args` | Arguments, no shell. Placeholders: `{source}` (repository checkout), `{output}` (report file), `{target_url}` (url and api targets), `{openapi}` (the api target's OpenAPI file), `{image}` (image reference), `{artifact}` (the scan directory of an uploaded artifact or mobile app), `{llm_target}` (llm-endpoint targets: a JSON file, mode 0600, with the URL, model and credential headers, so the credential is never on a command line), `{cache}` (persistent per tool), `{tmp}` (per run). Every declared target needs its placeholder |
| `version_args` | Arguments that print the version (default `--version`). The version command runs with the tool's `env` and the proxy settings of its `network` |
| `version_timeout` | Go duration between `1s` and `5m` for the version command (default `20s`) |
| `ok_exit_codes` | Exit codes meaning success (default `0`; many tools exit `1` when they find something) |
| `timeout` | Go duration between `10s` and `6h` (default: the job's timeout) |
| `env` | Extra variables (not `PATH`, `HOME`, `LD_*`, `*_PROXY`, `PATHOS_*`) |
| `output` | `file` (written to `{output}`, default) or `stdout` |
| `network` | `none`: the egress proxy variables are removed from the tool's environment (the worker networks reach nothing else). `registry`: the tool downloads databases or packages through the egress proxy. `target`: the tool sends requests to the scan target (url, api and llm-endpoint targets only); scans then need the target's authorization statement |
| `intrusive` | `true` for tools that send attack traffic (active scans, fuzzers, injection probes). Requires `network: target`; such tools run only for targets with the **intrusive testing authorized** flag |
| `requires_build` | The tool needs a built project (informational) |
| `sandbox` | `true`: the tool runs repository code, so the worker hands it to its sandbox runner (no network, no worker credentials, its own UID and limits; [SECURITY.md](SECURITY.md#scanning)) instead of running it; without a runner it is skipped. Requires `network: none`, `targets: [repository]`, `output: file` and only the `{source}`, `{output}` and `{tmp}` placeholders |
| `default_enabled` | Informational; manifest tools are never enabled by default |
| `parser` | `sarif` (default), `import:<format>` (any [result import format](api-reference/result-imports.md), e.g. `import:bandit`) or `jsonmap` |
| `jsonmap` | The mapping for `parser: jsonmap` (below) |

The worker uploads the tool's own output unchanged together with its parser; the API parses it and stores the parser with the raw report, so findings can always be located in the original output ([API](api-reference/scan-types-and-tools.md#tool-manifests)).

### jsonmap: mapping a JSON report

`jsonmap` maps each record of a JSON report (or JSON Lines) to a finding. Values are **paths** into a record: dot-separated keys and array indexes (`location.path`, `identifiers.0.value`), several **alternatives** separated by `|` (`rule|id`: the first non-empty one), or a **template** with paths in braces (`SC{code}`). An array of strings or numbers (for `cve`, `cwe`) is read as a list.

| Key | Meaning |
|---|---|
| `records` | Path of the array of records (empty: the report is the array). With `lines`, the path of the array inside each line (empty: each line is one record) |
| `lines` | `true` for JSON Lines (one JSON document per line) |
| `rule_id` | Required. The rule or check identifier |
| `title`, `message` | Title (default: the first line of the message) and description |
| `severity`, `severity_map`, `default_severity` | The severity value, a map from the tool's values to `critical`, `high`, `medium`, `low`, `info` (common words such as `error`, `warning`, `moderate` are recognised without a map), and the severity when none matches (default `info`) |
| `confidence` | `high`, `medium` or `low` |
| `file`, `line`, `end_line`, `url` | Location (workspace prefixes are removed from paths) |
| `package`, `version`, `fixed_version` | Affected package |
| `cve`, `cwe`, `cvss` | Identifiers (`CVE-…`, `CWE-…` or numbers) and a CVSS base score |
| `category` | The finding category of every record (default: the tool's) |
| `identity` | What distinguishes two findings of the same rule in the same file (default: the message). Records that are still identical are told apart by their order in the file, so no finding is merged into another; line numbers are not part of a finding's identity |

Example (ShellCheck, `workers/sast/tools.d/shellcheck.yaml`):

```yaml
parser: jsonmap
jsonmap:
  lines: true
  records: comments
  rule_id: "SC{code}"
  title: message
  severity: level
  severity_map: {error: high, warning: medium, info: low, style: info}
  file: file
  line: line
  end_line: endLine
  identity: "SC{code} {message}"
```

A record without a rule id fails the report (the error is shown on the scan); secrets in messages are redacted like in every import.

### Routing and family workers

Workers advertise their manifests (never their commands) when they register. A scan job that uses a manifest tool goes to a worker that advertises every manifest tool of the job; when no online worker has all of them, any worker takes the job and records the missing tools as skipped. Family images extend the core image, so a family worker also runs every core tool ([OPERATIONS.md](OPERATIONS.md#family-worker-images)).

### Operator plugins

Operators can add a tool to a worker without changing PATHOS: put a manifest in `deploy/scanners.d/` and make the tool's executable available in the worker container (a derived image or a read-only mount). See `deploy/scanners.d/example.yaml.disabled`. When the worker registers, the plugin appears in **Scanners & workers** and, if it scans repositories, can be added to scan profiles; tools for other targets are selected on the scan target. Results are normalized, deduplicated, risk-scored and triaged like any other scanner's. Invalid files are skipped with a log message; at most 50 plugins load.

Security: manifests are files on the worker host or in the image, never API input, so a PATHOS administrator cannot make workers run arbitrary programs. Tools run exactly like built-in scanners: no shell, the worker's unprivileged user, its read-only source checkout, its sandbox and egress policy, and the job's timeout. Tools that contact a target need its authorization statement, intrusive tools also its intrusive testing flag. The full trust model is in [SECURITY.md](SECURITY.md#scanner-plugins).



## Family images: mobile, binary, AI and fuzzing

Four opt-in family images (Compose profiles `mobile`, `binary`, `ai`, `fuzz`) extend `worker-core` with tools defined only by manifests (`workers/<family>/tools.d`). Every download is pinned by version (or commit) and SHA-256, pip `--require-hashes` or the npm lockfile; each image passes the Trivy gate (0 fixable high or critical vulnerabilities, checked on 2026-11-19). The fixtures of `backend/internal/worker/manifests_families_test.go` were produced by running each manifest command in these images. Image sizes (uncompressed, including the 1.77 GB core image): worker-mobile 2.83 GB, worker-binary 2.18 GB, worker-ai 2.97 GB, worker-fuzz 2.29 GB.

| Image | Tool (catalog key) | Version | Licence | Runs on | Output (parser) |
|---|---|---|---|---|---|
| worker-mobile | mobsfscan (`mobsfscan`), on Java sources decompiled by jadx 1.5.7 (Apache-2.0) on Temurin JRE 21.0.13.1 (GPL-2.0-with-classpath-exception) | 1.2.0 (Semgrep CE 1.172.0) | LGPL-3.0-or-later (Semgrep LGPL-2.1-or-later) | Mobile app targets (APK, AAB) | SARIF |
| worker-mobile | APKLeaks (`apkleaks`) | 2.6.3 | Apache-2.0 | Mobile app targets (APK) | JSON (`import:apkleaks`, secret values redacted) |
| worker-mobile | Quark-Engine (`quark-engine`) with PATHOS' own rules (Apache-2.0, `workers/mobile/quark-rules`) | 26.11.1 (androguard 4.1.4) | GPL-3.0-only | Mobile app targets (APK) | JSON (`jsonmap`; Quark's report kept under `quark`) |
| worker-mobile | Mobile app configuration checks (`mobile-app-checks`, PATHOS helper) | 1 (androguard 4.1.4, Apache-2.0) | Apache-2.0 | Mobile app targets (APK, IPA) | JSON (`jsonmap`) |
| worker-binary | CVE Binary Tool (`cve-bin-tool`) | 3.4.1, commit `ee13c919` of the main branch | GPL-3.0-or-later | Build artifact targets (binaries, firmware) | JSON (`jsonmap`; findings in the `sca` category) |
| worker-binary | capa (`capa`) with capa-rules 10.0.0 (Apache-2.0) | 10.0.0 | Apache-2.0 | Build artifact targets (ELF, PE, .NET) | JSON (`jsonmap`; capa's reports kept under `capa`) |
| worker-binary | YARA-X (`yara-x`) with the ReversingLabs YARA rules (MIT, commit `e0a0be54`) and a PATHOS test rule | 1.23.0 | BSD-3-Clause | Build artifacts, mobile apps, repositories (profile) | JSON (`jsonmap`) |
| worker-ai | ModelScan (`modelscan`) | 0.8.8 | Apache-2.0 | Repositories (profile), model artifacts | JSON (`import:modelscan`) |
| worker-ai | garak (`garak`) | 0.17.1 | Apache-2.0 | LLM endpoint targets (intrusive) | JSON Lines (`import:garak`) |
| worker-ai | promptfoo (`promptfoo`) with the PATHOS red-team suite (`workers/ai/promptfoo/redteam-tests.yaml`) on Node.js 26.13.1 (MIT) | 0.126.0 | MIT | LLM endpoint targets (intrusive) | JSON (`import:promptfoo`) |
| worker-fuzz | Go native fuzzing (`go-fuzz`), Go toolchain | 1.27.4 | BSD-3-Clause | Repositories (profile; builds the code) | JSON (`jsonmap`) |
| worker-fuzz | Atheris (`atheris`) | 3.1.0 | Apache-2.0 | Repositories (profile; runs the code) | JSON (`jsonmap`) |
| (every worker) | AI-BOM (`ai-bom`, built in) | PATHOS | Apache-2.0 | Repositories (profile) | CycloneDX 1.6 (inventory, no findings) |

Notes on each tool:

- **Mobile app targets** are uploaded packages (`POST /api/v1/scan-targets/mobile-app`). The worker extracts the package (native libraries, executables and Info.plist reach the binary hardening checks, which read ELF and Mach-O) and keeps the package itself beside the contents for the mobile tools. iOS packages have no Java code: mobsfscan, APKLeaks and Quark-Engine report nothing for them. The manifest of an Android App Bundle (`.aab`) is stored as protocol buffers and is not checked; mobsfscan and APKLeaks read AABs through jadx.
- **jadx** bundles Guava 31.1-android (CVE-2026-102554); the image replaces those classes in the jadx jar with Guava 33.8.0-android from Maven Central (pinned by SHA-256). The mobile fixtures were produced with the patched jar.
- **Quark-Engine** reports behaviours with a Quark confidence of 60 % or more (100 % high, 80 % medium, 60 % low). The community rule set (quark-engine/quark-rules) has no licence file, so it is not bundled; an operator who may use it mounts it at `/opt/pathos/mobile/quark-rules-extra` (`PATHOS_QUARK_RULES_DIR`).
- **Mobile app checks** (`workers/mobile/bin/pathos_mobile_checks.py`, with Python tests in `workers/mobile/test`): Android `debuggable`, `allowBackup`, cleartext traffic (manifest and network security configuration, user CAs), exported activities, services, receivers and providers without a permission (the launcher activity excepted), `minSdkVersion` below 23, v1-only signing (Janus, CVE-2017-13156), debug certificate, unsigned package; iOS `NSAllowsArbitraryLoads` and other App Transport Security exceptions, exception domains with insecure HTTP or TLS below 1.2, custom URL schemes, `MinimumOSVersion` below 14, `get-task-allow`, development push environment and wildcard keychain groups (entitlements of `embedded.mobileprovision` and of the executable's code signature).
- **CVE Binary Tool** runs offline (`--offline -u never`) on a database in the worker's cache volume; the image has no database and a scan fails with a hint until one is installed ([OPERATIONS.md](OPERATIONS.md#cve-binary-tool-database)). Release 3.4 (2024-09) reads the retired NVD JSON 1.1 feeds and cannot build a database any more, so the image installs a commit of the main branch (by archive SHA-256) that reads the NVD JSON 2.0 feeds.
- **capa** runs on up to 25 executables of up to 64 MiB per artifact (largest first, 10 minutes each). Capabilities typical of malware (anti-analysis, persistence, command and control, injection, ...) are medium, other ATT&CK-mapped capabilities low, the rest info.
- **YARA-X** rules are compiled when the image is built (310 ReversingLabs rules, which also proves they compile); more rules can be mounted at `/opt/pathos/binary/yara-extra` (`PATHOS_YARA_RULES_DIR`) and are compiled at scan time.
- **garak** runs only probes whose detectors match strings (`promptinject`, `dan.DAN_Jailbreak`, `encoding.InjectBase64`, `latentinjection.LatentJailbreak`, `web_injection.MarkdownImageExfil`, `web_injection.TaskXSS`; up to 256 prompts per probe, `GARAK_PROMPT_CAP`), one attempt at a time, through its REST generator. Its full dependency set (PyTorch, Transformers, provider SDKs, cloud clients) is not installed; probes and detectors that need a local model or a dataset download are not available.
- **promptfoo** runs `promptfoo eval` of a static PATHOS suite with deterministic assertions (prompt injection, indirect injection, encoded instructions, jailbreak, system prompt and secret disclosure, markdown exfiltration, script output, harmful requests). Telemetry, update checks, sharing and remote generation are off; no grader model is used. promptfoo's model-generated `redteam` plugins are not used, because they need a generator model or promptfoo's cloud.
- **LLM endpoint targets** are OpenAI-compatible chat completions URLs with a model name and an optional credential (stored encrypted like other target credentials). garak and promptfoo are `network: target` and `intrusive`: they run only for authorized targets with the intrusive testing flag, through the egress proxy (the host must be on the allowlist). The tests use a stub server (`workers/ai/test/stub_llm.py`), never a real provider.
- **Go native fuzzing and Atheris** build and run repository code: only in the sandbox runner (`sandbox: true`; the `worker-fuzz-sandbox` container has no network interface but loopback, no worker credentials, UID 10002 and its own memory, CPU and pids limits), only when a scan profile selects them (Go module downloads off, `GOPROXY=off`: only vendored or no dependencies), on a copy of the checkout, with nice 10, CPU-time, file-size and (Atheris) address-space limits, `FUZZ_SECONDS` per target (default 60), `FUZZ_TOTAL_SECONDS` (default 1200) and at most `FUZZ_MAX_TARGETS` (default 20). A crash is a `fuzz` finding located at the crashing line, with the reproducer input (base64, at most 4 KiB, with its size and SHA-256) in the stored report. Atheris harnesses can import the Python standard library and the repository's own modules only.
- **AI-BOM** (built into every worker, opt-in per profile) records AI and ML frameworks and LLM SDKs declared as dependencies (requirements files, pyproject.toml, Pipfile, setup.py/cfg, environment.yml, package.json, go.mod, pom.xml, build.gradle), model files (safetensors, GGUF, ONNX, PyTorch, Keras, TensorFlow Lite, Core ML, pickled models in model directories, with SHA-256), Hugging Face model references and hosted model names in code, and the LLM APIs the code calls (provider hosts and SDK imports) as SBOM components of type `framework`, `library`, `machine-learning-model` and `service`. They are kept apart from Syft's components: an SBOM scan does not remove them, the next AI-BOM replaces them.

Not shipped:

| Tool | Reason |
|---|---|
| Jazzer | JVM harnesses need the project built with Maven or Gradle, which downloads dependencies (the fuzz worker has no network). Jazzer crash logs can be imported (`libfuzzer` format) |
| Quark-Engine community rules | No licence; can be mounted by the operator |
| apktool | Not needed: jadx produces the Java sources and resources mobsfscan and APKLeaks read |
| garak model-based detectors and dataset probes, full garak dependency set | Need PyTorch/Transformers (several GB) or downloads at run time |
| promptfoo `redteam generate` plugins | Need a generator model or promptfoo's remote generation service |
| binwalk (firmware extraction) | Not evaluated in this pack; CVE Binary Tool extracts common archive and package formats itself |

## Import-only integrations: DAST, API, infrastructure, cloud, container, mobile, runtime, AI, pentest and fuzzing

These tools are not run by PATHOS workers; their reports are imported ([Result imports](api-reference/result-imports.md#dast-api-infrastructure-cloud-container-mobile-runtime-ai-pentest-and-fuzzing-formats)). The Category column names the default finding category of the import in brackets ("per finding": each finding keeps its own category, see the format notes). Nothing of these tools is bundled, so their licences do not restrict redistribution of PATHOS; commercial tools are never required. Licences are listed as published by each project (not re-checked against the repositories for this change). "Test report" says whether the import format was checked against a report produced by running the tool against a local test service, or built from the published format only.

| Tool | Import format | Category | License | Test report |
|---|---|---|---|---|
| Nikto | `nikto` | DAST (`dast`) | GPL-2.0 | real run |
| Wapiti | `wapiti` | DAST (`dast`) | GPL-2.0 | real run |
| Arachni | `arachni` | DAST (`dast`) | Arachni Public Source License (NOASSERTION); unmaintained since 2018 | real run |
| sqlmap | `sqlmap` | DAST (intrusive) (`dast`) | GPL-2.0-or-later | real run |
| Dalfox | `dalfox` | DAST (XSS) (`dast`) | MIT | real run |
| ffuf | `ffuf` | DAST (content discovery) (`dast`) | MIT | real run |
| Wfuzz | `wfuzz` | DAST (content discovery) (`dast`) | GPL-2.0 | real run |
| w3af | `w3af` | DAST (`dast`) | GPL-2.0; unmaintained | published format |
| Schemathesis | `schemathesis` | API (`api`) | MIT | real run |
| RESTler | `restler` | API fuzzing (`api`) | MIT | published format |
| 42Crunch API Security Audit | `42crunch` | API (`api`) | Commercial | published format |
| Acunetix, Acunetix 360 | `acunetix` | DAST (`dast`) | Commercial | published format |
| Invicti / Netsparker | `invicti` | DAST (`dast`) | Commercial | published format |
| Rapid7 AppSpider | `appspider` | DAST (`dast`) | Commercial | published format |
| Rapid7 InsightAppSec | `insightappsec` | DAST (`dast`) | Commercial | published format |
| Qualys WAS | `qualys-was` | DAST (`dast`) | Commercial | published format |
| HCL AppScan (DAST) | `appscan-dast` | DAST (`dast`) | Commercial | published format |
| Burp Suite DAST / Enterprise | `burp-enterprise` | DAST (`dast`) | Commercial | published format |
| StackHawk | `stackhawk` | DAST (`dast`) | Commercial | published format |
| Nmap | `nmap` | Network (`other`) | Nmap Public Source License (LicenseRef-NPSL) | real run |
| Qualys VMDR | `qualys-vm` | Network (`other`) | Commercial | published format |
| Tenable.io / Nessus / Tenable.sc (CSV) | `tenable-csv` | Network (`other`) | Commercial | published format |
| Rapid7 Nexpose / InsightVM | `nexpose` | Network (`other`) | Commercial | published format |
| testssl.sh | `testssl` | TLS (`misconfiguration`) | GPL-2.0 | real run |
| SSLyze | `sslyze` | TLS (`misconfiguration`) | AGPL-3.0 | real run |
| sslscan | `sslscan` | TLS (`misconfiguration`) | GPL-3.0 | real run |
| Wazuh | `wazuh` | Host vulnerabilities (`other`) | GPL-2.0 | published format |
| Prowler | `prowler`, `prowler-csv` | Cloud posture (`compliance`) | Apache-2.0 | published format (needs a cloud account) |
| ScoutSuite | `scoutsuite` | Cloud posture (`compliance`) | GPL-2.0 | published format (needs a cloud account) |
| CloudSploit | `cloudsploit` | Cloud posture (`compliance`) | GPL-3.0 | published format (needs a cloud account) |
| AWS Security Hub (ASFF) | `asff` | Cloud posture (per finding) | Cloud service | published format |
| Amazon Inspector | `inspector2` | Cloud vulnerabilities (`other`) | Cloud service | published format |
| Microsoft Defender for Cloud | `defender-cloud` | Cloud posture (`compliance`) | Cloud service | published format |
| Google Cloud Security Command Center | `gcp-scc` | Cloud posture (per finding) | Cloud service | published format |
| Dockle | `dockle` | Container image (`container`) | Apache-2.0 | real run |
| Clair | `clair` | Container image (`container`) | Apache-2.0 | published format |
| Harbor | `harbor` | Container registry (`container`) | Apache-2.0 | published format |
| Trivy (Kubernetes) | `trivy-k8s` | Kubernetes (per finding) | Apache-2.0 | published format |
| Anchore Engine / Enterprise | `anchore` | Container image (`container`) | Apache-2.0 (Engine) / Commercial | published format |
| Prisma Cloud / Twistlock | `twistlock`, `twistlock-csv` | Container image (`container`) | Commercial | published format |
| Sysdig Secure | `sysdig`, `sysdig-csv` | Container image (`container`) | Commercial | published format |
| Docker Scout | `docker-scout` (SARIF) | Container image (`container`) | Proprietary (Docker subscription) | published format |
| MobSF | `mobsf` | Mobile (`mobile`) | GPL-3.0 | exports from the DefectDojo test corpus |
| APKLeaks | `apkleaks` | Mobile (`mobile`) | Apache-2.0 | published format |
| NowSecure | `nowsecure` (SARIF) | Mobile (`mobile`) | Commercial | published format |
| Contrast Assess | `contrast` | IAST (`iast`) | Commercial | published format |
| Falco | `falco` | Runtime (`runtime`) | Apache-2.0 | published format (needs kernel privileges) |
| Tetragon | `tetragon` | Runtime (`runtime`) | Apache-2.0 | published format (needs kernel privileges) |
| Tracee | `tracee` | Runtime (`runtime`) | Apache-2.0 | published format (needs kernel privileges) |
| garak | `garak` | AI/LLM (`ai`) | Apache-2.0 | real run |
| promptfoo | `promptfoo` | AI/LLM (`ai`) | MIT | real run |
| ProtectAI ModelScan | `modelscan` | AI model files (`ai`) | Apache-2.0 | real run |
| HackerOne | `hackerone`, `hackerone-csv` | Pentest / bug bounty (`other`) | Commercial | published format |
| Bugcrowd | `bugcrowd` | Pentest / bug bounty (`other`) | Commercial | published format |
| Intigriti | `intigriti` | Pentest / bug bounty (`other`) | Commercial | published format |
| ClusterFuzzLite / CIFuzz | `clusterfuzzlite` (SARIF) | Fuzzing (`fuzz`) | Apache-2.0 | published format |
| libFuzzer, Jazzer | `libfuzzer` | Fuzzing (`fuzz`) | Apache-2.0 WITH LLVM-exception (libFuzzer), Apache-2.0 (Jazzer) | real run (libFuzzer); published format (Jazzer) |

Not added: Oversecured (no published report format found), Akto (only HTML and PDF reports are documented), Black Duck Seeker and HCL AppScan IAST (no publicly documented export), Intigriti CSV (only the API JSON is documented).
