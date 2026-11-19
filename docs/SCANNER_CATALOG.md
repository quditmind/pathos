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

The opt-in `worker-sast` family image adds three tools defined only by [tool manifests](#adding-a-tool-tool-manifests) (`workers/sast/tools.d`):

| Tool | Runs on | Output (parser) |
|---|---|---|
| Bandit 1.9.4 | Repositories (Python) | Bandit JSON (`import:bandit`, the result import parser) |
| njsscan 1.0.2 | Repositories (Node.js) | SARIF |
| ShellCheck 0.11.0 | Repositories (shell scripts; findings in the `code-quality` category) | json1 (`jsonmap`) |

Opengrep runs PATHOS' own Apache-2.0 baseline rules; the community `opengrep-rules` pack carries a Commons Clause restriction and is not bundled. All other catalogue entries have no adapter yet: they can be selected only once a worker provides them, for example as a [declarative plugin](#adding-a-tool-tool-manifests). Versions are listed in [DEPENDENCIES.md](DEPENDENCIES.md#scanners-in-worker-core).

Opengrep also runs the PATHOS framework configuration rules (`workers/rules/pathos-misconfig-*.yml`: Spring Boot, Django, Express), whose findings use the `misconfiguration` category. Each rule has a message, CWE, severity and references; the fixtures in `workers/rules-tests/` are run with `scripts/test-opengrep-rules.py`.

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
| 36 | KICS | IaC | Apache-2.0 | active | Use | |
| 37 | KubeLinter | K8s manifests | Apache-2.0 | active | Use | |
| 38 | Kubescape | K8s posture (manifests/Helm) | Apache-2.0 | active | Use | |
| 39 | TFLint | Terraform | MPL-2.0 (*unverified*) | *unverified* | Use (verify) | |
| 40 | Conftest | Policy-as-code (OPA) | Apache-2.0 (*unverified*) | *unverified* | Use (verify) | Org-defined policies |
| 41 | Hadolint | Dockerfile | GPL-3.0 | active | Use | |
| 42 | Dockle | Container image | Apache-2.0 | active (2026-08) | Use | Image targets |
| 43 | Trivy (image) | Container image vulns | Apache-2.0 | active | Use | **Implemented** (image targets) |
| 44 | actionlint | CI/CD (GitHub Actions) | MIT | active (1.7.12, 2026-03-30) | Use | **Implemented**: built from source; runs on `.github/workflows` without shellcheck or pyflakes, so no repository script is run |
| 45 | zizmor | CI/CD security (GitHub Actions) | MIT | *unverified* | Use | **Implemented**; runs offline |
| 46 | OpenSSF Scorecard | Supply-chain posture | Apache-2.0 | active | Use | Uses SCM API |
| 47 | ScanCode Toolkit | License compliance | Apache-2.0 + CC-BY (data) | active | Use | Replaces FOSSology for repo scanning |
| 48 | Trivy (license) | License compliance | Apache-2.0 | active | Use | |
| 48a | File licences (licensecheck) | License compliance (file level) | BSD-3-Clause (library) | active | Use | **Implemented** (built into the worker); violations of the licence policy become findings |
| 48b | ClamAV (repository content) | Malware | GPL-2.0 (separate service) | active | Use | **Implemented** (opt-in; needs the clamd service) |
| 48c | Binary hardening (checksec-style) | Binary analysis | Apache-2.0 (PATHOS) | n/a | Use | **Implemented** (built into the worker; ELF, PE, Mach-O) |
| 49 | OWASP ZAP | DAST | Apache-2.0 | active | Use (target URL, not repo) | Runs against deployed app. Separate worker family and network policy |
| 50 | Nuclei | DAST / templated checks | MIT | active | Use (target URL) | **Implemented** (URL and API targets) |
| 51 | Schemathesis | API fuzzing (OpenAPI) | MIT | active | Use (target URL) | |
| 52 | kube-bench | K8s CIS (cluster) | Apache-2.0 (*unverified*) | *unverified* | Opt | Cluster target, not repo |

Count: **55 scanner integrations**: 48 "Use" plus 7 optional or license-restricted. The 8 supporting utilities below bring the total to 63 integrations. Licence policy evaluation (`license-policy` in a finding's *Detected by*) runs on the server against the SBOM inventory; it is a finding source, not a catalogued scanner.

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

PATHOS reports on 25 scan types. The registry is code (`backend/internal/scanners/scantypes.go`): each type has an id, a name, the finding categories its findings are recorded under and the catalog tools that cover it. `GET /api/v1/scan-types` ([API](api-reference/scan-types-and-tools.md)) and the **Scan coverage** page add what a deployment provides: the tools an online worker can run, and the import formats.

| Scan type (id) | Finding categories | Tools in the catalog |
|---|---|---|
| SAST (`sast`) | sast | Opengrep, Bandit, njsscan, Semgrep CE, CodeQL, Gosec, … |
| DAST (`dast`) | dast | Nuclei, OWASP ZAP, PATHOS endpoint verification |
| SCA (`sca`) | sca, eol | Trivy, Grype, OSV-Scanner, Dependency-Check, …, endoflife.date |
| Secrets (`secrets`) | secrets | Gitleaks, TruffleHog, detect-secrets, Kingfisher |
| IaC (`iac`) | iac | Checkov, KICS, KubeLinter, Kubescape, TFLint, Conftest, Hadolint |
| Container (`container`) | container | Trivy (image), Dockle |
| API security (`api`) | api, dast | Nuclei (API targets), Schemathesis |
| IAST (`iast`) | iast | (imports only) |
| Mobile (`mobile`) | mobile | mobsfscan |
| Fuzzing (`fuzzing`) | fuzz | (imports and plugins) |
| Licence (`license`) | license | licensecheck, ScanCode, Trivy (license) |
| SBOM (`sbom`) | (inventory, no findings) | Syft |
| Malware (`malware`) | malware | ClamAV |
| Code-quality security (`code-quality`) | code-quality | ShellCheck, PMD, Ruff |
| Supply chain (`supply-chain`) | supply-chain | cosign, OpenSSF Scorecard |
| Cryptography (`crypto`) | crypto | (imports and plugins) |
| Configuration (`configuration`) | misconfiguration | Opengrep (framework configuration rules) |
| CI/CD pipeline (`cicd`) | cicd, iac | zizmor, actionlint (their findings are recorded as iac) |
| Binary (`binary`) | binary | Binary hardening |
| AI / LLM (`ai`) | ai | (imports and plugins) |
| Runtime (`runtime`) | runtime | (imports and plugins) |
| Compliance (`compliance`) | compliance | kube-bench |
| Licence policy (`license-policy`) | license | Licence policy (evaluated by the server) |
| Database security (`database`) | database | (imports and plugins) |
| Manual review (`manual`) | any | PATHOS findings JSON, CSV and SARIF imports, Human Eye reviews |

The finding categories added for these types are `api`, `iast`, `mobile`, `fuzz`, `crypto`, `cicd`, `ai`, `runtime`, `compliance`, `database` and `code-quality` (migration 00029). Configuration findings keep `misconfiguration`.

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
| `targets` | What the tool scans: `repository` (default), `image`, `url`, `api`, `mobile-app`, `binary`, `model` |
| `command` | Absolute path of an existing executable that is not writable by group or others |
| `args` | Arguments, no shell. Placeholders: `{source}` (repository checkout), `{output}` (report file), `{target_url}` (url and api targets), `{openapi}` (the api target's OpenAPI file), `{image}` (image reference), `{artifact}` (uploaded artifact file), `{cache}` (persistent per tool), `{tmp}` (per run). Every declared target needs its placeholder |
| `version_args` | Arguments that print the version (default `--version`) |
| `ok_exit_codes` | Exit codes meaning success (default `0`; many tools exit `1` when they find something) |
| `timeout` | Go duration between `10s` and `6h` (default: the job's timeout) |
| `env` | Extra variables (not `PATH`, `HOME`, `LD_*`, `*_PROXY`, `PATHOS_*`) |
| `output` | `file` (written to `{output}`, default) or `stdout` |
| `network` | `none`: the egress proxy variables are removed from the tool's environment (the worker networks reach nothing else). `registry`: the tool downloads databases or packages through the egress proxy. `target`: the tool sends requests to the scan target (url and api targets only); scans then need the target's authorization statement |
| `intrusive` | `true` for tools that send attack traffic (active scans, fuzzers, injection probes). Requires `network: target`; such tools run only for targets with the **intrusive testing authorized** flag |
| `requires_build` | The tool needs a built project (informational) |
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



## Import-only integrations: DAST, API, infrastructure, cloud, container, mobile, runtime, AI, pentest and fuzzing

These tools are not run by PATHOS workers; their reports are imported ([Result imports](api-reference/result-imports.md#dast-api-infrastructure-cloud-container-mobile-runtime-ai-pentest-and-fuzzing-formats)). Nothing of these tools is bundled, so their licences do not restrict redistribution of PATHOS; commercial tools are never required. Licences are listed as published by each project (not re-checked against the repositories for this change). "Test report" says whether the import format was checked against a report produced by running the tool against a local test service, or built from the published format only.

| Tool | Import format | Category | License | Test report |
|---|---|---|---|---|
| Nikto | `nikto` | DAST | GPL-2.0 | real run |
| Wapiti | `wapiti` | DAST | GPL-2.0 | real run |
| Arachni | `arachni` | DAST | Arachni Public Source License (NOASSERTION); unmaintained since 2018 | real run |
| sqlmap | `sqlmap` | DAST (intrusive) | GPL-2.0-or-later | real run |
| Dalfox | `dalfox` | DAST (XSS) | MIT | real run |
| ffuf | `ffuf` | DAST (content discovery) | MIT | real run |
| Wfuzz | `wfuzz` | DAST (content discovery) | GPL-2.0 | real run |
| w3af | `w3af` | DAST | GPL-2.0; unmaintained | published format |
| Schemathesis | `schemathesis` | API | MIT | real run |
| RESTler | `restler` | API fuzzing | MIT | published format |
| 42Crunch API Security Audit | `42crunch` | API | Commercial | published format |
| Acunetix, Acunetix 360 | `acunetix` | DAST | Commercial | published format |
| Invicti / Netsparker | `invicti` | DAST | Commercial | published format |
| Rapid7 AppSpider | `appspider` | DAST | Commercial | published format |
| Rapid7 InsightAppSec | `insightappsec` | DAST | Commercial | published format |
| Qualys WAS | `qualys-was` | DAST | Commercial | published format |
| HCL AppScan (DAST) | `appscan-dast` | DAST | Commercial | published format |
| Burp Suite DAST / Enterprise | `burp-enterprise` | DAST | Commercial | published format |
| StackHawk | `stackhawk` | DAST | Commercial | published format |
| Nmap | `nmap` | Network | Nmap Public Source License (LicenseRef-NPSL) | real run |
| Qualys VMDR | `qualys-vm` | Network | Commercial | published format |
| Tenable.io / Nessus / Tenable.sc (CSV) | `tenable-csv` | Network | Commercial | published format |
| Rapid7 Nexpose / InsightVM | `nexpose` | Network | Commercial | published format |
| testssl.sh | `testssl` | TLS | GPL-2.0 | real run |
| SSLyze | `sslyze` | TLS | AGPL-3.0 | real run |
| sslscan | `sslscan` | TLS | GPL-3.0 | real run |
| Wazuh | `wazuh` | Host vulnerabilities | GPL-2.0 | published format |
| Prowler | `prowler`, `prowler-csv` | Cloud posture | Apache-2.0 | published format (needs a cloud account) |
| ScoutSuite | `scoutsuite` | Cloud posture | GPL-2.0 | published format (needs a cloud account) |
| CloudSploit | `cloudsploit` | Cloud posture | GPL-3.0 | published format (needs a cloud account) |
| AWS Security Hub (ASFF) | `asff` | Cloud posture | Cloud service | published format |
| Amazon Inspector | `inspector2` | Cloud vulnerabilities | Cloud service | published format |
| Microsoft Defender for Cloud | `defender-cloud` | Cloud posture | Cloud service | published format |
| Google Cloud Security Command Center | `gcp-scc` | Cloud posture | Cloud service | published format |
| Dockle | `dockle` | Container image | Apache-2.0 | real run |
| Clair | `clair` | Container image | Apache-2.0 | published format |
| Harbor | `harbor` | Container registry | Apache-2.0 | published format |
| Trivy (Kubernetes) | `trivy-k8s` | Kubernetes | Apache-2.0 | published format |
| Anchore Engine / Enterprise | `anchore` | Container image | Apache-2.0 (Engine) / Commercial | published format |
| Prisma Cloud / Twistlock | `twistlock`, `twistlock-csv` | Container image | Commercial | published format |
| Sysdig Secure | `sysdig`, `sysdig-csv` | Container image | Commercial | published format |
| Docker Scout | `docker-scout` (SARIF) | Container image | Proprietary (Docker subscription) | published format |
| MobSF | `mobsf` | Mobile | GPL-3.0 | exports from the DefectDojo test corpus |
| APKLeaks | `apkleaks` | Mobile | Apache-2.0 | published format |
| NowSecure | `nowsecure` (SARIF) | Mobile | Commercial | published format |
| Contrast Assess | `contrast` | IAST | Commercial | published format |
| Falco | `falco` | Runtime | Apache-2.0 | published format (needs kernel privileges) |
| Tetragon | `tetragon` | Runtime | Apache-2.0 | published format (needs kernel privileges) |
| Tracee | `tracee` | Runtime | Apache-2.0 | published format (needs kernel privileges) |
| garak | `garak` | AI/LLM | Apache-2.0 | real run |
| promptfoo | `promptfoo` | AI/LLM | MIT | real run |
| ProtectAI ModelScan | `modelscan` | AI model files | Apache-2.0 | real run |
| HackerOne | `hackerone`, `hackerone-csv` | Pentest / bug bounty | Commercial | published format |
| Bugcrowd | `bugcrowd` | Pentest / bug bounty | Commercial | published format |
| Intigriti | `intigriti` | Pentest / bug bounty | Commercial | published format |
| ClusterFuzzLite / CIFuzz | `clusterfuzzlite` (SARIF) | Fuzzing | Apache-2.0 | published format |
| libFuzzer, Jazzer | `libfuzzer` | Fuzzing | Apache-2.0 WITH LLVM-exception (libFuzzer), Apache-2.0 (Jazzer) | real run (libFuzzer); published format (Jazzer) |

Not added: Oversecured (no published report format found), Akto (only HTML and PDF reports are documented), Black Duck Seeker and HCL AppScan IAST (no publicly documented export), Intigriti CSV (only the API JSON is documented).
