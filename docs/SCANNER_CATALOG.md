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

Opengrep runs PATHOS' own Apache-2.0 baseline rules; the community `opengrep-rules` pack carries a Commons Clause restriction and is not bundled. All other catalogue entries have no adapter yet: they can be selected only once a worker provides them, for example as a [declarative plugin](#declarative-scanner-adapters-plugins). Versions are listed in [DEPENDENCIES.md](DEPENDENCIES.md#scanners-in-worker-core).

**Not a scanner, but related:** ClamAV (GPL-2.0, optional `clamav` Compose profile) scans uploaded source archives and build artifacts for malware before PATHOS accepts them ([OPERATIONS.md](OPERATIONS.md#malware-scanning-clamav)). It does not produce findings and is not in the catalog.

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
| 8 | Bandit | SAST (Python) | Apache-2.0 | active | Use | |
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
| 21 | njsscan | SAST (Node) | LGPL-3.0 (*unverified*) | *unverified* | Use (verify) | |
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
| 49 | OWASP ZAP | DAST | Apache-2.0 | active | Use (target URL, not repo) | Runs against deployed app. Separate worker family and network policy |
| 50 | Nuclei | DAST / templated checks | MIT | active | Use (target URL) | **Implemented** (URL and API targets) |
| 51 | Schemathesis | API fuzzing (OpenAPI) | MIT | active | Use (target URL) | |
| 52 | kube-bench | K8s CIS (cluster) | Apache-2.0 (*unverified*) | *unverified* | Opt | Cluster target, not repo |

Count: **52 scanner integrations**: 45 "Use" plus 7 optional or license-restricted. The 8 supporting utilities below bring the total to 60 integrations.

## Supporting utilities (not counted as scanners)

| Tool | Role | License | Status |
|---|---|---|---|
| Syft | SBOM generation | Apache-2.0 | active |
| cdxgen (OWASP) | SBOM generation (CycloneDX) | Apache-2.0 | active (repo moved) |
| CycloneDX CLI | SBOM conversion/validation/merge | Apache-2.0 | active |
| SPDX tools-python | SPDX validation/conversion | Apache-2.0 | maintained (2026-03) |
| Cosign | Signature verification | Apache-2.0 | active |
| in-toto | Attestation verification | Apache-2.0 | active |
| slsa-verifier | SLSA provenance verification | Apache-2.0 | active |
| GUAC | Supply-chain graph (integration, later) | Apache-2.0 | active |

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

## Declarative scanner adapters (plugins)

Operators can add a scanner to `worker-core` without changing PATHOS: put a definition file in `deploy/scanners.d/` (mounted read-only at `/etc/pathos/scanners.d`; `PATHOS_SCANNER_PLUGINS_DIR` changes the path) and make the tool's executable available in the worker container (a derived image or a read-only mount). See `deploy/scanners.d/example.yaml.disabled`.

| Field | Meaning |
|---|---|
| `name` | Lowercase letters, digits, dashes (≤ 23). The scanner key is `plugin-<category>-<name>` |
| `display_name`, `homepage` | Shown in the catalog (homepage must be https) |
| `category` | `sast`, `sca`, `secrets`, `iac`, `container`, `license`, `dast` or `other` (the findings' type) |
| `command` | Absolute path of an existing executable that is not writable by group or others |
| `version_args` | Arguments that print the version (default `--version`) |
| `args` | Arguments; placeholders `{source}` (required), `{output}` (required unless `output: stdout`), `{cache}` (persistent per plugin), `{tmp}` (per run) |
| `ok_exit_codes` | Exit codes meaning success (default `0`; many tools exit `1` when they find something) |
| `output` | `file` (SARIF written to `{output}`, default) or `stdout` |
| `env` | Extra variables (not `PATH`, `HOME`, `LD_*`, `*_PROXY`, `PATHOS_*`) |

The tool must produce **SARIF 2.1.0**. When the worker registers, the plugin appears in **Scanners & workers** and can be added to scan profiles; results are normalized, deduplicated, risk-scored and triaged like any other scanner's. Invalid files are skipped with a log message; at most 20 plugins load.

Security: definitions are files on the worker host, never API input, so a PATHOS administrator cannot make workers run arbitrary programs. Plugins run exactly like built-in scanners: no shell, the worker's unprivileged user, its read-only source checkout, its sandbox and egress policy, and the job's timeout. They scan repository source only (not scan targets). The full trust model is in [SECURITY.md](SECURITY.md#scanner-plugins).


