# PATHOS 2.2.0 end-to-end validation report

| | |
|---|---|
| Date | 2026-11-19/20 (UTC 18:50 – 21:00) |
| Release under test | PATHOS **2.2.0**, tag `v2.2.0`, commit `f3c5efd` (origin/main), signed GHCR release images `ghcr.io/quditmind/*:2.2.0` (their revision label is the same commit) |
| Fixes | Branch `test/e2e-validation`, 25 fix commits plus this report on top of `v2.2.0` (§6). The re-run in §5.3 used these fixes: patched `pathos`, `pathos-worker` and worker scripts mounted over the 2.2.0 images |
| Purpose | Find out what works and what breaks before deploying to about 50 customers |

## 1. Summary

PATHOS installed cleanly from the documented steps, and the core platform worked end to end on real projects: archive import, scanning, findings, dashboard, posture, SBOM, reports, the CLI, CI templates, the MCP server, AI review with a local model, and backup. The smoke test passed 90 of 90 checks. The Go unit tests, the Go integration suite (including the multi-tenancy isolation suite) and the frontend tests all passed before and after the fixes.

The opt-in **family worker images** did not work cleanly in 2.2.0. Every one of the 14 SAST-family scans and 12 of 15 IaC-family scans ended *partial*, because language tools failed on repositories without their language, the Psalm report path was wrong, and Kubescape's wording had changed. Several shared-cache races made scans fail at random once more than one worker ran: Trivy's database (SIGBUS) and Trivy's scan cache (lock timeout). The SBOM download returned an empty file. API scan targets could not be scanned without the intrusive flag. Turning on S3 object storage on an existing installation made every repository unscannable, and a worker that died during a scan could block a repository's queue forever. All of these are fixed on the branch, with tests, and the re-run confirms the fixes on the live stack (§5.3).

Before customer rollout, decide whether these limits are acceptable or must be fixed first (2.2.2 fixes the first four; see §9 for the status of each open issue):

- the SCM import needs a token even for public repositories;
- there is no private-CA option for registries, webhooks and ticketing;
- only one execution per repository runs at a time (DAST blocks CI imports);
- the secret scanners of the SAST family are noisy.

| Scan type / feature | 2.2.0 as released | With the fixes on this branch |
|---|---|---|
| Secrets (Gitleaks; TruffleHog, detect-secrets, Kingfisher, Talisman) | Pass (noisy) | Pass (noisy; detect-secrets hangs on juice-shop) |
| SAST (Opengrep; Semgrep CE, Bandit, gosec, Psalm, PHPStan, ESLint, njsscan, Bearer, Flawfinder, cppcheck, Ruff, Pylint, ShellCheck, golangci-lint) | **Fail**: every family scan partial | Pass on 12 of 15. gosec runs out of memory on alertmanager and gitlab-cli; golangci-lint needs vendored modules (O4) |
| SCA (Trivy fs, Grype, OSV-Scanner) | Partial (OSV fails on Maven; Trivy SIGBUS race) | Pass |
| SCA family (govulncheck, pip-audit, npm/yarn/pnpm/Composer audit, bundler-audit, cargo-audit, Retire.js, Dependency-Check, GuardDog, depcheck, cdxgen, pathos-reach) | **Fail**: every scan partial (Dependency-Check could never reach the NVD) | Partial: pip-audit, cdxgen, govulncheck and yarn fixed; Dependency-Check reaches the NVD after its fix but stalled in scans (O17) |
| IaC (Checkov; KICS, Kubescape, KubeLinter, TFLint, Conftest, Hadolint, cfn-lint, cfn_nag, Polaris, kube-score, Trivy config, Scorecard) | **Fail**: Kubescape failed on 12 of 15 | Pass on 11 of 15. Kubescape still fails on repositories with unparseable YAML/JSON (O16); TFLint fails on terragoat (O8) |
| CI/CD (actionlint, zizmor) | Pass | Pass |
| Licences | Pass | Pass |
| SBOM: generate, import, export | **Fail**: the CycloneDX export was the AI-BOM (0 components) | Pass |
| Container images (Trivy image) | **Fail** with the documented allowlist (Docker Hub hosts missing; concurrent Trivy lock) | Pass |
| DAST URL, not intrusive (Nuclei, ZAP baseline) | Pass: Juice Shop 17 findings (Nuclei), DVWA 5; with ZAP baseline, Juice Shop 64 | Pass |
| DAST URL, intrusive (Wapiti, Dalfox, ffuf, Arjun), intrusive gate | Gate pass (409 without authorization) | Untested: on the small validation API, Nuclei (which always runs first on URL targets) stalled with no traffic, three times, before the intrusive tools started (O14); the intrusive gate works |
| API DAST without intrusive flag (Nuclei on OpenAPI) | **Fail**: "no templates provided" | Partial: runs, but exceeds the 30-minute default timeout at 20 req/s |
| API DAST intrusive (Nuclei DAST, ZAP API scan, Schemathesis) | Partial: Nuclei DAST fails on required parameters | Pass: ZAP API finds SQLi and XSS, Schemathesis a server error; Nuclei DAST fixed (`2f034bc`, verified manually) |
| Mobile (APK: mobsfscan, APKLeaks, Quark, mobile checks, hardening) | Pass | Pass |
| Binary artifacts (CVE Binary Tool, capa, YARA-X, hardening) | Partial: CVE Binary Tool needs a database build (5 GB RAM) | Pass after the database build |
| AI (ModelScan on a model file) | Pass | Pass |
| LLM endpoint (garak, promptfoo) | Partial: promptfoo 6 findings; garak aborted on a 60 s timeout of the CPU model | Same (O18) |
| Fuzzing (Go native in the sandbox) | Pass on self-contained modules; "build-failed" reported as success elsewhere | Same (open issue) |
| Malware (ClamAV) | Untested (profile not enabled, 2 GB RAM) | Untested |
| Endpoint verification, live secret validation | Untested (would contact internet hosts) | Untested |
| Result imports (SARIF, Gitleaks, Grype, Trivy, Semgrep, AWS Security Hub ASFF, Amazon Inspector) | Pass (progress left at 50 %) | Pass |
| CLI (`scan`, `gate`, `import`, `findings`, `sbom export`) | Partial (`gate --repo` picked target scans) | Pass |
| MCP server (JSON-RPC over streamable HTTP) | Pass | Pass |
| AI review and analyst (Ollama, local model) | **Fail** with a small model: no output limit, 3-minute timeouts | Pass with qwen2.5:1.5b; 0.5b ends as "truncated" |
| Object storage (LocalStack S3) | **Fail** when enabled on an existing installation | Pass |
| Backup | Pass | Pass |
| Restore | Pass (41 s; data back to the backup state) | Pass |

## 2. Environment

| | |
|---|---|
| Host | Laptop, 13th Gen Intel Core i7-13800H (20 threads), 30 GB RAM (about 11 GB free at the start, swap full), NVIDIA RTX 3500 Ada 12 GB (not used), NVMe |
| OS | Ubuntu 26.04.1 LTS, kernel 7.0.0-42 |
| Docker | Engine 29.9.3, Compose 5.7.1 |
| Stack | Compose project `e2e`, ports 9443/9080, Mailpit on 8026. Other stacks were running on the same host (the owner's `pathos-*` stack and other projects), so memory was tight throughout |
| Images | `ghcr.io/quditmind/pathos{,-proxy,-worker-core,-worker-sast,-worker-iac,-worker-sca,-worker-dast,-worker-mobile,-worker-binary,-worker-ai,-worker-fuzz}:2.2.0`, Keycloak 26.8.2, PostgreSQL 18.7, Valkey 9.1.3, Squid 7.2, Ollama 0.40.13, LocalStack 4.4 |
| Tool versions | From the workers' registrations: actionlint 1.7.12, apkleaks 2.6.3, arjun 2.2.7, atheris 3.1.0, bandit 1.9.4, bearer 2.1.3, bundler-audit 0.9.3, capa 10.0.0, cargo-audit 0.23.0, cdxgen 12.9.2, cfn-lint 1.60.1, cfn-nag 3.3.0, checkov 3.4.5, composer 2.11.2, conftest 0.71.1, cosign 3.1.4, cppcheck 2.19.0, cve-bin-tool 3.4.1, dalfox 3.3.0, dependency-check 13.0.0, detect-secrets 1.5.0, eslint 10.15.0, ffuf 2.3.0, flawfinder 2.0.20, garak 0.17.1, gitleaks 8.30.1, Go 1.27.4, golangci-lint 2.15.0, gosec 2.30.0, govulncheck 1.10.0, grype 0.121.3, guarddog 3.2.0, hadolint 2.15.1, kics 2.2.1, kingfisher 2.19.1, kube-linter 0.8.3, kube-score 1.20.0, kubescape 4.0.21, mobsfscan 1.2.0, modelscan 0.8.8, njsscan 1.0.2, npm 12.2.3, nuclei 3.11.1, opengrep 2.0.0, osv-scanner 2.7.1, phpstan 2.3.6, pip-audit 2.10.1, pnpm 11.28.12, polaris 10.2.6, promptfoo 0.126.0, psalm 7.11.0, pylint 4.1.4, quark-engine 26.11.1, retire.js 6.1.1, ruff 0.17.5, schemathesis 4.33.4, scorecard 5.7.0, semgrep 1.172.0, shellcheck 0.11.0, sslyze 6.3.1, syft 1.57.1, talisman 1.37.0, testssl 3.2.5, tflint 0.66.0, trivy 0.76.2, trufflehog 3.99.9, wapiti 3.3.2, yara-x 1.23.0, yarn 1.22.22, ZAP 2.17.0, zizmor 1.32.0 |
| Local model | Ollama `qwen2.5:0.5b` and `qwen2.5:1.5b` on CPU in the stack's own `ollama` service |

## 3. Method

1. **Install as a customer would.** Run `deploy/scripts/install.sh` in the worktree. In `.env`, set the release image prefix and version, ports 9443/9080 and `COMPOSE_PROJECT_NAME=e2e`. Start with `docker compose up -d --wait`, then run `scripts/smoke-test.py`. Every confusing step is listed in §8.
2. **Projects.** 15 public repositories cloned anonymously (`git clone --depth 1`), packed with `git archive` and imported through the documented upload API (resumable parts, then `POST /api/v1/repository-imports`). The SCM import needs a token for every provider (§7), so the upload path was the only option.
3. **Scan profiles.** One profile per worker family: `e2e-core` (every core repository scanner plus the SBOM), `e2e-sast`, `e2e-iac`, `e2e-sca`, `e2e-binary`, `e2e-ai` and `e2e-fuzz`, each with every runnable non-target tool of its family. Family workers were started in batches (sast, iac and sca; then dast and mobile; then binary, ai and fuzz with the sandbox runner). Each batch was stopped when its scans were done, and `free -g` was watched throughout.
4. **Scan targets.** Images from Docker Hub and Quay. Deliberately vulnerable apps started on a private, internal Docker network (`e2e-targets`, no internet) that only the egress proxy could reach through a `conf.d` override: OWASP Juice Shop 17.1.1, DVWA, and a small deliberately vulnerable Python API with an OpenAPI document (SQL injection, reflected XSS). Also an APK, a binary, a pickle model file and an LLM endpoint (the local Ollama).
5. **Everything else.** Run through the API, CLI and MCP; connectors were tested by a parallel agent on local services only (§7). Results were collected from `GET /api/v1/scans` and `/stages` (`~/.cache/pathos-e2e/evidence/executions.json`), and screenshots were taken with Playwright (§5.4).
6. **Fixes.** Every bug that was clearly a bug and small enough was fixed on the branch with a unit or integration test (which fails without the fix where practical). Then `gofmt`, `go vet ./...`, `go test ./...`, the integration suite and the frontend tests were run. Patched binaries and scripts were mounted over the 2.2.0 images, and the affected scans were run again.

## 4. Projects

| # | Asset name | Source (anonymous clone) | Covers | Archive (bytes) | Import time |
|---|---|---|---|---:|---:|
| 1 | alertmanager | https://github.com/prometheus/alertmanager | Go, mid-size CNCF production project, Dockerfile, GitHub Actions, JS UI | 962,117 | 3.1 s |
| 2 | webgoat | https://github.com/WebGoat/WebGoat | Java (Maven), deliberately vulnerable | 16,262,613 | 3.1 s |
| 3 | dvpwa | https://github.com/anxolerd/dvpwa | Python (aiohttp), deliberately vulnerable, Dockerfile | 1,004,970 | 3.1 s |
| 4 | juice-shop | https://github.com/juice-shop/juice-shop | JavaScript/TypeScript, deliberately vulnerable | 20,338,108 | 3.2 s |
| 5 | dvcsharp-api | https://github.com/appsecco/dvcsharp-api | C#/.NET, deliberately vulnerable | 18,529 | 3.1 s |
| 6 | dvwa | https://github.com/digininja/DVWA | PHP, deliberately vulnerable | 934,173 | 3.1 s |
| 7 | railsgoat | https://github.com/OWASP/railsgoat | Ruby on Rails, deliberately vulnerable | 6,311,373 | 3.1 s |
| 8 | insecurebankv2 | https://github.com/dineshshetty/Android-InsecureBankv2 | Android app (Java, Gradle) plus APKs, Python server | 24,981,625 | 3.2 s |
| 9 | terragoat | https://github.com/bridgecrewio/terragoat | Terraform (AWS, Azure, GCP), deliberately vulnerable | 391,683 | 3.1 s |
| 10 | kubernetes-goat | https://github.com/madhuakula/kubernetes-goat | Kubernetes manifests, Helm charts, Dockerfiles, Go | 102,268,556 | 3.5 s |
| 11 | spring-petclinic | https://github.com/spring-projects/spring-petclinic | Java (Maven and Gradle), Spring Boot | 460,668 | 3.0 s |
| 12 | gitlab-cli | https://gitlab.com/gitlab-org/cli | Go, GitLab CI (`.gitlab-ci.yml`), from GitLab.com | 18,686,548 | 3.1 s |
| 13 | go-toml | https://github.com/pelletier/go-toml | Go library with native fuzz tests | 1,013,724 | 3.1 s |
| 14 | ado-dotnet-public-wiki | https://dev.azure.com/dnceng-public/public/_git/dotnet-public-wiki | Public Azure DevOps repository (Markdown) | 3,282 | 3.1 s |
| 15 | bb-aws-ecr-push-image | https://bitbucket.org/atlassian/aws-ecr-push-image | Bitbucket Cloud: Python, Dockerfile, `bitbucket-pipelines.yml` | 15,611 | 3.1 s |

Every import completed. Each item took about 3 s from the start of the upload to the registered repository.

## 5. Results

### 5.1 Totals

| Executions | Count |
|---|---:|
| cancelled | 13 |
| failed | 56 |
| partial | 64 |
| succeeded | 115 |
| **total** | 248 |

The 56 *failed* include:

- 39 scans that failed on the missing source snapshots after S3 was enabled; they were retried after fix 14;
- 9 image-target scans that failed on the egress allowlist, the Trivy cache lock and the Java DB tmpfs before the fixes;
- 2 executions failed by the lease fix;
- scans killed when workers were recreated;
- the API scan that timed out.

Findings in the database at the end, by category (open / all):

| Category | Open | All |
|---|---:|---:|
| secrets | 25640 | 26651 |
| iac | 4323 | 4323 |
| container | 2988 | 2988 |
| sca | 2598 | 2598 |
| sast | 2004 | 2011 |
| code-quality | 736 | 736 |
| mobile | 631 | 631 |
| malware | 579 | 580 |
| license | 503 | 503 |
| other | 160 | 160 |
| supply-chain | 75 | 157 |
| dast | 69 | 70 |
| database | 32 | 32 |
| crypto | 32 | 32 |
| misconfiguration | 32 | 32 |
| api | 23 | 23 |
| binary | 18 | 18 |
| cicd | 16 | 16 |
| ai | 7 | 7 |
| compliance | 2 | 2 |
| runtime | 1 | 1 |

### 5.2 Per execution (2.2.0 run and re-run with the fixes)

Durations are wall-clock seconds as PATHOS reports them. Findings are the distinct findings of the execution; C/H/M/L/I are critical, high, medium, low and info. "By category" adds up the per-scanner counts, so it can exceed the distinct total. QD-SCAN-000001–000104 ran on 2.2.0 as released. QD-SCAN-000105–000195 ran with the fixes but with the family tools refused because of the mounted scripts' permissions (see §5.3). QD-SCAN-000196 and later are the valid re-run with the fixes.


#### Profile `e2e-core`

| Scan | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners |
|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000001 | ado-dotnet-public-wiki | succeeded | 165 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000002 | alertmanager | partial | 185 | 75 | 1/43/27/4/0 | – | – |
| QD-SCAN-000003 | bb-aws-ecr-push-image | succeeded | 182 | 15 | 2/0/13/0/0 | – | – |
| QD-SCAN-000004 | dvcsharp-api | succeeded | 176 | 21 | 0/12/9/0/0 | iac 4, sast 2, sca 4, secrets 21 | – |
| QD-SCAN-000005 | dvpwa | succeeded | 27 | 7 | 0/1/6/0/0 | – | – |
| QD-SCAN-000006 | dvwa | succeeded | 19 | 40 | 0/16/18/6/0 | – | – |
| QD-SCAN-000007 | gitlab-cli | succeeded | 31 | 35 | 0/22/11/2/0 | – | – |
| QD-SCAN-000008 | go-toml | succeeded | 22 | 59 | 0/26/25/8/0 | – | – |
| QD-SCAN-000009 | insecurebankv2 | succeeded | 14 | 1 | 0/0/1/0/0 | – | – |
| QD-SCAN-000010 | juice-shop | succeeded | 27 | 261 | 0/61/186/13/1 | – | – |
| QD-SCAN-000011 | kubernetes-goat | succeeded | 25 | 504 | 7/90/382/25/0 | – | – |
| QD-SCAN-000012 | railsgoat | succeeded | 19 | 331 | 8/43/138/131/11 | iac 16, sast 1, sca 531, secrets 1 | – |
| QD-SCAN-000013 | spring-petclinic | partial | 15 | 58 | 0/8/49/1/0 | – | – |
| QD-SCAN-000014 | terragoat | succeeded | 28 | 1329 | 96/396/791/46/0 | – | – |
| QD-SCAN-000015 | webgoat | succeeded | 26 | 608 | 1/67/532/7/1 | – | – |
| QD-SCAN-000149 | alertmanager | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000150 | spring-petclinic | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000151 | railsgoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000155 | railsgoat | succeeded | 25 | 331 | 8/43/138/131/11 | iac 16, sast 1, sca 531, secrets 1 | – |
| QD-SCAN-000156 | spring-petclinic | succeeded | 21 | 58 | 0/8/49/1/0 | iac 57, sast 1 | – |
| QD-SCAN-000157 | alertmanager | succeeded | 28 | 75 | 1/43/27/4/0 | iac 7, sast 1, sca 80, secrets 19 | – |

#### Profile `e2e-sast`

| Scan | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners |
|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000016 | ado-dotnet-public-wiki | partial | 33 | 1 | 0/1/0/0/0 | – | – |
| QD-SCAN-000017 | alertmanager | partial | 75 | 3137 | 0/2193/4/940/0 | – | – |
| QD-SCAN-000018 | bb-aws-ecr-push-image | partial | 30 | 43 | 0/8/0/34/1 | – | – |
| QD-SCAN-000019 | dvcsharp-api | partial | 24 | 123 | 0/52/2/69/0 | – | – |
| QD-SCAN-000020 | dvpwa | partial | 75 | 148 | 1/8/4/128/7 | sast 297, secrets 128 | gosec (failed), cppcheck (failed), psalm (failed) |
| QD-SCAN-000021 | dvwa | partial | 60 | 1024 | 20/178/38/788/0 | – | – |
| QD-SCAN-000022 | gitlab-cli | partial | 195 | 3853 | 15/1418/22/2391/7 | – | – |
| QD-SCAN-000023 | go-toml | partial | 55 | 684 | 0/26/6/645/7 | – | – |
| QD-SCAN-000024 | insecurebankv2 | partial | 40 | 561 | 1/223/55/216/66 | – | – |
| QD-SCAN-000025 | juice-shop | failed | 1640 | 35 | 0/35/0/0/0 | – | – |
| QD-SCAN-000026 | kubernetes-goat | partial | 77 | 2412 | 3/2178/17/209/5 | – | – |
| QD-SCAN-000027 | railsgoat | partial | 52 | 723 | 14/324/14/369/2 | – | – |
| QD-SCAN-000028 | spring-petclinic | partial | 30 | 33 | 0/8/0/25/0 | sast 1, secrets 32 | gosec (failed), cppcheck (failed), psalm (failed), eslint-security (failed) |
| QD-SCAN-000029 | terragoat | partial | 72 | 2122 | 0/1994/0/128/0 | – | – |
| QD-SCAN-000030 | webgoat | partial | 205 | 1833 | 33/237/81/1445/37 | – | – |
| QD-SCAN-000106 | ado-dotnet-public-wiki | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000107 | alertmanager | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000108 | bb-aws-ecr-push-image | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000109 | dvcsharp-api | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000110 | dvpwa | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000111 | dvwa | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000112 | gitlab-cli | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000113 | go-toml | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000114 | insecurebankv2 | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000115 | juice-shop | succeeded | 203 | 10976 | 21/4086/44/6823/2 | code-quality 4, sast 1935, secrets 10480 | – |
| QD-SCAN-000116 | kubernetes-goat | succeeded | 1 | 5 | 0/5/0/0/0 | secrets 11 | – |
| QD-SCAN-000117 | railsgoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000118 | spring-petclinic | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000119 | terragoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000120 | webgoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000182 | webgoat | succeeded | 195 | 1846 | 33/237/81/1445/50 | code-quality 52, sast 1628, secrets 1581 | – |
| QD-SCAN-000183 | terragoat | succeeded | 1 | 3 | 0/3/0/0/0 | secrets 4 | – |
| QD-SCAN-000184 | spring-petclinic | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000185 | railsgoat | succeeded | 1 | 1 | 0/1/0/0/0 | secrets 1 | – |
| QD-SCAN-000186 | insecurebankv2 | succeeded | 1 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000187 | go-toml | succeeded | 1 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000188 | gitlab-cli | succeeded | 5 | 16 | 0/16/0/0/0 | secrets 17 | – |
| QD-SCAN-000189 | dvwa | succeeded | 0 | 1 | 0/1/0/0/0 | secrets 1 | – |
| QD-SCAN-000190 | dvcsharp-api | succeeded | 0 | 11 | 0/11/0/0/0 | secrets 21 | – |
| QD-SCAN-000191 | bb-aws-ecr-push-image | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000192 | alertmanager | succeeded | 1 | 16 | 0/16/0/0/0 | secrets 19 | – |
| QD-SCAN-000193 | ado-dotnet-public-wiki | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000195 | ado-dotnet-public-wiki | succeeded | 35 | 1 | 0/1/0/0/0 | secrets 1 | – |
| QD-SCAN-000196 | alertmanager | partial | 91 | 3137 | 0/2193/4/940/0 | sast 24, secrets 3116 | gosec (failed), golangci-lint (failed) |
| QD-SCAN-000197 | bb-aws-ecr-push-image | succeeded | 44 | 43 | 0/8/0/34/1 | code-quality 1, sast 10, secrets 33 | – |
| QD-SCAN-000198 | dvcsharp-api | succeeded | 26 | 123 | 0/52/2/69/0 | sast 2, secrets 131 | – |
| QD-SCAN-000199 | dvpwa | succeeded | 74 | 148 | 1/8/4/128/7 | sast 297, secrets 128 | – |
| QD-SCAN-000200 | dvwa | succeeded | 49 | 1747 | 20/254/38/1435/0 | code-quality 399, sast 983, secrets 461 | – |
| QD-SCAN-000201 | gitlab-cli | partial | 198 | 3853 | 15/1418/22/2391/7 | code-quality 31, sast 158, secrets 3697 | gosec (failed) |
| QD-SCAN-000202 | go-toml | succeeded | 56 | 689 | 0/31/6/645/7 | code-quality 95, sast 17, secrets 587 | – |
| QD-SCAN-000203 | insecurebankv2 | succeeded | 47 | 561 | 1/223/55/216/66 | code-quality 145, sast 70, secrets 395 | – |
| QD-SCAN-000204 | juice-shop | succeeded | 249 | 10976 | 21/4086/44/6823/2 | code-quality 4, sast 1935, secrets 10480 | – |
| QD-SCAN-000205 | kubernetes-goat | succeeded | 70 | 2412 | 3/2178/17/209/5 | code-quality 30, sast 51, secrets 2363 | – |
| QD-SCAN-000206 | railsgoat | succeeded | 49 | 723 | 14/324/14/369/2 | sast 578, secrets 640 | – |
| QD-SCAN-000207 | spring-petclinic | succeeded | 28 | 33 | 0/8/0/25/0 | sast 1, secrets 32 | – |
| QD-SCAN-000208 | terragoat | succeeded | 76 | 2122 | 0/1994/0/128/0 | secrets 2123 | – |
| QD-SCAN-000209 | webgoat | succeeded | 200 | 1839 | 33/237/81/1445/43 | code-quality 52, sast 1620, secrets 1581 | – |

#### Profile `e2e-iac`

| Scan | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners |
|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000044 | ado-dotnet-public-wiki | partial | 6 | 4 | 0/1/2/1/0 | – | – |
| QD-SCAN-000045 | alertmanager | partial | 8 | 258 | 0/30/72/75/81 | – | – |
| QD-SCAN-000046 | bb-aws-ecr-push-image | partial | 47 | 33 | 0/10/6/16/1 | – | – |
| QD-SCAN-000047 | dvcsharp-api | partial | 13 | 32 | 0/14/12/5/1 | iac 17, secrets 21, supply-chain 4 | kubescape (failed) |
| QD-SCAN-000048 | dvpwa | partial | 15 | 44 | 0/7/25/10/2 | – | – |
| QD-SCAN-000049 | dvwa | partial | 22 | 264 | 0/24/60/151/29 | – | – |
| QD-SCAN-000050 | gitlab-cli | partial | 25 | 33 | 0/20/6/4/3 | – | – |
| QD-SCAN-000051 | go-toml | partial | 5 | 17 | 0/2/1/13/1 | – | – |
| QD-SCAN-000052 | insecurebankv2 | partial | 6 | 5 | 0/2/2/0/1 | – | – |
| QD-SCAN-000053 | juice-shop | partial | 81 | 337 | 10/75/133/57/62 | – | – |
| QD-SCAN-000054 | kubernetes-goat | succeeded | 201 | 1449 | 4/481/549/365/50 | – | – |
| QD-SCAN-000055 | railsgoat | succeeded | 25 | 71 | 0/15/28/17/11 | – | – |
| QD-SCAN-000056 | spring-petclinic | succeeded | 25 | 159 | 1/41/63/52/2 | iac 152, supply-chain 7 | – |
| QD-SCAN-000057 | terragoat | partial | 26 | 492 | 18/124/190/102/58 | – | – |
| QD-SCAN-000058 | webgoat | partial | 44 | 57 | 0/18/23/14/2 | – | – |
| QD-SCAN-000121 | ado-dotnet-public-wiki | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000122 | alertmanager | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000123 | bb-aws-ecr-push-image | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000124 | dvcsharp-api | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000125 | dvpwa | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000126 | dvwa | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000127 | gitlab-cli | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000128 | go-toml | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000129 | insecurebankv2 | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000130 | juice-shop | succeeded | 3 | 29 | 0/29/0/0/0 | secrets 75 | – |
| QD-SCAN-000131 | kubernetes-goat | succeeded | 138 | 1449 | 4/481/549/365/50 | iac 1448, secrets 11, supply-chain 5 | – |
| QD-SCAN-000132 | railsgoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000133 | spring-petclinic | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000134 | terragoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000135 | webgoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000170 | webgoat | succeeded | 2 | 16 | 0/16/0/0/0 | secrets 24 | – |
| QD-SCAN-000171 | terragoat | succeeded | 1 | 3 | 0/3/0/0/0 | secrets 4 | – |
| QD-SCAN-000172 | spring-petclinic | succeeded | 1 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000173 | railsgoat | succeeded | 1 | 1 | 0/1/0/0/0 | secrets 1 | – |
| QD-SCAN-000174 | insecurebankv2 | succeeded | 1 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000175 | go-toml | succeeded | 7 | 17 | 0/2/1/13/1 | iac 14, supply-chain 3 | – |
| QD-SCAN-000176 | gitlab-cli | succeeded | 5 | 16 | 0/16/0/0/0 | secrets 17 | – |
| QD-SCAN-000177 | dvwa | succeeded | 0 | 1 | 0/1/0/0/0 | secrets 1 | – |
| QD-SCAN-000178 | dvcsharp-api | succeeded | 0 | 11 | 0/11/0/0/0 | secrets 21 | – |
| QD-SCAN-000179 | bb-aws-ecr-push-image | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000180 | alertmanager | succeeded | 1 | 16 | 0/16/0/0/0 | secrets 19 | – |
| QD-SCAN-000181 | ado-dotnet-public-wiki | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000210 | ado-dotnet-public-wiki | succeeded | 5 | 4 | 0/1/2/1/0 | supply-chain 4 | – |
| QD-SCAN-000211 | alertmanager | succeeded | 9 | 258 | 0/30/72/75/81 | iac 238, secrets 19, supply-chain 4 | – |
| QD-SCAN-000212 | bb-aws-ecr-push-image | succeeded | 46 | 33 | 0/10/6/16/1 | iac 28, supply-chain 5 | – |
| QD-SCAN-000213 | dvcsharp-api | partial | 15 | 32 | 0/14/12/5/1 | iac 17, secrets 21, supply-chain 4 | kubescape (failed) |
| QD-SCAN-000214 | dvpwa | succeeded | 17 | 44 | 0/7/25/10/2 | iac 39, supply-chain 5 | – |
| QD-SCAN-000215 | dvwa | succeeded | 23 | 264 | 0/24/60/151/29 | iac 258, secrets 1, supply-chain 5 | – |
| QD-SCAN-000216 | gitlab-cli | partial | 23 | 33 | 0/20/6/4/3 | iac 13, secrets 17, supply-chain 4 | kubescape (failed) |
| QD-SCAN-000217 | go-toml | succeeded | 6 | 17 | 0/2/1/13/1 | iac 14, supply-chain 3 | – |
| QD-SCAN-000218 | insecurebankv2 | succeeded | 5 | 5 | 0/2/2/0/1 | supply-chain 5 | – |
| QD-SCAN-000219 | juice-shop | partial | 72 | 337 | 10/75/133/57/62 | iac 348, secrets 75, supply-chain 5 | kubescape (failed) |
| QD-SCAN-000220 | kubernetes-goat | succeeded | 210 | 1449 | 4/481/549/365/50 | iac 1448, secrets 11, supply-chain 5 | – |
| QD-SCAN-000221 | railsgoat | succeeded | 26 | 71 | 0/15/28/17/11 | iac 64, secrets 1, supply-chain 6 | – |
| QD-SCAN-000222 | spring-petclinic | succeeded | 25 | 159 | 1/41/63/52/2 | iac 152, supply-chain 7 | – |
| QD-SCAN-000223 | terragoat | partial | 22 | 492 | 18/124/190/102/58 | iac 564, secrets 4, supply-chain 6 | tflint (failed) |
| QD-SCAN-000224 | webgoat | succeeded | 41 | 57 | 0/18/23/14/2 | iac 35, secrets 24, supply-chain 6 | – |

#### Profile `e2e-sca`

| Scan | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners |
|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000078 | ado-dotnet-public-wiki | partial | 11 | 0 | 0/0/0/0/0 | – | dependency-check (failed) |
| QD-SCAN-000079 | alertmanager | partial | 51 | 74 | 0/33/17/24/0 | malware 24, sca 36, secrets 19 | dependency-check (failed), govulncheck (failed) |
| QD-SCAN-000080 | bb-aws-ecr-push-image | partial | 18 | 21 | 0/0/2/19/0 | malware 21 | dependency-check (failed), pip-audit (failed) |
| QD-SCAN-000081 | dvcsharp-api | partial | 9 | 11 | 0/11/0/0/0 | secrets 21 | dependency-check (failed) |
| QD-SCAN-000082 | dvpwa | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000083 | dvwa | partial | 12 | 1 | 0/1/0/0/0 | secrets 1 | dependency-check (failed) |
| QD-SCAN-000084 | gitlab-cli | partial | 32 | 23 | 0/16/2/5/0 | malware 3, sca 4, secrets 17 | dependency-check (failed), govulncheck (failed) |
| QD-SCAN-000085 | go-toml | partial | 13 | 0 | 0/0/0/0/0 | – | dependency-check (failed) |
| QD-SCAN-000086 | insecurebankv2 | partial | 13 | 16 | 0/0/2/14/0 | malware 16 | dependency-check (failed), pip-audit (failed), cdxgen (failed) |
| QD-SCAN-000087 | juice-shop | succeeded | 3 | 29 | 0/29/0/0/0 | secrets 75 | – |
| QD-SCAN-000088 | kubernetes-goat | partial | 65 | 53 | 1/10/9/33/0 | malware 33, sca 15, secrets 11 | dependency-check (failed), govulncheck (failed), pip-audit (failed), yarn-audit (failed) |
| QD-SCAN-000089 | railsgoat | partial | 10 | 151 | 8/37/74/21/11 | sca 302, secrets 1 | dependency-check (failed) |
| QD-SCAN-000090 | spring-petclinic | partial | 7 | 0 | 0/0/0/0/0 | – | dependency-check (failed), cdxgen (failed) |
| QD-SCAN-000091 | terragoat | partial | 126 | 845 | 72/253/241/279/0 | malware 287, sca 653, secrets 4, supply-chain 1 | dependency-check (failed), cdxgen (failed) |
| QD-SCAN-000092 | webgoat | partial | 11 | 61 | 0/18/39/4/0 | sca 45, secrets 24 | dependency-check (failed), cdxgen (failed) |
| QD-SCAN-000136 | ado-dotnet-public-wiki | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000137 | alertmanager | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000138 | bb-aws-ecr-push-image | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000139 | dvcsharp-api | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000140 | dvwa | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000141 | gitlab-cli | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000142 | go-toml | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000143 | insecurebankv2 | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000144 | kubernetes-goat | succeeded | 1 | 5 | 0/5/0/0/0 | secrets 11 | – |
| QD-SCAN-000145 | railsgoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000146 | spring-petclinic | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000147 | terragoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000148 | webgoat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000158 | webgoat | succeeded | 2 | 16 | 0/16/0/0/0 | secrets 24 | – |
| QD-SCAN-000159 | terragoat | succeeded | 1 | 3 | 0/3/0/0/0 | secrets 4 | – |
| QD-SCAN-000160 | spring-petclinic | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000161 | railsgoat | succeeded | 1 | 1 | 0/1/0/0/0 | secrets 1 | – |
| QD-SCAN-000162 | insecurebankv2 | succeeded | 1 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000163 | go-toml | succeeded | 1 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000164 | gitlab-cli | succeeded | 5 | 16 | 0/16/0/0/0 | secrets 17 | – |
| QD-SCAN-000165 | dvwa | succeeded | 0 | 1 | 0/1/0/0/0 | secrets 1 | – |
| QD-SCAN-000166 | dvcsharp-api | succeeded | 0 | 11 | 0/11/0/0/0 | secrets 21 | – |
| QD-SCAN-000167 | bb-aws-ecr-push-image | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000168 | alertmanager | succeeded | 1 | 16 | 0/16/0/0/0 | secrets 19 | – |
| QD-SCAN-000169 | ado-dotnet-public-wiki | succeeded | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000225 | ado-dotnet-public-wiki | partial | 8 | 0 | 0/0/0/0/0 | – | dependency-check (failed) |
| QD-SCAN-000226 | alertmanager | partial | 58 | 74 | 0/33/17/24/0 | malware 24, sca 36, secrets 19 | dependency-check (failed), govulncheck (failed) |
| QD-SCAN-000227 | bb-aws-ecr-push-image | partial | 16 | 21 | 0/0/2/19/0 | malware 21 | dependency-check (failed) |
| QD-SCAN-000228 | dvcsharp-api | partial | 7 | 11 | 0/11/0/0/0 | secrets 21 | dependency-check (failed) |
| QD-SCAN-000229 | dvpwa | cancelled | 1101 | 0 | 0/0/0/0/0 | – | dependency-check (cancelled), retirejs (cancelled), govulncheck (cancelled), pip-audit (cancelled), cargo-audit (cancelled), bundler-audit (cancelled), pathos-reach (cancelled), npm-audit (cancelled), yarn-audit (cancelled), pnpm-audit (cancelled), composer-audit (cancelled), guarddog (cancelled), pathos-depcheck (cancelled), cdxgen (cancelled) |
| QD-SCAN-000230 | dvwa | partial | 9 | 1 | 0/1/0/0/0 | secrets 1 | dependency-check (failed) |
| QD-SCAN-000231 | gitlab-cli | partial | 32 | 23 | 0/16/2/5/0 | malware 3, sca 4, secrets 17 | dependency-check (failed) |
| QD-SCAN-000232 | go-toml | partial | 8 | 0 | 0/0/0/0/0 | – | dependency-check (failed) |
| QD-SCAN-000233 | insecurebankv2 | partial | 21 | 16 | 0/0/2/14/0 | malware 16 | dependency-check (failed) |
| QD-SCAN-000234 | juice-shop | partial | 172 | 222 | 0/29/23/170/0 | malware 193, secrets 75 | dependency-check (failed) |
| QD-SCAN-000235 | kubernetes-goat | partial | 86 | 65 | 4/12/16/33/0 | malware 33, sca 28, secrets 11 | dependency-check (failed), yarn-audit (failed) |
| QD-SCAN-000236 | railsgoat | partial | 11 | 151 | 8/37/74/21/11 | sca 302, secrets 1 | dependency-check (failed) |
| QD-SCAN-000237 | spring-petclinic | partial | 9 | 0 | 0/0/0/0/0 | – | dependency-check (failed) |
| QD-SCAN-000238 | terragoat | partial | 141 | 845 | 72/253/241/279/0 | malware 287, sca 653, secrets 4, supply-chain 1 | dependency-check (failed) |
| QD-SCAN-000239 | webgoat | partial | 15 | 61 | 0/18/39/4/0 | sca 45, secrets 24 | dependency-check (failed) |
| QD-SCAN-000245 | alertmanager | cancelled | 1882 | 16 | 0/16/0/0/0 | secrets 19 | dependency-check (cancelled), retirejs (cancelled), govulncheck (cancelled), pip-audit (cancelled), cargo-audit (cancelled), bundler-audit (cancelled), pathos-reach (cancelled), npm-audit (cancelled), yarn-audit (cancelled), pnpm-audit (cancelled), composer-audit (cancelled), guarddog (cancelled), pathos-depcheck (cancelled), cdxgen (cancelled) |
| QD-SCAN-000246 | kubernetes-goat | cancelled | 0 | 0 | 0/0/0/0/0 | – | gitleaks (cancelled), dependency-check (cancelled), retirejs (cancelled), govulncheck (cancelled), pip-audit (cancelled), cargo-audit (cancelled), bundler-audit (cancelled), pathos-reach (cancelled), npm-audit (cancelled), yarn-audit (cancelled), pnpm-audit (cancelled), composer-audit (cancelled), guarddog (cancelled), pathos-depcheck (cancelled), cdxgen (cancelled) |
| QD-SCAN-000247 | railsgoat | cancelled | 0 | 0 | 0/0/0/0/0 | – | gitleaks (cancelled), dependency-check (cancelled), retirejs (cancelled), govulncheck (cancelled), pip-audit (cancelled), cargo-audit (cancelled), bundler-audit (cancelled), pathos-reach (cancelled), npm-audit (cancelled), yarn-audit (cancelled), pnpm-audit (cancelled), composer-audit (cancelled), guarddog (cancelled), pathos-depcheck (cancelled), cdxgen (cancelled) |
| QD-SCAN-000248 | webgoat | cancelled | 0 | 0 | 0/0/0/0/0 | – | gitleaks (cancelled), dependency-check (cancelled), retirejs (cancelled), govulncheck (cancelled), pip-audit (cancelled), cargo-audit (cancelled), bundler-audit (cancelled), pathos-reach (cancelled), npm-audit (cancelled), yarn-audit (cancelled), pnpm-audit (cancelled), composer-audit (cancelled), guarddog (cancelled), pathos-depcheck (cancelled), cdxgen (cancelled) |
| QD-SCAN-000249 | terragoat | cancelled | 0 | 0 | 0/0/0/0/0 | – | gitleaks (cancelled), dependency-check (cancelled), retirejs (cancelled), govulncheck (cancelled), pip-audit (cancelled), cargo-audit (cancelled), bundler-audit (cancelled), pathos-reach (cancelled), npm-audit (cancelled), yarn-audit (cancelled), pnpm-audit (cancelled), composer-audit (cancelled), guarddog (cancelled), pathos-depcheck (cancelled), cdxgen (cancelled) |

#### Profile `e2e-binary`

| Scan | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners |
|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000101 | insecurebankv2 | succeeded | 1 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000102 | dvwa | succeeded | 1 | 1 | 0/1/0/0/0 | secrets 1 | – |

#### Profile `e2e-ai`

| Scan | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners |
|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000099 | dvpwa | cancelled | 0 | 0 | 0/0/0/0/0 | – | gitleaks (cancelled), modelscan (cancelled) |
| QD-SCAN-000100 | juice-shop | succeeded | 6 | 29 | 0/29/0/0/0 | secrets 75 | – |

#### Profile `e2e-fuzz`

| Scan | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners |
|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000096 | go-toml | succeeded | 75 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000097 | dvpwa | succeeded | 2 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000098 | alertmanager | succeeded | 3 | 16 | 0/16/0/0/0 | secrets 19 | – |

#### Scan targets

| Scan | Kind | Target | Repository | Status | Duration (s) | Findings | C/H/M/L/I | By category | Failed scanners / error |
|---|---|---|---|---|---:|---:|---|---|---|
| QD-SCAN-000031 | image | nginx:1.25 | kubernetes-goat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000032 | image | vulnerables/web-dvwa | dvwa | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000033 | image | ghcr alertmanager | alertmanager | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000034 | url | juice-shop local | juice-shop | succeeded | 849 | 17 | 0/0/1/0/16 | – | – |
| QD-SCAN-000035 | url | dvwa local | dvwa | succeeded | 581 | 5 | 0/0/1/0/4 | – | – |
| QD-SCAN-000036 | api | vulnapi local | dvpwa | failed | 1 | 0 | 0/0/0/0/0 | – | nuclei (failed) |
| QD-SCAN-000037 | image | e2e-kind legacy nginx:1.16 | kubernetes-goat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000038 | image | e2e-registry shop:1.0 | alertmanager | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000060 | image | nginx:1.25 | kubernetes-goat | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000061 | image | vulnerables/web-dvwa | dvwa | failed | 0 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000062 | image | nginx:1.25 | kubernetes-goat | failed | 3 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000063 | image | vulnerables/web-dvwa | dvwa | failed | 2 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000064 | url | juice-shop local | juice-shop | succeeded | 1039 | 64 | 0/0/11/21/32 | dast 65 | – |
| QD-SCAN-000065 | url | vulnapi intrusive web | dvpwa | cancelled | 2402 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000066 | mobile-app | InsecureBankv2.apk | insecurebankv2 | succeeded | 64 | 634 | 6/4/208/414/2 | – | – |
| QD-SCAN-000072 | sbom | railsgoat-sbom | railsgoat | succeeded | 10 | 258 | 3/29/102/124/0 | sca 258 | – |
| QD-SCAN-000075 | image | e2e-registry shop:1.0 | alertmanager | failed | 0 | 0 | 0/0/0/0/0 | – | trivy-image (failed) |
| QD-SCAN-000076 | image | e2e-kind legacy nginx:1.16 | kubernetes-goat | failed | 2 | 0 | 0/0/0/0/0 | – | trivy-image (failed) |
| QD-SCAN-000093 | image | e2e-kind podinfo | ado-dotnet-public-wiki | succeeded | 4 | 471 | 22/228/205/14/2 | container 471 | – |
| QD-SCAN-000094 | image | nginx:1.25 | kubernetes-goat | failed | 734 | 0 | 0/0/0/0/0 | – | – |
| QD-SCAN-000095 | image | vulnerables/web-dvwa | dvwa | failed | 5 | 0 | 0/0/0/0/0 | – | trivy-image (failed) |
| QD-SCAN-000103 | artifact | curl-8.11.1 | go-toml | partial | 27 | 18 | 0/0/2/8/8 | binary 18 | cve-bin-tool (failed) |
| QD-SCAN-000104 | artifact | model.pkl | go-toml | succeeded | 1 | 1 | 1/0/0/0/0 | ai 1 | – |
| QD-SCAN-000105 | llm-endpoint | local qwen2.5 0.5b | dvpwa | partial | 286 | 6 | 0/5/1/0/0 | ai 6 | garak (failed) |
| QD-SCAN-000152 | image | nginx:1.25 | kubernetes-goat | failed | 148 | 0 | 0/0/0/0/0 | – | trivy-image (failed) |
| QD-SCAN-000153 | image | vulnerables/web-dvwa | dvwa | succeeded | 27 | 1575 | 254/551/643/115/12 | container 1575 | – |
| QD-SCAN-000154 | api | vulnapi local | dvpwa | failed | 1800 | 0 | 0/0/0/0/0 | – | nuclei (timed_out) |
| QD-SCAN-000194 | artifact | curl-8.11.1 | go-toml | succeeded | 30 | 78 | 11/28/21/10/8 | binary 18, sca 60 | – |
| QD-SCAN-000240 | api | vulnapi local | dvpwa | cancelled | 0 | 0 | 0/0/0/0/0 | – | nuclei (cancelled), zap-api-scan (cancelled), schemathesis (cancelled) |
| QD-SCAN-000241 | url | vulnapi intrusive web (2) | ado-dotnet-public-wiki | cancelled | 1134 | 0 | 0/0/0/0/0 | – | nuclei (cancelled), wapiti (cancelled), dalfox (cancelled), ffuf (cancelled), arjun (cancelled) |
| QD-SCAN-000242 | api | vulnapi intrusive api (2) | bb-aws-ecr-push-image | cancelled | 0 | 0 | 0/0/0/0/0 | – | nuclei (cancelled), zap-api-scan (cancelled), schemathesis (cancelled) |
| QD-SCAN-000243 | image | nginx:1.25 | kubernetes-goat | succeeded | 184 | 940 | 21/236/343/269/71 | container 940 | – |
| QD-SCAN-000244 | image | vulnerables/web-dvwa | dvwa | succeeded | 37 | 1575 | 254/551/643/115/12 | container 1575 | – |
| QD-SCAN-000250 | url | vulnapi intrusive web (2) | ado-dotnet-public-wiki | cancelled | 1463 | 0 | 0/0/0/0/0 | – | nuclei (cancelled), wapiti (cancelled), dalfox (cancelled), ffuf (cancelled), arjun (cancelled) |
| QD-SCAN-000251 | api | vulnapi intrusive api (2) | bb-aws-ecr-push-image | partial | 927 | 23 | 1/6/5/9/2 | api 25 | nuclei (failed) |
| QD-SCAN-000252 | url | vulnapi intrusive web (2) | ado-dotnet-public-wiki | cancelled | 198 | 0 | 0/0/0/0/0 | – | nuclei (cancelled), wapiti (cancelled), dalfox (cancelled), ffuf (cancelled), arjun (cancelled) |

#### Other repository executions (result imports, CLI and CI runs, onboarding)

| Scan | Name | Repository | Status | Duration (s) | Findings |
|---|---|---|---|---:|---:|
| QD-SCAN-000039 | Import · Semgrep | dvpwa | succeeded | 0 | 1 |
| QD-SCAN-000040 | dvpwa · Default | dvpwa | succeeded | 27 | 7 |
| QD-SCAN-000042 | Import · AWS Security Hub | bb-aws-ecr-push-image | succeeded | 0 | 4 |
| QD-SCAN-000043 | Import · Amazon Inspector | bb-aws-ecr-push-image | succeeded | 0 | 2 |
| QD-SCAN-000059 | Import · Semgrep | dvpwa | succeeded | 0 | 1 |
| QD-SCAN-000069 | Import · gitleaks | dvcsharp-api | succeeded | 0 | 1 |
| QD-SCAN-000070 | Import · Grype | dvcsharp-api | succeeded | 0 | 258 |
| QD-SCAN-000071 | Import · trivy | dvcsharp-api | succeeded | 0 | 159 |
| QD-SCAN-000073 | go-toml · e2e-core | go-toml | succeeded | 24 | 59 |
| QD-SCAN-000077 | Import · Semgrep | ado-dotnet-public-wiki | succeeded | 0 | 1 |


### 5.3 Re-run with the fixes

The re-runs used the 2.2.0 images with the patched `pathos` and `pathos-worker` binaries and the patched wrapper scripts mounted over them. The first re-run (QD-SCAN-000105 to 000195) is not valid as a test of the fixes. The mounted scripts were group-writable, so the workers correctly refused those manifests, and the scans "succeeded" with the family tools *skipped* (open issue O15). Second re-run (QD-SCAN-000196 and later, all 15 repositories per family):

| Profile | 2.2.0 | With fixes | Failed scanners, 2.2.0 → with fixes |
|---|---|---|---|
| `e2e-core` | 13 succeeded, 2 partial | 3 of 3 re-run succeeded (alertmanager, spring-petclinic, railsgoat) | osv-scanner 1, trivy-fs 1 → none |
| `e2e-sast` | 14 partial | 12 succeeded, 2 partial | gosec 12, cppcheck 14, psalm 14, eslint-security 6, golangci-lint 1 → gosec 2 (OOM on alertmanager and gitlab-cli, O4), golangci-lint 1 (alertmanager, O4) |
| `e2e-iac` | 12 partial, 3 succeeded | 11 succeeded, 4 partial | kubescape 12, tflint 1 → kubescape 3 (repositories with unparseable YAML/JSON: a duplicate key in gitlab-cli, a UTF-8 BOM in dvcsharp-api's `appsettings.json`; O16), tflint 1 (O8) |
| `e2e-sca` | 13 partial, 2 succeeded | 14 partial | dependency-check 13, cdxgen 4, govulncheck 3, pip-audit 3, yarn-audit 1 → dependency-check 14 (fixed afterwards, `0bc0772`, see below), govulncheck 1 and yarn-audit 1 (fixed afterwards, `329805f`) |

Other re-runs:

- **Psalm on DVWA:** it runs, with 77 taint issues in the manual check.
- **cdxgen on InsecureBankv2:** succeeded.
- **pip-audit:** succeeded on all repositories.
- **Image targets:**
  - `docker.io/library/nginx:1.25`: QD-SCAN-000243 succeeded, 940 findings. Before: refused hosts, then the Trivy scan-cache lock, then "no space left" for the Java DB.
  - `vulnerables/web-dvwa`: QD-SCAN-000244 succeeded, 1,575 findings.
- **SBOM export:** CycloneDX with 203 components; before the fix, 0.
- **`pathos gate --repo dvwa`:** now evaluates the repository scan.
- **AI review:** a valid verdict with qwen2.5:1.5b. With 0.5b it ends quickly as "truncated".
- **Stuck executions:** the two executions that had blocked their repositories were released by the lease fix as soon as it was deployed.
- **Object storage:** after the fallback fix, the 39 failed scans were retried and passed.
- **Dependency-Check (`0bc0772`):** with the proxy flags it downloaded the NVD feeds (255 MB) and wrote its report in a manual run in worker-sca. In the two scan runs afterwards, the process sat at 0 % CPU for 30+ minutes after creating `odc.update.lock`, and the scans were cancelled. This is not resolved (O17).
- **API target without the intrusive flag (`c0ba7f4`):** Nuclei now loads its templates on the URL list. With about 8,100 templates on 3 URLs at 20 req/s, it hit the 30-minute profile timeout (QD-SCAN-000154), and its partial results were discarded (O14).
- **API target with intrusive testing:** QD-SCAN-000251 partial.
  - ZAP API scan: 21 findings, including **SQL Injection** and **Cross Site Scripting (Reflected)** in the deliberately vulnerable API.
  - Schemathesis: 4 findings, including a critical "Server error (GET /api/users)" caused by the SQL injection.
  - Nuclei DAST: failed on required parameters without examples. Fixed afterwards (`2f034bc`); in a manual run it found the reflected XSS in 4 s.
- **LLM endpoint (QD-SCAN-000105, the local qwen2.5:0.5b):** promptfoo succeeded with 6 findings. garak failed: a 60-second read timeout of the slow CPU model aborted the whole run without a report (O18).

### 5.4 Dashboard, findings, posture, SBOM, reports, exports

All screenshots were captured by Playwright as the bootstrap administrator, with no page errors and no API 5xx responses on any of the 16 pages:

- **Dashboard** (`/`): 25,942 open findings (336 critical), 15 repositories, scan coverage 100 %, 86 scans completed, success rate 86 % (before the fixes).
- **Findings, posture, coverage, attack paths, SBOM inventory, reports, executive overview, repositories, scans, scan targets, scan coverage, scanners, runtime, AI, compliance:** every page loaded with the validation data.
- **API output saved:** `/api/v1/dashboard`, `/executive`, `/findings/summary` (critical 255, high 10,480, medium 4,090, low 9,213, info 482 at that time), `/posture/applications`, `/posture/coverage`, `/posture/attack-paths` (5 paths with runtime exposure from the kind cluster), `/scan-types`, `/sbom/components`.
- **Exports:** SBOM in CycloneDX (after the fix: 203 components for railsgoat) and SPDX 2.3 (199 packages); raw scanner artifacts (`/scans/{id}/results/{scanner}/artifact`); findings through the CLI.

### 5.5 Backup and restore

- `deploy/scripts/backup.sh` (online): 11 s, 209 MB (`pathos.dump` 20.6 MB, `keycloak.dump`, `caddy_data.tgz`, `sources.tgz` 197 MB, manifest with checksums).
- Restore: `deploy/scripts/restore.sh backups/pathos-20261119T194229Z --yes` took 41 s. Before the restore the database had 248 executions and 41,571 findings; afterwards it had the backup's state (15 repositories, 101 executions, 26,239 findings). The API, jobs, scheduler and workers came back healthy, the existing API token worked, and a new scan of a restored repository (go-toml) succeeded. The script's final `up --wait` reported an error only because the LocalStack container added for this test fails its own health check (no internet DNS); the PATHOS services were healthy.

## 6. Bugs found and fixed

All the commits are on `test/e2e-validation` and are not pushed. Each has a test; "fails before" means the new or changed test was run against the unfixed code and failed.

| # | Commit | Area | Bug (evidence) | Fix and test |
|---|---|---|---|---|
| 1 | `7913c1b` | worker, OSV-Scanner | OSV-Scanner resolves Maven parent POMs from `repo.maven.apache.org`, which is not on the allowlist. It exited 127 and failed on every Maven project with a remote parent (spring-petclinic: execution partial) | `--no-resolve`, online and offline. Unit test; verified with the real tool in worker-core |
| 2 | `43cf148` | worker, Trivy | Workers share the Trivy database. An update by one worker while another was scanning crashed the scan with SIGBUS in bbolt (alertmanager, after 2 min 36 s) | File lock on the shared cache: update under an exclusive lock, scan under a shared lock with `--skip-db-update`; a fresh database is not re-locked. Four unit tests (ordering, concurrency, failure, cancel) |
| 3 | `12dcde0` | worker, Trivy | Trivy locks its file-based scan cache for the whole run, so a second concurrent Trivy on another worker failed after 5 s ("cache may be in use by another process"): the dvwa image scan; three parallel `trivy fs` runs all failed | `--cache-backend memory`. Unit test; reproduced and verified in the container |
| 4 | `c0ba7f4` | worker, Nuclei | API targets without the intrusive flag ran Nuclei with `-im openapi` and the ordinary templates. Nuclei loads none of them for that input: "no templates provided for scan", so every such API scan failed | URL list of the base URL, servers and operations (path parameters filled in, at most 500). Unit tests; verified with the real Nuclei (8,187 templates loaded) |
| 5 | `fbfe37b` | worker, manifests | gosec, cppcheck, ESLint and Psalm failed on repositories without Go, C, JS or PHP, so every SAST-family scan was partial (15 of 15) | New manifest field `requires_files`: the tool is skipped when no file matches. Set for gosec, golangci-lint, cppcheck, Psalm, PHPStan and ESLint. Unit tests, docs |
| 6 | `631067b` | worker-sast, Psalm | Psalm infers the report format from the extension, and the output is `psalm.out`, so it crashed on every PHP repository ("Unknown report format") | Report to `report.json` and copy. Verified on DVWA: 792 issues, 77 with taint traces |
| 7 | `8cb6c6f` | worker-iac, Kubescape | Kubescape 4.0 reports "no scannable Kubernetes resources found" for a repository with YAML but no manifests, and the wrapper knew only the old message: Kubescape failed on 12 of 15 repositories | Accept both messages, plus a build-time check in the Dockerfile. Fails before with the original wrapper |
| 8 | `01733cb` | worker-sca, pip-audit | pip-audit refuses a whole requirements file with one unpinned or wildcard line (InsecureBankv2 "flask", "boto3==1.37.*") | Audit only the exactly pinned lines and log how many were left out. Python unit test with a stand-in; verified with the real pip-audit |
| 9 | `2c5c0e7` | worker-sca, cdxgen | Under the Node.js permission model, cdxgen crashed reading `~/.gradle` and `~/.m2` on Gradle and Maven projects (ERR_ACCESS_DENIED, InsecureBankv2) | HOME and GRADLE_USER_HOME inside its temporary directory. Unit test fails before; verified with the real cdxgen |
| 10 | `9e2bac3` | egress, govulncheck | proxy.golang.org redirects module downloads to `storage.googleapis.com`, which is not in the opt-in `sca-registries.conf`, so govulncheck failed on alertmanager and gitlab-cli | Host added to the file and OPERATIONS.md |
| 11 | `f248124` | API, SBOM export | `GET /repositories/{id}/sbom` (and `pathos sbom export`) returned the newest artifact of kind `sbom`, which is the AI-BOM: CycloneDX with 0 components (railsgoat; the SPDX export had 199) | Exclude the AI-BOM and target scans. Integration test fails before |
| 12 | `21d4c76` | CLI | `pathos gate --repo` took the newest execution of any kind, including image and DAST target scans (dvwa: a failed image scan failed the gate) | `asset_type=repository`. CLI test fails before; docs |
| 13 | `9eaba11` | AI | No output limit for OpenAI, xAI and self-hosted reviews: a small local model generated until the 3-minute timeout, and the review was retried | Default `max_tokens` 4096 (self-hosted) or 16000. Unit test |
| 14 | `4a6b4c3` | Object storage | With S3 enabled after repositories were imported, uploads and snapshots on the `sources` volume were never read again: 39 of 39 scans failed ("snapshot download failed … 500") | Read from the volume when the bucket lacks the object. Unit test; verified live with LocalStack |
| 15 | `9caf041` | Scan queue | An expired lease was not requeued while the same scan was queued again. The job stayed running for good and blocked the repository (one running execution per repository): kubernetes-goat and juice-shop were stuck | Fail the expired job ("the same scan is queued again"). Integration test fails before; verified live (both repositories resumed) |
| 16 | `a39b5ad` | Image targets | Trivy prints only "Forbidden" when the egress proxy refuses a registry host | The worker names the refused host and the allowlist to change. Unit test, INSTALLATION.md |
| 17 | `7d539cc` | worker, Trivy | Trivy downloads its Java database (about 1 GB) to `$TMPDIR`, which is the worker's 1 GB `/tmp` tmpfs, so image scans failed with "write /tmp/getter…: no space left on device" (nginx:1.25) | `TMPDIR` on the cache volume. Unit test; verified live (nginx:1.25 succeeded, 940 findings) |
| 18 | `329805f` | worker-sca | govulncheck failed on a module whose files all carry a build tag ("no packages matched", alertmanager `internal/tools`), and yarn 1 audits go to `registry.yarnpkg.com`, which was not in `sca-registries.conf` | Empty run for such modules; host added. Python unit test |
| 19 | `0bc0772` | worker-sca, Dependency-Check | Java ignores `HTTPS_PROXY` and the worker networks have no internet DNS, so Dependency-Check never reached the NVD (UnknownHostException, exit 13) on 15 of 15 repositories | `--proxyserver`/`--proxyport` from `HTTPS_PROXY`. Python unit test; verified manually (NVD downloaded, report written); see O17 |
| 20 | `2f034bc` | worker, Nuclei DAST | Intrusive API scans: Nuclei stopped on required OpenAPI parameters without examples ("Found 2 missing parameters", exit 1) and tried to write to the read-only working directory | `-skip-format-validation`. Unit test; verified manually (reflected XSS found) |
| 21 | `f2fa7d1`, `b154573` | Docs | The CVE Binary Tool database update was killed at 2 GB and 4 GB (exit 247), and the upload import example in the API docs failed with 422 (default required fields) | Docs |

Fixed by the connector agent (same branch):

| # | Commit | Bug | Fix |
|---|---|---|---|
| 22 | `3042043` | Result imports left the execution at stage "scanning", 50 %, so the CLI printed "succeeded (scanning, 50%)" | Update progress after finalizing. Integration test fails before |
| 23 | `12da86f` | The documented Docker Hub egress hosts were wrong, and so was the target's `egress_host` (`registry-1.docker.io` instead of `index.docker.io` and the CDN) | Code, test, docs |
| 24 | `ee206b2` | Editing a runtime cluster without pasting the CA again deleted the stored CA, so the next sync failed with x509 | Keep the CA. Integration test fails before; docs |

Tests after all fixes: `gofmt` clean, `go vet ./...` clean, `go test ./...` (44 packages) passed, integration suite `ok pathos/test/integration`, frontend typecheck plus vitest 43 files / 228 tests passed, `workers/sca/test/test_pathos_sca.py` 10 tests passed. The final run, after the last commit, was all green as well (`gofmt -l` empty, `go vet` 0, `go test ./...` 44 packages ok, integration ok in 28 s).

## 7. Connectors and integrations

All tested on local services or public read-only endpoints, with no real accounts.

| Connector | Result | Evidence |
|---|---|---|
| GitHub / GitLab.com / Bitbucket Cloud / Azure DevOps import of **public** repositories without a token | **Not supported** | `GET /api/v1/scm-providers`: every auth method requires a token or app credentials. `POST /scm-connections` with an empty token gives 400 "token is required". Workaround: anonymous clone plus archive upload (done for gitlab.com, bitbucket.org and dev.azure.com) |
| Generic git-URL import | Not supported | Import `source` is only `git`, `devops` or `upload` |
| Self-hosted Git (Gitea 1.22.6, org with dvpwa and terragoat pushed) | **Not supported** | There is no Gitea or Forgejo provider. `github_enterprise`/`gitlab` with `http://` give 400 "base URL must use https". With https the connection saves with status error (API not compatible, private address needs `PATHOS_SCM_ALLOW_PRIVATE_NETWORKS` and a restart) |
| Kubernetes runtime (kind cluster, read-only ClusterRole from `deploy/kubernetes`) | **Works** (after fix 24) | Sync found 12 workloads, Ingress exposure and a privileged container. A critical CVE on the image of a deployed workload went from risk 39.4 to 94.8 with the factors `deployed` (running in e2e-kind/shop/podinfo) and `runtime_exposure` (Ingress https://podinfo.example.com/) |
| Container registry connector (registry:2 with OCI labels, self-signed TLS) | **Fails for private CAs** | "x509: certificate signed by unknown authority". There is no `ca_cert` field (clusters have one), and `http://` is refused without `PATHOS_SCM_ALLOW_HTTP` |
| AWS S3 artifact store (LocalStack 4.4, S3 only) | **Works** (after fix 14) | Bucket created by the API; `pathosctl migrate-artifacts` moved 668 artifacts in 3 s; new SBOMs and raw reports are stored in S3 |
| MinIO | Not tested | MinIO images are no longer pullable anonymously from Docker Hub or Quay (registry 401) |
| Jenkins (LTS, JCasC, `integrations/jenkins/Jenkinsfile`) | **Works** | Build #1 SUCCESS: CLI 2.2.0 downloaded and checksum-verified, import, scan, gate PASSED with `PATHOS_CA_CERT` |
| GitHub Action template | **Works** (simulated runner) | install-cli.sh, import, gate PASSED, outputs `scan-id` and `gate-passed`; actionlint clean |
| GitLab CI template | **Works** (scripts run in alpine) | Import, then the gate correctly FAILED with exit 1 at `--fail-on high` |
| Email notifications (Mailpit) | **Works** | "[PATHOS] 148 new findings in dvpwa" and others delivered; 16 `findings.new` deliveries |
| Webhooks (Slack, Teams, signed JSON) to a local HTTPS receiver | **Partial** | Created with `allow_private`, but test and deliveries fail on a private CA (x509). `sign` is silently ignored for Slack and Teams |
| Jira / ServiceNow | Untested | No open-source mock available; connection create and delete only |
| AWS Security Hub ASFF import | **Works** | 4 findings imported (compliance ×2, runtime, container); the PASSED record skipped |
| Amazon Inspector import | **Works** | 2 imported; the CLOSED one skipped |
| PATHOS MCP server (stdlib MCP client, streamable HTTP) | **Works** | `initialize` 200, `tools/list` → `list_pending_findings`, `get_finding_evidence`, `submit_review`. A review submitted (`interactive_mcp`, pending approval); an unknown tool is rejected by the registry (-32602) |
| CLI | **Works** | `pathos scan --repo go-toml` waited and succeeded (exit 0); `gate` exit codes 0 and 1 as documented; `import` of Gitleaks SARIF, Grype JSON and Trivy SARIF (1, 258 and 159 findings); `import --sbom` (SPDX, 199 components); `sbom export` (CycloneDX, SPDX) |
| AI review (self-hosted, Ollama) | **Works** with qwen2.5:1.5b | Verdict true_positive, confidence 0.95, severity high, rationale cites file and line; approved and applied. qwen2.5:0.5b: timeout before fix 13, "response truncated at the output token limit" after |
| AI analyst | Works mechanically | It answered with citations, but the content was wrong with the 1.5B model (it named terragoat as having the most critical findings). Quality depends on the model |
| AI fix proposals | Not available for uploaded repositories | "uploaded repositories have no SCM connection to check out and verify a fix" |

## 8. Steps that confused a first-time installer

1. **Project name and images.** `docker-compose.yml` sets `name: pathos`, and local builds tag the images `pathos:dev`. A second installation on the same host (staging next to production, or a test install) must set `COMPOSE_PROJECT_NAME`, and two local builds overwrite each other's images. Nothing warns about this. Use release images or a distinct `PATHOS_VERSION`.
2. **Non-standard port:** you must change both `PATHOS_HTTPS_PORT` and `PATHOS_PUBLIC_URL`. This is documented, but easy to miss.
3. `install.sh` ends with "Next: docker compose up -d", while the README uses `--wait`.
4. **Admin password for tests:** `scripts/smoke-test.py` reads `PATHOS_ADMIN_NEW_PASSWORD` from `.env`, but `scripts/e2e.sh` reads it only from the environment. After the smoke test changed the password, the browser tests could not sign in until the variable was exported.
5. **No anonymous import:** importing a public GitHub, GitLab, Bitbucket or Azure DevOps repository needs a token. The import page offers no URL field. A first-time user evaluating PATHOS on public projects must pack archives.
6. **API import example:** the upload example in `docs/api-reference/imports.md` failed with 422 because the default required fields include the technical owner and data classification (fixed in the docs).
7. **Egress allowlist:**
   - There is no reload; every change needs `docker compose restart egress`, which breaks downloads in progress. `squid -k reconfigure` does not work in the image (no PID file).
   - The documented Docker Hub hosts were wrong (fixed).
   - GitLab.com and Bitbucket are not in the default allowlist.
   - The opt-in SCA file lacked `storage.googleapis.com` (fixed).
   - Errors from tools were a bare "Forbidden" (fixed for images).
8. **Family workers are all-or-nothing in practice:** enabling `sast` made every scan partial (fixed). `iac`, `sca` and `binary` each had at least one tool that failed by default: Kubescape (fixed); Dependency-Check (needs an NVD API key); CVE Binary Tool (needs a separate database build with 5 GB RAM).
9. **CVE Binary Tool database:** the documented command names the volume `pathos_scanner_cache`, but the volume name depends on the project (`e2e_scanner_cache` here). It was killed twice without a message before it succeeded with 5 GB.
10. **Object storage on an existing install** broke every repository's scans (fixed). The documented `migrate-artifacts` moves only scan artifacts.
11. **Stopping a family worker during a scan** leaves the execution "running" for the 5-minute lease. On SIGTERM the worker could not report the failure ("terminated signal received"), and in one case the repository's queue was blocked for good (fixed).
12. **Long DAST scans:** Nuclei alone took 10–15 minutes per URL target with the default rate of 20 req/s, and it uses the repository's profile timeout (Default 1800 s). One intrusive run stalled with no traffic for 10 minutes until the egress proxy was restarted.
13. **MinIO** can no longer be pulled anonymously (outside PATHOS), so LocalStack was used.

## 9. Open issues and their status (2.2.2)

The 2.2.2 hardening release fixes most of these; the last column says what is fixed, how it was verified, and what remains. Details are in the [CHANGELOG](../CHANGELOG.md).

| # | Issue | Impact | Reproduction | Status (2.2.2) |
|---|---|---|---|---|
| O1 | **SCM import of public repositories needs a token.** There is no anonymous mode, no git-URL import and no Gitea/Forgejo provider | Evaluation and open-source customers must upload archives; no sync or webhooks for those | `GET /api/v1/scm-providers`; `POST /api/v1/scm-connections {"provider":"github","auth_type":"pat","token":""}` → 400 | **Fixed in 2.2.2**: `POST /api/v1/repositories/import-url` (anonymous, public only; private → `PTH-ONB-1102`). Gitea/Forgejo providers: not added (use the generic HTTPS git URL, anonymous only). Unit tests against stand-in GitHub, GitLab, Bitbucket, Azure DevOps and git smart-HTTP servers; integration test (import, lease without credential, sync turning private) |
| O2 | **One running execution per repository**, including scan targets (`scan_jobs_running_uq`). Result imports return 409 while any scan of the repository runs | A 15-minute DAST or image scan delays the repository's code scans and fails CI imports at random | Start a URL target scan on repository R, then `pathos import --repo R …` → 409 "a scan of this repository is running" | **Fixed in 2.2.2**: imports and target scans run next to a repository scan (migration 00043); integration test runs a target scan, a repository scan and four concurrent imports |
| O3 | **No private-CA option** for registry connections, outbound webhooks and ticket systems | Customers with an internal PKI cannot use these without a custom `SSL_CERT_FILE` mount on jobs and the workers | registry:2 with a self-signed cert → `POST /api/v1/runtime/registries` → sync "x509: certificate signed by unknown authority"; same for `/notifications/webhooks/{id}/test` | **Fixed in 2.2.2**: `ca_bundle_pem` on registry connections, webhooks and ticket connections (verification on, TLS 1.2 minimum). Unit tests against TLS servers with a private CA; integration test of the APIs. Image *targets* pulled by the workers (Trivy) still need `SSL_CERT_FILE` on the workers |
| O4 | **Go tools offline.** gosec was OOM-killed (exit 137) at 4 GB on alertmanager and gitlab-cli. golangci-lint fails with "no go files to analyze" on modules with non-vendored dependencies (`GOPROXY=off`). The fuzzers report "build-failed" for such modules, but the execution is *succeeded* with 0 findings | Missing Go SAST and fuzzing coverage on most real Go projects, reported as a success | e2e-sast on alertmanager (gosec failed, -1); e2e-fuzz on alertmanager (log "config/FuzzLoad: build-failed", status succeeded) | **Fixed in 2.2.2** for gosec (chunked per module/directory with `GOMEMLIMIT`; on go-toml the old helper was OOM-killed at 2 GB, the new one finished with all of its findings plus one) and for the fuzzers (build failures make the tool fail, execution partial). **Remaining**: golangci-lint and the fuzzers still cannot build modules with non-vendored dependencies offline (`GOPROXY=off`, by design); such repositories need `go mod vendor` |
| O5 | **Dependency-Check needs an NVD API key** in practice (exit 13 without one, on every repository) | The SCA family shows a failed scanner | e2e-sca on any repository without `/etc/pathos/sca.env` | **Documented in 2.2.2**: an NVD API key is a prerequisite (PRODUCTION_CHECKLIST); without data the tool fails naming it. Dependency-Check is in no default profile |
| O6 | **Secret scanner noise:** Talisman produced 567 low "base64/hex content" findings on go-toml and 3,430 on gitlab-cli. The dashboard showed 15,253 "exposed secrets" across 15 repositories | Unusable without tuning | e2e-sast profile; `GET /api/v1/scans/{id}/findings?scanner=talisman` | **Fixed in 2.2.2**: default secret exclusions per profile (vendored code, fixtures, lockfiles, minified files); Talisman can never enter the default profile. Measured on gitlab-cli: Talisman 3,432 → 2,420, detect-secrets 145 → 104; a SAST profile without Talisman 3,577 → 104. **Remaining**: Talisman's own noise on ordinary source files (567 of 578 on go-toml are `filecontent:low`) — keep it out of profiles |
| O7 | **detect-secrets hang:** on juice-shop it ran 27 minutes at 0 % CPU (20 idle pool processes) until the lease or tool timeout | The SAST execution takes 30+ minutes and its secret findings are lost | e2e-sast on juice-shop | **Fixed in 2.2.2**: detect-secrets runs with 2 processes (the hang was its per-core pool, one process killed for memory), skips the excluded files, 20-minute limit. gitlab-cli: 20 s. Not re-run on juice-shop |
| O8 | **TFLint fails on terragoat** with exit 1 and no message | One IaC tool missing on Terraform-heavy repositories | e2e-iac on terragoat | **Fixed in 2.2.2**: `tflint-tree` reports module load errors (terragoat: `terraform/aws` uses Terraform 0.11 syntax) and keeps the 12 issues of the other modules (result partial). Verified with the 2.2.0 iac image |
| O9 | **Worker shutdown:** on SIGTERM the worker cannot report the job as failed (its context is cancelled first), so executions stay running until the 5-minute lease expires | Slower recovery during upgrades and restarts | `docker compose stop worker-iac` during a scan; worker log "complete failed … terminated signal received" | **Fixed in 2.2.2**: a stopping worker releases its job (`/release`, back to the queue); unit and integration tests |
| O10 | **Runtime linking is broad:** an image target on a repository marks all of the repository's code findings as deployed and exposed (2,608 kubernetes-goat findings); a tag link counts even when no target scan ever succeeded | Risk scores inflated | See the connector notes in §7 | **Fixed in 2.2.2**: image targets link repository code only when marked `built_from_repository`; tag links need a successful target scan. Integration test. *Behaviour change* for existing image targets |
| O11 | **Webhook `sign` ignored** for Slack and Teams without an error | Operators may believe deliveries are signed | Create a Slack webhook with `sign: true` → `signed: false` | **Fixed in 2.2.2**: the API returns a warning and the UI explains that Slack/Teams deliveries are not signed |
| O12 | **SBOM noise:** the inventory lists entries such as `$/.github/workflows/ci.yml` (version UNKNOWN) and GitHub Actions as libraries | Clutters the SBOM page and exports | `/sbom` page, first rows | **Fixed in 2.2.2**: path-like entries are dropped, GitHub Actions typed `github-action` |
| O13 | **Stage of failed-by-lease executions** stays `scanning:<tool>` | Cosmetic | QD-SCAN-000025 after fix 15 | **Fixed in 2.2.2** |
| O15 | **A family profile "succeeds" without its tools.** When no online worker advertises every routed tool of a scan, any worker runs it and marks the missing tools *skipped*, and the execution is *succeeded*. In the validation, a mounted wrapper script with group-write permission made the worker refuse 14 SCA manifests and Psalm ("command must not be writable by group or others", a correct check). The 45 family re-runs then "succeeded" in 0–5 s with 17 of 18 tools skipped | A broken or missing family worker turns into green scans with no coverage | Stop `worker-sast`, run an `e2e-sast` scan: the execution succeeds with every family tool *skipped: scanner not available in this worker image* | **Fixed in 2.2.2**: such executions are partial (failed when nothing ran) with `PTH-SCAN-1101`; integration test |
| O16 | **Kubescape fails the run on any unparseable YAML/JSON file** in the repository: a duplicate mapping key in gitlab-cli, a UTF-8 BOM in an `appsettings.json` | The IaC family is partial on ordinary repositories. Kubescape should skip such files | e2e-iac on gitlab-cli and dvcsharp-api | **Fixed in 2.2.2**: unparseable files are skipped when there are no Kubernetes resources (gitlab-cli: `.vscode/launch.json`, a test `.gitlab-ci.yml`); verified with the 2.2.0 iac image |
| O17 | **Dependency-Check stalls in scans.** After the proxy fix it downloaded the NVD data in a manual run, but in two scan runs the Java process sat at 0 % CPU for 30+ minutes after creating `odc.update.lock` (the second worker waits on that lock) | The SCA family cannot finish while Dependency-Check is in the profile | e2e-sca on alertmanager with `0bc0772`; `/cache/plugins/dependency-check/data/odc.update.lock` | **Fixed in 2.2.2**: cause and fix in the CHANGELOG (no read timeout on the NVD download; update now separate, time-limited and locked; stale `odc.update.lock` removed; offline scan; partial result on cached data). Wrapper tests with a stalling stand-in. **Not re-run** with the real NVD in a scan |
| O18 | **garak aborts the whole run on one read timeout** (60 s) of a slow model, without a report | No garak results against slow or self-hosted CPU models | LLM endpoint target pointing at Ollama qwen2.5:0.5b on CPU | **Fixed in 2.2.2**: one garak run per probe, `GARAK_REQUEST_TIMEOUT` 180 s; stand-in test. Not re-run against Ollama on CPU |
| O14 | **Nuclei duration and timeouts:** 10–15 minutes per URL target with about 8,100 templates at 20 req/s. On an API target, 3 URLs exceeded the 30-minute default profile timeout, and Nuclei's partial results were discarded. Nuclei runs against the small validation API stalled (no requests, about 1.5 % CPU) three times, once until an egress restart, which kept the intrusive URL tools from running | DAST capacity planning; set a longer profile timeout and a higher rate for DAST targets; see O2 | QD-SCAN-000154 (timed_out) | **Partly fixed in 2.2.2**: partial Nuclei results are kept on timeout, URL/API target scans get at least 90 minutes. **Remaining**: Nuclei's duration (10–15 min per target) and the stalls against the small validation API were not investigated |

## 10. What the owner must do

1. **Review and merge** `test/e2e-validation` (26 commits) and cut a 2.2.1 release with the rebuilt images: worker-core, sast, iac and sca, plus the API image. Customers should not get 2.2.0 with the family workers enabled.
2. **Decide on O1–O3** before onboarding customers that use public repositories, GitLab/Bitbucket/Azure DevOps without tokens, private PKI, or CI imports next to DAST.
3. **Make an NVD API key a documented prerequisite** for Dependency-Check, or leave the tool out of the recommended SCA profile.
4. **Pick the recommended profile per family.** Leave Talisman out by default, and add gosec only for small Go repositories or with more worker memory.
5. **Use [PRODUCTION_CHECKLIST.md](PRODUCTION_CHECKLIST.md)** for each customer deployment.
