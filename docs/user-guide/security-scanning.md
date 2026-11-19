---
title: "Security scanning: scanners and profiles"
section: user-guide
order: 10
version: "1.0"
updated: 2026-11-19
summary: How registered repositories enter the scanning pipeline, which scanners run, scanner plugins, scan profiles, custom rules, framework configuration rules, malware scanning, binary hardening, licence findings, SBOM and dependency analysis, source-version tracking and offline mode.
---

# Security scanning: scanners and profiles

Registering a repository makes it **eligible** for scanning. Scans run in isolated **worker** containers that fetch the code, run the scanners of a **scan profile**, and send normalized results back to PATHOS. Workers never receive platform secrets or a Docker socket.

This page explains *what* a scan does. How to start, schedule, follow and compare scans, scan deployed targets and import results from other tools is in [Running scans](scanning.md). What happens to the results is in [Working with findings](findings.md).

## How repositories enter the scanning pipeline

| Trigger (shown in **Scans → Trigger**) | When | Notes |
|---|---|---|
| `onboarding` | Right after registration, if **Administration → Asset settings → Scan on import** is on **and** *Start onboarding scan* was ticked in the wizard | **Off by default**: without it, importing does not start a scan |
| `manual` | **Start scan** on **Scanning → Scans**, **Scan now** on the repository's **Security** tab, or select repositories in the inventory and choose **Scan** (up to 1,000 at once) | Requires `scans.run`; also runs for repositories excluded from scheduled scans |
| `schedule` | A schedule under **Scanning → Scan Schedules** ([schedules](scanning.md#scan-schedules)) | Requires `schedules.manage`. Repositories marked *Excluded* from scheduled scans are skipped |
| `push`, `merge` | A provider [webhook](provider-integrations.md#webhooks) for a push or merge to the repository's **scan branch** | Pull requests are scanned only when [pull request checks](supply-chain.md#pull-request-checks) are on, and those scans never change the repository's findings |
| `emergency` | A bulk scan requested through the API with `trigger: emergency` (no button in the UI) | Highest queue priority; runs even for repositories excluded from scheduled scans |

Rules:

- **One queued scan per repository.** New triggers join the queued scan (*Already queued*) instead of piling up, and only one execution per repository runs at a time.
- **Archived repositories are never scanned**, nor repositories with scanning disabled on their **Security** tab.
- **Uploaded repositories** are scanned from their **current snapshot**; they cannot be scanned before the first snapshot exists. Push webhooks do not apply to them; upload a new version and scan it.
- **Git repositories** are cloned at scan time from the scan branch (shallow by default, full history if **Full history** was chosen at import).

## Scanners

**Configurations → Scanners & workers** lists the scanner catalog with license, **Availability** (*Available* or *Planned*) and policy (*mandatory*, *optional*, *license-restricted*, *requires build*). Filter with **Available now** to see what runs today; the other catalog entries (for example TruffleHog, Semgrep CE, CodeQL, KICS, ZAP) are planned and **do not run**.

Repository scanners of the `worker-core` image:

| Scanner (key) | Category | What it does in PATHOS |
|---|---|---|
| **Gitleaks** (`gitleaks`) | Secrets | Finds committed secrets such as API keys and passwords. **Mandatory** in every profile. Secret values are **redacted** in reports. Scans the working tree; with **Full history** it scans every commit |
| **Opengrep** (`opengrep`) | SAST | Static analysis with Semgrep-compatible rules: the PATHOS baseline rules, rule sets added by administrators and your [custom rules](#custom-rules). If no rule set is available it reports *no rule sets available* and produces no findings |
| **Trivy (filesystem)** (`trivy-fs`) | SCA | Known vulnerabilities in dependencies declared in lock files and manifests |
| **Syft** (`syft`) | SBOM | Generates a CycloneDX software bill of materials. A utility, not a finding source |
| **Grype** (`grype`) | SCA | Matches the Syft SBOM against vulnerability databases. Needs **Generate an SBOM** in the profile |
| **OSV-Scanner** (`osv-scanner`) | SCA | Checks dependencies against the OSV vulnerability database |
| **Checkov** (`checkov`) | IaC | Misconfiguration checks for Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM, Bicep, Serverless, GitHub Actions, GitLab CI and Azure Pipelines files |
| **actionlint** (`actionlint`) | IaC | GitHub Actions workflow checks (script injection, syntax, types); runs only when the repository has workflows |
| **zizmor** (`zizmor`) | IaC | GitHub Actions workflow security, see [CI/CD workflow security](#cicd-workflow-security) |
| **File licences (licensecheck)** (`licensecheck`) | License | Finds licences in repository files (SPDX-License-Identifier tags and licence texts); files whose licence the licence policy denies or flags for review become findings, see [Licence findings](#licence-findings). On by default in new profiles |
| **ClamAV (repository content)** (`clamav`) | Malware | Checks every file of the checked-out source with ClamAV, see [Malware scanning](#malware-scanning). Opt-in: needs the ClamAV service |
| **Binary hardening (checksec)** (`binary-hardening`) | Binary | Checks executables and shared libraries in the repository for missing compiler and linker hardening, see [Binary hardening](#binary-hardening). Always runs for build artifacts; add it to a profile to check repositories too |

Opengrep also runs the PATHOS **framework configuration rules**, whose findings have the type **Framework configuration**, see [Framework configuration rules](#framework-configuration-rules).

Scanners for [scan targets](scanning.md#scan-targets) run only for targets, never for repositories: **Trivy (image)** for container images, **Nuclei** for web applications and APIs, Grype for SBOMs, and Trivy and the binary hardening checks for build artifacts.

Application URLs, domains and IP addresses recorded on a repository are metadata only: PATHOS never scans them. Dynamic testing (DAST) runs only against web application and API **scan targets** that someone registered and authorized.

### Family workers and scanner plugins

Tools beyond the core set come from **tool manifests**:

- **Family worker images** add groups of tools. The `worker-sast` image (Compose profile `sast`, enabled by an administrator) adds **Bandit** (Python), **njsscan** (Node.js) and **ShellCheck** (shell scripts, findings of type *Code-quality security*). Once a family worker is online, its tools are marked *Runnable* in **Scanners & workers** and can be added to scan profiles; scans that use them run on that worker. The `worker-dast` image (profile `dast`) adds OWASP ZAP, Wapiti, Dalfox, ffuf, testssl.sh, SSLyze, Schemathesis and Arjun for authorized web application and API targets; they are chosen on the target, not in a scan profile ([DAST tools](dast.md)).
- **Scanner plugins**: operators can add a tool without changing PATHOS by placing a manifest in `deploy/scanners.d/` on the worker host and making the tool available in the worker container. When the worker registers, the plugin appears in **Scanners & workers** as *`<name>` (plugin)*. Plugins that scan repositories can be added to scan profiles; plugins for web applications, APIs, images or artifacts are selected on the [scan target](scanning.md#scan-targets) (**Additional tools**).

Results are normalized, de-duplicated, risk-scored and triaged like any other scanner's, and the tool's original output is kept as evidence. Manifests are files on the worker, never API input, so a PATHOS administrator cannot make workers run arbitrary programs. **Configurations → Scan coverage** shows which of the 25 scan types this installation can run ([Scan coverage](scan-coverage.md)). The manifest format is described in `docs/SCANNER_CATALOG.md` in the PATHOS repository.

## Scan profiles

**Configurations → Scan profiles** defines what a scan does. The Scanning pages only *use* profiles; they never change them.

![Scan profiles](images/configurations-profiles.png "Scan profiles: each profile with its scanners, threshold, timeout and retention")

- The **default** profile (**Make default**) applies to repositories without a profile of their own; set a different profile per repository on its **Security** tab (**Scan profile**).
- Settings: **Scanners** (Gitleaks always on; plugins of online workers can be added), **Record severities from**, **Generate an SBOM (Syft, CycloneDX). Required by Grype.**, **Mark the scan's security gate as failed when new critical findings appear**, **Timeout (min)**, **Raw report retention (days)**, **Exclusions** (globs such as `vendor/**`).
- Every change creates a new immutable version with a **Change note** (**Version history**). Each scan records the version it ran with; later edits never change it.
- New scanners are not added to existing profiles automatically.
- **Archive** retires a profile.

Managing profiles requires `profiles.manage`.

## Custom rules

**Configurations → Custom rules** holds your own Opengrep (Semgrep-syntax) rules: internal APIs, frameworks and coding standards. Managing them requires `profiles.manage` organization-wide.

- **New rule file**, with **Rules (YAML)** and a **Change note**.
- **Validate** checks a file without running it.
- Every save is a new version (**Versions**).
- Enabled files run in every new scan, and each scan records which versions it used.

## CI/CD workflow security

The **zizmor** scanner audits GitHub Actions workflows and actions in the repository: template injection, dangerous triggers such as `pull_request_target`, unpinned actions, excessive permissions and credential persistence. It works offline and runs only when the repository has workflows. **actionlint** adds syntax, type and script-injection checks. Add them to a scan profile to use them.

## Framework configuration rules

Opengrep runs PATHOS rules that find insecure **framework configuration** in code and configuration files. Their findings have the type **Framework configuration** (category `misconfiguration`), with the rule's CWE, a severity and references to the framework documentation:

| Framework | Checks |
|---|---|
| **Spring Boot / Spring Security** (Java, Kotlin, `application*.properties`, `application*.yml`) | CSRF disabled; `permitAll()` on actuator, admin, H2 console, management, heap dump or Jolokia paths; `anyRequest().permitAll()`; CORS allowing any origin (`"*"`, `@CrossOrigin(origins = "*")`); `@EnableWebSecurity(debug = true)`; actuator endpoints exposed (`management.endpoints.web.exposure.include=*` or sensitive endpoints); H2 console enabled; `debug=true` and stack traces in error responses; `management.security.enabled=false` |
| **Django** (settings modules `settings*.py`, `settings/*.py`; any module for `@csrf_exempt`) | `DEBUG = True`; `ALLOWED_HOSTS` with `"*"`; hard-coded `SECRET_KEY` (the key is never stored in the finding's code context); `CsrfViewMiddleware` or `SecurityMiddleware` missing from `MIDDLEWARE`; insecure session and CSRF cookie settings; HTTPS redirect or HSTS switched off; `CORS_ALLOW_ALL_ORIGINS`; `@csrf_exempt` views |
| **Express / Node.js** (JavaScript, TypeScript) | Application without `helmet`; `X-Powered-By` not disabled; cookies or the session cookie with `secure: false` or `httpOnly: false`; CORS for any origin (`cors()` defaults, `origin: "*"`, reflected origins with credentials, `Access-Control-Allow-Origin: *`); `trust proxy` set to `true` |

Rules you add yourself (custom rules or mounted rule sets) are reported as framework configuration too when their metadata has `category: misconfiguration`.

## Malware scanning

The **ClamAV (repository content)** scanner (`clamav`) checks every file of the checked-out repository for malware. It uses the optional ClamAV service that also scans uploaded archives: the worker streams each file to `clamd`, one file at a time, so each detection names its file. ClamAV also looks inside archives such as ZIP and JAR files.

- An infected file becomes a **critical** finding of type **Malware** with the signature name, the file path, the file's SHA-256 and the ClamAV engine and signature database version as evidence. Test signatures such as EICAR are reported too, so that every detection is looked at by a person.
- A file ClamAV could not scan (larger than clamd's limits, unreadable) becomes a **low** finding *File could not be scanned for malware*: files are never left out silently.
- If ClamAV is configured but stops answering during a scan, the scanner **fails** rather than reporting the repository clean.
- Without the ClamAV service the scanner is **skipped** with the reason *ClamAV is not configured for this worker*. A skipped or failed run never closes earlier malware findings.

To use it, an administrator enables the `clamav` service and sets `PATHOS_CLAMAV_ADDRESS` (see **Malware scanning (ClamAV)** in `docs/OPERATIONS.md`), then adds **ClamAV (repository content)** to a scan profile.

## Binary hardening

The **Binary hardening (checksec)** scanner (`binary-hardening`) reads the headers of executables and shared libraries, without running them, and reports protections that the compiler or linker did not enable. Each finding names the missing protection, the file and its format, the SHA-256 and all detected properties as evidence, and the compiler or linker flag that fixes it.

| Format | Checks |
|---|---|
| **ELF** (Linux) | PIE (executables), RELRO (none or partial), executable stack (NX), writable and executable segments, stack canaries, FORTIFY_SOURCE, insecure or deprecated RPATH/RUNPATH |
| **PE** (Windows EXE, DLL) | ASLR (`DYNAMICBASE`, relocations present), high-entropy ASLR (64-bit), DEP (`NX_COMPAT`), Control Flow Guard, SafeSEH (32-bit), `/GS` stack cookie |
| **Mach-O** (macOS) | PIE, stack execution allowed, stack canaries |

Checks that do not apply are skipped: Go and .NET binaries have no stack canaries, FORTIFY_SOURCE, CFG or SafeSEH; a non-PIE Go executable is reported as low. Canary and FORTIFY checks need symbols; for stripped static binaries they are reported as *unknown* in the evidence, not as findings.

The scanner always runs for [build artifact targets](scanning.md#scan-targets); add it to a scan profile to check binaries committed to repositories.

## Licence findings

The organization's **licence policy** (**Administration → Policies**, licences marked *deny* or *review*; see [Policies and compliance](policies-and-compliance.md)) is evaluated against two inventories of each repository, and every violation becomes a finding of type **License** with the normal lifecycle, SLA, assignment and risk acceptance:

- **Dependencies**: components of the latest SBOM (Syft or an imported SBOM). One finding per component version and licence, *Detected by* `license-policy`.
- **Files**: licences found in the repository's files by **File licences (licensecheck)**: `SPDX-License-Identifier` tags (deprecated `GPL-2.0+` is read as `GPL-2.0-or-later`; licence exceptions after `WITH` are ignored) and licence texts or notices in licence files and file headers. A licence text cannot say *only* or *or later*, so a detected `GPL-3.0` matches policy entries for `GPL-3.0-only` and `GPL-3.0-or-later`. A file under a choice such as `MIT OR GPL-2.0-or-later` is a violation only if every alternative is denied or flagged.

A **deny** licence is a **high** finding, a **review** licence a **medium** one; tag-based and dependency findings have high confidence, licence-text matches medium. Findings are de-duplicated (one per component and licence, or file and licence) and re-opened when a violation returns. When the component or file disappears, or the policy no longer denies or flags the licence, the finding is set to **Fixed** at once, with the reason in its history; findings are never deleted. A policy change applies at once to every repository's recorded inventories (latest SBOM and latest licensecheck run): new violations are opened, resolved ones fixed and severities follow the new decision. Pull request scans do not create licence findings.

## SBOM and SCA

- **SBOM**: when the profile has SBOM enabled, Syft produces a CycloneDX SBOM per scan. **Vulnerabilities → SBOM inventory** lists components from the latest SBOM of each repository with licenses, license-policy result and open vulnerabilities. Export and package health are described in [Supply chain](supply-chain.md).
- **SCA** (software composition analysis): Trivy, Grype and OSV-Scanner report vulnerable dependencies. Findings show the package, installed version, CVE or advisory ID and, if known, the **Fixed version**. The same vulnerability reported by several scanners is merged into one finding (**Detected by** lists the scanners).

## Commit-based tracking

Every scan is tied to an identified source version:

- **Git**: the scan records the commit the worker actually checked out (shown as **Commit** in the latest scan and in the scan details).
- **Upload**: the scan records the **snapshot** (shown as *Snapshot 01a1e5cc…*; ref `snapshot` in the scans list). The repository's **Source → Source snapshots** shows each snapshot's archive SHA-256.

Findings keep a **first seen** date and the commit of the first scan that found them (**First detected at commit**). When a scanner that ran successfully no longer reports a finding, it is set to **Fixed** automatically; if it reappears later it is reopened.

**Introduced by.** For code (SAST), secret and IaC findings with a file and line, the worker runs `git blame` on the scanned commit and records the commit that introduced the line and its **date**. The commit **author name** is shown only while [developer attribution](developer-insights.md) is turned on (it is off by default, and turning it off erases stored names); e-mail addresses are never stored. This needs the repository's history: turn on **Clone full history** in the repository's scan settings. With the default shallow clone the finding shows **Unknown (shallow clone)** instead of a guess; a line that is not in the scanned commit (for example a secret found only in history) shows *Unknown (the line is not in the scanned commit)*. Once known, the introducing commit is kept.

**Push summaries.** A scan started by a push or merge to the scan branch compares itself with the previous scan of the repository: the scan details show **Changes since the previous scanned commit** (previous commit → this commit, new and fixed findings by severity). The same summary is added to the *New findings* notification and to its webhook payload (`scan.changes`).

## Offline (air-gapped) operation

PATHOS can run without internet access. With `PATHOS_OFFLINE=true`, workers use only local vulnerability databases (Trivy and Grype never update, OSV-Scanner uses its offline databases) and the intelligence feeds are imported from files on **Administration → Risk & intelligence**. Administrators bring the databases in as an offline bundle (`scripts/offline-bundle.sh`); the procedure is in `docs/AIRGAP.md` in the PATHOS repository. A scanner whose database is missing fails with *offline mode: vulnerability database missing; import an offline bundle*.

**Related APIs.** [Scan configuration](../api-reference/scan-configuration.md) (profiles, scanners, custom rules), [Scans](../api-reference/scans.md), [Worker protocol](../api-reference/worker-protocol.md).
