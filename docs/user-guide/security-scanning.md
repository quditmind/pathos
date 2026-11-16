---
title: Security scanning
section: user-guide
order: 9
version: "1.0"
updated: 2026-11-17
summary: How registered repositories are scanned, which scanners run, SBOM and dependency analysis, findings, scan history and source-version tracking.
---

# Security scanning

Registering a repository makes it **eligible** for scanning. Scans run in isolated **worker** containers that fetch the code, run the scanners of a **scan profile**, and send normalized results back to PATHOS. Workers never receive platform secrets.

## How repositories enter the scanning pipeline

| Trigger (shown in **Scans → Trigger**) | When | Notes |
|---|---|---|
| `onboarding` | Right after registration, if **Administration → Asset settings → Scan on import** is on **and** *Start onboarding scan* was ticked in the wizard | **Off by default**: without it, importing does not start a scan |
| `manual` | **Scan now** on the repository's **Security** tab, or select repositories in the inventory and choose **Scan** (up to 1,000 at once) | Requires `scans.run`; also runs for repositories excluded from scheduled scans |
| `schedule` | A schedule under **Scanning → Schedules** (cron expression, at most once per hour, with a preview of the next runs) | Requires `schedules.manage`. Repositories marked *Excluded* from scheduled scans are skipped |
| `push`, `merge` | A provider [webhook](provider-integrations.md#webhooks) for a push or merge to the repository's **scan branch** | Pull requests are recorded but **not** scanned |
| `emergency` | A bulk scan requested through the API with `trigger: emergency` (no button in the UI) | Highest queue priority; runs even for repositories excluded from scheduled scans |

Rules:

- **One queued scan per repository.** New triggers join the queued scan (*Already queued*) instead of piling up.
- **Archived repositories are never scanned.**
- **Uploaded repositories** are scanned from their **current snapshot**; they cannot be scanned before the first snapshot exists. Push webhooks do not apply to them; upload a new version and scan it.
- **Git repositories** are cloned at scan time (shallow by default, full history if **Full history** was chosen at import) from the scan branch.

## Scanners

The scanners that actually run today are the seven tools of the `worker-core` image. **Administration → Scanners & workers** lists them with license and **Availability**; the other catalog entries (for example TruffleHog, Semgrep CE, CodeQL, KICS, ZAP) are catalogued as *planned* and **do not run** yet.

| Scanner (key) | Category | What it does in PATHOS |
|---|---|---|
| **Gitleaks** (`gitleaks`) | Secrets | Finds committed secrets such as API keys and passwords. **Mandatory** in every profile. Secret values are **redacted** in reports. Scans the working tree; with **Full history** it scans every commit |
| **Opengrep** (`opengrep`) | SAST | Static analysis with Semgrep-compatible rules: the PATHOS baseline rules plus rule sets added by administrators. If no rule set is available it reports *no rule sets available* and produces no findings |
| **Trivy (filesystem)** (`trivy-fs`) | SCA | Finds known vulnerabilities in dependencies declared in lock files and manifests |
| **Syft** (`syft`) | SBOM | Generates a CycloneDX software bill of materials. A utility, not a finding source |
| **Grype** (`grype`) | SCA | Matches the Syft SBOM against vulnerability databases. Needs **Generate an SBOM** enabled in the profile |
| **OSV-Scanner** (`osv-scanner`) | SCA | Checks dependencies against the OSV vulnerability database |
| **Checkov** (`checkov`) | IaC | Misconfiguration checks for Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM, Bicep, Serverless, GitHub Actions, GitLab CI and Azure Pipelines files |

PATHOS does **not** perform dynamic testing (DAST) of the staging or production URLs, domains or IP addresses recorded on a repository; those remain metadata.

## Scan profiles

**Configurations → Scan profiles** defines what a scan does (profiles and the scanner registry are managed in **Configurations**; the Scanning module only uses them). The **Default** profile (all core scanners) applies to repositories without a profile; a different profile can be set per repository on its **Security** tab (**Scan profile**). Profile settings: **Scanners** (Gitleaks always on), **Record severities from**, **Generate an SBOM (Syft, CycloneDX). Required by Grype.**, **Mark the scan's security gate as failed when new critical findings appear**, **Timeout (min)**, **Raw report retention (days)**, **Exclusions** (globs such as `vendor/**`). Every change creates a new profile version with a change note. Managing profiles requires `profiles.manage`.

## SBOM and SCA

- **SBOM**: when the profile has SBOM enabled, Syft produces a CycloneDX SBOM per scan. **Vulnerabilities → SBOM inventory** lists components from the latest SBOM of each repository with licenses, license-policy result and open vulnerabilities; the repository's **Security** tab links to **SBOM (CycloneDX)** to download it.
- **SCA** (software composition analysis): Trivy, Grype and OSV-Scanner report vulnerable dependencies. Findings show the package, installed version, CVE or advisory ID and, if known, the **Fixed version**. The same vulnerability reported by several scanners is merged into one finding (**Detected by** lists the scanners).

## Commit-based tracking

Every scan is tied to an identified source version:

- **Git**: the scan records the commit the worker actually checked out (shown as **Commit** in the latest scan and in scan details).
- **Upload**: the scan records the **snapshot** (shown as *Snapshot 01a1e5cc…*; ref `snapshot` in the scans list). The repository's **Source → Source snapshots** shows each snapshot's archive SHA-256.

Findings keep a **first seen** date. When a scanner that ran successfully no longer reports a finding, it is set to **Fixed** automatically; if it reappears later it is reopened.

## Findings, severity and risk

**Vulnerabilities → Findings** shows normalized, de-duplicated results from every scanner.

| Concept | Values |
|---|---|
| Severity | Critical, High, Medium, Low, Info |
| Type | Secrets, SAST, SCA, IaC (and others for future scanners) |
| Status | Open, In progress, Needs review, Fixed, False positive, Accepted risk |
| SLA | Remediation deadline per severity from **Administration → Policies**; filters *Breached* and *Due within 7 days* |
| Risk score (dashboard) | Severity-weighted open findings per repository: critical 10, high 5, medium 2, low 0.5 |

Columns include **Repository** and **Repository ID** (hidden by default, always exported), **Rule / CVE**, **Detected by**, **First seen**, **Fixed version** and **Location**. Prioritise using the repository's criticality, exposure and data classification together with the finding's severity.

![Findings](images/findings.png "Findings: severity counts, filters (status, assignee, SLA, type, scanner, repository) and the finding list")

## Scan history

**Scanning → Scans** lists every scan execution with its permanent Scan ID; open one for its Overview, Findings, Execution Logs, Stages, Configuration and History tabs. Comparing executions over time is done in **Scanning → Scan Comparison**. See [Scanning: executions, schedules and comparison](scanning.md) for the full guide.

## Step-by-step: scan a repository and view its findings

**Purpose.** Run a scan of a registered repository and review the results.

**Prerequisites.** The repository is registered and not archived; at least one worker is online (**Scans** shows *n worker online*).

**Required permissions.** `scans.run` to start a scan; `scans.read` and `findings.read` to view results; `findings.triage` to change finding status.

**Example values.** Repository `payments-api` (`QD-REPO-000042`), Default profile.

1. Open **Assets → Repositories**, select the repository and open the **Security** tab.
2. Select **Scan now**. The button shows *Scan queued* (or *Already queued*).
3. Wait for the scan to finish: **Scanning → Scans** shows its progress and stage live; select the Scan ID to follow the stages and execution log (the example took under a minute).
4. Back on the **Security** tab, check **Open findings** by severity and the **Latest scan**: status, trigger, profile, commit or snapshot, and the table of scanners with versions, status and findings.
   ![Repository Security tab](images/repository-security.png "Security tab: open findings by severity, the latest scan with every scanner's version and result, scan profile and recent scans")
5. Select **All findings** to open the findings list filtered to this repository, or **Scan history** for its scans.
6. Open a finding to see its details, lifecycle and history; change its status or request a risk acceptance if you have the permissions.

**Expected result.** A succeeded (or partial) scan job, findings linked to the repository and its Repository ID, and an updated **Last scan** column in the inventory.

**Troubleshooting.**

| Problem | Cause and fix |
|---|---|
| **Scan now** missing | No `scans.run` permission |
| *repository is archived or scanning is disabled* | Unarchive the repository; scheduled scans skip repositories excluded from scheduled scans |
| *repository has no source snapshot yet* | The upload import has not completed |
| Scan stays **Queued** | No worker online: **Administration → Scanners & workers** must list a worker |
| Status **Partial** | One or more scanners failed or timed out; the scan details show which |
| Git scan fails to clone | The connection's credential expired or lost access; **Test** the connection |
| Opengrep reports *no rule sets available* | Ask an administrator to install rule sets |
| No SBOM | **Generate an SBOM** is off in the profile |

**Related APIs.** [Repositories API](../api-reference/repositories.md) (repository security summary) and the scanning endpoints listed in the [API reference](../api-reference/index.md).
