---
title: Supply chain and pull requests
section: user-guide
order: 17
version: "1.0"
updated: 2026-11-19
summary: Export SBOMs, check package health and provenance, spot malicious packages, scan build artifacts, check pull requests before they merge and open fix pull requests for vulnerable dependencies.
---
# Supply chain and pull requests

## Export an SBOM

Open a repository and use **SBOM (CycloneDX)** or **SBOM (SPDX)** on its **Security** tab. **Vulnerabilities → SBOM inventory** lists the components of every repository. CycloneDX is the file from the latest scan; SPDX 2.3 is generated from the repository's component inventory and keeps the dependency graph (which package depends on which). Imported SBOMs can be exported in both formats.

## Package health

The repository's **Dependencies** tab shows, for each package, whether a newer release exists, whether the version in use is **deprecated** by its maintainers, the **OpenSSF Scorecard** of its source repository (0–10, higher is better maintained) and, for direct dependencies, whether the registry has **build provenance** for that version. Filter by **Outdated** or **Deprecated version**.

This data comes from deps.dev. The feed is **off by default** because PATHOS sends the names of your packages, including private ones, to deps.dev. An administrator can turn it on in **Administration → Risk & intelligence** (deps.dev package health). It is not available offline. Until then the Health column shows a dash.

## Malicious packages

A finding marked **Malicious** is a package known to contain malware (for example an OSV `MAL-` advisory). Its code runs when it is installed, so PATHOS treats it as urgent as an actively exploited vulnerability. Remove the package, rotate credentials on every machine and CI runner that installed it, and check them for compromise. Use the **Malicious packages** filter on Findings to list them all.

Each finding also shows **First detected at commit**: the commit of the first scan that found it. The finding was introduced at or before that commit.

## Scan a build artifact

In **Scanning → Scan targets**, choose **Add target** → **Build artifact** and upload a release file (up to 200 MiB): a zip or tar archive, a Java archive (`.jar`, `.war`, `.ear`) or a binary. Scanning finds vulnerable components inside it and checks its executables and libraries for missing compiler and linker hardening ([Binary hardening](security-scanning.md#binary-hardening)). Archives are checked and unpacked safely on a worker, and nothing in them is ever run. See [Scan targets](scanning.md#scan-targets).

## Pull request checks

PATHOS can check every pull request and report the result on the pull request itself. This works for Git repositories only; uploaded repositories have no pull requests.

1. Open **Scanning → Pull request checks**, pick the repository under **Repository settings**, select **Check pull requests**, choose when to block (default: a new **High** or **Critical** finding) and save.
2. Make sure the repository's SCM connection has a webhook and that its credential can write commit statuses (GitHub *Commit statuses: write*, GitLab `api`, Bitbucket *Repositories: write*, Azure DevOps *Code (status)*).
3. Optionally make the status **PATHOS / security** a required check in your branch protection rules, so blocked pull requests cannot merge.

When a pull request is opened or updated, PATHOS scans its head with the repository's scan profile and posts a status: pending while it scans, then passed, blocked or error.

Only what the pull request **introduces** counts. Findings already known on the scan branch (open, accepted as a risk or marked false positive) are listed separately and never block it. Pull request scans never change the repository's findings.

Open a check to see the new findings and the known ones, the scan execution, and whether the status reached the provider. **Post status again** retries a status that could not be posted. Pull requests from forks are not checked.

## Fix pull requests

For a vulnerable dependency with a known fixed version, PATHOS can open a pull request (merge request on GitLab) that upgrades it. This works on GitHub, GitLab, Bitbucket Cloud and Azure DevOps, for repositories imported from an SCM connection.

1. Open the repository, go to the **Security** tab and, under **Fix pull requests**, select **Allow fix pull requests**. Choose the grouping: **one PR per package** (every open finding of that package version is fixed by one upgrade) or **one PR per finding**. Save. You need *repos.manage* on the repository.
2. The repository's SCM connection must be allowed to write: GitHub *Contents: write* and *Pull requests: write*, GitLab Developer role with the `api` scope, Bitbucket *Repositories: write* and *Pull requests: write*, Azure DevOps *Code (read & write)*. If it cannot, the request fails with a message that says so.
3. Open a dependency finding. The **Fix pull request** box shows the version PATHOS proposes; you may type another target version or change the grouping, then select **Open fix PR**. You need both *findings.triage* and *repos.manage* on the repository.

A worker clones the scan branch and edits the manifest as text; no package manager, build or code from the repository runs. PATHOS then creates a branch named `pathos/fix/…`, commits the edited files and opens the pull request against the scan branch. It never pushes to the default branch or any other existing branch. The box follows the request (queued, editing, opening, open) and links to the pull request; the refresh button reads its state from the SCM, which PATHOS also does every 15 minutes.

**Merging does not close the finding.** It is marked fixed when the next scan of the branch no longer detects the vulnerability, so a fix that does not actually remove the vulnerable version stays visible.

What PATHOS can edit:

| Ecosystem | Supported | Not supported (the box says why) |
|---|---|---|
| Python | `requirements*.txt` and `constraints*.txt` (the package is pinned) | Files with `--hash` lines; Pipfile, Poetry and uv lockfiles |
| Java (Maven, Gradle) | `pom.xml` versions and properties; Gradle build files and version catalogs | Versions from a parent POM or BOM outside the repository; Gradle dependency locking |
| .NET (NuGet) | Project files and `Directory.Packages.props` | Projects with `packages.lock.json` |
| JavaScript (npm) | `package.json` when the project has no lockfile | Projects with `package-lock.json`, `yarn.lock` or `pnpm-lock.yaml`: the lockfile must be regenerated with the package manager, which PATHOS does not run |
| Go, Rust, PHP, Ruby | — | `go.sum`, `Cargo.lock`, `composer.lock` and `Gemfile.lock` need the ecosystem's own tool |

A dependency that is only pulled in transitively cannot be edited directly; PATHOS reports that instead of guessing. Every request, pull request and state change is in the audit log.
