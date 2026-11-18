---
title: Supply chain and pull requests
section: user-guide
order: 17
version: "1.0"
updated: 2026-11-19
summary: Export SBOMs, check package health and provenance, spot malicious packages, scan build artifacts and check pull requests before they merge.
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

In **Scanning → Scan targets**, choose **Add target** → **Build artifact** and upload a release file (up to 200 MiB): a zip or tar archive, a Java archive (`.jar`, `.war`, `.ear`) or a binary. Scanning finds vulnerable components inside it. Archives are checked and unpacked safely on a worker, and nothing in them is ever run. See [Scan targets](scanning.md#scan-targets).

## Pull request checks

PATHOS can check every pull request and report the result on the pull request itself. This works for Git repositories only; uploaded repositories have no pull requests.

1. Open **Scanning → Pull request checks**, pick the repository under **Repository settings**, select **Check pull requests**, choose when to block (default: a new **High** or **Critical** finding) and save.
2. Make sure the repository's SCM connection has a webhook and that its credential can write commit statuses (GitHub *Commit statuses: write*, GitLab `api`, Bitbucket *Repositories: write*, Azure DevOps *Code (status)*).
3. Optionally make the status **PATHOS / security** a required check in your branch protection rules, so blocked pull requests cannot merge.

When a pull request is opened or updated, PATHOS scans its head with the repository's scan profile and posts a status: pending while it scans, then passed, blocked or error.

Only what the pull request **introduces** counts. Findings already known on the scan branch (open, accepted as a risk or marked false positive) are listed separately and never block it. Pull request scans never change the repository's findings.

Open a check to see the new findings and the known ones, the scan execution, and whether the status reached the provider. **Post status again** retries a status that could not be posted. Pull requests from forks are not checked.
