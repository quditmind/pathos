---
title: Application versions, VEX and component policies
section: user-guide
order: 18
version: "1.1"
updated: 2026-11-19
summary: Record application releases with their SBOM and findings, find which versions contain a vulnerable component, exchange VEX statements with suppliers and customers, and set component policies.
---
# Application versions, VEX and component policies

## Record an application version

A version (release) records what an application consisted of when it shipped: for each of its repositories, the commit that was scanned, the components (SBOM) and the findings. Later scans do not change it, so you can still answer "was 2.3.1 affected?" after the code moved on.

1. Open **Assets → Applications** and select **Versions** on the application's row.
2. Select **New version**, enter the version (for example `2.3.1`), an optional description and release date, and select **Create version**.

PATHOS uses each repository's latest successful scan of its scan branch. A repository that was never scanned successfully is included without components or findings, and PATHOS shows a warning. Scan the repositories before you create the version.

Select a version to see its repositories (branch and commit), the findings at release with their status then and now, and its components. You need **repos.manage** on the application to create or delete versions.

## Find which versions contain a component

**Vulnerabilities → Component portfolio** searches by component name (optionally with a version), package URL or CVE. It lists the application versions that contain it, and the repositories whose current inventory contains it, within the repositories you may see.

Use it when a new vulnerability is announced: search the CVE or the package, and you see which shipped versions need a patch release.

## Export VEX

VEX (Vulnerability Exploitability eXchange) tells customers which known vulnerabilities affect your product. PATHOS writes VEX from your decisions:

| Your decision in PATHOS | VEX statement |
|---|---|
| False positive | Not affected (with the reason you gave; "vulnerable code not in execute path" when reachability analysis found it unreachable) |
| Accepted risk | Affected, no fix planned (with the expiry and justification) |
| Fixed | Fixed |
| Open, in progress | Affected (with the fixed version, when known) |
| Needs review | Under investigation |

Download **OpenVEX** or **CycloneDX VEX** from a version's page (statements for that release) or from **Vulnerabilities → VEX statements** (choose a repository). You need **findings.export**.

## Import VEX from suppliers

Suppliers publish VEX for components you use. On a version's page, or on **VEX statements** for a repository, select **Import VEX** and choose an OpenVEX or CycloneDX VEX file (JSON, at most 10 MB). You need **findings.triage**.

Importing never changes a finding. PATHOS matches each statement to findings by vulnerability and component, and:

- **not affected** and **fixed** statements become suggestions on the **VEX statements** page;
- **affected** and **under investigation** statements are counted only (PATHOS already tracks those findings as open);
- statements that match no finding are counted as unmatched.

## Review VEX suggestions

On **Vulnerabilities → VEX statements**, a reviewer with **findings.accept_risk** on the repository approves or rejects each suggestion, with an optional note. The person who imported a statement cannot decide it: another person must check it.

- Approving **not affected** closes the finding as a false positive. The finding's history records the statement, who imported it and who approved it.
- Approving **fixed** records the supplier's statement but does not close the finding. A finding is resolved only when a scan no longer detects it, so rescan after you update the component.

## Component policies

**Vulnerabilities → Component policies** defines operational rules over the SBOM inventory, like Dependency-Track's policies:

| Condition | Example |
|---|---|
| Licence | No `GPL-3.0-only` or `AGPL-3.0-only`; optionally flag components that declare no licence |
| Vulnerability severity | No component with an open vulnerability of high severity or above |
| Outdated version | A newer version (or a newer major version) exists |
| Package age | The package has had no release for more than 730 days (possibly unmaintained) |

Each policy has a state (**fail**, **warn** or **info**) shown on its violations. Outdated version and package age need package health from deps.dev, which an administrator enables under **Administration → Risk & intelligence** (it sends package names to deps.dev, so it is off by default). Without it those conditions are skipped, not reported as violations.

Policies are evaluated when saved, hourly, and when an administrator selects **Evaluate now**. A violation is resolved automatically when the component no longer matches. Creating and editing policies requires **settings.manage**; anyone with **sbom.read** sees the policies and the violations in their repositories.
