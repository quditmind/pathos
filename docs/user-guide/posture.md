---
title: Posture
section: user-guide
group: threat-model, discover, report
order: 15
version: "1.0"
updated: 2026-11-19
summary: Application posture and risk rollup, scan coverage, unmanaged and shadow repositories, benchmarking, attack paths, blast radius, the context graph and dependency paths.
---
# Posture

The **Posture** section answers application-level questions:
- which applications are riskiest
- what isn't scanned
- what nobody owns
- what a new vulnerability affects

Everything is computed live from findings, scans and ownership, within the repositories you can see. **Posture → Compliance** is described in [Security policies and compliance](policies-and-compliance.md#compliance).

## Application posture

**Posture → Application posture** lists every application with:

- **Risk**: the application's riskiest open finding, raised by one point for every other open finding with a contextual risk of 50 or more (at most 15 points), capped at 100. Hover over the score for its explanation.
  - One critical issue and twenty critical issues both rank high, the second slightly higher.
  - Many low-risk findings never add up to a high risk.
- **Open findings** by severity, **KEV** (actively exploited) findings, and **SLA breaches**.
- **Mean time to fix**: the average time from first detection to fix, for findings fixed in the chosen window.
- **Coverage**: the share of the application's repositories with a successful code, dependency and secrets scan in the last 30 days.
- **Last scan**.

Repositories without an application are grouped as **No application**. Use **Group by** to see the same figures by business unit, team, owner or region.

## Coverage

**Posture → Coverage** is a matrix of repositories × kinds of scanning:

- code (SAST), secrets, dependencies, infrastructure as code
- CI/CD workflows (zizmor)
- container images and web and API (DAST), which come from **scan targets**

Each cell can be in one of four states:

| State | Meaning |
|---|---|
| **Covered** | A scan succeeded within the window (7, 30 or 90 days) |
| **Stale** | It succeeded only before the window |
| **Never** | It never succeeded |
| **No target** | Container or DAST scanning has no target for the repository |

Hover over a cell for the date and the scanners. Imported results count for their category. A target scan counts only while its target exists and is enabled.

## Unmanaged assets

**Posture → Unmanaged assets** finds governance gaps in the repositories PATHOS manages:

- not mapped to an application
- no owner or responsible team
- never scanned, or not scanned recently
- scanning disabled
- SCM synchronization failing
- archived in the SCM but still active in PATHOS

Select a gap to filter the list.

**Shadow repositories** are repositories a connected SCM account can see, that were pushed to recently, but that are not in PATHOS. PATHOS refreshes the list of each connection's repositories daily. Administrators who manage repositories organization-wide can refresh it on demand. Shadow repositories are shown only to people who can see every repository.

## Benchmarking

**Posture → Benchmarking** compares applications, business units, teams, owners or regions on normalised metrics, so that large and small groups compare fairly:

- risk
- open findings per repository
- critical and high findings per repository
- KEV findings
- mean time to remediate
- share fixed within SLA
- scan coverage

The best and worst value of each metric are marked, and the last row shows the median.

## Attack paths

**Posture → Attack paths** lists how an attacker on the internet could reach a weakness, ordered by risk:

- through a **tested web application or API** (a DAST [scan target](scanning.md#scan-targets)) to the weakness found there
- through an **internet-exposed asset** (Public internet exposure: yes) to a weakness in its code
- to its **container image**
- to a **vulnerable package its code uses**

Unreachable dependencies ([reachability](vulnerability-intelligence.md#reachability)) are not attack paths. Each path says why it matters, for example *actively exploited (CISA KEV)*.

## Blast radius

**Posture → Blast radius** answers "a new vulnerability was announced: what does it affect?":

- Search a **CVE or GHSA** identifier to list the repositories with open findings for it.
- Search a **package** (optionally a version) to list the repositories whose latest SBOM contains it, even when no vulnerability is reported yet.

Each repository shows:
- its application, owner, team and business unit
- whether it is exposed to the internet
- whether the package is a **direct** or **transitive** dependency
- the versions found, the open findings and the highest risk
- for container findings, the scan target they were found in

## Context graph

**Posture → Context graph** draws everything connected to an application or repository:

- who owns it
- its repositories and scan targets
- the vulnerable components
- the riskiest open findings

Select a node to open it. The graph opens from **Application posture** and **Blast radius** too.

With the `codegraph` feature flag on, the same ownership information is the **Ownership** layer and view of the [CodeGraph](codegraph.md#views). This page and its URL (`/posture/graph`) stay as they are.

## Dependencies of a repository

A repository's **Dependencies** tab (Repositories → open a repository) shows its latest SBOM as a dependency graph:

- how many components are direct, transitive or without graph data
- which ones have open vulnerabilities
- for each package, **how it gets in**: the shortest paths from the project to it, for example `goof › mongoose › async`

A dependency finding also shows how its package gets in, under **How the package gets in** in the finding's details.

Dependency relationships come from the SBOM: CycloneDX `dependencies`, or SPDX `DEPENDS_ON` and `…DEPENDENCY_OF` relationships. SBOMs generated by PATHOS scans include them. An imported SBOM without them lists components as **No graph data**.

**Related APIs.** [Posture](../api-reference/posture.md).
