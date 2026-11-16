---
title: Introduction to PATHOS
section: user-guide
order: 1
version: "1.0"
updated: 2026-11-17
summary: What PATHOS is, how it manages software security posture, and how the Repository Asset Management module fits in.
---

# Introduction to PATHOS

PATHOS is a self-hosted platform for managing the security posture of the software your organization builds. It keeps an inventory of your source code repositories, records who owns them and how important they are, scans them with open-source security scanners in isolated workers, and turns the results into findings, dashboards and reports that can be filtered by business unit, region, application and owner.

This guide covers the **Repository Asset Management** module: registering repositories (from a local PC, from GitHub, GitLab or Bitbucket, or from Azure DevOps), describing them with business metadata, grouping them into applications, and following them into security scanning and reporting.

![The Help button in the top bar opens this Help Center](images/help-button.png "The Help button in the top bar opens the Help Center from any page")

## Software security posture management in plain terms

*Software Security Posture Management* (SSPM) and *Application Security Posture Management* (ASPM) describe the same idea: instead of running scanners in isolation and collecting separate reports, you keep one current picture of

1. **what software you have** (the asset inventory),
2. **who is accountable for it and how much it matters** (ownership, criticality, data classification, exposure),
3. **what is wrong with it** (findings from secret scanning, static analysis, dependency analysis and infrastructure-as-code checks), and
4. **what is being done about it** (triage, remediation deadlines, accepted risks, trends).

PATHOS implements this as follows:

| Posture question | Where PATHOS answers it |
|---|---|
| What do we have? | **Repositories** inventory, each with a permanent Repository ID such as `QD-REPO-000042`, and **Applications** that group repositories |
| Who owns it and how critical is it? | Registration metadata: business, technical and application owner, business unit, regions, criticality, data classification, environment, compliance scope, public exposure |
| What is wrong with it? | **Scans** run by isolated workers (Gitleaks, Opengrep, Trivy, Grype, OSV-Scanner, Checkov, plus Syft for the SBOM), normalized into **Findings** |
| What is being done? | Finding status and SLA, **Risk acceptances**, **Dashboard** trends and the audit log |

PATHOS does not test running applications. Application URLs, public domains and IP addresses that you record on a repository are **metadata only**: PATHOS never contacts, resolves or scans them.

## Purpose of the Repository Asset Management module

The module makes sure every repository that should be assessed is known, described and owned:

- **One registration process for every source.** All three import methods share the same registration wizard and the same background import engine, so a repository uploaded as a ZIP file and one imported from Azure DevOps carry the same metadata.
- **A permanent identity.** Every repository receives a Repository ID that never changes and is never reused. It appears in the inventory, scan jobs, findings, CSV exports, global search and the audit log.
- **Accountability.** A business owner, a business unit, a business region and an answer to "Is this publicly exposed to the internet?" are always required; your administrator can require more.
- **Traceability.** Every import is a job with a status history, error codes and audit entries. Every scan records the commit (Git) or snapshot (upload) it analysed.

![How the three import methods share one wizard and one import engine](images/import-workflow.svg "Import workflow: three sources, one registration wizard, one background import job, then security scanning")

## Repositories, applications and business assets

| Concept | What it is in PATHOS |
|---|---|
| **Repository** | One code base: a Git repository from a provider, or an uploaded archive. It is the unit that is scanned, carries the Repository ID and holds all registration metadata, including staging and production URLs and public exposure. |
| **Application** | A business application (for example "Payments Platform") that groups one or more repositories and has its own owner, security owner, business unit and criticality. |
| **Business asset** | In PATHOS terms, the application together with its repositories. There is no separate asset object: the repository record plus its application *is* the asset record. |

A repository belongs to at most one application; an application can have many repositories. See [Applications](applications.md).

## How repository data feeds assessments and reporting

1. **Registration** stores ownership, placement (business unit, country, region) and classification on the repository.
2. **Access control** uses the placement: role assignments can be scoped to a business unit, a region or a single repository, and every list is filtered accordingly.
3. **Scanning** uses the source: the scan branch or the current upload snapshot. Findings are linked to the repository and its Repository ID.
4. **Prioritisation and reporting** combine both: dashboards and the repository insights can be filtered by business unit, region, criticality, exposure and application, and the KPI strip highlights gaps such as repositories without an owner, without a production URL or with unknown exposure.

## How this Help Center is organised

1. [Introduction to PATHOS](introduction.md) (this page)
2. [Repository management](repository-management.md): the repository record, the Repository ID, status, viewing and editing
3. [Importing repositories](repository-import.md): Local PC, GitHub / GitLab / Bitbucket, Azure DevOps
4. [Provider integrations](provider-integrations.md): SCM connections, OAuth applications, testing, webhooks, re-sync, deletion
5. [Authentication methods](authentication.md): every supported sign-in method per provider, and the unsupported ones
6. [Asset registration](asset-registration.md): every wizard field, what is required, regions, exposure
7. [Applications](applications.md): grouping repositories into business applications
8. [Import history](import-history.md): statuses, error codes, retry and cancel
9. [Security scanning](security-scanning.md): how registered repositories are scanned and where results appear
10. [Dashboards and reporting](dashboards.md): KPIs, insights, filters, search and CSV export
11. [Troubleshooting and FAQ](troubleshooting.md)

The [API reference](../api-reference/index.md) documents the endpoints behind every screen.

> **Permissions.** What you can see and do depends on your role and its scope. This guide names the permission each task needs, for example `repos.manage` to import repositories. Ask your PATHOS administrator if a menu item or button is missing.
