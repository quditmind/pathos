---
title: "Application onboarding, profile and lifecycle overview"
section: user-guide
group: connect, inventory, home
order: 8
version: "3.0"
updated: 2026-11-20
summary: Onboard an application in one flow (connect, discover, find existing assets, register, classify, save, start discovery), work with drafts, the application profile hub, the tag framework and the lifecycle overview.
---
# Application onboarding, profile and lifecycle overview

Quditmind PATHOS · applies to v3.0 (milestone M3) · status: Prototype (behind the feature flags `onboarding` and `lifecycle_overview`, off by default)

These pages bring the first two lifecycle phases (Connect and Inventory) together. They build on what PATHOS already has: SCM connections, the repository import wizard and import jobs, applications, tags and the classification catalogues of **Asset settings**. Nothing is duplicated: repositories are still registered by the import pipeline, and tags and catalogues are the same ones.

An administrator turns the modules on under **Administration › Feature flags**:

| Flag | What it enables |
|---|---|
| `onboarding` | **1 · Connect › Onboard an application** (`/onboarding`), the application profile (`/applications/{id}`), application classification, the tag framework on **Inventory › Tags**, and **Application fields** in **Configurations › Asset settings** |
| `lifecycle_overview` | **Home › Lifecycle overview** (`/lifecycle`) |

While a flag is off, its sidebar item shows *Phase 3* and cannot be opened, and its pages say the feature is not enabled.

## The onboarding flow

Open **1 · Connect › Onboard an application**. The step bar shows the seven steps:

1. **Connect**: choose *Git providers* or *DevOps projects* and a connection. The connection picker is the one of the repository import wizard. To add a connection, use **Manage SCM connections** (or **Manage connectors** when the Connectors hub is enabled).
2. **Discover repositories**: search and select repositories of the connection. Repositories already registered in PATHOS are marked.
3. **Find existing asset**: select **Find existing assets**. Before anything is created, PATHOS compares the repositories with what it already knows:
   - **The repository itself**, by the same connection and external ID, or by the same normalised location. `https://github.com/Acme/Payments-API`, `https://github.com/acme/payments-api.git` and `git@github.com:acme/payments-api.git` are the same repository. A repository that is already in PATHOS is **linked, never imported again**.
   - **Onboardings in progress**: a repository can be onboarded once. If it is already being onboarded, the flow stops and links to that application.
   - **Applications**: those that already contain the repository, those whose repositories share the owner or team (the namespace, for example `acme` in `acme/payments-api`), and those with a similar name. Each candidate shows a match percentage and the reasons.
4. **Register**: choose **Link to <application ID>** for a candidate, or **Register as new** with a name (suggested from the repository name). Registering creates the application as a **draft** and fills what PATHOS can detect.
5. **Tag & classify**: fill the gaps. Fields with a green background and the *detected* mark were filled automatically (see [Detected fields](#detected-fields)). **Save as draft** saves at any point.
6. **Save to inventory**: checks the mandatory fields and tag categories and registers the application. Repositories already in PATHOS without an application join it. A repository that **belongs to another application never moves silently**: see [Repositories of other applications](#repositories-of-other-applications).
7. **Start discovery**: new repositories are registered through the import pipeline with the application's classification (two extra answers are asked: business region and whether the repository is publicly exposed), and every repository gets its first scan. When the CodeGraph module is on (flag `codegraph`) and a graph worker is online, the application's [CodeGraph](codegraph.md) is built after that scan.

To continue a draft later, open it from **Applications** (status *Onboarding: N of M fields*) or from its profile (**Continue onboarding**).

### No duplicates

Onboarding the same repository twice never creates a second application, onboarding record or repository, also when two people start it at the same time. The database enforces it: one onboarding record per repository location per organization. The second attempt fails with [PTH-ONB-1008](#troubleshooting) and creates nothing. Registering a new application with the name of an existing one fails with PTH-ONB-1011.

### Repositories of other applications

When a repository you onboard already belongs to another application, the *Find existing asset* step shows **"<repository> belongs to <App X>. Move it to <this application>?"**, unticked by default. *Save to inventory* asks again with your earlier choice filled in.

- **Unticked** (default): the repository stays in App X and is listed as *kept in App X* (also on the profile's Repositories tab).
- **Ticked**: the repository moves into this application. Each move is recorded in the audit log as `repository.application_move` with who moved it, the repository, and the old and new application.

The API enforces the same rule: completing an onboarding without saying, for each such repository, whether it moves or stays is refused with PTH-ONB-1012, and nothing moves.

### Drafts

An incomplete application is saved as a draft and stays visible on **Applications** with the status **Onboarding: N of M fields**. M is the number of mandatory application fields (see [Mandatory application fields](#mandatory-application-fields)); N how many of them are filled. Drafts have a profile and can be classified, tagged and searched like any application. **Save to inventory** completes them.

### Detected fields

| Field | Detected from |
|---|---|
| Languages | Language statistics of linked repositories (languages under 2% of the code are ignored), otherwise the primary language the provider reports |
| Frameworks | Packages in the SBOM of linked repositories (for example `react` → React, `github.com/go-chi/chi` → chi, `org.springframework.boot` → Spring Boot) |
| Runtime | Package ecosystems in the SBOM (npm → Node.js, Maven → JVM, Go modules → Go), otherwise derived from the languages |
| Hosting region, data residency | The value set on the linked repositories, when they all agree |

Detection fills empty fields only and never overwrites a value a person entered. Editing a detected field removes its *detected* mark. Repositories that are not yet scanned have no SBOM: after the first scan, select **Detect again** on the profile's **Classification & tags** tab.

## Classification

| Group | Fields |
|---|---|
| Business | Business owner, business unit, criticality, security owner, technical owner, description |
| Technical | Application type, languages, frameworks, runtime |
| Security | Data classification, internet exposure, compliance scope, authentication model |
| Geography | Hosting region, data residency |
| Environment | Environment, lifecycle |

Application type, data classification, internet exposure, compliance scope, authentication model and hosting region use the catalogues of **Configurations › Asset settings** (the *Authentication model* catalogue is new). Data residency uses the organization's regions.

### Mandatory application fields

**Configurations › Asset settings › Application fields** sets which fields an application needs before it is saved to the inventory. The default is: business owner, business unit, criticality, languages, frameworks, data classification, internet exposure, hosting region and environment (9 fields). The repository fields required by the import wizard are configured above, as before.

## Application profile

Select an application name on **Applications** to open its profile (`/applications/{id}`). Selecting elsewhere in the row still opens the edit dialog, and `/applications?app={id}` keeps opening it.

| Tab | Content |
|---|---|
| Overview | The lifecycle progress strip, security posture of the last 90 days (risk, open findings, KEV, SLA, coverage, last scan) and the classification |
| Repositories | Repositories of the application and those still in onboarding |
| Classification & tags | The classification form with detected fields and tags |
| Versions | Release versions (the existing versions page) |
| CodeGraph | The application's [CodeGraph](codegraph.md) (views, inspector, path tracing, snapshots); "not enabled" while the `codegraph` flag is off |
| Threat model | The application's [threat models](threat-models.md), their status and top open threats; "not enabled" while the `threat_models` flag is off |
| Findings | Open findings of the application's repositories, with the kind of check; **Open in Findings** applies the application filter |
| SBOM & components | Components of the application's repositories |
| Remediation | The application's [remediation items](remediation.md#remediation-workspace) (open, overdue and unassigned counts; status, priority, owner, due date and last verification) with **Open in the remediation workspace**, which filters the workspace to the application; "not enabled" while the `remediation_workspace` flag is off |
| Activity & audit | Tag changes, and audit entries of the application and its repositories for people with the audit log permission |

The **lifecycle progress strip** shows the nine phases and which of them hold real data for the application. Phases without data say so; Threat model and Reverse engineering are not available yet.

## Tag framework

With the `onboarding` flag, **Inventory › Tags** adds:

- **Category settings**: a colour per category, and the application types for which the category is mandatory (or all applications). A missing mandatory tag blocks **Save to inventory** ([PTH-ONB-1010](#troubleshooting)). Mandatory categories for repositories work as before.
- **Automatic tagging rules**: add a tag when an application's classification has a value (for example *Compliance scope = PCI DSS* adds `compliance: pci-dss`), when a repository has a topic, or when a repository path matches a pattern (`acme/payments-*`; `*` stays within one path segment, `**` crosses segments). Rules run when an application is classified or registered, and on demand with **Run now**. They only add tags and never replace a tag a person chose in a single-value category.
- **Bulk tagging**: add or remove a tag on many applications or repositories after a confirmation.
- **Tag history**: who changed which tags of which asset, when, the tags before and after, and whether a person, a rule or a bulk action did it.

Repository topics: PATHOS does not read topics from the providers yet; topic rules match the repository's technology labels.

## Lifecycle overview

**Home › Lifecycle overview** (`/lifecycle`) lists every application you can see and, for each of the nine phases, whether PATHOS holds real data: repositories (Connect), registration (Inventory), SBOM components (Discover), scans and findings (Assess), AI and human reviews and AI evidence records (Validate), fix pull requests, risk acceptances and pull request checks (Remediate), release versions and runtime mappings (Report & monitor). A cell links to the data when there is some. Threat model and Reverse engineering show *not available yet*. Phases that need a permission you lack show a lock.

## Troubleshooting

| Code | Symptom | Cause and fix |
|---|---|---|
| PTH-PLAT-1007 | *… is not enabled* | The `onboarding` or `lifecycle_overview` flag is off. An administrator enables it under **Administration › Feature flags**. |
| PTH-ONB-1008 | *… is already being onboarded* | The repository was onboarded before or a moment ago by someone else. Open the application named in the message and continue there. Nothing was created. |
| PTH-ONB-1004 | *… is already registered in PATHOS in a scope you cannot see* | The repository exists in a business unit you have no access to. Ask an administrator to link it. |
| PTH-ONB-1011 | *An application named … already exists* | Choose **Link to existing** for that application, or another name. |
| PTH-ONB-1009 | *Fill the mandatory fields before saving to the inventory* | Fill the fields marked *Needed to save to the inventory* in **Tag & classify**. The application stays a draft until then. |
| PTH-ONB-1012 | *These repositories belong to another application* | Decide for each listed repository: tick *Move it to this application* or leave it unticked to keep it where it is, then save again. Nothing moved. |
| PTH-ONB-1010 | *A tag is required in: …* | The application type has mandatory tag categories. Add a tag from each listed category. |
| PTH-ONB-1006 | *A tag is required in* when starting discovery | Repository registration needs a tag of a category mandatory for repositories. Add it to the application's tags, or complete the registration in the import wizard. |
| PTH-PLAT-0003 | *unknown value … (see Configurations › Asset settings)* | A catalogue value was archived meanwhile. Choose another value. |
| — | A detected field is empty | The repository has no SBOM or language statistics yet. Scan it, then detect again. |
| — | A repository was not proposed as existing | It is registered under another location (for example an uploaded archive). Link it from the repository's details instead. |
