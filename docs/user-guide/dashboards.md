---
title: Dashboards and reporting
section: user-guide
order: 10
version: "1.0"
updated: 2026-11-17
summary: The repository KPI strip and insights, the security posture dashboard, filters, search, sorting, CSV export and common reporting scenarios.
---

# Dashboards and reporting

PATHOS reports on repositories in three places: the **KPI strip** and **Insights** on the Repositories page, the organization-wide **Dashboard**, and CSV exports of any list. Everything respects your permissions: you only see and count repositories in your scope.

## Repository KPI strip

The strip at the top of **Assets → Repositories** summarises the repositories that match the current filters. Each card is a link to the matching list.

![Repository KPI strip](images/repositories-kpis.png "KPI strip: each card opens the matching filtered list")

| Card | Counts | Opens |
|---|---|---|
| Total | Active and archived repositories | List with status *Active and archived* |
| Active | Repositories that are not archived | Default list |
| Archived | Archived repositories | List filtered to Archived |
| Pending imports | Import items still running | Import history, *Active* |
| Failed imports | Import items that failed or need attention in the last 30 days | Import history, *Finished* |
| Critical | Active repositories with criticality Critical | Filter Criticality |
| No business owner | Active repositories without a business owner | Filter Missing owner |
| No technical owner | Active repositories without a technical owner | Filter Missing owner |
| Missing ownership | Active repositories without a business **or** a technical owner | Filter *Missing any owner* |
| Publicly exposed | Active repositories with public exposure Yes | Filter Public exposure |
| Not public | Active repositories with public exposure No | Filter Public exposure |
| Unknown exposure | Active repositories with public exposure Unknown | Filter Public exposure |
| Missing production URL | Active repositories without a production URL | *Missing production URL* filter |
| Last successful sync | Time of the most recent successful sync; below it, the number of active repositories whose sync failed, is missing upstream or has no access (*n sync failures*) | List filtered to *Sync failed* when there are failures, otherwise sorted by last sync |

Warning and danger colours highlight cards that need action (for example failed imports, missing owners, publicly exposed assets).

## Insights

Switch the Repositories page from **List** to **Insights** to see charts for the current filters: **Public exposure**, **By source / provider**, **By business region**, **By business unit**, **By data classification**, **By criticality**, **By environment**, **By compliance scope**, **By lifecycle status** and **Top business owners**. *Not set* shows repositories without a value. **Show as table** displays the numbers.

![Repository insights](images/repositories-insights.png "Insights: distribution charts for the filtered repositories")

## Filters, search and sorting

![All repository filters](images/repositories-filters.png "More filters: connection, application, country, environment, network reachability, compliance scope, tag, ownership, Repository ID and URL filters")

| Control | Options |
|---|---|
| Standard filters | Source (provider or Local upload), Business unit, Business region, Criticality, Public exposure, Data classification, Lifecycle, Sync status, Status (Active / Archived / Active and archived) |
| **More filters** | Connection, Application, Country, Environment, Network reachability, Compliance scope, Tag, Missing owner, Application ownership (*No application*), **Repository ID (exact)**, **Production URL contains**, **Staging URL contains**, Business owner, Technical owner |
| Checkbox | **Missing production URL** |
| Search | **Search repositories** matches names, Repository IDs and staging or production URLs; the **Repository ID** filter matches one exact ID such as `QD-REPO-000042`. The top-bar **Search…** (Ctrl K) also finds repositories by Repository ID |
| Sort | Default order, Name (A–Z / Z–A), Repository ID (ascending / descending), Newest / Oldest first, Most / Least critical first, Recently / Least recently synced |
| Columns | **Columns** shows or hides columns, for example Application, Environment, Technical owner, Lifecycle, Last sync, Technologies |

Filters are kept in the page address, so you can bookmark or share a filtered view.

## CSV export

Every table (repositories, applications, import history, scans, findings) has **Export**, which downloads the **loaded rows** as CSV (*Export loaded rows as CSV*). Scroll or load further pages first if you need more rows. Some columns are always exported even when hidden, for example **Public exposure** in the repository list and **Repository ID** in scans and findings. Owner columns are exported as e-mail addresses.

## Security posture dashboard

**Overview → Dashboard** shows organization-wide metrics grouped into *Risk posture*, *Remediation*, *Assets & coverage*, *Scanning*, *AI review*, *Supply chain* and *Platform*. Select a card to drill down.

![Security posture dashboard](images/dashboard.png "Dashboard: risk posture, remediation, assets and coverage, scanning")

Relevant to repositories:

| Card | Meaning |
|---|---|
| Repositories | Active repositories under management |
| Applications | Applications grouping repositories |
| **Scan coverage** | Share of active repositories scanned in the selected period |
| Without owner | Repositories with no application or owner |
| Open findings, Critical open, High open, Risk score, Exposed secrets, Vulnerable dependencies | Finding metrics (risk score: critical 10, high 5, medium 2, low 0.5 per open finding, per repository) |
| Repositories by criticality, Riskiest repositories | Charts |

Dashboard filters: **Period** (Last 7 / 30 / 90 days, Last 12 months), **Region**, **Country**, **Business unit**. The **Severity** and **Scanner** filters are shown but disabled. Filtering the dashboard by provider, environment, criticality or application is **not available**; use the Repositories page filters and Insights for those.

## Reporting scenarios

### 1. Which internet-facing, critical assets do we have?

1. Open **Repositories**.
2. Set **Public exposure** to *Public* and **Criticality** to *Critical* (repeat with *High*).
3. Show the **Public endpoints** and **Production URL** columns.
4. Select **Export**.

### 2. Which assets still lack an exposure assessment?

1. Select the **Unknown exposure** card.
2. Add **Business unit** to split by owner organization.
3. Show the **Business owner** column and **Export** to send the list to the owners.

### 3. Ownership gaps per business unit

1. Select the **Missing ownership** card (or **More filters → Missing owner → Missing any owner**).
2. Switch to **Insights** and look at **By business unit**.
3. Back in **List**, **Export** for follow-up.

### 4. Repositories of one application, with their posture

1. **More filters → Application** → *Payments Platform*.
2. Check the KPI strip (exposure, critical, ownership) and **Insights**.
3. Open **Findings**, filter **Repository** for each listed repository, or export findings and filter on the **Repository ID** column.

### 5. Import and sync health

1. Select **Failed imports** to open finished jobs; open each failed job for the error code ([Import history](import-history.md#error-codes)).
2. Set **Sync status** to *Sync failed* or *No access* to find repositories whose connection lost access.
3. Check **Administration → SCM connections** for connections in **Error** or **Expired**.

### 6. Scan coverage by region

1. Open **Dashboard**, choose **Period** *Last 30 days* and a **Region**.
2. Read **Scan coverage** and **Repositories**.
3. To find unscanned repositories, open **Repositories**, filter the same business region and sort or show the **Last scan** column (*Never* for unscanned ones).

## Related APIs

[Repositories API](../api-reference/repositories.md) (list filters, insights), [Applications API](../api-reference/applications.md), [Imports API](../api-reference/imports.md).
