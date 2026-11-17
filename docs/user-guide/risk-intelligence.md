---
title: "Contextual risk and vulnerability intelligence"
section: user-guide
order: 9.6
version: "1.0"
updated: 2026-11-17
summary: How PATHOS ranks findings by contextual risk (CVSS, EPSS, CISA KEV, criticality, exposure, confidence, human review), what the lifecycle statuses mean, and how administrators manage feeds and the risk model.
---
# Contextual risk and vulnerability intelligence

Severity tells you how bad a vulnerability *could* be. **Contextual risk** tells you what to fix first. PATHOS scores every open finding from 0 to 100 using:

| Signal | Effect |
|---|---|
| CVSS or severity | The starting point (a human-assessed severity from Human Eye wins) |
| **EPSS** | Probability that the CVE will be exploited in the next 30 days (FIRST) |
| **CISA KEV** | The CVE is known to be exploited in the wild: the strongest signal |
| Business criticality | Of the application or repository, whichever is higher |
| Internet exposure | Public-facing assets count more; internal ones less |
| Confidence | How likely the scanner result is real; findings a reviewer confirmed count more |
| Compensating controls | Recorded during a Human Eye review |
| Fix available | A small boost, so quick wins come first |

The severity never changes. The score is a separate ranking.

## In the Findings list

- **Risk** shows the score and its band (critical ≥ 75, high ≥ 50, medium ≥ 25, low). A **KEV** badge marks exploited CVEs.
- Use **Order by contextual risk**, and filter by **Risk**, **Exploited (KEV)** and **Lifecycle**.
- The **EPSS**, **KEV**, **Confidence** and **Application** columns can be added with **Columns**.
- Open a finding to see **Contextual risk**: every factor with its weight. The explanation answers "why is this ranked here?".

## Lifecycle statuses

| Status | Meaning |
|---|---|
| New | First seen by the latest scan; nobody has looked at it yet |
| Open | Known and open |
| In progress | Someone is working on it |
| Under review | Needs a decision: automated triage flagged it or a Human Eye review is open |
| Confirmed | A Human Eye reviewer confirmed it is real |
| False positive / Accepted risk | Closed by a decision |
| Resolved | A scan no longer detects it |
| Reopened | Detected again after being resolved |

## For administrators: Risk & intelligence

**Administration → Risk & intelligence**:

- **Feeds.** EPSS and CISA KEV download daily by default. You can:
  - **Download now**
  - change the download URL (for an internal mirror) or the interval
  - turn online updates off
  - **Import file (offline)**, for air-gapped installations: the EPSS CSV (or `.csv.gz`) and the KEV JSON
- **Risk model.** Tune the weights. Each save is a new version (with a change note) and every finding is re-scored in the background. **Defaults** restores the built-in values.

Feed files:

- EPSS: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
