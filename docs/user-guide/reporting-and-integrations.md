---
title: Reports and integrations
section: user-guide
order: 9.77
version: "1.0"
updated: 2026-11-18
summary: The executive overview, saved and scheduled reports, webhooks to Slack, Teams or a SIEM, Jira and ServiceNow tickets, and REST API tokens.
---
# Reports and integrations

## Executive overview

**Overview → Executive overview** summarizes the security posture for leadership over 30, 90, 180 or 365 days: open critical and high findings, actively exploited vulnerabilities, SLA compliance and overdue findings, findings found and fixed each week, the open backlog, mean time to fix by severity, and the applications and business units with the most critical findings. **Print** produces a clean page (or a PDF from the print dialog). Everything is computed from the findings you can access.

## Reports

**Overview → Reports** keeps the views you need again and again. **New report**: choose the findings (status, severity, type, risk, KEV, past SLA, repository), then show them as a list with the columns you want or as counts per severity, status, type, repository, application, business unit, scanner, assignee or vulnerability. The preview updates as you change it.

- **Share** a report with everyone who can read findings.
- **Deliver** it daily, weekly or monthly: recipients get a notification with a link. A report always shows each person only the findings they may see, whoever created it.
- **CSV** downloads the result (needs the export permission); **Print** gives a printable page.

## Webhooks (Slack, Microsoft Teams, SIEM)

**Administration → Notifications → Webhooks → New webhook**. Pick the format (**JSON** for a SIEM or your own service, **Slack**, **Microsoft Teams**), paste the URL (it is stored encrypted and only its host is shown afterwards), choose the events and, optionally, a minimum severity. **Test** sends a sample message at once; **Deliveries** shows what was sent and any errors. Failed deliveries are retried for about nine hours.

For JSON webhooks, keep the signing secret shown at creation and check the `X-PATHOS-Signature` header on every request (see the API reference). Internal addresses (for example an on-premises SIEM) need **Allow an internal address**.

- Slack: create an *Incoming Webhook* for the channel and use its URL.
- Teams: create a *Workflows* webhook (“Post to a channel when a webhook request is received”) and use its URL.

## Jira and ServiceNow

An administrator adds a connection under **Administration → Integrations**: the server URL, a technical user's credentials (Jira Cloud: e-mail + API token; Jira Data Center: a personal access token; ServiceNow: user + password or an OAuth token) and the Jira project or ServiceNow table. **Test** checks the credentials.

Then anyone who triages findings can open a finding and choose **Open a ticket in… → Create ticket**. The ticket contains the finding's facts and a link back to PATHOS, never code or secret values. The finding shows the ticket's key and status, refreshed every few minutes. Closing the ticket does not close the finding: the next scan does, once the issue is gone.

## REST API tokens

User menu → **API tokens**: create a token that allows **REST API: read** or **read and write** (and/or the MCP server). Use it as `Authorization: Bearer <token>` with `https://<PATHOS>/api/v1/…`. A token has exactly your current permissions, expires after at most 90 days, and stops working if you are deactivated; revoke it at any time. Changes made with a token are recorded in the audit log with the token's id.
