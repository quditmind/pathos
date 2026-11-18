---
title: Integrations and API tokens
section: user-guide
order: 19
version: "1.0"
updated: 2026-11-19
summary: Webhooks to Slack, Teams or a SIEM, Jira and ServiceNow tickets, and personal REST API and MCP tokens.
---
# Integrations and API tokens

Dashboards, the executive overview and saved reports are described in [Dashboards and reporting](dashboards.md). Notification rules and e-mail are in [Administration](administration.md#notifications).

## Webhooks (Slack, Microsoft Teams, SIEM)

**Administration → Notifications → Webhooks → New webhook** (permission `notifications.manage`). Pick the format (**JSON** for a SIEM or your own service, **Slack**, **Microsoft Teams**), paste the URL (it is stored encrypted and only its host is shown afterwards), choose the events and, optionally, a minimum severity. **Test** sends a sample message at once; **Deliveries** shows what was sent and any errors. Failed deliveries are retried for about nine hours.

For JSON webhooks, keep the signing secret shown at creation and check the `X-PATHOS-Signature` header on every request (see [Notifications API](../api-reference/notifications.md)). Internal addresses (for example an on-premises SIEM) need **Allow an internal address**.

- Slack: create an *Incoming Webhook* for the channel and use its URL.
- Teams: create a *Workflows* webhook (“Post to a channel when a webhook request is received”) and use its URL.

## Jira and ServiceNow

An administrator (permission `settings.manage`) adds a connection under **Administration → Integrations**: the server URL, a technical user's credentials (Jira Cloud: e-mail + API token; Jira Data Center: a personal access token; ServiceNow: user + password or an OAuth token) and the Jira project or ServiceNow table. **Test** checks the credentials.

Then anyone who triages findings can open a finding and choose **Open a ticket in… → Create ticket**. The ticket contains the finding's facts and a link back to PATHOS, never code or secret values. The finding shows the ticket's key and status, refreshed every few minutes. Closing the ticket does not close the finding: the next scan does, once the issue is gone.

## REST API tokens

User menu → **API tokens (MCP)**: enter a **Name**, choose **Expires in** (7, 30 or 90 days) and what it **Allows**: **MCP server**, **REST API: read** and/or **REST API: read and write**, then **Create token**. Copy the token at once; it is not shown again.

- Use it as `Authorization: Bearer <token>` with `https://<PATHOS>/api/v1/…`, or add PATHOS to an AI assistant with the command shown for MCP tokens (see [AI features](ai-analyst.md#mcp-review-findings-from-your-own-ai-assistant)).
- A token has exactly your current permissions, never more, and stops working if you are deactivated; revoke it at any time with the bin icon in the token list.
- Tokens cannot manage tokens, sign-in or MFA. Changes made with a token are recorded in the audit log with the token's id.

**Related APIs.** [Integrations and reporting](../api-reference/integrations-reporting.md), [Notifications](../api-reference/notifications.md).
