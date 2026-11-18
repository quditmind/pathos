---
title: AI features
section: user-guide
order: 25
version: "1.0"
updated: 2026-11-19
summary: AI providers, automated AI reviews of findings and their approval, reviewing findings from your own AI assistant over MCP, the MCP registry, the AI Security Analyst, AI reports and AI usage.
---
# AI features

PATHOS uses AI in a few clearly separated places. None of them can change a finding on its own unless your configuration allows it, and Critical findings are never closed automatically.

| Feature | Where | Permission |
|---|---|---|
| AI providers and review configuration | **AI & MCP → AI settings** | `ai.configure` |
| Automated and requested AI reviews of findings | **AI & MCP → AI reviews**, **AI review** in a finding | `findings.read` to see, `ai.review` to request and decide |
| Reviews from your own AI assistant (MCP) | User menu → **API tokens (MCP)** | `ai.review` |
| Approved MCP servers | **AI & MCP → MCP registry** | `ai.review` to request, `mcp.manage` to approve |
| AI Security Analyst | **AI & MCP → AI Security Analyst** | `ai.review` |
| AI reports | **AI & MCP → AI reports** | `findings.read` |
| AI usage | **AI & MCP → AI usage** | `ai.configure` |
| AI assistant in a Human Eye review | The review workspace | See [Human Eye](human-review.md#ai-assistant) |

## AI settings (administrators)

**AI & MCP → AI settings** has two parts:

- **Providers.** **Add provider**: *Anthropic (Claude)*, *OpenAI*, *xAI (Grok)* or *Self-hosted (Ollama, vLLM, LM Studio…)*, with its **API key** (optional for most self-hosted servers), **Base URL** (required for self-hosted: the OpenAI-compatible endpoint, usually ending in `/v1`) and a model for the connection test. The key is tested immediately and stored encrypted. A self-hosted model, such as Ollama in the PATHOS stack, keeps code and findings on your network. Claude subscriptions cannot be used for automated reviews; use an API key, or review interactively over [MCP](#mcp-review-findings-from-your-own-ai-assistant).
- **Review configuration.** The provider and **Model**, **Effort**, **Review new findings automatically after each scan**, **Finding types**, **Minimum severity**, **Automated reviews per day**, **Human approval** (*Always*, *Only false positives*, *Never (Critical still requires approval)*), **Send redacted code context (never sent for secret findings)**, **Extra redaction patterns**, **Organization instructions**, and **Allow self-approval of interactive (MCP) reviews** for single-person installations. Each save is a new version with a **Change note**.

## AI reviews of findings

An AI review gives a verdict on one finding: *True positive*, *False positive* or *Needs human review*, with reasoning and remediation. Reviews run automatically after scans when the configuration says so, or on request with **Request AI review** in a finding's details.

- **AI & MCP → AI reviews** lists the verdicts: *All*, *Awaiting approval*, *Applied*, *Rejected* and *MCP* (reviews submitted from an AI assistant).
- Depending on **Human approval**, a verdict waits for a person. Someone with `ai.review` and `findings.triage` enters an optional note and selects **Approve** (apply the verdict to the finding) or **Reject**. You cannot approve your own MCP review unless self-approval is allowed. Closing a Critical finding as a false positive always needs a written justification.
- When AI review cannot decide, or suggests a false positive, the finding can be queued for [Human Eye](human-review.md#how-findings-reach-the-queue).

## MCP: review findings from your own AI assistant

PATHOS runs an MCP server, so an AI assistant such as Claude Code can read and review the findings you may see:

1. User menu → **API tokens (MCP)**, create a token that allows **MCP server** ([API tokens](reporting-and-integrations.md#rest-api-tokens)).
2. Run the `claude mcp add …` command the page shows. With the default self-signed certificate, the page also shows how to trust the PATHOS certificate.
3. Ask, for example: *List my pending high-severity findings in PATHOS and review them.* Your reviews are attributed to you and follow the approval policy.

**AI & MCP → MCP registry** lists the MCP servers approved for use with PATHOS data and which of their tools are allowed. **Request server** (or **Register server** for administrators) with its **Transport** (*Streamable HTTP* or *stdio (local command)*), the **PATHOS data it would receive** (*None*, *Redacted findings*, *Full findings*) and its **Tools** (one per line: `name read|write`). New requests start pending with every tool disallowed; an administrator with `mcp.manage` **Approve**s, **Reject**s, **Disable**s or deletes them.

## AI Security Analyst

**AI & MCP → AI Security Analyst** lets you ask questions in plain language, for example:

- *What should we fix first this week?*
- *Which actively exploited (KEV) vulnerabilities are open?*
- *Which applications have the highest risk, and why?*

What happens when you ask:

- **What the analyst receives.** For each question PATHOS assembles the data you may read:
  - overall figures
  - the riskiest applications
  - the findings that match your question, or the riskiest ones
  - CVE details for identifiers you mention

  Questions about exploited vulnerabilities receive exactly those findings.
- **What it never receives.** Only finding metadata is sent: never source code and never secret values. Values that look like secrets are redacted.
- **Cited findings.** The answer lists the findings it relies on. PATHOS keeps only citations of findings the analyst was actually given.
- **Conversations are private** to you, and each answer records the model, the number of findings it was based on and the tokens used.
- **Read-only.** The analyst cannot change anything in PATHOS.

Answers are AI-generated. Check the cited findings before you act, especially with small local models.

## AI reports

**AI & MCP → AI reports** creates two kinds of report:

- **Executive summaries**, for leadership
- **Technical reports**, for engineering and security teams

Each report covers the organization, one application or one repository. Reports include:

- open findings by severity, actively exploited findings and findings with critical risk
- new and fixed findings, mean time to fix and the share fixed within SLA
- scan coverage
- the riskiest applications and findings

PATHOS computes every figure for your scope. With **AI narrative** on, the AI writes a summary, key risks and recommendations from those figures only. Without it, or without an AI provider, the report has the figures alone. Download any report as Markdown.

## AI usage

**AI & MCP → AI usage** (permission `ai.configure`) shows the requests and tokens of every AI feature, broken down by:

- feature: automated finding reviews, Human Eye suggestions, the analyst and reports
- model
- person
- day

Use it to watch the cost of hosted providers and the load on self-hosted models.

**Related APIs.** [AI and MCP](../api-reference/ai-and-mcp.md), [AI Security Analyst](../api-reference/ai-analyst.md).
