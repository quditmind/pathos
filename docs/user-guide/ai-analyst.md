---
title: AI Security Analyst and AI reports
section: user-guide
order: 9.9
version: "1.0"
updated: 2026-11-18
summary: Ask questions about your security data, generate technical and executive reports, and follow AI usage.
---
# AI Security Analyst and AI reports

These features need an AI provider. Administrators set it up under **AI & MCP → AI settings**. A self-hosted model, such as Ollama in the PATHOS stack, keeps everything on your network.

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

**Administration: AI & MCP → AI usage** shows the requests and tokens of every AI feature, broken down by:

- feature: automated finding reviews, Human Eye suggestions, the analyst and reports
- model
- person
- day

Use it to watch the cost of hosted providers and the load on self-hosted models.

**Related APIs.** [AI Security Analyst](../api-reference/ai-analyst.md).
