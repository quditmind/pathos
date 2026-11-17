---
title: Security policies and compliance
section: user-guide
order: 9.76
version: "1.0"
updated: 2026-11-18
summary: Write rules that block risky changes, require reviews and tighten deadlines, and see open findings against OWASP, PCI DSS, ISO 27001 and SOC 2 controls.
---
# Security policies and compliance

## Security policies

A security policy says *"findings like this, in places like that, must be handled like so"*. Examples:

- **No actively exploited vulnerabilities in production**: KEV = yes, environment = production → block, deadline 7 days, notify.
- **Hard-coded secrets in PCI repositories need a second look**: type = Secrets, compliance scope = PCI DSS → require a Human Eye review.
- **Malicious packages are never merged**: malicious package = yes → block.

Open **Policies** (administration) → **Security policies** → **New policy**. While you edit, PATHOS shows how many open findings would match right now, so you can check a policy before saving it.

What the actions do:

| Action | Effect |
|---|---|
| **Block** | A scan's security gate fails when it finds a new finding that matches; a pull request check fails when the pull request introduces one. The scan's events and the pull request status name the policy |
| **Require a Human Eye review** | Matching findings are queued for review, citing the policy |
| **Remediation deadline** | The deadline becomes at most N days after detection. Removing or relaxing the policy restores the normal SLA |
| **Notify** | A *Security policy violated* notification (by default to security managers and repository owners); change recipients in Notifications |

Click a policy's **open violations** count to see the findings that violate it (and, with **Show resolved**, those that no longer do). A finding's details list the policies it violates. Every change is versioned and recorded in the audit log.

Policies are checked after every scan, for every pull request check, and every 10 minutes, because a finding's risk, exploit status and age change between scans. Conditions on contextual risk, reachability, age or public exploits need data that pull request findings do not have yet, so those policies apply to the scan branch only (the list marks them).

## Compliance

**Compliance** (under Posture) shows open findings against the controls of five frameworks:

| Framework | Applies to |
|---|---|
| OWASP Top 10 (2021), OWASP ASVS (4.0.3) | Every repository |
| PCI DSS (4.0.1) | Repositories with the **PCI DSS** compliance scope |
| ISO/IEC 27001 Annex A (2022) | Repositories with the **ISO 27001** scope |
| SOC 2 Trust Services Criteria | Repositories with the **SOC 2** scope |

Set a repository's compliance scopes in its details (classification). Each control shows **Failing** (open critical or high findings), **Attention** (other open findings) or **No open findings**, with the counts by severity; click the counts to open those findings.

Findings are mapped to controls by their type, their CWE and malicious package intelligence (for example, hard-coded secrets → PCI DSS 8.6.2; vulnerable dependencies → OWASP A06 and PCI DSS 6.3.3). The mapping is **indicative**: it is evidence to prepare an assessment, not a statement that you comply. Controls that are about processes rather than code cannot be shown by findings.
