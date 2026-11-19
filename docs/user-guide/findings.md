---
title: Working with findings
section: user-guide
group: assess
order: 12
version: "1.0"
updated: 2026-11-19
summary: The findings list and details, status and lifecycle, assignment, bulk actions, risk acceptance, remediation SLAs and suppression rules.
---
# Working with findings

A **finding** is one security problem that a scanner, an imported report or a scan target reported. PATHOS normalizes and de-duplicates the results of every tool: the same vulnerability reported by several scanners is one finding, and **Detected by** lists the scanners.

Open **Vulnerabilities → Findings** (permission `findings.read`). You see the findings of the repositories in your scope.

![Findings](images/findings.png "Findings: severity counts, filters (status, assignee, SLA, type, scanner, repository) and the finding list")

## The findings list

- **Severity cards** (Critical, High, Medium, Low, Info) count the findings that match the other filters. Select a card to filter by that severity.
- **Search findings** matches the title, rule, CVE, file or package.
- **Filters**: Status (default *Open*), Assignee (*Assigned to me*, *Unassigned*), Lifecycle, Exploited (KEV), Malicious packages, Deployed and Internet-exposed ([runtime context](runtime.md#in-the-findings-list-and-the-finding-drawer)), Risk, Order (*Order by severity* or *Order by contextual risk*), Human Eye (review state or outcome), SLA (*Breached*, *Due within 7 days*), Reachability (*Reachable*, *Not reachable*, *Unknown*, and by how it was decided: *function level (call graph)*, *function level (calls in the code)*, *package imports*), Asset (source code, container images, web applications, APIs, imported SBOMs, build artifacts), Type, Scanner and Repository.
- **Columns** shows or hides columns. Hidden by default: Repository, Repository ID, Runtime, Detected by, EPSS, KEV, Confidence, Application, Fixed version and Location. Repository, Repository ID, Runtime, EPSS, KEV, Confidence and Application are always included in **Export** (CSV of the loaded rows).

Filters are kept in the page address, so a filtered view can be bookmarked or shared.

| Concept | Values |
|---|---|
| Severity | Critical, High, Medium, Low, Info. PATHOS never changes it; a Human Eye reviewer records an *assessed* severity separately |
| Type | Secrets, Code (SAST), Dependencies (SCA), Infrastructure as code, Container, License, Web and API (DAST), Malware, Framework configuration, Binary hardening, Other |
| Risk | Contextual risk score 0–100, see [Contextual risk](vulnerability-intelligence.md#contextual-risk) |

## Finding details

Select a finding to open its details panel:

- severity, lifecycle, CVSS, the SLA badge, *reappeared n×* when it came back after being fixed, and *risk accepted until …*
- the **Status** and **Assignee** controls, **Risk acceptance** and the **History** of every status change (who or what changed it, when and why)
- **Contextual risk** with every factor ([explained here](vulnerability-intelligence.md#contextual-risk))
- **Where it runs**: the clusters, namespaces and workloads that run the finding, with the evidence of the link, exposure and matched runtime alerts ([runtime context](runtime.md))
- **How the package gets in** for dependency findings ([dependency paths](posture.md#dependencies-of-a-repository))
- the Human Eye review and its outcome, if there is one
- type, rule, CVE (links to the [vulnerability page](vulnerability-intelligence.md#vulnerability-details)), CWE, package, **Fixed in**, location, **Detected by**, first and last seen, **First detected at commit**, and whether a suppression rule decided it
- **Reachability** for dependency findings: reachable, not reachable or unknown, why, and how it was decided. For a function-level answer it also shows the vulnerable functions checked, the **call paths** (each a chain of `file:line` frames, outermost caller first, ending at the call of the vulnerable function), the dynamic uses or untyped calls that made it unknown, the tool and scan behind it and what the method cannot see ([reachability](vulnerability-intelligence.md#function-level))
- the security policies it violates, linked tickets, **Fix pull request** (dependency findings), **AI-proposed fix** (SAST, secrets and IaC findings, see [below](#ai-proposed-fixes)), related findings, the code snippet, **AI review** and **Sightings** (every scan that saw it)

### Where a finding came from

- **First detected at commit**: the commit of the first scan that found the finding.
- **Live secret validation** (secret findings): whether the credential is still active at its provider, with the request, HTTP status and identity as evidence, and **Re-check**. Off unless an administrator enables providers; see [Live secret validation](secret-validation.md).
- **Introduced by** (code, secret and IaC findings): the commit that introduced the line, with the author's name and date, from `git blame` of the scanned commit. Repositories cloned without history show **Unknown (shallow clone)**; enable full history to record it. See [Commit-based tracking](security-scanning.md#commit-based-tracking).
- Two further types exist besides scanner results: **End of life** (a runtime, framework or image no longer supported, see [End of life](supply-chain.md#end-of-life)) and **Supply chain (signatures)** (a required signature that could not be verified, see [Signature and provenance verification](supply-chain.md#signature-and-provenance-verification)).

## AI-proposed fixes

For SAST, secrets and IaC findings, **Propose fix** in the finding's details asks the organization's AI provider for a code change. Nothing an AI model writes is offered as ready until PATHOS has checked it.

**Before you start.** An administrator must add an AI provider and a default AI configuration that allows sending code (**AI settings**; a self-hosted model such as Ollama works). Without one, the panel says that AI fixes are off. You need the `ai.fix` permission on the repository ([RBAC](https://github.com/quditmind/pathos/blob/main/docs/RBAC_MATRIX.md#ai-proposed-fixes-aifix)).

**What happens:**

1. PATHOS reads the finding's file at the scanned commit and sends the finding and the code around it to the provider. Secrets are redacted first (built-in and organization patterns; for secrets findings, the value itself and every copy of it). The hash of what was sent is stored.
2. The provider returns a unified diff. PATHOS **rejects** it when it changes anything but the finding's file and at most two files next to it, touches a CI pipeline, build script, dependency manifest or lockfile (unless the finding is in that file), creates, deletes or renames files, is larger than the limits, or writes the redaction marker into the code.
3. A worker **applies** the diff to a fresh checkout of the scanned commit and **re-runs the scanner** that reported the finding on the changed file, once without and once with the change. The finding must have been reported before and be gone after, and no new result may appear in the changed files.
4. If an administrator chose a **test runner** for the repository (repository details, Security tab, **AI fix verification**: `go test ./...` or `python -m unittest discover`), the repository's tests run without and with the change in the sandboxed fuzz worker, with no network access and CPU, memory and time limits. They must pass both times. This runs the repository's code, which is why it is off by default. Go modules must vendor their dependencies, and Python tests run with the standard library only.

The panel shows the diff, each step with its status and detail, the scanner's results before and after (with the raw reports to download) and the test log. A fix that fails shows the reason, for example *the scanner still reports rule … after the fix* or *the tests pass without the fix and fail with it*.

**Open pull request** appears only on a **verified** fix, for people who also have `findings.triage` and `repos.manage` on the repository, and only when the repository allows [fix pull requests](supply-chain.md#fix-pull-requests). PATHOS creates a `pathos/fix/ai-…` branch from the verified commit, commits the verified files and opens the pull request; it never merges. The finding stays open until a later scan no longer detects it.

Limits: 10 requests per person per hour and 200 per organization per day. Every request, proposal, verdict and pull request is in the audit log (`ai_fix.*`).

Verification shows that the scanner no longer reports the finding in the changed file and that the tests still pass. It does not prove that the change is correct in every case: review it like any other contribution.

## Status and lifecycle

Every finding has a **status**, which people change, and a **lifecycle**, which PATHOS derives from the status, scans and reviews. The **Status** column of the list shows the lifecycle.

| Status | Meaning |
|---|---|
| Open | Known and not yet handled (the default filter) |
| In progress | Someone is working on it |
| Needs review | Needs a decision |
| Fixed | Fixed; set automatically when a scan no longer detects it |
| False positive | The detection is wrong |
| Accepted risk | Set only through an approved [risk acceptance](#risk-acceptance) or suppression rule |

| Lifecycle | Meaning |
|---|---|
| New | First seen by the latest scan; nobody has looked at it yet |
| Open | Known and open |
| In progress | Someone is working on it |
| Under review | Needs a decision: automated triage flagged it or a Human Eye review is open |
| Confirmed | A Human Eye reviewer confirmed it is real |
| False positive / Accepted risk | Closed by a decision |
| Resolved | A scan no longer detects it |
| Reopened | Detected again after being resolved |

### Change the status

**Required permission.** `findings.triage` on the repository.

1. Open the finding and choose the new value in **Status**. Only allowed changes are offered: Open, In progress and Needs review can move to each other, to False positive or to Fixed; False positive and Fixed can only go back to Open.
2. Enter a **Reason**. It is required (at least 5 characters) for *False positive* and *Fixed*.
3. Select **Apply**.

Closing a **Critical** finding as a false positive also needs `findings.accept_risk`. Every change is recorded in the finding's history and the audit log (`finding.status`).

PATHOS changes statuses too: a finding that a successful scan no longer reports becomes **Fixed**, and it is reopened when a later scan finds it again. Failed or cancelled scans never close findings.

### Assign

In **Assignee**, choose a person (the list is shown when you may list users organization-wide), or use **Assign to me** / **Unassign**. The assignee receives the *Finding assigned* notification. Needs `findings.triage`.

### Bulk actions

Select rows with the checkboxes (1–500 findings) to show the bulk bar:

| Action | Permission |
|---|---|
| **Set status…** with a reason, then **Apply** | `findings.triage` |
| **Assign to me**, **Unassign** | `findings.triage` |
| **Send to Human Eye** with a reason, then **Add to review queue** | `reviews.assign` |

Findings already in the review queue are reported as *already queued* and not added twice.

## Risk acceptance

A risk acceptance is a time-boxed exception: the finding counts as **Accepted risk** until the acceptance expires, then it reopens automatically.

1. Open the finding and select **Request acceptance** (needs `findings.triage`; the finding must be Open, In progress or Needs review).
2. Write the **Justification** (at least 10 characters: compensating controls, exposure, plan), choose the duration (30, 90, 180 or 365 days) and select **Submit for approval**.
3. Someone **else** with `findings.accept_risk` approves or rejects it, in the finding or on **Vulnerabilities → Risk acceptances**. You cannot approve your own request.

**Vulnerabilities → Risk acceptances** lists acceptances by status (*Pending*, *Approved*, *Expired*, *Rejected*, *Revoked*, *All*). Approvers can enter a **Decision note** and **Approve**, **Reject**, or **Revoke** an approved acceptance; revoking reopens the finding. The *Risk acceptance requested* and *Risk acceptance decided* notifications inform approvers and the requester.

A risk acceptance that belongs to a Human Eye review (disposition *Accepted risk*) is decided in Human Eye by the independent reviewer; see [Human Eye](human-review.md#deciding).

## Remediation SLAs

Each open finding gets a remediation deadline: its first detection plus the number of days set for its severity. The defaults are Critical 7, High 30, Medium 90 and Low 180 days, and no deadline for Info. Administrators change them in **Administration → Policies → Remediation SLAs** ([Policies](policies-and-compliance.md#remediation-slas-and-license-policy)); a [security policy](policies-and-compliance.md#security-policies) can set a shorter deadline for matching findings.

- The **SLA** column shows *due in n d* (highlighted within 7 days) or *breached n d ago*.
- The **SLA** filter shows *Breached* or *Due within 7 days*.
- When findings pass their deadline, the *SLA breached* notification is sent (one message per repository and run).

## Suppression rules

**Vulnerabilities → Suppression rules** decides many findings at once, for example:

- findings in generated code
- test fixtures
- an advisory that does not apply to how you use a package

The rule's safeguards:

- **Four eyes.** A rule takes effect only when **someone other than the person who proposed it** approves it. Approving needs `findings.accept_risk`.
- **Specific matching.** A rule matches by rule ID, file path, package or CVE (at least one), optionally narrowed by scanner or type, within one repository, one application or the whole organization. **Preview matches** shows the open findings it would decide before you propose it.
- **Expiry and justification.** Every rule has a justification and an expiry, at most one year away.
- **Lifecycle, not deletion.** Matching findings become **False positive** or **Accepted risk** through the normal lifecycle. Their history names the rule and its approver, and their evidence is kept. Findings detected later that match an active rule get the same decision when their scan finishes.
- **Reopening.** When a rule expires or is revoked, every finding it decided reopens.

## Step-by-step: triage a new critical finding

**Purpose.** Decide what happens to a new critical finding and who fixes it.

**Required permissions.** `findings.read`; `findings.triage` to change the status and assign; `findings.accept_risk` to approve a risk acceptance.

1. Open **Vulnerabilities → Findings**, select the **Critical** card and set **Order** to *Order by contextual risk*.
2. Open the first finding. Read **Contextual risk**, the location and the code snippet. For a CVE, open its vulnerability page for exploit evidence.
3. If it is real: set **Status** to *In progress* and choose the **Assignee** (or **Assign to me**). Optionally open a ticket ([Jira and ServiceNow](reporting-and-integrations.md#jira-and-servicenow)).
4. If it is not: set **Status** to *False positive* with a reason, or select it in the list and **Send to Human Eye** when a second opinion is needed.
5. If it cannot be fixed in time: **Request acceptance** with a justification and a duration.

**Expected result.** The finding shows the new status, assignee and history entry. The first successful scan that no longer detects it closes it as Fixed.

**Related APIs.** [Findings](../api-reference/findings.md), [Vulnerability intelligence](../api-reference/vulnerability-intelligence.md) (suppression rules).
