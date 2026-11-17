---
title: "Human Eye: manual security assessment"
section: user-guide
order: 9.7
version: "1.0"
updated: 2026-11-17
summary: Investigate scanner findings by hand, record exploitability, risk and evidence, decide a disposition (with independent review where required) and track remediation.
---
# Human Eye: manual security assessment

Scanners and AI review produce many findings; some need a person to decide whether they are real. **Human Eye** is where security analysts do that work: it collects the findings that need a decision, gives you the code, data flow, evidence and history in one workspace, and records an auditable decision.

The **Human Eye** section in the navigation has six pages:

| Page | What it is for |
|---|---|
| **Overview** | Counts and charts: what is pending, in progress and completed, outcomes, workload, trends and confirmed vulnerabilities awaiting remediation |
| **Review Queue** | Findings waiting for review, with search, filters, sorting, bulk assignment, priority and due dates |
| **Assessments** | Your assessments, those awaiting a second reviewer, in progress and completed |
| **Assignments** | Workload per analyst and (re)assignment |
| **Review Reports** | Results for a period: reviewed, confirmed, false-positive rate, severity changes, independent review results; CSV export and print to PDF |
| **Review Configurations** | Workflow rules (administrators) |

## How findings reach the queue

PATHOS adds a finding to the queue when automated triage marks it *needs review*, when AI review cannot decide, or when AI review suggests a false positive (a person must confirm). Administrators can also queue every new finding above a severity. You can add findings yourself from the **Findings** page: select them and choose **Send to Human Eye**. A finding is never queued twice.

Each review has a permanent **Finding ID** such as `QD-HR-000042`.

## Working on a review

Open a review from the queue. If it is not assigned yet, choose **Assign to me & start**. The workspace has eight tabs:

1. **Overview**: the vulnerability, scanner and human-assessed severity, CWE, CVE and OWASP category, the location as scanned (repository, branch, commit, file and line), the original scanner output, the automated triage state and the AI review summary.
2. **Source code**: the file at the **commit that was scanned**, never the current branch head, with the vulnerable line highlighted. Choose ±20, 30 or 50 lines or the whole file, click an identifier to find its references, jump to functions, open other files by path, and **compare** with the branch head or later commits. If the code cannot be retrieved, the tab says why.
3. **Data flow**: source-to-sink paths when the scanner reported them. *Confirmed*, *incomplete* and *inferred* (related locations without a proven flow) are shown differently. Click a step to open its code and note input validation, sanitization or authorization checks. Record the flow you traced yourself in **Analyst-traced data flow**.
4. **Exploitability**: twelve questions (reachable? attacker-controlled input? authentication required? …) answered Yes, No, Unknown or N/A, plus the attack scenario, complexity, privileges, network accessibility and impacts. Unknown is a valid answer and is never taken as proof that the finding is not exploitable. Fields marked * are required before a final decision.
5. **Evidence**: upload screenshots, documents and logs, or paste HTTP requests and responses and command output. Each item gets an evidence ID, type, classification and description. Fill in the reproduction template (preconditions, environment, steps, expected and actual result, impact).
6. **Risk assessment**: the scanner's severity, score and vector next to yours. Build a CVSS 3.1 vector (the score is calculated) or a CVSS 4.0 vector (enter the score from the FIRST calculator), choose the assessed severity and **justify** it. The scanner's values are never changed.
7. **Remediation**: guidance for developers (root cause, recommendation, secure example, references, action items, verification steps). Once a finding is confirmed, track remediation status, owner, target date, priority and a link to your ticket.
8. **History**: every change with who, what, before and after, and when, plus comments. History cannot be edited.

Save each tab with **Save assessment**. Use **Awaiting info…** when you are blocked, with a note on what you need.

## Deciding

Choose **Submit decision** and pick a final disposition:

- **Confirmed**: a real vulnerability. It goes to remediation; the remediation owner becomes the finding's assignee.
- **False positive**: explain why the detection is wrong. The finding is closed as a false positive.
- **Duplicate**: pick the primary finding.
- **Not exploitable**: needs evidence or an exploitability justification.
- **Accepted risk**: name the risk owner and expiry. Someone allowed to accept risk must approve it.
- **Mitigated**, **Out of scope**, or **Needs more information** (keeps the review open).

Every decision needs a documented reason. Depending on the configuration (by default Critical and High findings, and every accepted risk), the decision goes to an **independent reviewer** before the review is closed. While it waits, the assessment is locked.

## Independent review

If you hold the Independent Reviewer role, reviews awaiting you are under **Assessments → Awaiting independent review**. Read the assessment, source code and evidence, then **approve**, **reject** (it goes back to the analyst) or **request information**, with your comments. Your outcome is recorded separately; you cannot change the first reviewer's work, and you cannot review your own decision.

### Final approval (three levels)

For the most sensitive decisions, a third person can be required:

1. In **Review Configurations → Final approval**, choose severities or dispositions, for example every **Critical** finding or every **False positive**.
2. Matching decisions first go to the independent reviewer.
3. When the independent reviewer approves, the review stays locked and shows that a **final approval** is required.
4. Someone with the approval permission who is neither the analyst nor the independent reviewer gives it with **Final approval**. A rejection or a request for information sends the review back to the analyst, as at the first level.

Both approvals appear in the history and the reports. With nothing selected, reviews keep the two-level flow.

## Reopening

Review managers and independent reviewers can **Reopen** a completed review with a reason. A new round starts from the previous assessment; the earlier decision stays in the history. A false positive or accepted risk reopens the finding.

## AI assistant

**AI assist** opens a panel of suggestions: a plain-language explanation, code summary, likely vulnerable paths, investigation questions, false-positive indicators, evidence to collect, remediation, secure code, CWE and OWASP references, and a draft assessment summary. Suggestions are labelled, kept with the review, and only added to your assessment when you choose **Add to …**. AI never completes a review or approves anything. It needs an AI provider (Administration → AI settings).

### Patch proposals, risk explanations and possible duplicates

The AI assistant can also:

- **Propose a patch.** The AI writes a unified diff for the reviewed file.
  - PATHOS checks that it is a well-formed patch of exactly that file and that it changes more than whitespace. Anything else is refused.
  - The proposal stays **Proposed** until an analyst **approves** it or **rejects** it with a note. Both decisions are recorded in the history.
  - An approved patch can be downloaded as a `.patch` file for a developer to apply through the normal code review. **PATHOS never changes a repository.**
  - Patch proposals need the source code, so sending code to AI must be allowed.
- **Explain the risk score.** The AI turns the finding's contextual risk score and its factors into plain language, including what would lower the score.
- **Find possible duplicates.** The AI compares the finding with nearby or similar findings in the same repository and says which are likely the same issue. The analyst decides.

## Permissions

| Role | Can |
|---|---|
| Viewer, Auditor and other read-only roles | See completed assessments in their scope |
| Security Analyst, AppSec Engineer | Work on assigned reviews: assess, upload evidence, comment, decide |
| Independent Reviewer | Approve, reject or request information on others' decisions |
| Security Manager | All of the above, assign reviewers, configure, approve accepted risk |
| Platform Administrator | Assign reviewers and manage the configuration |

## Troubleshooting

- **Source code unavailable: credential rejected.** The repository's SCM connection token has expired or was revoked; update it under **Administration → SCM connections**.
- **The queue is empty.** Only findings that need a decision arrive automatically. Check **Review Configurations** or send findings from the Findings page.
- **"Complete the required assessment fields".** Answer the questions marked * in the Exploitability tab.
