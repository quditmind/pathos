# Human Eye module

Human Eye is the manual security assessment workflow of PATHOS. Security analysts investigate findings produced by the scanners (SAST, SCA, secrets, IaC, container), document exploitability, risk and evidence, and decide a final disposition. Automated triage and AI review feed the queue; a person always makes the decision.

It is a standalone module (navigation section **Human Eye**): Overview, Review Queue, Assessments, Assignments, Review Reports and Review Configurations, plus the assessment workspace at `/human-review/reviews/{id}`.

- User guide: `docs/user-guide/human-review.md` (also in the in-app Help Center)
- API: `docs/api-reference/human-reviews.md`
- Code: `backend/internal/review`, `frontend/src/features/review`, migration `00012_human_review.sql`

## Design principles

1. **A review references a finding; it never copies it.** `human_reviews.finding_id` is unique, so importing a finding again (automatically or manually) returns the existing review. Re-reviews are new **rounds** of the same review.
2. **Scanner data is preserved.** The scanner's severity, score and vector are snapshotted on the review and protected by a trigger; the scanner's own record of the finding (redacted SARIF result or Grype match, rule and code flows) is captured from the raw report before retention prunes it. The human-assessed severity is a separate field.
3. **Three separate classifications**: review status (workflow), final disposition (outcome), remediation status. They are never combined.
4. **Decisions are append-only.** Each submission is a new `human_review_decisions` row; independent reviewers write `human_review_approvals` and never edit the first reviewer's assessment or decision. History, decisions, approvals, comments and AI suggestions cannot be updated or deleted by the application role.
5. **No fabrication.** Source code is read at the scanned commit (or the uploaded snapshot), never the branch head. Data flow comes only from what the scanner reported; related locations are labelled *inferred*, and nothing is shown when nothing was reported. When something is unavailable, the UI says why.
6. **AI assists, people decide.** AI suggestions are stored for traceability, clearly labelled, and only enter an assessment when the analyst explicitly adds them. AI never completes a review, approves accepted risk or marks a false positive.

## Workflow

```
pending ──assign──▶ assigned ──start──▶ in_progress ◀──▶ awaiting_information
                                          │
                                   submit decision
                    ┌─────────────────────┼──────────────────────────┐
              independent required     final                needs more information
                    ▼                     ▼                          ▼
     awaiting_independent_review ──approve──▶ completed ──reopen──▶ reopened (round + 1)
                    │ reject / request info
                    ▼
            in_progress / awaiting_information
```

Dispositions and their rules (all need a documented reason of at least 10 characters):

| Disposition | Additional requirement | Effect on the finding |
|---|---|---|
| Confirmed | — (optional remediation owner, date, priority) | `needs_review` → `open`; an AI false positive is reopened; remediation status `open`; the owner becomes the finding assignee |
| False positive | Explanation of why the detection is wrong (≥ 30 characters) | Status `false_positive` (recorded in the finding lifecycle) |
| Duplicate | Primary finding (or explicitly not in PATHOS) | Leaves `needs_review` |
| Not exploitable | Evidence or an exploitability justification | Leaves `needs_review` |
| Accepted risk | Risk owner, expiry (≤ 3 years); always independently approved by someone with `findings.accept_risk` | A pending **risk acceptance** is opened and approved by the independent reviewer; the finding becomes `accepted_risk` until expiry |
| Mitigated, Out of scope | — | Leaves `needs_review` |
| Needs more information | — | The review stays open (`awaiting_information`) |

Configured requirements (Review Configurations) are enforced on the server: required assessment fields, evidence for given dispositions or severities, and independent review for given severities (scanner or assessed) and dispositions. "Unknown" answers count as answered but are never read as evidence of non-exploitability.

Every finding change carries the actor and reason through the existing finding lifecycle trigger, so `finding_status_history` shows "Human Eye review QD-HR-… : …".

### Remediation sync

A trigger on `findings.status` keeps confirmed reviews in step with scans: a scan that no longer detects the finding moves remediation to **Pending verification**; detection after a fix moves it to **Reopened**. **Verified** can only be set by an analyst once the finding is no longer detected.

## Ingestion

`review.Service.Ingest` runs after every scan (chained after AI auto-review), every two minutes in the jobs role, and on demand (**Sync queue**). It selects open findings, filtered by category, minimum severity and scanners, whose trigger matches the configuration:

- `needs_review` — automated triage or a person set the finding to *needs review*
- `ai_needs_review` — the latest AI verdict is *needs review*
- `ai_false_positive` — the latest AI verdict is *false positive* (including findings the AI already closed): a human confirms
- `new_findings` — every new finding that matches the filters

Inserts use `ON CONFLICT (finding_id) DO NOTHING`. Priority and due date come from the severity rules. New reviews can be assigned automatically (round robin or least loaded) among a pool of analysts who hold `reviews.assess` on the repository.

## Source code and data flow

- **SCM repositories**: `scm.ContentReader` (GitHub, GitLab, Bitbucket Cloud, Azure DevOps) reads a file at the exact commit recorded on the review, plus its commit history. The repository's existing connection and credential are used, so provider permissions apply.
- **Uploaded repositories**: the file is read from the encrypted snapshot the scan used.
- Files over 1 MiB, binary files and unreachable providers produce a clear unavailable state; the scanner-captured (redacted) context is shown when available. Code around secret findings is redacted.
- Comparison with a later version (branch head, later scans, file history) is a line diff in the browser.
- Data flow: SARIF `codeFlows` (taint paths) are **confirmed**; a path with fewer than two steps is **incomplete**; `relatedLocations` without a flow are **inferred**; otherwise **unavailable** with the reason. Analysts annotate steps (validation, sanitization, authorization, transformation) and record their own traced flow separately.

## Evidence

Files are validated by extension *and* content (PNG, JPEG, GIF, WebP, PDF, UTF-8 text, CSV, JSON, HAR, DOCX, XLSX; never HTML, SVG, scripts, archives or executables), limited in size (configurable, default 20 MB), hashed (SHA-256), stored encrypted in the source store under `evidence/{org}/{review}/{id}` and served with `Content-Security-Policy: sandbox`, `nosniff` and as attachments (images may be previewed inline). Text evidence (HTTP requests and responses, command output, logs) is stored inline. Deleting evidence removes the content but keeps the record, its hash and the reason. Without a configured source store, file uploads are disabled and text evidence still works.

## Authorization

| Permission | Scope | Granted to |
|---|---|---|
| `reviews.read` | scoped | every read-only role (read-only users see **completed** assessments only) |
| `reviews.assess` | scoped | Security Analyst, AppSec Engineer, Security Manager |
| `reviews.assign` | scoped | Security Manager, Platform Administrator |
| `reviews.approve` | scoped | **Independent Reviewer** (new role), Security Manager |
| `reviews.configure` | org-only | Security Manager, Platform Administrator |

The API enforces everything: an analyst works on reviews assigned to them (or self-assigns if allowed); review managers can step in; independent reviewers cannot approve their own decision (also enforced by a database trigger) and only the designated one may decide when one is assigned; accepted risk needs `findings.accept_risk`. Reviews outside the caller's scope return 404. Every change is in the immutable review history and in the audit log (`human_review.*`).

## Notifications

Events `review.assigned`, `review.independent_requested` (to eligible independent reviewers, or the designated one), `review.independent_decided` and `review.overdue` (once per review), each with a built-in rule that administrators can edit. Configuration switches can turn them off.

## Reports and exports

The overview and reports aggregate the database (no stored metrics). CSV export (`findings.export`) streams up to 50,000 reviews with formula-injection protection. PDF: the reports page has a print layout (browser **Print → Save as PDF**); PATHOS does not generate PDFs on the server.

## Limitations and dependencies

- CVSS 4.0 scores are entered from the FIRST calculator; PATHOS validates 4.0 vectors and computes CVSS 3.x base scores.
- Reference search covers the open file; cross-file navigation is by path (no repository-wide code index).
- Data flow depends on the scanner: Opengrep taint rules report code flows; most other scanners do not.
- Source retrieval needs a working SCM credential that can read the repository; an expired token shows *credential rejected*.
- AI assistance needs a default AI configuration (Administration → AI settings).
- Remediation links point to external trackers; PATHOS does not change code or open pull requests.
