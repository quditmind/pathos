---
title: Remediation workspace and security gates
section: user-guide
group: remediate
order: 22
version: "3.0"
updated: 2026-11-20
summary: Track fixes from finding to proof (owner, SLA due date, guidance, fix pull request, targeted rescan with before-and-after evidence) and decide at every stage — IDE, pre-commit, pull request, CI, release, deploy — with policy-driven gates that never block without a policy.
---
# Remediation workspace and security gates

Quditmind PATHOS · applies to v3.0 (unreleased) · status: Prototype (behind the `remediation_workspace` feature flag)

**Remediate & gate → Remediation workspace** (`/remediation`) brings three views together:

- **Workspace**: remediation items, one per finding or per group of findings, with owner, due date, status, root cause, secure fix guidance, fix pull request and verification.
- **Gates & decisions** (`/remediation/gates`): the security gates of every stage and the log of their decisions.
- **Exceptions & approvals** (`/remediation/exceptions`): time-limited exceptions and approval requests, decided by someone other than the requester.

The module is behind the feature flag `remediation_workspace` (off by default). An administrator with `settings.manage` turns it on under **Administration → Feature flags**. While it is off, the pages show a "not enabled" notice and the API answers `404` with `PTH-PLAT-1007`.

Permissions: `remediation.read` to see items, gates and decisions; `remediation.manage` to create and update items and request exceptions; `remediation.manage` and `scans.run` to request a verification (it runs a scanner) — except that an item's assigned owner may always verify their own item, with `remediation.read` alone; `gates.manage` (organization-wide) to add and change gates; `gates.approve_exception` to approve or reject exceptions and approvals.

## Remediation workspace

Create items from **Findings**: select findings, choose **One item per finding** or **One item for all selected**, then **Create remediation items**. A finding belongs to at most one open item (`PTH-REM-1103`).

Each item shows:

| Field | Where it comes from |
|---|---|
| Owner | Set by hand (**Assign to me**, or a user picker with `users.read`) |
| Due date | The earliest SLA deadline of its findings (the existing SLA engine and policies that tighten it), labelled *SLA*; or a date set by hand, labelled *set by hand* (**Use SLA** returns to the SLA) |
| Status | Open, Planned, In progress, Fix submitted, Verifying, Closed (verified), Won't fix |
| Root cause | Free text written by the team |
| Secure fix guidance | The upgrade target of a vulnerable dependency (scanner data), verified AI fixes (*verified*), AI review recommendations (*AI-inferred*) and Human Eye guidance (*human*), each labelled with its evidence |
| Affected files | The files of its findings |
| Fix pull request | Dependency-upgrade and verified-AI-fix pull requests opened for its findings |
| Verification | Before-and-after evidence of every verification |

Filter by status, owner (mine or unassigned), priority, repository, overdue and text; sort by due date, priority or age. **Save current view** stores the filters for you, or for the whole organization when shared.

Select rows to **assign**, set the **status**, **priority** or **due date** of many items at once; every bulk change asks for confirmation and is audited.

An item closes only through a verification that proves the fix. Choosing *Closed* by hand is refused (`PTH-REM-1101`); *Won't fix* is a manual decision.

## Fix verification

**Verify fix** on an item queues a targeted rescan:

1. A worker that has the finding's check checks out the commit the finding was last seen on (*before*) and the current head of the repository's scan branch (*after*).
2. It runs the finding's own check on the affected files only, in both checkouts, the same way verified AI fixes are checked.
3. PATHOS records the evidence: the scan execution and commit of each side, the number of results, each finding's status before and after, and whether the check reported it before and not after.

Results:

| Result | Meaning | Item |
|---|---|---|
| Fixed (proven) | Reported before, gone after | Closed |
| Still present | Still reported after | Back to In progress |
| Regression found | Gone, but new results appeared in the same files (listed) | Back to In progress |
| Inconclusive | The baseline did not reproduce the finding, so its absence proves nothing | Back to In progress (`PTH-REM-1106`) |
| Failed | The rescan could not run (clone, scanner or worker); the reason is recorded | Back to In progress (`PTH-REM-1105`) |

Verification needs a repository with an SCM connection, a finding with a file location, a commit from its last scan and a check PATHOS can re-run (not an imported report). When one is missing, the button is disabled with the reason (`PTH-REM-1102`). Through the API, an item can also be verified with a finished scan of the scan branch (`scan_job_id`): the finding must be absent from it while its check ran successfully, and findings that scan first reported in the affected files are listed as regressions. A verification never changes the findings themselves; scans resolve them.

**Fix merged → targeted rescan.** When a fix pull request linked to an item is merged, PATHOS queues the same targeted rescan automatically (trigger *Fix PR merged*), so the item closes as soon as the merge proves the fix.

## Security gates

A gate applies one **security policy** (Administration → Policies) at one **stage**:

| Stage | Who asks | How |
|---|---|---|
| IDE | Developers | The VS Code and JetBrains plugins' existing finding views list the repository's open findings, which the IDE gate evaluates; `pathos gate --stage ide --repo <repository>` gives the decision |
| Pre-commit | Developers | `pathos gate --stage pre-commit --repo <repository>` in a pre-commit hook |
| Pull request | PATHOS | Pull request checks call the gate when the PR scan finishes |
| CI | Pipelines | `pathos gate --stage ci --scan <scan id>` |
| Release | Release pipelines | `POST /api/v1/gates/evaluate` with `stage: release` |
| Deploy | CD (Argo CD, others) | `POST /api/v1/gates/evaluate` with `stage: deploy` |

When the policy matches the findings in scope (new findings of the scan, otherwise the open findings of the repository or application), the gate's **mode** decides:

- **Block**: the decision is *block* (the CLI exits 1, the pull request status fails).
- **Warn**: the decision is *warn*; nothing is blocked.
- **Require approval**: the decision is *approval_required* until someone approves it.

Security policies with the **Block** action also block pull request and CI decisions, as before.

### No gate blocks without a policy

A *block* or *approval required* decision always names the policies that caused it. With no gate configured, or no policy matching, the decision is **pass** and the log records it as *no policy*. The database itself refuses a blocking decision without a policy. A disabled policy makes its gate pass.

### Pull request checks: block or warn

Enabling pull request checks for a repository (**Pull request checks → Repository settings**) requires an explicit choice: **Block the pull request** or **Warn only** (`PTH-GATE-1106` otherwise). The choice and the threshold are saved as an explicit security policy and a pull request gate, shown read-only under Gates & decisions as *managed by the repository's pull request settings* and editable only there (`PTH-GATE-1105`).

Existing repositories were migrated with their current behaviour: a repository that blocked at a threshold now has a generated *block* policy with the same threshold; one with the threshold *Never* has *Warn only*. Nothing changed silently. Repositories that had pull request checks off keep their threshold as a suggestion and ask for the choice when you enable them. An API client that enables checks with the threshold *none* and no choice gets *Warn only*, because that threshold cannot block.

### Gate decisions log

Every evaluation is recorded with its stage, decision, reasons, the gates and policy versions involved, and its evidence (findings by severity, the scan). Filter by stage and decision.

### CLI: pre-commit, IDE and CI

```bash
# CI: decide on the new findings of a scan
pathos gate --stage ci --scan "$PATHOS_SCAN_ID"

# pre-commit hook (.git/hooks/pre-commit or the pre-commit framework)
pathos gate --stage pre-commit --repo acme/payments --commit "$(git rev-parse HEAD)"
```

Exit codes: 0 pass, warn or exception applied; 1 block or approval required; 2 usage error; other codes for connection errors. Without `--stage`, `pathos gate` keeps its earlier behaviour: the scan's own gate plus your `--fail-on` threshold, which is your pipeline's explicit choice.

### Release and deploy: Argo CD and generic CD

Call the evaluate endpoint with an API token that has `scans.read` on the repository:

```bash
curl -fsS -X POST "$PATHOS_URL/api/v1/gates/evaluate" \
  -H "Authorization: Bearer $PATHOS_TOKEN" -H "Content-Type: application/json" \
  -d '{"stage":"deploy","repository_id":"'"$REPO_ID"'","commit_sha":"'"$GIT_SHA"'"}' \
  | tee decision.json
jq -e '.outcome | IN("pass","warn","exception_applied")' decision.json
```

Argo CD: run the same call in a `PreSync` hook Job; a failed Job stops the sync.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: pathos-deploy-gate
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: gate
          image: alpine:3.22
          env:
            - { name: PATHOS_URL, value: "https://pathos.example.internal" }
            - { name: REPO_ID, value: "<repository id>" }
            - { name: GIT_SHA, value: "<commit being deployed>" }
            - name: PATHOS_TOKEN
              valueFrom: { secretKeyRef: { name: pathos-gate-token, key: token } }
          command: ["/bin/sh", "-c"]
          args:
            - apk add --no-cache curl jq >/dev/null &&
              curl -fsS -X POST "$PATHOS_URL/api/v1/gates/evaluate"
              -H "Authorization: Bearer $PATHOS_TOKEN" -H "Content-Type: application/json"
              -d "{\"stage\":\"deploy\",\"repository_id\":\"$REPO_ID\",\"commit_sha\":\"$GIT_SHA\"}" > /tmp/d.json &&
              cat /tmp/d.json &&
              jq -e '.outcome | IN("pass","warn","exception_applied")' /tmp/d.json
```

Keep the token in a Kubernetes Secret; never put it in the manifest. No PATHOS agent runs in the cluster.

## Exceptions and approvals

On a *block* or *approval required* decision, **Request exception** (or **Request approval**) asks for a time-limited pass: give a reason and an expiry (1 to 90 days). The gate must allow exceptions (`PTH-GATE-1102`).

Someone with `gates.approve_exception` who is **not the requester** approves or rejects it (`PTH-GATE-1103`); only a pending request can be decided (`PTH-GATE-1104`). An approved exception turns later decisions for the same scope into *exception applied* until it expires or is revoked. Requests, approvals, rejections and revocations are written to the audit log.

## Troubleshooting

| Code | Meaning | Fix |
|---|---|---|
| `PTH-PLAT-1007` | The `remediation_workspace` feature is not enabled | An administrator turns the flag on under Administration → Feature flags |
| `PTH-REM-1101` | Invalid status change (for example closing by hand) | Use Verify fix to close; choose another status |
| `PTH-REM-1102` | The fix cannot be verified (no re-runnable check, file location, commit or SCM connection) | Re-scan the repository so the finding has a commit; verify findings from imported reports with a new scan instead |
| `PTH-REM-1103` | A finding already belongs to an open remediation item | Open the existing item, or close it first |
| `PTH-REM-1104` | A verification is already queued or running | Wait for it to finish |
| `PTH-REM-1105` | The verification failed in the worker (clone or check failed) | Check the worker and the repository connection; retry |
| `PTH-REM-1106` | The rescan was inconclusive (the baseline did not reproduce the finding) | Re-scan the repository, then verify again |
| `PTH-GATE-1101` | A gate needs an existing security policy | Choose a policy that exists, or create one under Administration → Policies |
| `PTH-GATE-1102` | The gate does not allow exceptions | Fix the findings, or ask a gate administrator to allow exceptions |
| `PTH-GATE-1103` | The requester cannot approve their own request | Ask another approver with `gates.approve_exception` |
| `PTH-GATE-1104` | The exception is no longer pending | Refresh; request a new exception if needed |
| `PTH-GATE-1105` | The gate or policy is managed by a repository's pull request settings | Change it in Pull request checks → Repository settings |
| `PTH-GATE-1106` | Enabling pull request checks needs Block or Warn | Choose Block the pull request or Warn only |
| `PTH-GATE-1107` | Evidence incomplete: the scan has not finished or did not succeed | Wait for the scan, or fix the failed scan and evaluate again |
| `PTH-GATE-1108` | The policy is used by security gates and cannot be deleted | Delete or re-point those gates first, or disable the policy |
