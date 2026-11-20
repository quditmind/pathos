---
title: Troubleshooting: Security gates
section: troubleshooting
order: 113
version: "1.0"
updated: 2026-11-20
summary: Policy gates in CI, pull requests and releases (10 codes, PTH-GATE-*)
---

# Troubleshooting: Security gates

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Policy gates in CI, pull requests and releases.

| Code | Title | Severity |
|---|---|---|
| [PTH-GATE-1001](#PTH-GATE-1001) | Security gate failed | warning |
| [PTH-GATE-1002](#PTH-GATE-1002) | Gate not evaluated: the scan did not succeed | warning |
| [PTH-GATE-1101](#PTH-GATE-1101) | A gate needs a security policy | info |
| [PTH-GATE-1102](#PTH-GATE-1102) | No exception possible for this decision | info |
| [PTH-GATE-1103](#PTH-GATE-1103) | The requester cannot decide their own exception | info |
| [PTH-GATE-1104](#PTH-GATE-1104) | Exception not pending | info |
| [PTH-GATE-1105](#PTH-GATE-1105) | Managed by the repository's pull request settings | info |
| [PTH-GATE-1106](#PTH-GATE-1106) | Choose block or warn for pull request checks | info |
| [PTH-GATE-1107](#PTH-GATE-1107) | Gate evidence incomplete | warning |
| [PTH-GATE-1108](#PTH-GATE-1108) | Policy used by security gates | info |

<a id="PTH-GATE-1001"></a>

## PTH-GATE-1001: Security gate failed

| | |
|---|---|
| Severity | warning |
| Category | policy |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/scans/gate.go, cmd/pathos-cli (gate) |

**What it means.** The execution's gate failed: findings at or above the fail_on threshold, a blocking security policy, or the execution's own gate.

**Confirmed cause.** The gate evaluation returned passed = false (reasons listed with it). Confirmed automatically when this code is raised.

**Probable causes**

1. New findings at or above the threshold
2. A security policy marked blocking matched

**Impact.** The CI step fails (exit code 1) as configured by the pipeline's policy.

**How to fix**

1. Open the execution to see the findings named in the reasons.
2. Fix them, or record a risk acceptance where justified.

**Verify**

1. A new scan's gate passes.


<a id="PTH-GATE-1002"></a>

## PTH-GATE-1002: Gate not evaluated: the scan did not succeed

| | |
|---|---|
| Severity | warning |
| Category | policy |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/scans/gate.go |

**What it means.** The gate needs a finished, successful scan (or partial with allow_partial).

**Confirmed cause.** The scan has not finished, or ended failed, cancelled or partial. Confirmed automatically when this code is raised.

**Probable causes**

1. The scan is still running
2. The scan failed (see its PTH-SCAN or PTH-WORK code)

**Impact.** The CI step does not pass until a successful scan exists.

**How to fix**

1. Wait for the scan, or fix the scan failure and run it again.

**Verify**

1. The gate shows finished = true and passed = true.


<a id="PTH-GATE-1101"></a>

## PTH-GATE-1101: A gate needs a security policy

| | |
|---|---|
| Severity | info |
| Category | policy |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `gate_policy_required` |
| Raised in | internal/gates/api.go |

**What it means.** Every security gate references an existing, user-managed security policy of the organization; a gate without a policy cannot exist (rule 7: no blocking without policy).

**Confirmed cause.** policy_id is missing or names no policy of this organization. Confirmed automatically when this code is raised.

**Probable causes**

1. No policy was chosen in the gate form
2. The policy was deleted

**Impact.** The gate was not saved.

**How to fix**

1. Create the policy first (Remediate & gate › Policies), then choose it in the gate form.

**Verify**

1. The gate appears in the list with its policy.


<a id="PTH-GATE-1102"></a>

## PTH-GATE-1102: No exception possible for this decision

| | |
|---|---|
| Severity | info |
| Category | policy |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `gate_exceptions_not_allowed`, `nothing_to_except` |
| Raised in | internal/gates/api.go |

**What it means.** Exceptions apply only to a blocking gate that allows them (approvals only to require-approval gates). The decision has no such gate, or the gate does not allow exceptions.

**Confirmed cause.** The gate's allow_exceptions is off, or the decision has no blocking gate. Confirmed automatically when this code is raised.

**Probable causes**

1. The gate was configured without exceptions on purpose
2. The decision passed or only warned
3. The decision was blocked by a security policy with the block action (no gate): use a risk acceptance of the findings instead

**Impact.** No exception was requested; the gate keeps blocking.

**How to fix**

1. Fix the findings, or ask a gates manager to allow exceptions on the gate.
2. For a block by a security policy, record a risk acceptance on the findings.

**Verify**

1. A new evaluation passes.


<a id="PTH-GATE-1103"></a>

## PTH-GATE-1103: The requester cannot decide their own exception

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `self_approval` |
| Raised in | internal/gates/api.go, migrations/00056_gates.sql (gate_exceptions_four_eyes) |

**What it means.** Exceptions and approvals follow the four-eyes rule: the person who requested one can never approve or reject it (also a database constraint).

**Confirmed cause.** The approver is the requester. Confirmed automatically when this code is raised.

**Probable causes**

1. The requester also holds gates.approve_exception

**Impact.** The exception stays requested.

**How to fix**

1. Ask another person with gates.approve_exception to decide it.

**Verify**

1. The exception shows approved or rejected by someone else.


<a id="PTH-GATE-1104"></a>

## PTH-GATE-1104: Exception not pending

| | |
|---|---|
| Severity | info |
| Category | workflow |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `exception_not_pending` |
| Raised in | internal/gates/api.go |

**What it means.** Only a requested exception can be approved or rejected, and only a requested or approved one revoked; expired exceptions cannot change.

**Confirmed cause.** The exception's status does not allow the action. Confirmed automatically when this code is raised.

**Probable causes**

1. Someone else decided it first
2. It expired

**Impact.** Nothing changed.

**How to fix**

1. Reload the exceptions list; request a new exception if needed.

**Verify**

1. The list shows the current status.


<a id="PTH-GATE-1105"></a>

## PTH-GATE-1105: Managed by the repository's pull request settings

| | |
|---|---|
| Severity | info |
| Category | policy |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `managed_gate`, `managed_policy` |
| Raised in | internal/gates/api.go, internal/policy/api.go |

**What it means.** The policy and gate generated from a repository's pull request settings (threshold and block or warn) are changed only there, so the settings and the policy cannot disagree.

**Confirmed cause.** The policy or gate is managed (managed_by repository_pr_gate). Confirmed automatically when this code is raised.

**Probable causes**

1. The change was made on the Policies or Gates page

**Impact.** Nothing changed.

**How to fix**

1. Open Pull request checks › settings of the repository and change the threshold or mode there.

**Verify**

1. The generated policy shows the new threshold.


<a id="PTH-GATE-1106"></a>

## PTH-GATE-1106: Choose block or warn for pull request checks

| | |
|---|---|
| Severity | info |
| Category | policy |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `pr_gate_mode_required` |
| Raised in | internal/gates/prgate.go, internal/scans/prchecks.go |

**What it means.** Enabling pull request checks needs an explicit choice: block the pull request when new findings reach the threshold, or only warn. There is no default (decision C6, rule 7).

**Confirmed cause.** gate_mode was not given and the repository has none yet. Confirmed automatically when this code is raised.

**Probable causes**

1. An API client from before PATHOS 3.0 enabled pull request checks without gate_mode

**Impact.** Pull request checks stay as they were.

**How to fix**

1. Choose Block the pull request or Warn only in the repository's pull request settings (API: gate_mode block or warn).

**Verify**

1. The settings show the mode and a generated policy link.


<a id="PTH-GATE-1107"></a>

## PTH-GATE-1107: Gate evidence incomplete

| | |
|---|---|
| Severity | warning |
| Category | evidence |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `gate_evidence_incomplete` |
| Raised in | internal/gates/engine.go |

**What it means.** The gate evaluation needs a finished, successful scan (or a finished pull request check) and found none, so no decision was recorded. This is an error, never a block.

**Confirmed cause.** The scan given has not finished or did not succeed, or the pull request has no finished check. Confirmed automatically when this code is raised.

**Probable causes**

1. The pipeline evaluated the gate before the scan finished
2. The scan failed (see its PTH-SCAN or PTH-WORK code)

**Impact.** The calling step gets an error; nothing is recorded.

**How to fix**

1. Wait for the scan (pathos scan --wait) and evaluate again.
2. Evaluate without scan_id to use the repository's open findings.

**Verify**

1. POST /api/v1/gates/evaluate returns a decision.


<a id="PTH-GATE-1108"></a>

## PTH-GATE-1108: Policy used by security gates

| | |
|---|---|
| Severity | info |
| Category | policy |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `policy_in_use` |
| Raised in | internal/policy/api.go |

**What it means.** A policy that security gates reference cannot be deleted: a gate never exists without its policy.

**Confirmed cause.** At least one gate references the policy. Confirmed automatically when this code is raised.

**Probable causes**

1. The policy is the condition of a gate at some stage

**Impact.** The policy was not deleted.

**How to fix**

1. Delete the gates that use it, or point them at another policy (Remediate & gate › Gates); or disable the policy instead.

**Verify**

1. The policy shows 0 gates and can be deleted.

