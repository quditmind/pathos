---
title: Security policies and compliance
section: api-reference
order: 50
version: "1.0"
updated: 2026-11-19
summary: Security policies (conditions → actions) and their violations, and compliance framework views.
---
# Security policies and compliance

All endpoints follow the [common conventions](index.md#authentication).

## Security policies

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/security-policies` | `findings.read` | Policies with `open_violations`, `version`, `applies_to_pull_requests` |
| `POST` | `/api/v1/security-policies` | `settings.manage` | Create `{ name, description, enabled?, conditions, actions }` → `201`. `409` for a duplicate name |
| `GET` | `/api/v1/security-policies/{id}` | `findings.read` | One policy |
| `PUT` | `/api/v1/security-policies/{id}` | `settings.manage` | Replace (version + 1). Disabling resolves its open violations |
| `DELETE` | `/api/v1/security-policies/{id}` | `settings.manage` | Delete with its violation history → `204` |
| `POST` | `/api/v1/security-policies/preview` | `findings.read` | `{ conditions }` → `{ matching, sample[≤20], applies_to_pull_requests }` over open findings in the caller's scope; nothing is saved |
| `POST` | `/api/v1/security-policies/evaluate` | `settings.manage` | Evaluate every policy now → `{ open_violations }` |
| `GET` | `/api/v1/security-policies/{id}/violations?status=resolved` | `findings.read` | Open (default) or resolved violations in scope, at most 500 |
| `GET` | `/api/v1/findings/{id}/policies` | `findings.read` | Policies an open finding violates |

Create, update and delete are audited (`security_policy.*`, with the definition before and after).

### Conditions

All set conditions must hold; values in one list are alternatives. At least one is required.

| Field | Type | Matches |
|---|---|---|
| `min_severity` | `critical` … `info` | Severity at or above |
| `categories` | list | Finding categories ([list](findings.md)), e.g. `secrets`, `sast`, `sca`, `iac`, `container`, `dast`, `api`, `crypto`, `code-quality`, `license`, `eol`, `supply-chain`, `other` |
| `scanners` | list | Detected by one of the scanners |
| `cwe` | list | Any of the CWEs (`CWE-89` or `89`) |
| `min_risk` | 0–100 | Contextual risk score at least *(scan branch only)* |
| `kev`, `malicious`, `exploit_available` | boolean | CISA KEV, malicious package, public exploit (`exploit_available` scan branch only) |
| `reachability` | list | `reachable`, `not_reachable`, `unknown` *(scan branch only)* |
| `min_age_days` | 0–3650 | First seen at least this long ago *(scan branch only)* |
| `criticality`, `internet_exposure`, `environments`, `data_classification`, `compliance_scopes` | lists of keys | The repository's classification |
| `repository_ids`, `application_ids` | lists of UUIDs | Specific repositories or applications |
| `material_change_categories` | list | The finding's file had a [security-material change](developer-context.md) of one of these categories (`auth`, `api_endpoint`, `dependency`, `crypto`, `iac_exposure`, `secrets_handling`, `cicd`, `sensitive_data`) in the scan that first reported it *(scan branch only)* |

Conditions marked *scan branch only* need data that pull request findings do not have; policies using them are not applied to pull requests (`applies_to_pull_requests: false`).

### Actions

At least one is required.

| Field | Effect |
|---|---|
| `block` | A scan execution's security gate fails (`gate_failed`) when a finding it detected for the first time violates the policy (an execution event names the policy). A pull request check fails when a finding the PR introduces violates it, whatever the PR's severity gate |
| `require_review` | Matching findings are queued for Human Eye review (reason *Required by security policy: …*), even when automatic queuing is off |
| `sla_days` (1–365) | The remediation deadline is at most this many days after first detection. When the policy is changed, disabled or deleted, those deadlines are recomputed from the SLA policies and the other policies |
| `notify` | Event `policy.violated` (one per policy and repository per evaluation, for new violations only); the built-in rule *Security policy violations* notifies security managers and repository owners |

Policies are evaluated after every scan (before the gate), when pull request scans finish, after any policy or SLA change, and every 10 minutes (risk, intelligence, context and age change between scans). A violation is resolved when its finding is no longer open or no longer matches, and re-opened if it matches again.

## Compliance

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/compliance/frameworks` | `findings.read` | Each framework with `repositories_in_scope` and the number of `failing`, `attention` and `passing` controls |
| `GET` | `/api/v1/compliance/frameworks/{key}` | `findings.read` | Controls with `status`, `open_findings`, `by_severity`, `repositories` |
| `GET` | `/api/v1/findings?control=<framework>:<control>` | `findings.read` | Open findings mapped to a control in the framework's scope |

Frameworks: `owasp_top10_2021`, `owasp_asvs_4` (every repository), `pci_dss_4` (repositories with compliance scope `pci_dss`), `iso_27001_2022` (`iso_27001`), `soc2_2017` (`soc_2`). A control maps findings by category, CWE and malicious packages. Status: `failing` (open critical or high findings), `attention` (other open findings), `passing` (none), `not_applicable` (no repository in scope). Everything is limited to the caller's scope. The mapping is indicative evidence for an assessment, not a compliance verdict.

## Sign-in security

MFA status, required enrolment and recovery codes are documented in [Administration: MFA and recovery codes](administration.md#mfa-and-recovery-codes).
