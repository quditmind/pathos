---
title: Troubleshooting: Security gates
section: troubleshooting
order: 113
version: "1.0"
updated: 2026-11-20
summary: Policy gates in CI, pull requests and releases (2 codes, PTH-GATE-*)
---

# Troubleshooting: Security gates

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Policy gates in CI, pull requests and releases.

| Code | Title | Severity |
|---|---|---|
| [PTH-GATE-1001](#PTH-GATE-1001) | Security gate failed | warning |
| [PTH-GATE-1002](#PTH-GATE-1002) | Gate not evaluated: the scan did not succeed | warning |

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

