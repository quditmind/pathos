---
title: Scan coverage
section: user-guide
group: configurations
order: 10
version: "2.0"
updated: 2026-11-19
summary: Which of the 25 scan types this installation can run, with which tools and workers, and which results you can import instead.
---

# Scan coverage

**Configurations → Scan coverage** answers the question "what can this PATHOS installation test?". It lists the 25 scan types PATHOS reports on: SAST, DAST, SCA, secrets, infrastructure as code, container, API security, IAST, mobile (MAST), fuzzing, licence, SBOM, malware, code-quality security, supply chain, cryptography, configuration, CI/CD pipeline, binary, AI/LLM, runtime, compliance, licence policy, database security and manual review. You need the `scanners.read` permission.

The page is built from the live state of the installation each time it loads (and every 30 seconds): the workers that are online, the tools they provide, and the import formats PATHOS can read. Nothing on it is a fixed number.

## Reading the page

The cards at the top show how many scan types have a tool on an online worker, how many can only be imported, and how many workers are online.

Each row of the table is a scan type:

| Column | Meaning |
|---|---|
| **Scan type** | Name and short description. Select it to see its tools |
| **Finding categories** | The *Type* its findings have on the Findings page. For example CI/CD pipeline findings of zizmor and actionlint are recorded as *Infrastructure as code* |
| **Tools** | How many of the tools that cover the type an online worker can run now |
| **Import formats** | Report formats specific to the type that **Scanning → Import Results** reads. SARIF, PATHOS findings JSON and CSV work for every type and are listed above the table |
| **Status** | *N tools runnable*: PATHOS can produce these results itself. *Import only*: no worker runs a tool for it, but a dedicated import format exists. *Generic import only*: results can be imported with the generic formats |

Expanding a scan type lists its tools with their licence and state:

- **N workers** (green): online workers provide the tool; add it to a scan profile, or select it on a scan target.
- **no online worker**: a PATHOS worker image provides the tool, but none is running. For example Bandit needs the `worker-sast` family worker, which an administrator enables (see the operations guide, "Family worker images").
- **catalogued**: the tool is in the catalog but no worker image provides it yet. Import its results instead.
- **active**: a check the PATHOS server runs itself (licence policy; end of life when its feed is enabled).
- **operator plugin**: a tool your administrators added to a worker.
- **intrusive** / **contacts target**: the tool sends attack traffic or requests to a running application; it runs only for authorized [scan targets](scanning.md#additional-tools-and-intrusive-testing).

Use the filter to show the scan types that are runnable now, import only, or covered by generic imports only.

## Closing a gap

| Situation | What to do |
|---|---|
| A tool shows **no online worker** | Ask an administrator to start the family worker that provides it |
| A scan type is **Import only** | Run the tool in your CI pipeline and import its report (**Scanning → Import Results**, or the `pathos` CLI) |
| No tool and no dedicated format | Import a SARIF, PATHOS findings JSON or CSV report with the category of the scan type, or ask an administrator to add the tool as a scanner plugin |

Related: [Security scanning: scanners and profiles](security-scanning.md), [Scans](scanning.md).
