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

**Kinds of check.** Below the cards, the 20 kinds of check of the PATHOS tool plan (for example *Infrastructure as code*, *Secrets*, *Web app & API testing*) group the scan types: each kind lists its scan types, how many of its 10 reference tools PATHOS catalogues (with the count of other catalogued tools), how many an online worker runs now, and how many are still on the gap list. Expand a kind to see its 10 tools: *runnable*, *catalogued*, *intelligence feed*, *PATHOS engine* or *gap list* (a mode of a catalogued tool that is not wired yet says so). AI / LLM and manual review are shown outside the 20 kinds. The licence and maintenance status of every tool on the gap list is in the scanner catalog (`docs/SCANNER_CATALOG.md` in the PATHOS repository, section *Gap list*). This page, like Scan profiles and Scanners & workers, names tools; the rest of PATHOS shows the kind of check instead.

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

## Troubleshooting

| Code | Where | Fix |
|---|---|---|
| `PTH-AUTH-1002` | The page answers *forbidden* | You need `scanners.read`; ask an administrator. |
| — | A kind of check shows *0 runnable* | Start the worker image that runs its tools (**Scanners & workers** shows which), or import results. Tools on the gap list are not in PATHOS yet. |

Related: [Security scanning: scanners and profiles](security-scanning.md), [Scans](scanning.md).
