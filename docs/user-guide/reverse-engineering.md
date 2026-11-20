---
title: Reverse engineering
section: user-guide
group: reverse-engineering
order: 50
version: "3.0"
updated: 2026-11-20
summary: Analyse the binaries you build and ship, statically and isolated, and compare them with their source code — functions, call graph, strings and imports, and what is only in the binary.
---
# Reverse engineering

Reverse engineering checks that what you build and ship does what your source code says. PATHOS takes a build artifact (an executable, a library, firmware, an Android or .NET package), pulls facts out of it — its sections, functions, imports, strings and the calls between functions — and compares them with the [CodeGraph](codegraph.md) of the commit it was built from. Code that is in the shipped binary but not in your source (for example debugging handlers that a blank import registers) shows up as **only in binary**, with the evidence.

This release is the **static tier**: the artifact is read, never run. Runtime behaviour (function traces, system calls) needs the sandbox tier, which arrives after 3.0 and will run only in a throwaway virtual machine, never on the PATHOS host.

Reverse engineering is behind the feature flag `reverse_engineering` (off by default; an administrator turns it on under **Administration › Feature flags**). Viewing analyses needs `findings.read`; starting one needs `scans.run` and `rea.run`; authorising an untrusted artifact needs `rea.authorize`.

## Which artifacts are analysed

By default PATHOS analyses only artifacts it can tie to **your own builds**:

- a build artifact uploaded with a signature that verifies against the target's signature policy (key or keyless), or
- a build artifact uploaded with build provenance (a signed SLSA provenance attestation) that verifies; the provenance also says which commit the artifact was built from.

Upload the artifact as a scan target (**Inventory › Scan targets › Add target › Build artifact**) together with its signature or Sigstore bundle and the provenance, and set its signature policy. The verification runs with the target's scan; its result is what reverse engineering trusts. An artifact without verified signature or provenance is **untrusted** and is refused (`PTH-REA-1001`).

### Authorising an untrusted artifact

Someone with `rea.authorize` can authorise one untrusted artifact for analysis: select **Authorise untrusted artifact** on its row and give a reason. The authorisation applies to that exact file (its SHA-256) only, is recorded in the audit log with the reason, and can be revoked. If the organization's input policy is **Own builds only**, authorising is switched off (`PTH-REA-1007`).

An authorised artifact is still analysed under the same isolation as any other, and never run.

## Binary analysis workspace

**5 · Reverse engineering › Binary analysis** lists the build artifacts you can see, with:

- **Trust**: *Trusted · verified signature*, *Trusted · verified provenance*, *Authorised untrusted artifact* (with the reason, who and when), or *Untrusted · refused by default*.
- **Last analysis** and its status (queued, running, ready, partial, failed).
- **Analyse** starts an analysis. It runs on the reverse-engineering worker in its own queue, separate from scans, so a long analysis does not hold up scanning. The page refreshes while it runs.

## The analysis tabs

An analysis opens on its workspace, with the artifact's format, architecture and language, the commit it was built from (and how that is known), and the analyses that ran (binary triage, decompiler, firmware extraction, Android decompiler, .NET decompiler).

- **Functions** — every function found, server-paginated and searchable, with a badge: *Matched* (the same function exists in the source), *Only in binary*, *Library* (standard library or a dependency) and *Sensitive*. Select a function to see its code — labelled **Decompiled (pseudo-C)** when a decompiler produced it, or **Disassembly** when only disassembly is available — its callers and callees, the strings it references and the evidence (offset in the binary and the kind of analysis that found it).
- **Call graph** — the shared graph component (zoom, search, filters, inspector, path tracing, export) with three views: *Call graph*, *Imports* and *Layout* (sections and the functions they contain). Every edge is *verified* and carries its offset.
- **Strings & imports** — the strings with their kind (URL, route, path, format, text) and offset, and the imported libraries, packages and functions. Secrets found in strings are redacted inside the isolated analysis: their values never reach PATHOS and are shown as *Redacted secret*.
- **Runtime behaviour** — shows *Sandbox tier arrives after 3.0*. There is no runtime data in this release.
- **Source ↔ binary** — the comparison with the source (below).
- **History** — the earlier analyses of the same artifact.

### Source ↔ binary

PATHOS compares the binary's functions, packages, routes and strings with the CodeGraph snapshot of the **same commit**. The commit comes from the verified provenance, else from build information embedded in the binary (for example Go's `vcs.revision`); the page says which. Three sides:

- **Only in binary** — present in the shipped binary but not in the source graph, for example `/debug/pprof/*` handlers registered by a blank import of `net/http/pprof`, or a function linked from a dependency.
- **Only in source** — in the source graph but not in the binary (dead code removed by the compiler, build-tagged files, tests).
- **Matched** — in both, with the binary offset and the source file and line.

Each item lists its evidence: *verified* binary offsets and *verified* source lines. When there is no snapshot for the commit, the page says so (`PTH-REA-1008`): build the CodeGraph at that commit, or choose another snapshot to compare with; a comparison you chose is labelled *chosen by a person*.

### Finding proposals

Sensitive items that are only in the binary (debug handlers, command execution, unsafe or dynamic loading and similar) become **proposals**, labelled *Proposal · needs human review*. They are never created as confirmed findings. For each one you can:

- **Create finding** — after a confirmation, creates a finding with status *Needs review* that keeps the evidence (needs `findings.triage`).
- **Add to threat model** — adds a manual threat, with the binary evidence in its description, to the application's threat model (needs `threats.manage`). If the application has no threat model yet, create one in [Threat models](threat-models.md) first.
- **Dismiss** — with a reason.

Weak cryptography (DES, RC4, MD5, SHA-1) is shown only when your source imports it, as a sensitive item matched to the import line: the Go standard library links these packages into every network program, so they are not reported on their own.

## Configuration

**Configurations › Reverse engineering tools** (view: `scanners.read`, change: `scanners.manage`):

- **Tools** — which tools run: radare2 (binary triage, LGPL-3.0), binwalk (firmware extraction, MIT), and, when the worker image was built with them, Ghidra headless (decompiler, Apache-2.0), Jadx (Android, Apache-2.0) and ILSpy `ilspycmd` (.NET, MIT). The page shows each tool's licence and the version installed on the online worker.
- **Limits** — memory per analysis (512–16384 MB, default 4096) and time limit (5–230 minutes, default 30; one execution is limited to 4 hours). The sandbox container's own memory limit is the hard cap.
- **Input policy** — *Own builds; others only with an authorisation* (default) or *Own builds only*.
- **AI models that may see decompiled code** — *No AI model* (default), *Local models only*, or *Local and cloud models*. Cloud is available only when the default AI configuration allows sending code (**Configurations › AI settings**); otherwise decompiled code is withheld from AI (`PTH-REA-1010`).

## Isolation

The analysis tools run in a separate sandbox runner container with no network interface, a read-only root filesystem, no capabilities, its own user and its own memory, CPU and process limits. The worker that hands it the job reaches only the PATHOS worker API, never the internet or the scan egress proxy. The artifact is parsed, never executed. The isolation is described in the security documentation (SECURITY.md, "Scanning") of the installation.

## Troubleshooting

| Code | What happened | What to do |
|---|---|---|
| `PTH-REA-1001` | The artifact is untrusted: no verified signature or provenance ties it to your own builds | Upload it with its signature or provenance and a signature policy, scan the target so the verification runs, then analyse; or authorise this artifact with a reason |
| `PTH-REA-1002` | No reverse-engineering worker is online | Start the `worker-rea` and `worker-rea-sandbox` services (Compose profile `rea`); the analysis waits in its queue until then |
| `PTH-REA-1003` | The analysis could not run in the sandbox (no sandbox runner, or it failed inside the sandbox) | Check that `worker-rea-sandbox` runs and shares the sandbox volume with `worker-rea`; read the analysis log |
| `PTH-REA-1004` | The analysis reached its time limit | Raise the time limit in Reverse engineering tools, or disable the decompiler for large binaries |
| `PTH-REA-1005` | The analysis result was not a valid analysis document | Retry; if it persists, report it with the request id and the worker version |
| `PTH-REA-1006` | The target is not an uploaded build artifact | Analyse build artifact or mobile app targets only |
| `PTH-REA-1007` | The input policy allows only artifacts from your own builds, so authorisations are off | Upload the artifact with a signature or provenance, or change the input policy |
| `PTH-REA-1008` | There is no CodeGraph snapshot of the commit the artifact was built from | Build the CodeGraph for that commit, or choose another snapshot to compare with |
| `PTH-REA-1009` | The analysis results could not be stored | Try again; if it persists, report it with the request id |
| `PTH-REA-1010` | Decompiled code was withheld from an AI model by the configuration | Allow local or cloud models in Reverse engineering tools (cloud also needs AI settings to allow sending code) |
| `PTH-REA-1011` | The analysis has not finished, so its results are not available yet | Wait until it is ready; the page refreshes on its own |
| `PTH-REA-1012` | The artifact changed since it was verified (its SHA-256 differs) | Upload the artifact again with its signature or provenance and verify it again |

More detail for each code: [Troubleshooting: reverse engineering](../troubleshooting/rea.md).
