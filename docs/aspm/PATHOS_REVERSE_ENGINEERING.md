Quditmind PATHOS · applies to v2.2.0 · status: Prototype

# PATHOS reverse engineering (static tier)

## Purpose

Reverse engineering (milestone M10, phase 5 of the lifecycle) checks that what an organization builds and ships does what its source says. PATHOS analyses a build artifact **statically** — it never executes it — extracts normalised facts (sections, functions, imports, strings, the call graph, firmware contents, code views), stores them as a binary graph in the [CodeGraph](PATHOS_CODEGRAPH_ARCHITECTURE.md) store and compares them with the CodeGraph snapshot of the commit the artifact was built from. Items that are only in the binary and involve sensitive APIs (the classic case: `net/http/pprof` debug handlers in a production server) become finding **proposals** a person reviews. The user view is in the [user guide](../user-guide/reverse-engineering.md), the endpoints in the [API reference](../api-reference/reverse-engineering.md); the isolation decision is [ADR-009](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-009-reverse-engineering-isolation).

Done-when of M10: **it runs only on artifacts from our own builds by default.**

## Scope

In scope (static tier, flag `reverse_engineering`): the `worker-rea` family image and its sandbox runner; the input policy (own builds by default, audited per-artifact authorisation otherwise); analyses in their own queue lane; radare2 triage and call graph; binwalk firmware signatures and extraction; Go symbol tables and build information read with the Go standard library; the optional decompilers (Ghidra headless, Jadx, ILSpy) when built into the image; secret redaction of strings and code; the binary graph in the CodeGraph store; the source ↔ binary diff; finding drafts with "Create finding" and "Add to threat model"; settings (tools, limits, input policy, which AI model may see decompiled code); the Binary analysis workspace and the configuration page.

Out of scope: the **sandbox tier** (M11: Frida, Tracee, Qiling, throwaway VM; separate approval); executing artifacts in any form; AI analysis of decompiled code (only the policy that governs it exists); Joern and angr (see Dependencies); artifacts "produced by a connected CI" (no CI connector exists on this branch; see Known limitations).

## Architecture

```
 build artifact upload (scan target artifact | mobile-app) ── signature / provenance bundle (cosign) ──┐
                                                                                                      ▼
 target scan (core worker) ── cosign verify-blob / verify-blob-attestation ──▶ signature_verifications
                                                                                                      ▼
 POST /rea/analyses ── input policy (rea.evaluate) ── refused: 403 PTH-REA-1001, audited, nothing queued
        │ accepted (signature | provenance | authorisation)
        ▼
 scan_jobs (trigger rea, system profile, config snapshot) ── lease lane: workers advertising pathos-rea only
        ▼
 worker-rea (worker-api network only) ── artifact (SHA-256 verified) ──▶ rea_sandbox volume ──▶ worker-rea-sandbox
                                                                   (network none, UID 10002, read-only, no capabilities, limits)
                                                                   pathos-rea: Go debug/*, radare2, binwalk, [Ghidra, Jadx, ILSpy]
        ◀── pathos.rea/v1 (secrets redacted) ── result upload
        ▼
 API: rea.ParseDoc (validate, redact again) ─▶ codegraph.StoreBinary (snapshot kind binary) + rea_code
        ▼
 source ↔ binary diff (rea.Compare) against the CodeGraph source snapshot of the commit ─▶ rea_diff_items ─▶ rea_finding_drafts
        ▼
 workspace (Functions · Call graph · Strings & imports · Runtime behaviour · Source ↔ binary · History)
        └─ Create finding (needs_review) · Dismiss · Add to threat model (M5 API)
```

## Components

| Component | Where | Role |
|---|---|---|
| Input policy | `backend/internal/rea/policy.go` | `evaluate`: newest `signature_verifications` row of the target (signature verified with a key or keyless policy; or SLSA provenance attestation verified and its subject equal to the artifact SHA-256), else an active authorisation for the same SHA-256 when the policy allows; `DecompiledCodeAllowed`; settings |
| Queue lane | `backend/internal/scans/rea.go`, `worker_api.go` (`reaLaneCondition`) | `EnqueueREA` (trigger `rea`, the "Reverse engineering (system)" profile, configuration in the snapshot), `leaseREA` (artifact only, no credentials or signature material), one running execution per repository and lane |
| Provenance | `backend/internal/scans/provenance_attestation.go`, `backend/internal/worker/signature.go` | Upload and storage of the provenance bundle; `cosign verify-blob-attestation` against the target's policy; `ParseProvenance` reads the statement (subjects, builder, source repository, commit) |
| Worker tool | `backend/internal/worker/rea.go` | `reaTool`: copies the artifact and configuration into the sandbox job, runs `pathos-rea analyse` through `RunUntrusted`; without a runner it fails (never runs elsewhere). The `rea` family leases no fix or AI-fix jobs |
| Analyser | `workers/rea/analyse` (`pathos-rea`) | Format, sections, Go symbols and build information (Go `debug/*`), radare2 triage, imports, exports, strings, functions and call references, binwalk, optional decompilers; secret redaction; `selftest` (isolation probe) |
| Image | `workers/rea/Dockerfile` | Standalone Debian image: `pathos-worker` (built from this repository, same build metadata as worker-core), `pathos-rea`, radare2, binwalk, ilspycmd; optional Ghidra and Jadx build arguments |
| Store | `backend/internal/codegraph/binary.go` | `ValidateBinary`, `StoreBinary`, binary views, `BinaryGraph`, `BinaryNode`; source queries filter `kind = 'source'` |
| Diff and drafts | `backend/internal/rea/diff.go` | `Compare` (functions, packages, routes, URLs), sensitive rules, `Drafts` (grouped by rule) |
| API | `backend/internal/rea/service.go`, `read.go`, `ingest.go` | Routes under `/api/v1/rea`, ingest hook `OnREAResult`, reconcile of executions that ended without a result |
| UI | `frontend/src/features/rea` | Binary analysis workspace and Reverse engineering tools configuration |

## Data flow

1. A build uploads its artifact with a signature (`cosign sign-blob --bundle`) and/or an SLSA provenance attestation (`cosign attest-blob --type slsaprovenance1 --bundle`) as a scan target, and the target's signature policy names the organization's key or keyless identity (`attestation: slsaprovenance1` for provenance).
2. A target scan runs cosign on a core worker; the verdict is recorded in `signature_verifications` (the existing cosign check of image and artifact targets, extended to blob attestations).
3. Binary analysis lists artifacts with their trust. Starting an analysis evaluates the policy again; untrusted artifacts are refused (`PTH-REA-1001`, audited) unless authorised.
4. The execution waits in the `rea` lane. A `worker-rea` worker leases it, downloads the artifact (SHA-256 checked), and its sandbox runner runs `pathos-rea` with the organization's tools, memory and time limits.
5. The API validates the document (schema, limits, references, the artifact SHA-256), redacts strings and code again, and stores the binary graph, code views and the analysis summary in one transaction.
6. The commit is the verified provenance commit; otherwise the Go build information of the binary (`vcs.revision`); otherwise none. The diff runs against the newest ready source snapshot of that commit, or against a snapshot a person chooses (labelled `user`).
7. Sensitive binary-only items become drafts. A person creates a finding (status `needs_review`), dismisses the draft with a reason, or adds a threat to the application's threat model.

## Dependencies

Tools of the static tier (prompt §7, "Reverse engineering"), each pinned and checksum-verified in `workers/rea/Dockerfile`:

| Tool | Licence | In the image | Use |
|---|---|---|---|
| radare2 6.2.6 | LGPL-3.0-only | default | Triage: format, sections, imports, exports, symbols, strings, functions, call references |
| binwalk 3.1.0 | MIT | default | Firmware signatures and extraction |
| Go `debug/elf`, `debug/pe`, `debug/macho`, `debug/gosym`, `debug/buildinfo` | BSD-3-Clause (Go) | built into `pathos-rea` | Exact Go symbol names, packages, module and VCS information |
| Ghidra 12.2 (headless), Eclipse Temurin 25 JDK | Apache-2.0; GPL-2.0 with Classpath Exception | optional (`WITH_GHIDRA`): 1.43 GB image, passes the Trivy gate after removing the GhidraServer wrapper and replacing Guava with 33.7.2; about 180 s on a 10 MB Go binary | Decompiler: pseudo-C, extra call edges |
| Jadx 1.5.7 | Apache-2.0 | optional (`WITH_JADX`), off: fails the Trivy gate (its single jar bundles Guava 31.1 with a fixable CVE that cannot be replaced) | Android DEX/APK and Java decompiler |
| ILSpy (ilspycmd) 11.2 | MIT | default (`WITH_ILSPY=true`; a native 20 MB build, no .NET runtime) | .NET decompiler (not yet exercised on a real assembly in the tests) |
| Joern | Apache-2.0 | not included | The CLI distribution is about 1.8 GB (JVM, many front ends); not feasible in the image budget, and ADR-006 already left it out of M4 |
| angr | BSD-2-Clause | not included | Python with native dependencies (unicorn, z3, pyvex) of several hundred MB and high memory use; not feasible in the static tier's budget |

Default image: 253 MB, Trivy 0 fixable HIGH/CRITICAL. Measurements: [OPERATIONS.md](../OPERATIONS.md#reverse-engineering-worker).

## APIs

See the [API reference](../api-reference/reverse-engineering.md). Worker protocol: lease `kind: "rea"` ([worker protocol](../api-reference/worker-protocol.md)). Analysis document: `pathos.rea/v1` (schema in `backend/internal/rea/doc.go`).

## Protocols

No new external protocol. Sigstore verification uses the pinned cosign of the core image (`verify-blob`, `verify-blob-attestation`; offline with key-based policies). The worker reaches only the API's worker listener.

## Authentication

Sessions, API tokens and worker tokens as before. Permissions: `findings.read` (view), `scans.run` + `rea.run` (start), `rea.authorize` (authorise untrusted artifacts; Security Manager and Super Administrator), `findings.triage` (create a finding from or dismiss a draft), `scanners.manage` (settings). See [RBAC_MATRIX.md](../RBAC_MATRIX.md).

## Security requirements

- **Own builds by default.** Trust comes only from evidence PATHOS recorded: a verified signature, or a verified provenance attestation whose subject is the artifact's SHA-256. Everything else needs a per-artifact authorisation (bound to the SHA-256, with a reason of at least 10 characters, by a user with `rea.authorize`, audited), and the stricter policy `own_builds_only` refuses authorisations entirely. Refusals are audited (`rea.analysis.refused`). Integration test: an unsigned, unknown artifact is refused and nothing is queued.
- **Never executed.** `pathos-rea` only reads the file. Firmware extraction writes into the job's temporary directory.
- **Isolation (ADR-009).** Parsers of untrusted binaries run only in `worker-rea-sandbox`: `network_mode: none` (loopback only, no DNS), UID 10002, `ipc: none`, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, memory, CPU and pids limits, a size-limited tmpfs volume shared only with `worker-rea`. The agent `worker-rea` is on the internal `worker-api` network only (no `scan` network, no egress proxy, no proxy settings), read-only, non-root, all capabilities dropped. Without a runner the analysis fails; it never runs in the agent. Tested by `workers/rea/test/rea-e2e.sh` (`pathos-rea selftest` through the real runner).
- **Own lane.** Only workers that advertise `pathos-rea` lease `rea` executions and they lease nothing else; there is no fallback to other workers.
- **Secrets.** Strings, code and build settings are redacted by the analyser and again by the API (AI redactor: tokens, keys, assignments, long hex and base64, private keys). A redacted string is never returned, searched or matched.
- **Decompiled code and AI.** Decompiled code is source-equivalent: shown to people with `findings.read`; the setting `decompiled_code_ai` (default `none`; `local` = self-hosted providers only; `cloud` only while the AI configuration's `send_code_context` allows code) governs every future AI use (`rea.DecompiledCodeAllowed`). M10 sends no decompiled code to any model.
- **Evidence (rule 5).** Every binary graph edge is `verified` with evidence kind `binary` (file offset and tool); the database refuses other kinds and malformed offsets. Diff items carry binary offsets and source file:line references.
- **No silent findings.** Drafts are proposals labelled as such; a finding exists only after a person's decision and starts as `needs_review`.
- **Tenant isolation.** Every new table has `organization_id` and the standard row-level security policy; the isolation suite covers every new route.

## Error handling

Codes `PTH-REA-1001` … `PTH-REA-1012` ([troubleshooting](../troubleshooting/rea.md)): 1001 untrusted artifact, 1002 no worker, 1003 sandbox failure, 1004 timeout, 1005 invalid document, 1006 not an artifact, 1007 authorisations disabled, 1008 no source snapshot, 1009 store failure, 1010 decompiled-code AI policy, 1011 not ready, 1012 provenance or authorisation for another file. Analyses record their code (`rea_analyses.error_code`); executions that end without a result are settled as `PTH-REA-1003` by the reconcile step.

## Operations

- Enable with `COMPOSE_PROFILES=rea` (services `worker-rea` and `worker-rea-sandbox`) and the `reverse_engineering` flag. Container limits: `PATHOS_REA_MEMORY` (default 4g), `PATHOS_REA_CPUS` (2), `PATHOS_REA_PIDS` (256), `PATHOS_REA_SANDBOX_TMPFS` (4g). Run one `worker-rea` replica per runner.
- Settings (Configurations → Reverse engineering tools): enabled tools, memory per analysis (512–16384 MB; the container limit is the hard cap), time limit (5–230 minutes), input policy, decompiled-code AI policy.
- Image build, size and scan results: see [OPERATIONS.md](../OPERATIONS.md#reverse-engineering-worker).

## Implementation status

Implemented behind the `reverse_engineering` flag (off by default): backend, migrations 00061–00063, worker family image (built, signed and pushed by the release workflow as `pathos-worker-rea`), workspace and configuration pages, docs and tests are in place. ADR-009 is approved as built (option 1); the decisions taken at approval — `rea.authorize` separate from `rea.run`, the 230-minute limit, Ghidra opt-in, weak-cryptography drafts only with a source import, tool names on the Reverse engineering tools configuration page — are recorded in its [implementation notes](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-009-reverse-engineering-isolation).

## Known limitations

- **Connected CI** as a trust basis (prompt: "or produced by a connected CI") is not implemented: there is no CI connector on this branch (M2 is integrated separately). A CI that signs or attests its artifacts with the organization's key or keyless identity is covered by the signature and provenance bases.
- The newest verification of a target is used; changing the target's signature policy does not invalidate an earlier verification until the next target scan.
- Source ↔ binary matching is exact for Go (symbol names from the pclntab, module path from the build information). Other languages are matched by plain symbol name, which works for unstripped C/C++ only; stripped binaries have no names to compare. CodeGraph has no C/C++ parser, so native functions show as unmatched.
- Go inlines small functions and the linker drops unused ones, so "only in the source" functions are expected and labelled as such.
- Routes are found as path strings; routes built at run time are not seen. Path-like strings are reported only when sensitive or referenced by the artifact's own code.
- Decompiled code is kept only for a bounded number of functions (`max_code`, 200), each at most 16 KiB.
- An analysis analyses one artifact; firmware contents are listed and extracted, but extracted executables are not analysed one by one.

## Future improvements

- M11 sandbox tier (separate approval).
- Trust from connected CI connectors (M2) once they exist: provenance produced and verified by the CI integration.
- AI analyst over the binary graph with read-only tool calls (decompile, xrefs, query), bound to `DecompiledCodeAllowed`.
- Per-file analysis of extracted firmware executables; LIEF-based checks; C/C++ source parsing in CodeGraph for native matching.
