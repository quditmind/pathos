---
title: Scan targets
section: api-reference
order: 24
version: "2.0"
updated: 2026-11-19
summary: Container images, web applications (DAST), APIs (OpenAPI), build artifacts, mobile apps, LLM endpoints, SBOMs and declared public endpoints as scan targets; authorization statements, credentials, signature verification, scanning and filters.
---
# Scan targets

A scan target is something PATHOS scans besides a repository's source code. Each target belongs to a repository, so its findings get that repository's application, owners, criticality and access scope.

| Kind | Reference | Scanner | What it finds |
|---|---|---|---|
| `image` | Image reference, e.g. `ghcr.io/acme/api:1.4.2` or `…@sha256:<digest>` | Trivy (image) | Vulnerable OS and language packages in the image |
| `url` | Base URL of a running application | Nuclei; optionally the `worker-dast` tools in `config.tools` ([DAST tools](../user-guide/dast.md)) | Misconfigurations, exposures, known vulnerabilities (non-intrusive templates); with worker-dast tools also injection, XSS, TLS configuration and exposed files |
| `api` | Base URL plus an OpenAPI 3 / Swagger 2 document | Nuclei: exposure, misconfiguration and known-vulnerability checks on each operation; its DAST templates, which send injection payloads, only with intrusive testing authorized. Optionally the `worker-dast` tools (ZAP API scan and Schemathesis use the OpenAPI document) | Injection and other flaws in each operation; schema violations and server errors |
| `sbom` | Uploaded CycloneDX or SPDX JSON | Grype | Known vulnerabilities in the SBOM's components |
| `artifact` | Uploaded build artifact: zip or tar archive, Java archive, binary | Trivy (filesystem), binary hardening | Vulnerable components inside the artifact and missing hardening of its executables and libraries ([details](supply-chain.md#build-artifact-targets)) |
| `mobile-app` | Uploaded Android (`.apk`, `.aab`) or iOS (`.ipa`) package | Binary hardening (native libraries and executables); the [worker-mobile](../SCANNER_CATALOG.md#family-images-mobile-binary-ai-and-fuzzing) tools selected in `config.tools` | Insecure manifest, Info.plist and entitlement settings, weak signing, hard-coded secrets, insecure code, malware behaviour |
| `llm-endpoint` | Chat completions URL of an LLM application (OpenAI-compatible request format) plus `config.model` | Only the tools selected in `config.tools` (garak, promptfoo of [worker-ai](../SCANNER_CATALOG.md#family-images-mobile-binary-ai-and-fuzzing)) | Prompt injection, jailbreaks, system prompt and secret disclosure, unsafe output. Needs an authorization statement, and the intrusive testing flag for these tools |
| `endpoints` | The repository's declared public URLs, domains and IPs (`declared-public-endpoints`) | `pathos-endpoints` (built in), optionally Nuclei exposure templates | DNS, reachability, TLS and security-header problems. Created and managed only through [endpoint verification](repositories.md#endpoint-verification); the generic create and update endpoints refuse this kind (`400`) |

Image, artifact and mobile app targets also run **cosign** when a [signature verification policy](#signature-verification) is set.

## Permissions

| Action | Permission (on the target's repository) |
|---|---|
| List and read | `scans.read` |
| Create, update, delete | `repos.manage` |
| Scan | `scans.run` |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/scan-targets?repository_id=&kind=` | Targets in the caller's scope, with open findings and the last scan |
| `GET` | `/api/v1/scan-targets/{id}` | One target (includes `api_spec` for API targets) |
| `POST` | `/api/v1/scan-targets` | Create an `image`, `url`, `api` or `llm-endpoint` target (JSON) |
| `POST` | `/api/v1/scan-targets/sbom` | Create an SBOM target (`multipart/form-data`: `file`, `repository_id`, optional `name`) |
| `POST` | `/api/v1/scan-targets/artifact` | Create a build artifact target (`multipart/form-data`: `file` up to 200 MiB, `repository_id`, optional `name`, optional `signature`: a base64 signature or Sigstore bundle JSON, ≤ 64 KiB) |
| `POST` | `/api/v1/scan-targets/mobile-app` | Create a mobile app target: the same form and limits as artifacts; the file must be a ZIP-based package named `.apk`, `.aab` or `.ipa` (`400` otherwise) |
| `PUT` | `/api/v1/scan-targets/{id}` | Update (any field below; the kind cannot change) |
| `DELETE` | `/api/v1/scan-targets/{id}` | Delete. `409` while it has findings (disable it instead) or a scan is queued or running |
| `POST` | `/api/v1/scan-targets/{id}/scan` | Queue a scan → `202 { job_id, coalesced }`. `409` if disabled or not authorized, if a tool in `config.tools` contacts the target (`network: target`) and the target has no authorization statement, or if an intrusive tool is selected and intrusive testing is not authorized |

### Create and update fields

| Field | Description |
|---|---|
| `repository_id`, `kind` | Create only |
| `name` | 1–200 characters |
| `reference` | Image reference, base URL or (LLM endpoints) chat completions URL (`http`/`https`, no credentials or fragment) |
| `api_spec` | OpenAPI document (YAML or JSON, ≤ 2 MiB). Every `servers[].url` (or Swagger `host`) must be an absolute URL on the base URL's host |
| `auth_type` | `none`, `basic` (registry or HTTP username and password/token) or `header` (web and API targets: any header, e.g. `Authorization`, `X-API-Key`, `Cookie`) |
| `auth_username`, `auth_header_name` | For `basic` and `header` |
| `auth_secret` | Password, token or header value. Encrypted at rest and never returned (`has_secret` shows that one is stored). On update, omit to keep it, `""` to remove it |
| `authorized`, `authorization_note` | Web application, API and LLM endpoint targets: `authorized: true` records that you are authorized to test the application (your user and the time are stored as `authorized_by` / `authorized_at`). Required on create and whenever the address changes |
| `config` | `{ rate_limit: 1–100 (requests/s, default 20), min_severity: low|medium|high|critical }` for web and API targets; `{ signature: {…} }` for image, artifact and mobile app targets ([signature verification](#signature-verification)); `{ model, rate_limit }` for LLM endpoint targets (`model` is required: the `model` field of the chat completions request, letters, digits and `. _ : / @ + -`, ≤ 200 characters); `tools`: up to 20 keys of [manifest tools](scan-types-and-tools.md#tool-manifests) (family images or operator plugins) that also run for the target. Each must scan the target's kind (`url`; `api`: api or url tools; `image`; `artifact`: binary, mobile-app or model tools; `mobile-app`: mobile-app tools; `llm-endpoint`: llm-endpoint tools) and be registered by a worker, otherwise `400` |
| `intrusive_authorized`, `intrusive_authorization_note` | Web application, API and LLM endpoint targets with an authorization statement: `true` records that **intrusive testing** (active scans, fuzzing, injection probes) is authorized (`intrusive_authorized_by` / `intrusive_authorized_at` in the response), `false` withdraws it. A changed address withdraws it unless the same request sets it again. Audited as `scan_target.intrusive_authorize` and `scan_target.intrusive_revoke` |
| `signature_material` | Artifact and mobile app targets: the detached signature (base64, `cosign sign-blob --output-signature`) or Sigstore bundle (JSON); `""` removes it. Stored as given; `has_signature` shows that one is attached |
| `enabled` | Disabled targets are kept with their findings but cannot be scanned |

`egress_host` in the response is the host the worker must reach through the egress proxy (see the installation guide). `scanners` lists the scanners the target runs; `last_verification` is the latest [signature verification](#signature-verification) evidence (`null` before the first).

## Signature verification

`config.signature` of an image or artifact target:

| Field | Description |
|---|---|
| `mode` | `""` (off), `key` or `keyless` |
| `public_key` | `key`: the cosign public key in PEM (`-----BEGIN PUBLIC KEY-----`, ≤ 4096 characters) |
| `identity` or `identity_regexp` | `keyless`: the certificate identity (exact) or a regular expression (one of them) |
| `issuer` | `keyless`: the OIDC issuer, an `https` URL (e.g. `https://token.actions.githubusercontent.com`) |
| `attestation` | Image targets, optional: an in-toto predicate type verified with `cosign verify-attestation`: `slsaprovenance`, `slsaprovenance02`, `slsaprovenance1`, `spdx`, `spdxjson`, `cyclonedx`, `vuln`, `openvex`, `link` |
| `require` | `true`: a signature (and attestation) that is not verified creates a `high` finding (category `supply-chain`, scanner `cosign`, rule `signature/<status>` or `attestation/<status>`) and fails the execution's security gate (`gate_failed`) |
| `ignore_tlog` | `key`: do not require a Rekor transparency log entry |

Each scan stores a verification record, returned as `last_verification`:

```json
{
  "status": "verified",
  "mode": "keyless",
  "required": true,
  "attestation_status": "verified",
  "details": {
    "subject": "ghcr.io/acme/api:1.4.2",
    "signatures": [{ "digest": "sha256:9d50…", "identity": "https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1.4.2", "issuer": "https://token.actions.githubusercontent.com" }],
    "attestation": { "type": "slsaprovenance", "status": "verified", "predicate_type": "https://slsa.dev/provenance/v1", "builder_id": "https://github.com/actions/runner", "source_repository": "https://github.com/acme/api" },
    "offline": false
  },
  "scan_job_id": "0193…",
  "verified_at": "2026-11-19T10:00:00Z"
}
```

`status` is `verified`, `unsigned` (no signature found), `invalid` (signatures exist but none matches the key or identity, or the signature is wrong), `skipped` (keyless verification while offline) or `error` (for example the registry could not be reached). `attestation_status` is `""` (not configured), `verified`, `missing`, `invalid`, `skipped` or `error`. The raw cosign report is kept with the execution's results (raw scanner output). Offline, key-based verification runs without the transparency log (`details.offline: true`).

## How a target scan runs

- The scan uses the repository's scan profile for timeout, severity threshold and exclusions. The scanners follow from the kind; target scanners cannot be added to repository profiles (`400`).
- The execution appears under **Scans** with `asset_type` = the kind and `target_id`, `target_name`, `target_reference`. Its configuration snapshot records the target and scanners.
- Before a web or API scan, the worker checks that the egress proxy lets it reach the target; otherwise the scan fails with an explanation and no findings change.
- A mobile app is extracted on the worker like an archive artifact (the safe extraction of uploaded sources); the package file is kept beside its contents for the mobile tools. A package the extraction rejects is scanned as a file only.
- For an LLM endpoint, the worker checks that the egress proxy lets it reach the URL, then writes the endpoint description (URL, model, credential header) to a file readable only by the worker user in the job directory; the tools read the credential from it, never from a command line.
- An `endpoints` scan checks only the endpoints covered by the authorization statement; with `PATHOS_OFFLINE=true` queuing it returns `409`.
- Findings record `scan_target_id`, `scan_target_kind` and `scan_target_name`. A target's findings are separate from the repository's (the same CVE in the image and in the manifests are two findings), and only a successful scan of the same target marks them fixed.
- Retrying a failed target scan queues a new scan of the target.

## Filters

- Findings of targets: `scan_target_id` and `target_kind` on [list findings](findings.md#list-findings).
- Target scans: `asset_type` and `target_id` on [list executions](scans.md#list-executions).
