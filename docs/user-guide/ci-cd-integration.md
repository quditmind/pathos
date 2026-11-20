---
title: CI/CD integration
section: user-guide
group: connect
order: 23
version: "1.1"
updated: 2026-11-20
summary: Use the pathos CLI and the GitHub Action, GitLab CI, Azure Pipelines, Bitbucket Pipelines and Jenkins templates to import results, start scans and fail builds on the PATHOS security gate.
---
# CI/CD integration

PATHOS fits into a build pipeline in three ways:

- **Import** the results of scanners your pipeline already runs (Semgrep, Snyk, Trivy, ZAP and [20 more formats](../api-reference/result-imports.md#supported-formats)). PATHOS de-duplicates, risk-scores and triages them like its own findings.
- **Scan**: start a PATHOS scan of the repository and follow it to the end.
- **Gate**: fail the build when the security gate fails. The gate fails when the execution's own gate failed (the profile's *fail on critical* setting or a blocking [security policy](policies-and-compliance.md)), or when findings at or above a severity you choose exist.

All three use the **`pathos` command-line tool**. Ready-made templates wrap it for GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket Pipelines and Jenkins.

## Before you start

1. **Create a REST API token** for the pipeline: user menu → **API tokens (MCP)** ([REST API tokens](reporting-and-integrations.md#rest-api-tokens)). Allow **REST API: read and write** for imports and scans; **REST API: read** is enough for the gate and for listing findings. The token acts with your current permissions: importing and scanning need `scans.run` on the repository, the gate needs `scans.read`. Tokens expire after at most 90 days; renew them in time.
2. **Store the token as a secret** of the CI system (GitHub *Actions secret*, GitLab *masked and protected variable*, Azure Pipelines *secret variable*, Bitbucket *secured repository or deployment variable*, Jenkins *Secret text credential*). Never write it into a pipeline file.
3. Note the repository's **name** (for example `acme/payments-api`) or its **Repository ID** (`QD-REPO-000042`). The CLI accepts either, or the UUID.
4. If PATHOS uses a certificate from a private CA, make the CA's PEM file available to the pipeline (`--ca-cert`).

## The pathos CLI

Download the binary for your platform (Linux, macOS or Windows; amd64 or arm64) from the PATHOS release on GitHub. Each release has a `checksums.txt` with the SHA-256 of every binary, signed with Sigstore cosign (keyless, by the release workflow):

```bash
v=3.0.0
curl -fsSLO https://github.com/quditmind/pathos/releases/download/v$v/pathos_${v}_linux_amd64
curl -fsSLO https://github.com/quditmind/pathos/releases/download/v$v/checksums.txt
sha256sum -c --ignore-missing checksums.txt
install -m 0755 pathos_${v}_linux_amd64 /usr/local/bin/pathos
```

To also verify the signature: download `checksums.txt.sigstore.json` and run `cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json --certificate-identity "https://github.com/quditmind/pathos/.github/workflows/release.yml@refs/tags/v$v" --certificate-oidc-issuer https://token.actions.githubusercontent.com`. The script `integrations/install-cli.sh` in the PATHOS repository does all of this.

### Connection settings

| Flag | Environment variable | Meaning |
|---|---|---|
| `--url` | `PATHOS_URL` | PATHOS base URL, for example `https://pathos.example.com` |
| `--token` | `PATHOS_TOKEN` | REST API token. Prefer the environment variable or `--token-file`, so the token never appears in the command line |
| `--token-file` | `PATHOS_TOKEN_FILE` | File containing the token |
| `--ca-cert` | `PATHOS_CA_CERT` | PEM file with additional CA certificates. Certificates are always verified; there is no option to turn verification off |
| `--allow-http` | | Allow plain `http://` to a host other than `localhost` (prints a warning). Without it, only `https://` and loopback addresses are accepted |
| `--timeout` | | Timeout of each request (default `2m`) |
| `--json` | | Machine-readable output on stdout |
| `--quiet` | | No progress messages on stderr |

The token is sent only as an `Authorization: Bearer` header to the configured server. It is never printed, logged or forwarded on a redirect to another host.

### Commands

| Command | What it does |
|---|---|
| `pathos import --repo R --file F [--format ID] [--tool NAME] [--category CAT] [--commit SHA] [--branch NAME] [--complete]` | Uploads a results file and waits until the import's execution is finished. `--format` names the format (detected when omitted); `--tool` and `--category` default from the format. `--complete` marks findings the tool no longer reports as fixed (only for the tool's complete result). Commit and branch default from the CI environment (`GITHUB_SHA`, `CI_COMMIT_SHA`, `BUILD_SOURCEVERSION`, `BITBUCKET_COMMIT`, `GIT_COMMIT`, and the matching branch variables, including `BITBUCKET_BRANCH`) |
| `pathos import --sbom --repo R --file F` | Uploads a CycloneDX or SPDX JSON SBOM; it replaces the repository's component inventory |
| `pathos scan --repo R [--profile UUID] [--name NAME] [--no-wait] [--wait-timeout 30m]` | Starts a scan and follows its stages and progress until it finishes |
| `pathos gate (--scan UUID \| --repo R) [--fail-on SEV] [--scope new\|all] [--allow-partial]` | Evaluates the security gate of an execution (with `--repo`: the latest finished execution of the repository's source code or of a result import; scan target executions such as images and URLs are not considered). See below |
| `pathos gate --stage ide\|pre-commit\|pull-request\|ci\|release\|deploy (--repo R \| --application UUID) [--commit SHA] [--scan UUID] [--pull-request N]` | Asks the organization's [security gates](remediation.md#security-gates) of a stage for a decision (PATHOS 3.0, flag `remediation_workspace`). Exit 1 on *block* or *approval required*; 0 on *pass*, *warn* or *exception applied*. `--fail-on`, `--scope` and `--allow-partial` do not apply |
| `pathos findings [--repo R] [--severity critical,high] [--status open] [--category C] [--scanner KEY] [--limit 100] [--output table\|json]` | Lists findings |
| `pathos sbom export --repo R [--format cyclonedx\|spdx] [--output FILE]` | Downloads the repository's SBOM |
| `pathos version` | Prints the CLI version and build, e.g. `Quditmind PATHOS v3.0.0 (build 0123456789ab, 2026-11-20T10:00:00Z)` (also `pathos --version`) |

### The gate

`pathos gate` fails (exit code 1) when any of these is true:

- the execution has not finished, or its status is not *succeeded* (*partial* is accepted with `--allow-partial`)
- the execution's own security gate failed: the profile's *fail on critical* setting or a blocking security policy
- `--fail-on` is a severity and findings at or above it exist: findings **new** in this execution (`--scope new`, the default), or **all** open findings of the repository (`--scope all`)

It prints the reasons, so the build log says why the build failed. `--fail-on` is the pipeline's own explicit threshold (decision C6 of the lifecycle design): it never applies unless you pass it.

With `--stage`, the decision comes from the organization's [security gates](remediation.md#security-gates) instead: each gate applies a security policy at a stage, and no gate blocks without a policy. With no gate configured the decision is *pass*. Every decision is recorded in **Remediate & gate → Gates & decisions**.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; the gate passed |
| 1 | The gate failed |
| 2 | Wrong usage (unknown flag, missing argument) |
| 3 | API, authentication, network or configuration error (for example an invalid token, a read-only token for a write, a file PATHOS cannot parse) |
| 4 | The scan failed, was cancelled or did not finish in time |

## GitHub Actions

The action in `integrations/github-action` installs the verified CLI of its own release and runs the steps you enable:

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: semgrep scan --json --output semgrep.json   # any supported scanner
      - uses: quditmind/pathos/integrations/github-action@v3.0.0
        with:
          url: https://pathos.example.com
          token: ${{ secrets.PATHOS_TOKEN }}
          repository: acme/payments-api
          import-file: semgrep.json
          fail-on: high
```

| Input | Default | Meaning |
|---|---|---|
| `url`, `token`, `repository` | (required) | Connection and repository |
| `cli-version` | the action's tag | CLI release to install |
| `ca-cert` | | PEM file for a private CA |
| `import-file`, `import-format`, `import-tool`, `import-category`, `complete` | | Results import (skipped when `import-file` is empty) |
| `sbom-file` | | SBOM import |
| `scan` | `false` | Start a PATHOS scan and wait for it |
| `gate` | `true` | Evaluate the gate of the import's or scan's execution (else the latest) |
| `fail-on`, `scope` | `none`, `new` | Gate threshold |

Outputs: `scan-id` and `gate-passed`. Pin the action to a release tag (or its commit SHA).

## GitLab CI

Include the template and extend its hidden jobs:

```yaml
include:
  - remote: https://raw.githubusercontent.com/quditmind/pathos/v3.0.0/integrations/gitlab/pathos.gitlab-ci.yml

variables:
  PATHOS_URL: https://pathos.example.com
  PATHOS_REPOSITORY: acme/payments-api
  PATHOS_CLI_VERSION: "3.0.0"
  # PATHOS_TOKEN: masked, protected CI/CD variable

pathos-import:
  extends: .pathos-import
  needs: [semgrep]
  variables:
    PATHOS_IMPORT_FILE: semgrep.json

pathos-gate:
  extends: .pathos-gate
  needs: [pathos-import]
  variables:
    PATHOS_FAIL_ON: high
```

The template provides `.pathos-import` (variables `PATHOS_IMPORT_FILE`, `PATHOS_IMPORT_FORMAT`, `PATHOS_IMPORT_TOOL`, `PATHOS_IMPORT_CATEGORY`, `PATHOS_COMPLETE`), `.pathos-scan` and `.pathos-gate` (`PATHOS_FAIL_ON`, `PATHOS_SCOPE`). Each installs the CLI and checks its SHA-256 first.

## Azure Pipelines

Copy `integrations/azure-pipelines/pathos.yml` into your repository and use it as a steps template. Define `PATHOS_TOKEN` as a secret pipeline variable; the template maps it into the steps that need it.

```yaml
steps:
  - script: semgrep scan --json --output semgrep.json
  - template: pathos.yml
    parameters:
      url: https://pathos.example.com
      repository: acme/payments-api
      cliVersion: "3.0.0"
      importFile: semgrep.json
      failOn: high
```

Parameters: `importFile`, `importFormat`, `importTool`, `importCategory`, `complete`, `scan`, `gate` (default `true`), `failOn`, `scope`.

## Bitbucket Pipelines

`integrations/bitbucket-pipelines/bitbucket-pipelines.yml` (Bitbucket Cloud Pipelines) defines three reusable steps under `definitions.steps` with YAML anchors: `&pathos-import`, `&pathos-scan` and `&pathos-gate`. Bitbucket has no remote include for ordinary repositories, so copy the `definitions` block into your `bitbucket-pipelines.yml` and reuse the steps with `*pathos-gate` or `<<: *pathos-import` ([YAML anchors](https://support.atlassian.com/bitbucket-cloud/docs/yaml-anchors/)). Each step installs the CLI and checks its SHA-256 first.

Set these as repository or deployment variables ([Variables and secrets](https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/)): `PATHOS_URL`, `PATHOS_REPOSITORY`, `PATHOS_CLI_VERSION`, and `PATHOS_TOKEN` as a **secured** variable (masked in logs, not editable after creation). Optional: `PATHOS_FAIL_ON`, `PATHOS_SCOPE`, `PATHOS_IMPORT_FILE`, `PATHOS_IMPORT_FORMAT`, `PATHOS_IMPORT_TOOL`, `PATHOS_IMPORT_CATEGORY`, `PATHOS_COMPLETE`, and `PATHOS_CA_CERT_PEM` (the PEM of a private CA that signs PATHOS' certificate). The CLI takes the commit and branch from `BITBUCKET_COMMIT` and `BITBUCKET_BRANCH`.

```yaml
pipelines:
  default:
    - step:
        name: Semgrep
        image: semgrep/semgrep
        script:
          - semgrep scan --config auto --json --output semgrep.json || true
        artifacts:
          - semgrep.json
    - step:
        <<: *pathos-import
        script:
          - export PATHOS_IMPORT_FILE=semgrep.json
          - *pathos-install
          - pathos import --repo "$PATHOS_REPOSITORY" --file "$PATHOS_IMPORT_FILE"
  pull-requests:
    '**':
      - step: *pathos-gate
```

PATHOS never stores Bitbucket credentials for this integration: the pipeline calls PATHOS with its own token. Bitbucket Data Center has no built-in Pipelines; use its CI (Bamboo, Jenkins) with the Jenkins snippet or the CLI directly.

## Jenkins

`integrations/jenkins/Jenkinsfile` is a declarative pipeline snippet with three stages: install the CLI (with checksum verification), import, gate. Store the token as a *Secret text* credential (`pathos-token` in the snippet) and keep the `sh` steps in single quotes so that the shell, not Groovy, expands it.

## Other CI systems

Any system that can run a shell works: install the CLI as above, set `PATHOS_URL` and `PATHOS_TOKEN` from its secret store, and call `pathos import …` and `pathos gate …`. The exit code decides whether the build fails.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `invalid_token` | The token is wrong, expired or revoked. Create a new one |
| `token_read_only` | Imports and scans need a token with the `api:write` scope |
| *the file is X, not Y* | `--format` does not match the file. Omit it to detect the format |
| *unrecognised report* | The file is empty or not a supported format; name it with `--format` (an empty report of a named format is a valid, complete result) |
| *a tool name is required* | SARIF, PATHOS JSON and CSV imports need `--tool` |
| *a scan of this repository is running* | An import cannot run while a scan of the repository is running; retry when it has finished |
| certificate errors | Pass the CA with `--ca-cert` (Bitbucket Pipelines: set `PATHOS_CA_CERT_PEM`) |
| Bitbucket: *unknown alias* / *anchor not defined* | The `definitions` block of the template was not copied into `bitbucket-pipelines.yml`; anchors work only within one file |

**Related APIs.** [Result imports](../api-reference/result-imports.md), [Scans: evaluate the security gate](../api-reference/scans.md#evaluate-the-security-gate), [REST API tokens](../api-reference/index.md#rest-api-tokens).
