# PATHOS

[![CI](https://github.com/quditmind/pathos/actions/workflows/ci.yml/badge.svg)](https://github.com/quditmind/pathos/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Application Security Posture Management Platform.** PATHOS is an open-source, Docker-first platform that centralizes source-code security scanning, repository and asset management, vulnerability intelligence, AI-assisted finding review, SBOM management and security posture analytics.

> **Status: 1.1.0 (stable).** The eight platform phases (P1–P8), the ten ASPM phases and the 1.1 gap closure are implemented and tested (99 of 100 register capabilities; multi-tenant is out by design). Highlights:
>
> - Keycloak login with TOTP, recovery codes and optional SAML/OIDC single sign-on; scoped RBAC and an audit log.
> - Repository and asset management for GitHub, GitLab, Bitbucket Cloud and Azure DevOps, plus local uploads and applications.
> - Isolated scan workers running open-source scanners (Gitleaks, Opengrep, Trivy, Grype, OSV-Scanner, Checkov, zizmor, actionlint, Nuclei) on repositories, container images, web applications, APIs, build artifacts and SBOMs, with de-duplicated findings; declarative scanner plugins.
> - Contextual risk scoring with EPSS, CISA KEV and OSV; reachability, attack paths and posture analytics.
> - Human Eye manual review, AI review (Anthropic, OpenAI, xAI) with human approval, the AI Security Analyst and an MCP server.
> - Vulnerability lifecycle: SLAs, risk acceptance, security policies, compliance views, SBOM export and license policy.
> - Supply chain: package health, malicious packages, pull request checks.
> - Reporting and integrations: executive overview, scheduled reports, REST API tokens, webhooks (Slack, Teams), Jira and ServiceNow.
> - 1.1: malware, licence, binary-hardening and framework-configuration scanning; endpoint verification, end-of-life dates, introducing commits and Sigstore verification; 25 import formats, the `pathos` CLI and CI templates; automatic fix pull requests; VEX and application versions; secret push protection; material change detection, opt-in developer insights and a VS Code extension.
> - Production readiness: scheduling, notifications, rate limiting, backup, restore and upgrade, OpenTelemetry, S3 artifacts, offline (air-gapped) mode and security self-tests.
>
> See [docs/DEVELOPMENT_ROADMAP.md](docs/DEVELOPMENT_ROADMAP.md) and [docs/aspm/PATHOS_IMPLEMENTATION_ROADMAP.md](docs/aspm/PATHOS_IMPLEMENTATION_ROADMAP.md) for the milestone reports.

## Installation

```bash
git clone https://github.com/quditmind/pathos.git && cd pathos
./deploy/scripts/install.sh    # generates .env with secrets and prints the admin login
docker compose up -d --wait
```

Then open https://localhost. Details: [docs/INSTALLATION.md](docs/INSTALLATION.md). This builds the images locally; to install a tested, cosign-signed release from GHCR instead, see [Installing a release](docs/OPERATIONS.md#installing-a-release-signed-images).

The only host requirement is Docker Engine with the Compose plugin. For production, see [docs/OPERATIONS.md](docs/OPERATIONS.md) (`docker-compose.prod.yml`).

## Development

```bash
make test               # Go and frontend unit tests (in containers)
make test-integration   # Go integration tests against a throwaway PostgreSQL
make smoke              # end-to-end API checks against the running stack
make e2e                # Playwright browser tests against the running stack
make security           # gosec, govulncheck, npm audit, Trivy, ZAP baseline
make load-test          # k6 load test (see docs/OPERATIONS.md)
```

CI (`.github/workflows/ci.yml`) runs all of the above on every pull request. It starts with fast checks (gofmt, vet, race-enabled unit and integration tests, gosec, govulncheck, the frontend build and npm audit), then does a fresh install of the full Compose stack, followed by the smoke test, the browser tests, Trivy on the built images and a ZAP baseline. Dependabot proposes weekly dependency updates.

## Documentation

**Using PATHOS** (also in the in-app Help Center):

| Document | Contents |
|---|---|
| [User guide](docs/user-guide/introduction.md) | Every module, step by step: repositories, scanning, findings, Human Eye, posture, AI, policies, integrations |
| [API reference](docs/api-reference/index.md) | Authentication, errors, pagination, and every REST endpoint with its permission |

**Installing and operating:**

| Document | Contents |
|---|---|
| [INSTALLATION](docs/INSTALLATION.md) | Install, what runs, configure, verify |
| [OPERATIONS](docs/OPERATIONS.md) | Production deployment, releases, backup/restore/upgrade, scaling, monitoring, configuration reference, rate limits, object storage, malware scanning, AI options, self-tests |
| [AIRGAP](docs/AIRGAP.md) | Air-gapped installation with offline vulnerability data |
| [SECURITY](docs/SECURITY.md) | Implemented security controls, key rotation |
| [RBAC_MATRIX](docs/RBAC_MATRIX.md) | Roles, scopes, permission matrix |

**Design and engineering:**

| Document | Contents |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | System design, isolation model, deployment, decisions, sizing, extension points |
| [DATABASE](docs/DATABASE.md) | Schema and migrations |
| [SCANNING_MODULE](docs/SCANNING_MODULE.md) | Scan executions, schedules and comparison: design notes |
| [REPOSITORY_ONBOARDING](docs/REPOSITORY_ONBOARDING.md) | Repository onboarding: design notes |
| [HUMAN_REVIEW](docs/HUMAN_REVIEW.md) | Human Eye: design notes |
| [SCANNER_CATALOG](docs/SCANNER_CATALOG.md) | Implemented scanners, licensing review, scanner plugins |
| [DEPENDENCIES](docs/DEPENDENCIES.md) | Dependencies, versions and licenses |
| [OpenAPI](backend/api/openapi.yaml) | OpenAPI 3.1 description |

**Roadmaps and history:**

| Document | Contents |
|---|---|
| [ASPM roadmap](docs/aspm/PATHOS_IMPLEMENTATION_ROADMAP.md) | ASPM phases 1–10 and their completion reports |
| [ASPM register](docs/aspm/PATHOS_FEATURE_GAP_ANALYSIS.md) | The 100 target capabilities and their status |
| [DEVELOPMENT_ROADMAP](docs/DEVELOPMENT_ROADMAP.md) | Original platform build (phases P1–P8) and milestone reports |
| [CHANGELOG](CHANGELOG.md) | Changes per release |

## Contributing and security

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

PATHOS is licensed under the [Apache License 2.0](LICENSE). Third-party scanners and images keep their own licenses; see [DEPENDENCIES](docs/DEPENDENCIES.md) and [SCANNER_CATALOG](docs/SCANNER_CATALOG.md).
