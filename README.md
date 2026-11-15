# PATHOS

[![CI](https://github.com/quditmind/pathos/actions/workflows/ci.yml/badge.svg)](https://github.com/quditmind/pathos/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Application Security Posture Management Platform.** PATHOS is an open-source, Docker-first platform that centralizes source-code security scanning, repository and asset management, vulnerability intelligence, AI-assisted finding review, SBOM management and security posture analytics.

> **Status: release candidate. All eight roadmap phases are implemented and tested.** Delivered so far:
>
> - Keycloak login with scoped RBAC and an audit log.
> - GitHub and Azure DevOps repository management.
> - Isolated scan workers running 7 open-source scanners with de-duplicated findings.
> - AI review (Anthropic, OpenAI, xAI) with human approval, and an MCP server.
> - Vulnerability lifecycle: SLAs, risk acceptance, SBOM and license policy.
> - Scheduling and notifications.
> - Production hardening: rate limiting, backup, restore and upgrade, OpenTelemetry, S3 artifacts and security self-tests.
>
> See [docs/DEVELOPMENT_ROADMAP.md](docs/DEVELOPMENT_ROADMAP.md) for the milestone reports.

## Installation

```bash
git clone https://github.com/quditmind/pathos.git && cd pathos
./deploy/scripts/install.sh    # generates .env with secrets and prints the admin login
docker compose up -d --wait
```

Then open https://localhost. Details: [docs/INSTALLATION.md](docs/INSTALLATION.md).

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

| Document | Contents |
|---|---|
| [INSTALLATION](docs/INSTALLATION.md) | Install, configure, verify |
| [OPERATIONS](docs/OPERATIONS.md) | Production deployment, backup/restore/upgrade, scaling, monitoring, rate limits, object storage, self-tests |
| [SECURITY](docs/SECURITY.md) | Implemented security controls, key rotation |
| [RBAC_MATRIX](docs/RBAC_MATRIX.md) | Roles, scopes, permission matrix |
| [API](backend/api/openapi.yaml) | OpenAPI 3.1 spec |
| [CHANGELOG](CHANGELOG.md) | Changes per phase |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | System design, isolation model, deployment, UI plan, decisions, sizing |
| [DATABASE](docs/DATABASE.md) | Entity-relationship design |
| [SCANNER_CATALOG](docs/SCANNER_CATALOG.md) | Scanner licensing and maintenance review |
| [DEPENDENCIES](docs/DEPENDENCIES.md) | Dependencies and licenses |
| [DEVELOPMENT_ROADMAP](docs/DEVELOPMENT_ROADMAP.md) | Phase plan and status |

## Contributing and security

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

PATHOS is licensed under the [Apache License 2.0](LICENSE). Third-party scanners and images keep their own licenses; see [DEPENDENCIES](docs/DEPENDENCIES.md) and [SCANNER_CATALOG](docs/SCANNER_CATALOG.md).
