# PATHOS

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
git clone <repo-url> pathos && cd pathos
./deploy/scripts/install.sh    # generates .env with secrets and prints the admin login
docker compose up -d --wait
```

Then open https://localhost. Details: [docs/INSTALLATION.md](docs/INSTALLATION.md).

The only host requirement is Docker Engine with the Compose plugin. For production, see [docs/OPERATIONS.md](docs/OPERATIONS.md) (`docker-compose.prod.yml`).

## Development

```bash
make test               # Go and frontend unit tests (in containers)
make test-integration   # Go integration tests against a throwaway PostgreSQL
make smoke              # end-to-end checks against the running stack
make security           # gosec, govulncheck, npm audit, Trivy, ZAP baseline
make load-test          # k6 load test (see docs/OPERATIONS.md)
```

## Documentation

| Document | Contents |
|---|---|
| [INSTALLATION](docs/INSTALLATION.md) | Install, configure, verify |
| [OPERATIONS](docs/OPERATIONS.md) | Production deployment, backup/restore/upgrade, scaling, monitoring, rate limits, object storage, self-tests |
| [SECURITY](docs/SECURITY.md) | Implemented security controls, key rotation |
| [RBAC_MATRIX](docs/RBAC_MATRIX.md) | Roles, scopes, permission matrix |
| [API](backend/api/openapi.yaml) | OpenAPI 3.1 spec |
| [CHANGELOG](CHANGELOG.md) | Changes per phase |
| [ENVIRONMENT_ASSESSMENT](docs/ENVIRONMENT_ASSESSMENT.md) | Dev host assessment |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | System design, isolation model, deployment, UI plan, decisions, sizing |
| [DATABASE](docs/DATABASE.md) | Entity-relationship design |
| [SCANNER_CATALOG](docs/SCANNER_CATALOG.md) | Scanner licensing and maintenance review |
| [DEPENDENCIES](docs/DEPENDENCIES.md) | Dependencies and licenses |
| [DEVELOPMENT_ROADMAP](docs/DEVELOPMENT_ROADMAP.md) | Phase plan and status |

## License

To be decided before first release (Apache-2.0 recommended: compatible with all planned dependencies and common in enterprise security tooling).
