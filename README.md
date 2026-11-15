# PATHOS

**Application Security Posture Management Platform.** PATHOS is an open-source, Docker-first platform that centralizes source-code security scanning, repository and asset management, vulnerability intelligence, AI-assisted finding review, SBOM management and security posture analytics.

> **Status: pre-alpha. Phase 1 (Foundation) complete:** login via Keycloak, scoped RBAC, user management, audit log, encrypted secrets, and a full `docker compose` stack. Scanning arrives in Phase 4. See [docs/DEVELOPMENT_ROADMAP.md](docs/DEVELOPMENT_ROADMAP.md).

## Installation

```bash
git clone <repo-url> pathos && cd pathos
./deploy/scripts/install.sh    # generates .env with secrets and prints the admin login
docker compose up -d --wait
```

Then open https://localhost. Details: [docs/INSTALLATION.md](docs/INSTALLATION.md).

The only host requirement is Docker Engine with the Compose plugin.

## Documentation

| Document | Contents |
|---|---|
| [INSTALLATION](docs/INSTALLATION.md) | Install, configure, operate, verify |
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
