# Security policy

PATHOS is a security product, so we take reports about its own security seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Report them privately through GitHub:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, the affected version or commit, and the steps to reproduce. Include a proof of concept if you have one.

You can expect:
- An acknowledgement within 5 working days.
- An assessment and a fix plan within 14 days for confirmed issues.
- Coordinated disclosure: a fix and a GitHub security advisory before details are published, with credit if you want it.

## Supported versions

| Version | Supported |
|---|---|
| `main` and the latest release | Yes |
| Older releases | Upgrade first; fixes are not backported before 1.0 |

## Scope

In scope:
- the PATHOS API, UI, worker agent and scanner isolation;
- the Compose deployment and the shipped images;
- the authentication and authorization model;
- secret handling;
- the AI review and MCP integration.

Out of scope:
- findings that PATHOS reports *about scanned repositories* (that is the product working as intended);
- vulnerabilities in third-party scanners or images without a PATHOS-specific impact (report those upstream; we track them with `make security`);
- deployments that ignore [docs/OPERATIONS.md](docs/OPERATIONS.md), for example exposing the Keycloak admin console publicly.

## How PATHOS is secured

The implemented controls, the threat model and the accepted residual risks are documented in [docs/SECURITY.md](docs/SECURITY.md).
