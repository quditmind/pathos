# Dependencies

Everything PATHOS ships or runs, with pinned versions and licences. The pins themselves are the source of truth:

- Container images: pinned by digest in `docker-compose.yml` and the Dockerfiles (`backend/Dockerfile`, `deploy/caddy/Dockerfile`, `workers/core/Dockerfile`).
- Go modules: `backend/go.mod` and `go.sum`.
- npm packages: exact versions in `frontend/package.json` and `package-lock.json` (and `e2e/package.json` for the browser tests).

Dependabot proposes weekly updates. When you change a pin, update this page in the same pull request.

## Platform services (containers)

| Component | Image | License | Notes |
|---|---|---|---|
| PostgreSQL | `postgres:18.7-alpine` | PostgreSQL License | Databases `pathos` and `keycloak` |
| Valkey | `valkey/valkey:9.1.3-alpine` | BSD-3-Clause | Instead of Redis (licence, see [ARCHITECTURE D2](ARCHITECTURE.md#9-architectural-decisions-and-risks)) |
| Keycloak | `quay.io/keycloak/keycloak:26.8.2` | Apache-2.0 | Also runs the one-shot `keycloak-setup` job |
| Caddy | `caddy:2.11.9-alpine`, built with `caddy:2.11.9-builder-alpine` (xcaddy, `golang.org/x/net` v0.62.0) | Apache-2.0 | Edge proxy; rebuilt to pick up patched dependencies |
| Squid (egress proxy) | `ubuntu/squid:7.2-26.04_edge` | GPL-2.0-or-later | Scanner egress allowlist |
| PATHOS runtime base | `gcr.io/distroless/static-debian13:nonroot` | Apache-2.0 | API, jobs, scheduler and migrate |
| Mailpit (profile `dev`) | `axllent/mailpit:v1.33.1` | MIT | SMTP sink for development |
| SeaweedFS (profile `objectstore`) | `chrislusf/seaweedfs:4.51` | Apache-2.0 | Optional S3-compatible store (instead of MinIO, ARCHITECTURE D1) |
| ClamAV (profile `clamav`) | `clamav/clamav:1.5` | GPL-2.0 | Optional malware scanning of uploads and (the `clamav` scanner) of repository content. A separate service; PATHOS talks to it over the clamd network protocol and does not link or distribute it |
| Ollama (profile `ollama`) | `ollama/ollama:0.40.13` | MIT | Optional local model server |
| Grafana otel-lgtm (profile `observability`) | `grafana/otel-lgtm:0.39.0` | Apache-2.0 | Local observability backend, evaluation only |

## Build images

| Image | Used for |
|---|---|
| `golang:1.27.4-alpine` | The PATHOS binaries, the worker agent, and Gitleaks, Nuclei, actionlint and cosign built from source |
| `node:26.13.1-alpine` | The frontend build (inside the proxy image) |
| `debian:trixie-slim` | Downloading and verifying the scanner binaries |
| `python:3.13-slim-trixie` | The `worker-core` runtime (Checkov needs Python); `pip` is removed after installing Checkov |

## Optional Git hooks (`integrations/`)

Not shipped in any image; installed by repository owners or Git server administrators (see the user guide page *Secret push protection*).

| Tool | Version | License | Used by |
|---|---|---|---|
| Gitleaks | 8.30.1 (binary, `zricethezav/gitleaks:v8.30.1` image, or the upstream pre-commit hook at tag `v8.30.1`) | MIT | `integrations/pre-commit/` and `integrations/pre-receive/` |
| pre-commit | any | MIT | Optional framework for `integrations/pre-commit/` |

## Scanners in worker-core

| Tool | Version | License | How it is installed |
|---|---|---|---|
| Gitleaks | 8.30.1 | MIT | Built from its Go module with Go 1.27.4 and patched `x/crypto` v0.55.0, `x/text` v0.41.0, `klauspost/compress` v1.18.7 |
| Opengrep | 2.0.0 | LGPL-2.1 | Release binary, SHA-256 pinned |
| Trivy | 0.76.2 | Apache-2.0 | Built from its Go module with Go 1.27.4 (the release binary was built with Go 1.27.3: CVE-2026-97054) |
| Syft | 1.57.1 | Apache-2.0 | Built from its Go module with Go 1.27.4 (same reason) |
| Grype | 0.121.3 | Apache-2.0 | Built from its Go module with Go 1.27.4 (same reason) |
| OSV-Scanner | 2.7.1 | Apache-2.0 | Built from its Go module with Go 1.27.4 (same reason) |
| Checkov | 3.4.5 | Apache-2.0 | `pip install` |
| zizmor | 1.32.0 | MIT | Release archive, SHA-256 pinned |
| actionlint | 1.7.12 | MIT | Built from its Go module |
| Nuclei | 3.11.1 | MIT | Built from its Go module with patched dependencies (`kin-openapi`, `go-git`, `go-jose`, `grpc`, `x/crypto`, `x/net`, `x/text`) |
| Nuclei templates | 10.5.1 | MIT | Source archive, SHA-256 pinned; a reviewed subset only ([SECURITY.md](SECURITY.md#scan-targets)) |
| File licences (`licensecheck`), binary hardening (`binary-hardening`), ClamAV client (`clamav`) | PATHOS version | Apache-2.0 | Built into the worker agent (`pathos-worker`): no additional binary |
| cosign (Sigstore) | 3.1.4 | Apache-2.0 | Built from its Go module; the module hash (`h1:d3UHS8oJebMf6XUhPtWv9weU1ZYRyXq9HJ7QPccmqvY=`, Go checksum database) is checked before building. Signature and attestation verification of image and artifact targets |

## Scanners in family worker images

Family images extend `worker-core`; their tools are defined by manifests in `workers/<family>/tools.d`.

| Image | Tool | Version | License | How it is installed |
|---|---|---|---|---|
| worker-sast | Bandit | 1.9.4 | Apache-2.0 | `pip install --require-hashes` into `/opt/pathos/sast` (`workers/sast/requirements.txt`) |
| worker-sast | njsscan (with libsast 3.2.0 and Semgrep CE 1.172.0) | 1.0.2 | LGPL-3.0-or-later (Semgrep: LGPL-2.1-or-later) | Same; mcp 1.28.1 and PyJWT 2.14.0 replace the versions Semgrep pins (fixable CVEs) |
| worker-sast | ShellCheck | 0.11.0 | GPL-3.0-only | Release archive, SHA-256 pinned; run through the `shellcheck-tree` helper (`workers/sast/bin`) |
| worker-sast | gosec | 2.30.0 | Apache-2.0 | Built from its Go module with Go 1.27.4 (Go checksum database); golang.org/x/net 0.62.0 replaces 0.61.0 (fixable CVE). Run through `gosec-tree` with the image's Go toolchain (Go 1.27.4, `/opt/pathos/sast/go`), offline |
| worker-sast | golangci-lint | 2.15.0 | GPL-3.0-only | Built from its Go module with Go 1.27.4; run through `golangci-lint-tree` with the image's configuration (`workers/sast/config/golangci.yml`) |
| worker-sast | TruffleHog | 3.99.9 | AGPL-3.0-only | Built from its Go module with Go 1.27.4; run unmodified as a separate process, verification off |
| worker-sast | Talisman | 1.37.0 | MIT | GitHub source archive of the tag, SHA-256 pinned, built with Go 1.27.4 (dependencies checked against its go.sum); golang.org/x/text 0.43.0 replaces 0.23.0 (fixable CVEs) |
| worker-sast | Bearer CLI (with Bearer/bearer-rules 0.48.4) | 2.1.3 | Elastic-2.0 | GitHub source archive of the tag, SHA-256 pinned, built with Go 1.27.4 and cgo on Debian trixie; golang.org/x/net 0.62.0 replaces 0.61.0. Rule archives SHA-256 pinned |
| worker-sast | Kingfisher | 2.19.1 | Apache-2.0 | Release archive (linux-x64), SHA-256 pinned |
| worker-sast | cppcheck | 2.19.0 | GPL-3.0-or-later | GitHub source archive of the tag, SHA-256 pinned, built with CMake (the Debian package depends on a second Python) |
| worker-sast | PHPStan | 2.3.6 | MIT | Release PHAR, SHA-256 pinned; runs on Debian's php8.4-cli |
| worker-sast | Psalm | 7.11.0 | MIT | Release PHAR, SHA-256 pinned; run through `psalm-taint` |
| worker-sast | ESLint, eslint-plugin-security, @typescript-eslint/parser, TypeScript | 10.15.0, 4.2.1, 8.73.0, 6.0.3 | MIT, Apache-2.0, MIT, Apache-2.0 | `npm ci` from `workers/sast/eslint/package-lock.json` (integrity hashes, no install scripts); Node.js 24.22.3 (MIT) release archive, SHA-256 pinned (only the `node` binary is kept) |
| worker-sast | Flawfinder | 2.0.20 | GPL-2.0-or-later | `pip install --require-hashes` (`workers/sast/requirements.txt`) |
| worker-sast | Ruff | 0.17.5 | MIT | Same |
| worker-sast | detect-secrets | 1.5.0 | Apache-2.0 | Same |
| worker-sast | Pylint (with astroid 4.3.4) | 4.1.4 | GPL-2.0-or-later | Same |
| worker-sast | Semgrep CE | 1.172.0 | LGPL-2.1-or-later | Installed as njsscan's dependency; the `semgrep-ce` manifest runs it with the PATHOS rules only |

Data: the optional end-of-life feed uses [endoflife.date](https://endoflife.date) data (MIT licence), downloaded at run time when an administrator enables it; nothing from it is shipped.

The licensing review of all catalogued scanners is in [SCANNER_CATALOG.md](SCANNER_CATALOG.md).

## Go backend (Go 1.27)

Direct dependencies from `backend/go.mod`:

| Module | Version | Purpose | License |
|---|---|---|---|
| Standard library (`net/http` pattern routing, `log/slog`, `crypto/*`) | Go 1.27 | HTTP, logging, cryptography | BSD-3-Clause |
| `github.com/jackc/pgx/v5` | v5.13.0 | PostgreSQL driver and pool | MIT |
| `github.com/pressly/goose/v3` | v3.30.1 | Migrations | MIT |
| `github.com/redis/go-redis/v9` | v9.23.0 | Valkey client | BSD-2-Clause |
| `github.com/coreos/go-oidc/v3` | v3.21.0 | OIDC token verification | Apache-2.0 |
| `golang.org/x/oauth2` | v0.38.0 | OAuth 2.0 (Keycloak, SCM providers) | BSD-3-Clause |
| `golang.org/x/net` | v0.62.0 | Networking helpers | BSD-3-Clause |
| `github.com/google/uuid` | v1.6.0 | UUIDv7 | BSD-3-Clause |
| `github.com/anthropics/anthropic-sdk-go/v2` | v2.9.0 | Anthropic provider | MIT |
| `github.com/aws/aws-sdk-go-v2` and `service/s3` | v1.47.5, v1.114.6 | S3-compatible object storage | Apache-2.0 |
| `go.opentelemetry.io/otel` (API, SDK, metric, trace, OTLP/HTTP exporters) | v1.47.0 | Traces and metrics | Apache-2.0 |
| `go.opentelemetry.io/contrib` (`otelhttp`, `runtime`) | v0.72.0 | HTTP and runtime instrumentation | Apache-2.0 |
| `go.yaml.in/yaml/v3` | v3.0.6 | Scanner plugin definitions, custom rules, OpenAPI documents | MIT and Apache-2.0 |
| `github.com/google/licensecheck` | v0.3.1 | File-level licence detection in the worker (`licensecheck` scanner); embeds the SPDX licence texts it matches | BSD-3-Clause |

Notable indirect modules: `github.com/go-jose/go-jose/v4` v4.1.6 (OIDC). The OpenAI, xAI and self-hosted providers, the MCP server and the SCM clients use the standard library only.

## Frontend (build time only)

From `frontend/package.json`:

| Package | Version | Purpose | License |
|---|---|---|---|
| `react`, `react-dom` | 19.3.1 | UI | MIT |
| `@tanstack/react-router` | 1.170.46 | Routing | MIT |
| `@tanstack/react-query` | 5.107.1 | Data fetching | MIT |
| `@radix-ui/react-dialog`, `-dropdown-menu`, `-popover`, `-slot` | 1.3.1, 2.2.1, 1.3.1, 1.5.0 | Accessible primitives | MIT |
| `cmdk` | 1.1.1 | Command palette | MIT |
| `recharts` | 3.10.1 | Charts | MIT |
| `lucide-react` | 1.73.0 | Icons | ISC |
| `marked` | 18.1.2 | Markdown rendering in the Help Center | MIT |
| `class-variance-authority`, `clsx`, `tailwind-merge` | 0.7.1, 2.1.1, 3.7.0 | Class name utilities | Apache-2.0, MIT, MIT |
| `@fontsource-variable/inter` | 5.3.0 | Inter font, self-hosted | OFL-1.1 (font), MIT (package) |
| `typescript` | 6.0.3 | Language | Apache-2.0 |
| `vite`, `@vitejs/plugin-react` | 8.3.8, 6.3.0 | Build and dev server | MIT |
| `tailwindcss`, `@tailwindcss/vite` | 4.3.5 | Styling | MIT |
| `vitest`, `jsdom`, `@testing-library/*` | 5.1.0, 31.0.1, … | Unit tests | MIT |

End-to-end tests use `@playwright/test` 1.65.1 (Apache-2.0), in `e2e/`.

## VS Code extension (ide/vscode)

The extension has no runtime dependencies (it uses the `fetch` built into VS Code's Node.js); the packages below are build and test tools from `ide/vscode/package.json` and are not shipped in the `.vsix`.

| Package | Version | Purpose | License |
|---|---|---|---|
| `typescript` | 6.0.3 | Language | Apache-2.0 |
| `@types/vscode` | 1.90.0 | VS Code API types (matches `engines.vscode`) | MIT |
| `@types/node` | 22.20.5 | Node.js types | MIT |
| `vitest` | 5.1.0 | Unit tests | MIT |
| `@vscode/vsce` | 4.1.0 | Packaging the `.vsix` | MIT (its optional `@vscode/vsce-sign` helper, used only for Marketplace signing, is under Microsoft's own licence) |

## Test and security tooling (not shipped)

| Tool | Version | License | Used by |
|---|---|---|---|
| gosec | v2.30.0 | Apache-2.0 | `make security`, CI |
| govulncheck | v1.9.0 | BSD-3-Clause | `make security`, CI |
| OWASP ZAP | `zaproxy/zap-stable` (digest-pinned) | Apache-2.0 | ZAP baseline and authenticated DAST |
| k6 | `grafana/k6:2.3.0` (digest-pinned) | AGPL-3.0 (standalone tool, not distributed) | `make load-test` |

## Optional paid or credentialed services

PATHOS works without any of them.

| Item | Needed for | Without it |
|---|---|---|
| Anthropic, OpenAI or xAI API key | Automated AI reviews with a cloud model | Use a self-hosted model, or review interactively over MCP with your own Claude Code |
| SCM credentials (GitHub App or token, GitLab, Bitbucket, Azure DevOps) | Importing and scanning repositories from a provider | Upload repositories as archives |
| SMTP relay | E-mail notifications | In-app notifications only |
| Jira or ServiceNow account | Tickets for findings | — |
