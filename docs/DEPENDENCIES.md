# Initial Dependency List

Status: **Phase 1**. Exact versions are pinned when each component is introduced, and every pin is recorded here. Container images are pinned by digest in `docker-compose.yml` and the Dockerfiles. Go modules are pinned in `backend/go.mod`/`go.sum`; npm packages are pinned exactly in `frontend/package.json` and `package-lock.json`.

## Pinned in Phase 1

| Component | Pinned version |
|---|---|
| PostgreSQL | `postgres:18.7-alpine` |
| Valkey | `valkey/valkey:9.0.7-alpine` |
| Keycloak | `quay.io/keycloak/keycloak:26.8.2` |
| Caddy | `caddy:2.11.9-alpine` |
| Mailpit (dev) | `axllent/mailpit:v1.33.1` |
| Runtime base | `gcr.io/distroless/static-debian13:nonroot` (Debian 13 replaces the planned debian12) |
| Build images | `golang:1.27.4-alpine`, `node:26.13.1-alpine` |
| Go modules | anthropic-sdk-go v2.9.0 (Anthropic provider), pgx v5.13.0, goose v3.30.1, go-redis v9.23.0, go-oidc v3.21.0, x/oauth2 v0.38.0, google/uuid v1.6.0 |
| Scanners (worker-core) | Gitleaks 8.30.1, Opengrep 2.0.0, Trivy 0.76.2, Syft 1.57.1, Grype 0.121.3, OSV-Scanner 2.7.1 (SHA-256 pinned); Checkov 3.4.5 (pip) on `python:3.13-slim-trixie` |
| Egress proxy | `ubuntu/squid:7.2-26.04_edge` (digest-pinned) |
| Frontend | React 19.3.1, TypeScript 6.0.3 (7.x deferred: Go-based compiler, tooling still settling), Vite 8.3.8, Tailwind 4.3.5, TanStack Query 5.107.1 / Router 1.170.46, Radix Dialog/Dropdown, lucide-react 1.73.0, Vitest 5.1.0 |

## Added in Phase 8

| Component | Pinned version | License | Use |
|---|---|---|---|
| OpenTelemetry Go | otel v1.47.0, contrib v0.72.0 (otelhttp, runtime), OTLP/HTTP exporters | Apache-2.0 | Traces and metrics |
| AWS SDK for Go v2 | service/s3 v1.114.5 | Apache-2.0 | S3-compatible artifact storage |
| SeaweedFS (optional profile) | `chrislusf/seaweedfs:4.51` (digest-pinned) | Apache-2.0 | Bundled object store |
| Grafana otel-lgtm (dev profile) | `grafana/otel-lgtm:0.39.0` (digest-pinned) | Apache-2.0 | Local observability backend |
| Caddy build | `caddy:2.11.9-builder-alpine` + xcaddy, x/net v0.62.0 | Apache-2.0 | Patched edge proxy binary |
| Gitleaks build | module v8.30.1 built with Go 1.27.4; x/crypto v0.55.0, x/text v0.41.0, klauspost/compress v1.18.7 | MIT | Patched secret scanner binary |
| go-jose | v4.1.6 | Apache-2.0 | Security update (OIDC) |
| Self-test tools (not shipped) | gosec v2.30.0, govulncheck v1.9.0, `zaproxy/zap-stable` (digest-pinned), `grafana/k6:2.3.0` (digest-pinned) | Apache-2.0 / BSD-3 / Apache-2.0 / AGPL-3.0 (k6, a standalone tool that is not distributed) | `make security`, `make load-test` |

## Platform services (containers)

| Component | Version target | License | Notes |
|---|---|---|---|
| PostgreSQL | latest stable major with ≥1 minor release | PostgreSQL License | Official image |
| Valkey (default) / Redis | Valkey 8.x–9.x / Redis 8.x | BSD-3 / AGPLv3·RSALv2·SSPL | See ARCHITECTURE D2 |
| Keycloak | 26.x | Apache-2.0 | |
| SeaweedFS | 3.x/4.x | Apache-2.0 | Replaces MinIO (D1) |
| Caddy | 2.x | Apache-2.0 | Edge proxy, TLS, headers |
| Egress proxy (Smokescreen or Squid) | TBD Phase 4 | MIT / GPL-2.0 | Scanner egress allowlist |
| Mailpit | 1.x (dev only) | MIT | SMTP sink for development |
| Distroless static base | `gcr.io/distroless/static-debian12` (digest-pinned) | Apache-2.0 | API runtime image |

## Go backend (Go 1.27)

| Module | Purpose | License |
|---|---|---|
| stdlib `net/http` (1.22+ pattern routing), `log/slog` | HTTP routing, structured logs | BSD-3 |
| `github.com/jackc/pgx/v5` | PostgreSQL driver/pool | MIT |
| `github.com/sqlc-dev/sqlc` (build tool) | Type-safe SQL codegen | MIT |
| `github.com/pressly/goose/v3` | Migrations | MIT |
| `github.com/redis/go-redis/v9` | Redis/Valkey client | BSD-2 |
| `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2` | OIDC | Apache-2.0 / BSD-3 |
| `github.com/oapi-codegen/oapi-codegen/v2` (build tool) | OpenAPI → Go server types | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2` (s3) | Object storage | Apache-2.0 |
| `go.opentelemetry.io/otel` | Tracing/metrics | Apache-2.0 |
| `github.com/google/uuid` | UUIDv7 | BSD-3 |
| `github.com/modelcontextprotocol/go-sdk` | MCP client/server (Phase 5, verify) | MIT (verify) |
| `github.com/testcontainers/testcontainers-go` (tests) | Integration tests | MIT |

Queue: a small purpose-built Redis Streams job layer (priorities, leases, retries, dead-letter), or `hibiken/asynq` (MIT) if its maintenance status checks out in Phase 1. Either way the queue sits behind an internal `jobs.Queue` interface.

## Frontend (Node 26 LTS, build-time only)

| Package | Purpose | License |
|---|---|---|
| React 19 + react-dom | UI | MIT |
| TypeScript | Language | Apache-2.0 |
| Vite | Build/dev server | MIT |
| Tailwind CSS 4 | Styling | MIT |
| shadcn/ui (copied source) + Radix UI | Components | MIT |
| TanStack Query / Router / Table | Data fetching, routing, tables | MIT |
| Recharts | Charts (shadcn chart primitives) | MIT |
| lucide-react | Icons | ISC |
| react-hook-form + zod | Forms/validation | MIT |
| openapi-typescript + openapi-fetch | Typed API client | MIT |
| Inter (font, self-hosted) | Typography | OFL-1.1 |
| Vitest + Testing Library + Playwright | Tests | MIT / Apache-2.0 |

## Paid / credentialed items (optional — PATHOS works without them)

| Item | Needed for | Without it |
|---|---|---|
| Anthropic API key (or Bedrock/Vertex) | Automated Claude reviews | Findings stay `pending_ai_review`. Interactive MCP mode still works with your own Claude Code |
| OpenAI API key | Automated GPT reviews | Same |
| xAI API key | Automated Grok reviews | Same |
| NVD API key (free) | Fast Dependency-Check updates | Slower DB sync |
| GitHub App / PAT, Azure DevOps credentials | Repository import | Manual repo URL entry only |
| SMTP relay | Email | Notifications recorded in-app only |
