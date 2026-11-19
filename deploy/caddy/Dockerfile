# syntax=docker/dockerfile:1
# Edge proxy image: Caddy serving the built frontend and proxying /api and /auth.
# Build context: repository root.
FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY frontend/ ./
# Help Center content (docs/user-guide, docs/api-reference) is bundled at build time.
COPY docs/ /docs/
# Shell: "What's new" (CHANGELOG.md) and third-party notices (NOTICE) in About.
COPY CHANGELOG.md NOTICE /
RUN npm run build

# Caddy rebuilt from the v2.11.9 release with golang.org/x/net v0.62.0
# (fixes a HIGH CVE in the upstream binary; Trivy self-scan, Phase 8).
FROM caddy:2.11.9-builder-alpine@sha256:646fee578e680989ca5c7fd1ce6f1de574d19fd71ef2221810cc0510a9f40c86 AS caddy
RUN xcaddy build v2.11.9 --replace golang.org/x/net=golang.org/x/net@v0.62.0 --output /out/caddy && /out/caddy version

FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
COPY --from=caddy /out/caddy /usr/bin/caddy
COPY deploy/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=web /web/dist /srv
