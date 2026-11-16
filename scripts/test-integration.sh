#!/usr/bin/env bash
# Runs Go integration tests against a throwaway PostgreSQL container.
# Requires only Docker.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NET="pathos-it-$$"
PG="pathos-it-pg-$$"
PG_IMAGE="postgres:18.7-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015"

cleanup() { docker rm -f "$PG" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" -e POSTGRES_PASSWORD=it --tmpfs /var/lib/postgresql "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

GO_DOCKER_ARGS="${GO_DOCKER_ARGS:-} --network $NET -e PATHOS_TEST_DATABASE_URL=postgres://postgres:it@$PG:5432/postgres?sslmode=disable" \
  "$ROOT/scripts/go.sh" test -tags integration -count=1 "${@:-./test/integration/...}"
