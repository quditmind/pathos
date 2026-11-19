#!/usr/bin/env bash
# Builds backend/cmd/pathos-loadgen and runs it next to a running stack, on
# its internal data and worker-api networks (dev only; see
# docs/PERFORMANCE.md). Never run it against an installation with real data.
#
#   scripts/load/loadgen.sh seed -repos 10000 -findings 1000000
#   scripts/load/loadgen.sh ingest -workers 8 -jobs 200
#   scripts/load/loadgen.sh recompute -limits 500,2000,5000
#   scripts/load/loadgen.sh sizes | cleanup
#
# COMPOSE_PROJECT_NAME selects the stack (default pathos). Connects as the
# PostgreSQL superuser from .env; output files land in reports/load/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PROJECT="${COMPOSE_PROJECT_NAME:-pathos}"
GO_IMAGE="${GO_IMAGE:-golang:1.27.4}"
env_get() { grep -E "^$1=" .env | tail -1 | cut -d= -f2-; }
mkdir -p reports/load
GOFLAGS= "$ROOT/scripts/go.sh" build -trimpath -o /repo/reports/load/pathos-loadgen ./cmd/pathos-loadgen
name="${PROJECT}-loadgen-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker create --name "$name" --network "${PROJECT}_data" -u "$(id -u):$(id -g)" \
  -v "$ROOT/reports/load:/out" -w /out \
  -e PATHOS_LOADGEN_DB="postgres://postgres:$(env_get POSTGRES_SUPERUSER_PASSWORD)@postgres:5432/pathos?sslmode=disable" \
  -e PATHOS_WORKER_BOOTSTRAP_TOKEN="$(env_get PATHOS_WORKER_BOOTSTRAP_TOKEN)" \
  "$GO_IMAGE" /out/pathos-loadgen "$@" >/dev/null
docker network connect "${PROJECT}_worker-api" "$name"
docker start -a "$name"
