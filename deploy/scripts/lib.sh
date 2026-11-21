# Shared helpers for the operations scripts. Sourced, not executed.
# shellcheck shell=bash

cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

[ -f .env ] || { echo "No .env found; run deploy/scripts/install.sh first." >&2; exit 1; }

# envval NAME: value of NAME from .env (without sourcing the file).
envval() { grep -E "^$1=" .env | tail -1 | cut -d= -f2-; }

# compose: docker compose with the production override when enabled.
compose() {
  if [ "${PATHOS_COMPOSE_PROD:-$(envval PATHOS_COMPOSE_PROD)}" = "1" ]; then
    docker compose -f docker-compose.yml -f docker-compose.prod.yml "$@"
  else
    docker compose "$@"
  fi
}

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# psql_admin DB SQL: run SQL as the postgres superuser (local socket).
psql_admin() { compose exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d "$1" -Atc "$2"; }

schema_version() { psql_admin pathos "SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied" 2>/dev/null || echo 0; }

# The version of the running api container; only when api is not running, the
# version of the configured image. (Before a --pull upgrade the configured image
# is already the new release, so asking it would report the target version.)
app_version() {
  if compose ps --status running --services 2>/dev/null | grep -qx api; then
    compose exec -T api /usr/local/bin/pathos version 2>/dev/null | tail -1
  else
    compose run --rm --no-deps -T --entrypoint /usr/local/bin/pathos api version 2>/dev/null | tail -1
  fi
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
