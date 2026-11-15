#!/usr/bin/env bash
# Restore a backup made by backup.sh into this installation.
#
#   deploy/scripts/restore.sh <backup-dir> --yes [--skip-certs]
#
# DESTRUCTIVE: replaces the pathos and keycloak databases. The current .env
# must hold the same PATHOS_MASTER_KEY (and database role passwords) as the
# installation that was backed up; restore the backup's "env" file first if
# you took one with --with-env.
#
# Steps: verify checksums -> stop application services -> recreate and
# restore both databases -> restore certificates -> run migrations (a backup
# from an older release is upgraded) -> start everything and wait for health.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

src="" yes=0 certs=1
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) yes=1; shift ;;
    --skip-certs) certs=0; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) src="$1"; shift ;;
  esac
done
[ -n "$src" ] && [ -f "$src/manifest.json" ] || die "usage: restore.sh <backup-dir> --yes  (no manifest.json in '$src')"
[ "$yes" = 1 ] || die "this replaces all PATHOS and Keycloak data; re-run with --yes to confirm"

log "verifying checksums"
for f in pathos.dump keycloak.dump; do
  [ -f "$src/$f" ] || die "$src/$f missing"
done
python3 - "$src" <<'PY' || die "checksum verification failed"
import hashlib, json, os, sys
d = sys.argv[1]
m = json.load(open(os.path.join(d, "manifest.json")))
for name, meta in m["files"].items():
    h = hashlib.sha256(open(os.path.join(d, name), "rb").read()).hexdigest()
    if h != meta["sha256"]:
        sys.exit(f"{name}: checksum mismatch")
print(f"  ok: {len(m['files'])} files, schema {m['schema_version']}, PATHOS {m['pathos_version']}")
PY

backup_schema="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["schema_version"])' "$src/manifest.json")"
if [ -d backend/migrations ]; then
  code_schema="$(ls backend/migrations/*.sql | sed -E 's|.*/0*([0-9]+)_.*|\1|' | sort -n | tail -1)"
  if [ "$backup_schema" -gt "$code_schema" ]; then
    die "backup schema $backup_schema is newer than this release ($code_schema); install the newer release first"
  fi
fi

log "stopping application services"
compose stop proxy api jobs scheduler worker-core keycloak >/dev/null 2>&1 || true
compose up -d --wait postgres >/dev/null

for db in pathos keycloak; do
  owner="pathos_owner"
  [ "$db" = keycloak ] && owner="keycloak"
  log "recreating database $db"
  psql_admin postgres "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$db' AND pid <> pg_backend_pid()" >/dev/null
  psql_admin postgres "DROP DATABASE IF EXISTS $db" >/dev/null
  psql_admin postgres "CREATE DATABASE $db OWNER $owner" >/dev/null
  log "restoring $db"
  compose exec -T postgres pg_restore -U postgres -d "$db" --exit-on-error --no-comments < "$src/$db.dump"
done
# The app role needs CONNECT on the recreated database.
psql_admin postgres "GRANT CONNECT ON DATABASE pathos TO pathos_app" >/dev/null
psql_admin pathos "REVOKE CREATE ON SCHEMA public FROM PUBLIC" >/dev/null

if [ "$certs" = 1 ] && [ -f "$src/caddy_data.tgz" ]; then
  log "restoring Caddy data"
  compose run --rm --no-deps -T --entrypoint sh proxy -c 'rm -rf /data/* && tar -C /data -xzf -' < "$src/caddy_data.tgz"
fi

if [ -f "$src/objectstore.tgz" ]; then
  log "restoring object storage"
  compose stop objectstore >/dev/null 2>&1 || true
  compose run --rm --no-deps -T --entrypoint sh objectstore -c 'rm -rf /data/* && tar -C /data -xzf -' < "$src/objectstore.tgz"
fi

log "running migrations and starting services"
compose up -d --wait
log "restored from $src (schema now $(schema_version))"
