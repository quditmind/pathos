#!/usr/bin/env bash
# Online backup of a PATHOS installation.
#
#   deploy/scripts/backup.sh [--dir backups] [--keep 14] [--with-env]
#
# Writes <dir>/pathos-<UTC timestamp>/ containing:
#   pathos.dump, keycloak.dump   pg_dump custom format (consistent snapshots)
#   caddy_data.tgz               TLS certificates and the local CA
#   objectstore.tgz              scan artifacts, when the objectstore profile runs
#   sources.tgz                  encrypted uploads and source snapshots (sources volume)
#   manifest.json                versions and SHA-256 checksums
#   env                          only with --with-env (contains every secret)
#
# The master key (PATHOS_MASTER_KEY in .env) is NOT included by default.
# Without it, encrypted credentials in the backup cannot be read: store it
# separately (password manager / vault). Restore with deploy/scripts/restore.sh.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

dir=backups keep=0 with_env=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="$2"; shift 2 ;;
    --keep) keep="$2"; shift 2 ;;
    --with-env) with_env=1; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

compose ps --status running --services | grep -qx postgres || die "postgres is not running (docker compose up -d postgres)"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="$dir/pathos-$ts"
umask 077
mkdir -p "$out"
log "backing up to $out"

for db in pathos keycloak; do
  log "dumping database $db"
  compose exec -T postgres pg_dump -U postgres -d "$db" -Fc --no-comments > "$out/$db.dump.partial"
  mv "$out/$db.dump.partial" "$out/$db.dump"
done

if compose ps --status running --services | grep -qx proxy; then
  log "archiving Caddy data (certificates)"
  compose exec -T proxy tar -C /data -czf - . > "$out/caddy_data.tgz"
else
  log "proxy not running; skipping Caddy data"
fi

if compose ps --status running --services | grep -qx objectstore; then
  # Artifacts are written once and never modified, so an online copy is
  # consistent for every artifact the database dump references.
  log "archiving object storage (scan artifacts)"
  compose exec -T objectstore tar -C /data -czf - . > "$out/objectstore.tgz"
fi

# Uploaded repositories: encrypted snapshots in the "sources" volume (when
# the S3 store is used they are in objectstore.tgz instead). Objects are
# written once via an atomic rename, so an online copy is consistent for
# every snapshot the database dump references. The pathos image has no
# shell, so tar runs in the proxy image with the api container's volumes.
api_ctr="$(compose ps -q api 2>/dev/null || true)"
proxy_img="$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q proxy 2>/dev/null)" 2>/dev/null || true)"
if [ -n "$api_ctr" ] && [ -n "$proxy_img" ]; then
  log "archiving source snapshots (encrypted)"
  docker run --rm --volumes-from "$api_ctr" --entrypoint tar "$proxy_img" -C /var/lib/pathos/sources -czf - . > "$out/sources.tgz"
else
  log "api or proxy not running; skipping source snapshots"
fi

if [ "$with_env" = 1 ]; then
  cp .env "$out/env"
  log "copied .env (contains all secrets, including the master key)"
fi

schema="$(schema_version)"
version="$(app_version || true)"
{
  printf '{\n  "created_at": "%s",\n  "pathos_version": "%s",\n  "schema_version": %s,\n  "files": {\n' "$ts" "${version:-unknown}" "$schema"
  first=1
  for f in "$out"/*; do
    name="$(basename "$f")"
    [ "$name" = manifest.json ] && continue
    [ $first = 1 ] || printf ',\n'
    first=0
    printf '    "%s": {"sha256": "%s", "bytes": %s}' "$name" "$(sha256 "$f")" "$(wc -c < "$f" | tr -d ' ')"
  done
  printf '\n  }\n}\n'
} > "$out/manifest.json"

if [ "$keep" -gt 0 ]; then
  # Keep the newest N backups in this directory.
  mapfile -t old < <(ls -1d "$dir"/pathos-* 2>/dev/null | sort -r | tail -n +"$((keep + 1))")
  for o in "${old[@]}"; do
    rm -rf -- "$o"
    log "pruned $o"
  done
fi

log "done: $out (schema version $schema, $(du -sh "$out" | cut -f1))"
[ "$with_env" = 1 ] || echo "Reminder: back up PATHOS_MASTER_KEY from .env separately; it is not in this backup."
