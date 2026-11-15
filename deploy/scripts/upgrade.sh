#!/usr/bin/env bash
# Upgrade PATHOS in place with a safety backup.
#
#   deploy/scripts/upgrade.sh [--no-backup] [--pull]
#
# Run it after checking out (or downloading) the new release:
#   1. validates the compose configuration
#   2. takes a backup (deploy/scripts/backup.sh) unless --no-backup
#   3. builds the images, or pulls signed release images with --pull
#      (set PATHOS_IMAGE_PREFIX=ghcr.io/quditmind/ and PATHOS_VERSION in .env)
#   4. recreates the services; the one-shot "migrate" service applies new
#      database migrations before api/jobs/scheduler start
#   5. waits for every health check and prints the version change
#
# If anything fails, the previous state is restorable with:
#   deploy/scripts/restore.sh <backup printed below> --yes
# after checking out the previous release.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

backup=1 pull=0
while [ $# -gt 0 ]; do
  case "$1" in
    --no-backup) backup=0; shift ;;
    --pull) pull=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

log "validating configuration"
compose config -q

before_schema="$(schema_version)"
before_version="$(app_version || echo unknown)"
log "current: PATHOS ${before_version:-unknown}, schema $before_schema"

last=""
if [ "$backup" = 1 ]; then
  if compose ps --status running --services | grep -qx postgres; then
    "$(dirname "$0")/backup.sh"
    last="$(ls -1d backups/pathos-* | sort | tail -1)"
  else
    log "postgres is not running; skipping the pre-upgrade backup"
  fi
fi

if [ "$pull" = 1 ]; then
  [ -n "$(envval PATHOS_IMAGE_PREFIX)" ] || die "--pull needs PATHOS_IMAGE_PREFIX (e.g. ghcr.io/quditmind/) and PATHOS_VERSION in .env"
  log "pulling images $(envval PATHOS_IMAGE_PREFIX)*:$(envval PATHOS_VERSION)"
  # Not --ignore-buildable: every PATHOS image also has a build section.
  compose pull
else
  log "building images"
  compose build -q
fi

log "recreating services (migrations run first)"
if ! compose up -d --wait --remove-orphans; then
  echo
  compose ps
  echo "Upgrade did not become healthy. Inspect: docker compose logs migrate api" >&2
  [ -n "$last" ] && echo "Roll back: check out the previous release, then deploy/scripts/restore.sh $last --yes" >&2
  exit 1
fi

after_schema="$(schema_version)"
after_version="$(app_version || echo unknown)"
log "upgraded: PATHOS ${before_version:-?} -> ${after_version:-?}, schema $before_schema -> $after_schema"
[ -n "$last" ] && log "pre-upgrade backup: $last"
