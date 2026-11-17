#!/usr/bin/env bash
# Offline (air-gapped) vulnerability data for PATHOS.
#
#   scripts/offline-bundle.sh create bundle.tar   on a connected machine
#   scripts/offline-bundle.sh import bundle.tar   on the air-gapped PATHOS host
#   scripts/offline-bundle.sh status              database dates on this host
#
# A bundle holds the Trivy and Grype databases, the OSV databases for the
# common ecosystems (for OSV-Scanner), and the EPSS, CISA KEV and OSV feed
# files, with a SHA-256 manifest. "create" downloads them with the PATHOS
# worker image's own tools; "import" verifies every checksum and copies the
# databases into the scanner cache volume. Feed files are imported with the
# API when PATHOS_API_TOKEN (a REST token with api:write of a settings
# administrator) is set, otherwise in the UI (Risk & intelligence).
#
# Run the worker with PATHOS_OFFLINE=true (and the API and jobs services too)
# so that nothing tries to download. Refresh bundles at least weekly: the
# databases are only as current as the bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && . ./.env && set +a
IMAGE="${PATHOS_IMAGE_PREFIX:-}pathos-worker-core:${PATHOS_VERSION:-dev}"
# Override with PATHOS_OSV_ECOSYSTEMS="npm PyPI" to bundle fewer ecosystems.
read -r -a OSV_ECOSYSTEMS <<<"${PATHOS_OSV_ECOSYSTEMS:-npm PyPI Go Maven crates.io NuGet RubyGems Packagist Pub Hex}"
EPSS_URL="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BASE="https://osv-vulnerabilities.storage.googleapis.com"

die() { echo "offline-bundle: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 is required"; }

cache_volume() {
  local project="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT" | tr '[:upper:]' '[:lower:]')}"
  echo "${PATHOS_SCANNER_CACHE_VOLUME:-${project}_scanner_cache}"
}

create() {
  local out="${1:-}"
  [ -n "$out" ] || die "usage: $0 create <bundle.tar>"
  need docker; need curl; need sha256sum; need tar
  local work
  work="$(mktemp -d)"
  # Files the container creates belong to its user until handed back.
  trap 'docker run --rm -u 0:0 -v "'"$work"':/b" --entrypoint rm "'"$IMAGE"'" -rf /b/trivy /b/grype >/dev/null 2>&1 || true; rm -rf "'"$work"'"' EXIT
  chmod 755 "$work"
  mkdir -p "$work/trivy" "$work/grype" "$work/osv/osv-scalibr" "$work/feeds"
  chmod 777 "$work/trivy" "$work/grype"

  echo "== Trivy databases"
  docker run --rm -u 10001:10001 -v "$work/trivy:/out" --entrypoint trivy "$IMAGE" image --download-db-only --cache-dir /out --quiet
  docker run --rm -u 10001:10001 -v "$work/trivy:/out" --entrypoint trivy "$IMAGE" image --download-java-db-only --cache-dir /out --quiet
  echo "== Grype database"
  docker run --rm -u 10001:10001 -e GRYPE_DB_CACHE_DIR=/out -v "$work/grype:/out" --entrypoint grype "$IMAGE" db update
  echo "== OSV databases (${OSV_ECOSYSTEMS[*]})"
  for eco in "${OSV_ECOSYSTEMS[@]}"; do
    mkdir -p "$work/osv/osv-scalibr/$eco"
    curl -fsSL --retry 3 -o "$work/osv/osv-scalibr/$eco/all.zip" "$OSV_BASE/$eco/all.zip"
  done
  echo "== Intelligence feeds"
  curl -fsSL --retry 3 -o "$work/feeds/epss.csv.gz" "$EPSS_URL"
  curl -fsSL --retry 3 -o "$work/feeds/kev.json" "$KEV_URL"

  # Hand the downloaded databases back to the current user.
  docker run --rm -u 0:0 -v "$work:/b" --entrypoint chown "$IMAGE" -R "$(id -u):$(id -g)" /b/trivy /b/grype
  chmod -R u+rwX,go+rX "$work/trivy" "$work/grype"
  local versions
  versions="$(docker run --rm --entrypoint sh "$IMAGE" -c 'trivy --version | head -1; grype version | grep "^Version"; osv-scanner --version | head -1' | tr '\n' ';')"
  # Manifest: one "sha256  path" line per file, plus metadata.
  (
    cd "$work"
    echo "# PATHOS offline bundle"
    echo "# created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# tools: $versions"
    find trivy grype osv feeds -type f | LC_ALL=C sort | xargs sha256sum
  ) > "$work/MANIFEST"
  tar -C "$work" -cf "$out" MANIFEST trivy grype osv feeds
  echo "bundle written: $out ($(du -h "$out" | cut -f1))"
}

import_bundle() {
  local in="${1:-}"
  [ -f "$in" ] || die "usage: $0 import <bundle.tar>"
  need docker; need tar
  local vol work
  vol="$(cache_volume)"
  docker volume inspect "$vol" >/dev/null 2>&1 || die "scanner cache volume $vol not found (set PATHOS_SCANNER_CACHE_VOLUME)"
  work="$(mktemp -d)"
  trap 'rm -rf "'"$work"'"' EXIT
  chmod 755 "$work"
  # Refuse links and absolute or parent paths before extracting anything.
  if tar -tvf "$in" | awk '{print $1, $NF}' | grep -Eq '^[lh]|[[:space:]](/|\.\./)|/\.\./'; then
    die "the bundle contains links or unsafe paths; refusing it"
  fi
  tar -C "$work" --no-same-owner --no-same-permissions -xf "$in"
  [ -f "$work/MANIFEST" ] || die "not a PATHOS offline bundle (no MANIFEST)"
  echo "== Verifying checksums"
  (cd "$work" && grep -v '^#' MANIFEST | sha256sum --quiet -c -) || die "checksum mismatch: the bundle is damaged or was modified"
  grep '^#' "$work/MANIFEST" | sed 's/^# /  /'
  echo "== Installing databases into volume $vol"
  docker run --rm -u 0:0 -v "$vol:/cache" -v "$work:/b:ro" --entrypoint sh "$IMAGE" -c '
    set -e
    for d in trivy grype osv; do
      rm -rf "/cache/$d.new" && cp -a "/b/$d" "/cache/$d.new"
      rm -rf "/cache/$d" && mv "/cache/$d.new" "/cache/$d"
    done
    chown -R 10001:10001 /cache/trivy /cache/grype /cache/osv'
  echo "== Intelligence feeds"
  if [ -n "${PATHOS_API_TOKEN:-}" ]; then
    local base="${PATHOS_PUBLIC_URL:-https://localhost}"
    local feed file
    for f in "epss epss.csv.gz" "kev kev.json"; do
      read -r feed file <<<"$f"
      curl -fsS ${PATHOS_CURL_INSECURE:+-k} -H "Authorization: Bearer $PATHOS_API_TOKEN" -F "file=@$work/feeds/$file" "$base/api/v1/intel/feeds/$feed/import" >/dev/null \
        && echo "  imported $feed" || echo "  $feed: import failed (import $file in the UI: Risk & intelligence)"
    done
    for eco in "${OSV_ECOSYSTEMS[@]}"; do
      [ -f "$work/osv/osv-scalibr/$eco/all.zip" ] || continue
      curl -fsS ${PATHOS_CURL_INSECURE:+-k} -H "Authorization: Bearer $PATHOS_API_TOKEN" -F "file=@$work/osv/osv-scalibr/$eco/all.zip" \
        "$base/api/v1/intel/feeds/osv/import" >/dev/null && echo "  imported OSV $eco" || echo "  OSV $eco: import failed (the UI limits files to 64 MiB)"
    done
  else
    local dest
    dest="${PATHOS_FEEDS_OUT:-$(cd "$(dirname "$in")" && pwd)/offline-feeds}"
    mkdir -p "$dest" && cp "$work/feeds/"* "$dest/"
    echo "  Feed files copied to $dest: import epss.csv.gz and kev.json in Risk & intelligence,"
    echo "  or set PATHOS_API_TOKEN (a REST token with api:write) to import them automatically."
  fi
  echo "done. Workers use the new databases from their next scan."
}

status() {
  need docker
  local vol
  vol="$(cache_volume)"
  docker run --rm -v "$vol:/cache:ro" --entrypoint sh "$IMAGE" -c '
    printf "Trivy DB:  "; if [ -f /cache/trivy/db/metadata.json ]; then sed -n "s/.*\"UpdatedAt\":\"\([^\"]*\)\".*/updated \1/p" /cache/trivy/db/metadata.json; else echo missing; fi
    printf "Grype DB:  "; if [ -d /cache/grype ] && [ -n "$(ls -A /cache/grype 2>/dev/null)" ]; then GRYPE_DB_CACHE_DIR=/cache/grype GRYPE_DB_AUTO_UPDATE=false grype db status 2>/dev/null | grep -Ei "built|status" | tr "\n" " "; echo; else echo missing; fi
    printf "OSV DBs:   "; if [ -d /cache/osv/osv-scalibr ]; then ls /cache/osv/osv-scalibr | tr "\n" " "; echo; else echo "missing (online lookups are used unless PATHOS_OFFLINE=true)"; fi'
}

case "${1:-}" in
  create) create "${2:-}" ;;
  import) import_bundle "${2:-}" ;;
  status) status ;;
  *) echo "usage: $0 create <bundle.tar> | import <bundle.tar> | status" >&2; exit 2 ;;
esac
