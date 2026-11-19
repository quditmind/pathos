#!/usr/bin/env bash
# PATHOS benchmark harness (docs/BENCHMARKS.md).
#
#   benchmarks/run.sh [--build] [--smoke] [suite ...]
#
# Suites: owasp-java owasp-python secrets sca reach (default: all of them).
#   --build   build the worker images first (core, sast, sca) from this checkout
#   --smoke   the small subset CI runs: the generated secrets suite with
#             Gitleaks only, and the reachability benchmark; nothing is
#             downloaded. Fails if Gitleaks' recall falls below the floor.
#
# Scanners run in the PATHOS worker images (`pathos-worker run-local`): the
# same tool table, manifests, arguments and parsers as a scan job. Reports
# are parsed and merged with PATHOS's own code (backend/cmd/pathos-bench).
#
# Environment:
#   PATHOS_BENCH_DIR           downloads, scan copies and results (default ~/.cache/pathos-benchmarks)
#   PATHOS_BENCH_IMAGE_PREFIX  prefix of the worker image names (default none: pathos-worker-core:dev ...)
#   PATHOS_BENCH_IMAGE_TAG     image tag (default dev)
#   PATHOS_BENCH_OUT           results directory (default $PATHOS_BENCH_DIR/results/<UTC time>)
#
# Network: suite downloads (curl, verified against benchmarks/suites.lock)
# and the SCA suite's vulnerability databases and registry lookups need the
# network; every other scanner runs with --network none.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${PATHOS_BENCH_DIR:-$HOME/.cache/pathos-benchmarks}"
PREFIX="${PATHOS_BENCH_IMAGE_PREFIX:-}"
TAG="${PATHOS_BENCH_IMAGE_TAG:-dev}"
OUT="${PATHOS_BENCH_OUT:-$BENCH_DIR/results/$(date -u +%Y%m%dT%H%M%SZ)}"
LOCK="$ROOT/benchmarks/suites.lock"
CACHE_VOLUME="${PREFIX}pathos-bench-cache"
SMOKE_RECALL_FLOOR="0.5"

BUILD=0
SMOKE=0
SUITES=()
for a in "$@"; do
  case "$a" in
    --build) BUILD=1 ;;
    --smoke) SMOKE=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    owasp-java|owasp-python|secrets|sca|reach) SUITES+=("$a") ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done
if [ "$SMOKE" = 1 ]; then
  SUITES=(secrets reach)
elif [ ${#SUITES[@]} -eq 0 ]; then
  SUITES=(owasp-java owasp-python secrets sca reach)
fi

image() { echo "${PREFIX}pathos-worker-$1:${TAG}"; }
log() { printf '[bench %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

mkdir -p "$BENCH_DIR/dl" "$BENCH_DIR/bin" "$OUT"
OUT="$(cd "$OUT" && pwd)"
log "results: $OUT"

if [ "$BUILD" = 1 ]; then
  log "building $(image core)"
  docker build -q -f "$ROOT/workers/core/Dockerfile" -t "$(image core)" "$ROOT" >/dev/null
  for fam in sast sca; do
    log "building $(image "$fam")"
    docker build -q -f "$ROOT/workers/$fam/Dockerfile" --build-arg CORE_IMAGE="$(image core)" -t "$(image "$fam")" "$ROOT" >/dev/null
  done
fi

# The scorer, built from this checkout (static binary, run on the host).
log "building pathos-bench"
GO_DOCKER_ARGS="-v $BENCH_DIR/bin:/binout -e CGO_ENABLED=0" "$ROOT/scripts/go.sh" build -o /binout/pathos-bench ./cmd/pathos-bench
BENCH="$BENCH_DIR/bin/pathos-bench"

# fetch NAME: download the pinned archive (once), verify its SHA-256 and
# extract it to $BENCH_DIR/x/NAME. Prints the extracted top directory.
fetch() {
  local name="$1" url sha file
  read -r url sha < <(awk -v n="$name" '$1 == n { print $2, $3 }' "$LOCK")
  [ -n "${url:-}" ] || { echo "no pinned source for $name in $LOCK" >&2; exit 1; }
  file="$BENCH_DIR/dl/$name.tar.gz"
  if [ ! -f "$file" ]; then
    log "downloading $name from $url"
    curl -fsSL --proto '=https' -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  if ! echo "$sha  $file" | sha256sum -c --status; then
    echo "checksum mismatch for $file (expected $sha); delete it to download again" >&2
    exit 1
  fi
  rm -rf "$BENCH_DIR/x/$name"
  mkdir -p "$BENCH_DIR/x/$name"
  tar -xzf "$file" -C "$BENCH_DIR/x/$name" --no-same-owner --no-same-permissions
  find "$BENCH_DIR/x/$name" -mindepth 1 -maxdepth 1 -type d | head -n1
}

# scan WORK FAMILY NETWORK SCANNERS: run scanners in a worker image on
# WORK/src; reports go to WORK/out-FAMILY.
scan() {
  local work="$1" fam="$2" net="$3" keys="$4" out="$1/out-$2" cache=(--tmpfs /cache)
  rm -rf "$out"
  mkdir -p "$out"
  chmod 0777 "$out" # the worker image runs as UID 10001
  chmod -R a+rX "$work/src"
  if [ "$net" != none ]; then
    docker volume create "$CACHE_VOLUME" >/dev/null
    cache=(-v "$CACHE_VOLUME:/cache")
  fi
  log "$(basename "$work"): $keys in $(image "$fam") (network: $net)"
  docker run --rm --network "$net" --read-only --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:exec --tmpfs /work:exec "${cache[@]}" \
    -v "$work/src:/work/bench/src:ro" -v "$out:/out" \
    "$(image "$fam")" run-local -src /work/bench/src -out /out -scanners "$keys" 2>"$out/worker.log" | tee "$out/summary.tsv" >&2
}

score() { # SUITE WORK LABELS [extra score flags]
  local suite="$1" work="$2" labels="$3"
  shift 3
  local dirs=()
  for d in "$work"/out-*; do dirs+=("$d"); done
  log "scoring $suite"
  "$BENCH" score -labels "$labels" -out "$OUT/$suite.json" "$@" "${dirs[@]}" | tee "$OUT/$suite.txt" >&2
}

declare -A ELAPSED

suite_owasp() { # SUITE LOCKNAME CSV-GLOB LICENCE SRC-PATHS FAMILY-SCANNERS...
  local suite="$1" name="$2" csvglob="$3" licence="$4" paths="$5"
  shift 5
  local top work
  top="$(fetch "$name")"
  work="$BENCH_DIR/work/$suite"
  rm -rf "$work"
  mkdir -p "$work/src"
  for p in $paths; do cp -r "$top/$p" "$work/src/"; done
  local csv
  # shellcheck disable=SC2086 # the glob must expand
  csv="$(ls "$top"/$csvglob)"
  "$BENCH" owasp-labels -csv "$csv" -suite "$suite" -license "$licence" \
    -source "$(awk -v n="$name" '$1 == n { print $2 }' "$LOCK") ($(basename "$csv"))" -out "$work/labels.json"
  for spec in "$@"; do scan "$work" "${spec%%:*}" none "${spec#*:}"; done
  score "$suite" "$work" "$work/labels.json"
}

run_suite() {
  local s="$1" start
  start=$(date +%s)
  case "$s" in
    owasp-java)
      suite_owasp owasp-java owasp-benchmark-java 'expectedresults-*.csv' GPL-2.0 "pom.xml src" \
        "core:opengrep" "sast:semgrep-ce,bearer" ;;
    owasp-python)
      suite_owasp owasp-python owasp-benchmark-python 'expectedresults-*.csv' GPL-3.0 "app.py helpers testcode templates requirements.txt" \
        "core:opengrep" "sast:semgrep-ce,bearer,bandit,ruff" ;;
    secrets)
      local work="$BENCH_DIR/work/secrets"
      rm -rf "$work"
      mkdir -p "$work"
      "$BENCH" gen-secrets -dir "$work"
      scan "$work" core none gitleaks
      if [ "$SMOKE" = 1 ]; then
        score secrets "$work" "$work/labels.json" -require-recall "$SMOKE_RECALL_FLOOR"
      else
        scan "$work" sast none trufflehog,kingfisher,detect-secrets,talisman
        score secrets "$work" "$work/labels.json"
        # Talisman flags most files of the corpus; the merged result without it:
        score secrets-without-talisman "$work" "$work/labels.json" -exclude talisman -name "secrets-selfmade without Talisman"
      fi ;;
    sca)
      local work="$BENCH_DIR/work/sca"
      rm -rf "$work"
      mkdir -p "$work"
      cp -r "$ROOT/benchmarks/suites/sca/src" "$work/src"
      scan "$work" core bridge trivy-fs,grype,osv-scanner
      scan "$work" sca bridge pip-audit,npm-audit,govulncheck
      # Which vulnerability databases the answers came from. OSV-Scanner
      # queries api.osv.dev; pip-audit, npm audit and govulncheck query
      # their registries during the scan.
      docker run --rm --network none -v "$CACHE_VOLUME:/cache:ro" --entrypoint sh "$(image core)" -c \
        'echo "trivy: $(cat /cache/trivy/db/metadata.json)"; echo "grype: $(cat /cache/grype/6/import.json | tr -d "\n")"' \
        > "$OUT/sca-databases.txt" 2>&1 || true
      score sca "$work" "$ROOT/benchmarks/suites/sca/labels.json" ;;
    reach)
      log "reachability benchmark (go test)"
      "$ROOT/scripts/go.sh" test -count=1 -run 'TestReachabilityBenchmark' -v ./internal/reach/ | tee "$OUT/reach.txt" >&2 ;;
  esac
  ELAPSED[$s]=$(($(date +%s) - start))
}

TOTAL_START=$(date +%s)
for s in "${SUITES[@]}"; do run_suite "$s"; done

# Environment of the run (docs/BENCHMARKS.md reports these with the numbers).
{
  printf '{\n'
  printf '  "date_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "commit": "%s",\n' "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  printf '  "nproc": %s,\n' "$(nproc)"
  printf '  "memory_kib": %s,\n' "$(awk '/MemTotal/ { print $2 }' /proc/meminfo)"
  printf '  "cpu": "%s",\n' "$(awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo | sed 's/"/\\"/g')"
  printf '  "kernel": "%s",\n' "$(uname -r)"
  printf '  "docker": "%s",\n' "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
  printf '  "images": {'
  sep=""
  for fam in core sast sca; do
    id="$(docker image inspect --format '{{.Id}}' "$(image "$fam")" 2>/dev/null || echo missing)"
    printf '%s"%s": "%s"' "$sep" "$(image "$fam")" "$id"
    sep=", "
  done
  printf '},\n'
  printf '  "smoke": %s,\n' "$([ "$SMOKE" = 1 ] && echo true || echo false)"
  printf '  "suite_seconds": {'
  sep=""
  for s in "${SUITES[@]}"; do printf '%s"%s": %s' "$sep" "$s" "${ELAPSED[$s]}"; sep=", "; done
  printf '},\n'
  printf '  "total_seconds": %s\n' "$(($(date +%s) - TOTAL_START))"
  printf '}\n'
} > "$OUT/env.json"

results=()
for s in "${SUITES[@]}"; do
  for f in "$OUT/$s.json" "$OUT/$s-without-talisman.json"; do [ -f "$f" ] && results+=("$f"); done
done
if [ ${#results[@]} -gt 0 ]; then
  "$BENCH" report -out "$OUT/results.md" "${results[@]}"
fi
log "done in $(($(date +%s) - TOTAL_START))s: $OUT"
