#!/usr/bin/env bash
# ADR-005 graph render benchmark (synthetic test data, no stack needed).
# Builds frontend/bench with Vite, then measures the first render of the
# shared graph component in Chromium (Playwright) for 500 to 5,000 nodes.
#
#   scripts/graph-bench.sh               BENCH_RUNS=10 (default)
#
# Results: e2e/perf/results/graph-render.json. Fails when the 2,000-node p95
# is not under 2 s.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
"$ROOT/scripts/npm.sh" exec -- vite build --config bench/vite.bench.config.ts --logLevel warn
IMAGE="mcr.microsoft.com/playwright:v1.65.1-noble"
CACHE="${PATHOS_NPM_CACHE:-$HOME/.cache/pathos-npm}"
exec docker run --rm --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/cache -e BENCH_RUNS="${BENCH_RUNS:-10}" \
  -v "$CACHE":/cache -v "$ROOT/e2e":/e2e -v "$ROOT/frontend/bench/dist":/bench:ro -w /e2e "$IMAGE" \
  sh -c 'npm ci --no-audit --no-fund --silent && npx playwright test --config=perf.config.ts "$@"' -- "$@"
