#!/usr/bin/env bash
# Browser end-to-end tests (Playwright) against the running stack.
#
#   scripts/e2e.sh [playwright args...]      e.g. scripts/e2e.sh -g schedule
#
# Signs in as the bootstrap administrator from .env (handles the forced
# password change exactly like scripts/smoke-test.py). The HTML report goes
# to e2e/playwright-report/. E2E_CODEGRAPH_APP (application id or name) and
# E2E_CODEGRAPH_WAIT_S are passed to e2e/tests/codegraph.spec.ts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
IMAGE="mcr.microsoft.com/playwright:v1.65.1-noble"
envval() { grep -E "^$1=" .env | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'; }
email="$(envval PATHOS_BOOTSTRAP_ADMIN_EMAIL)"
pw="$(envval PATHOS_BOOTSTRAP_ADMIN_PASSWORD)"
new="${PATHOS_ADMIN_NEW_PASSWORD:-Smoke-$(echo "$pw" | rev)!9}"
url="$(envval PATHOS_PUBLIC_URL)"
# Our own build for the reverse-engineering test (Docker is not available
# inside the Playwright container).
if [ -z "${E2E_SKIP_REA_BUILD:-}" ]; then "$ROOT/scripts/e2e-rea-build.sh"; fi
exec docker run --rm --network host --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp -e CI="${CI:-}" \
  -e PATHOS_URL="${url:-https://localhost}" -e E2E_EMAIL="$email" -e E2E_PASSWORD="$pw" -e E2E_NEW_PASSWORD="$new" \
  -e E2E_CODEGRAPH_APP="${E2E_CODEGRAPH_APP:-}" -e E2E_CODEGRAPH_WAIT_S="${E2E_CODEGRAPH_WAIT_S:-}" \
  -v "$ROOT/e2e":/e2e -w /e2e "$IMAGE" sh -c 'npm ci --no-audit --no-fund --silent && npx playwright test "$@"' -- "$@"
