#!/usr/bin/env bash
# Browser end-to-end tests (Playwright) against the running stack.
#
#   scripts/e2e.sh [playwright args...]      e.g. scripts/e2e.sh -g schedule
#
# Signs in as the bootstrap administrator from .env (handles the forced
# password change exactly like scripts/smoke-test.py). The HTML report goes
# to e2e/playwright-report/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
IMAGE="mcr.microsoft.com/playwright:v1.65.1-noble"
envval() { grep -E "^$1=" .env | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'; }
email="$(envval PATHOS_BOOTSTRAP_ADMIN_EMAIL)"
pw="$(envval PATHOS_BOOTSTRAP_ADMIN_PASSWORD)"
new="${PATHOS_ADMIN_NEW_PASSWORD:-Smoke-$(echo "$pw" | rev)!9}"
url="$(envval PATHOS_PUBLIC_URL)"
exec docker run --rm --network host --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp -e CI="${CI:-}" \
  -e PATHOS_URL="${url:-https://localhost}" -e E2E_EMAIL="$email" -e E2E_PASSWORD="$pw" -e E2E_NEW_PASSWORD="$new" \
  -v "$ROOT/e2e":/e2e -w /e2e "$IMAGE" sh -c 'npm ci --no-audit --no-fund --silent && npx playwright test "$@"' -- "$@"
