#!/usr/bin/env bash
# Scale test (k6, scripts/load/k6-scale.js) against a running stack filled
# by scripts/load/loadgen.sh seed. See docs/PERFORMANCE.md.
#
#   scripts/load/scale.sh sweep [ITER=20]
#   scripts/load/scale.sh mixed [RATE=20 DURATION=60s]
#   scripts/load/scale.sh users [USERS=50 RAMP=30s DURATION=60s]
#
# Extra settings are passed as NAME=value arguments (ONLY=findings_list,...
# restricts the endpoints). The bootstrap administrator signs in (same
# credentials as the smoke test). Turn rate limiting off on the API for the
# test (PATHOS_RATE_LIMIT_SCALE=0). Results: reports/load/<time>-<scenario>/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
K6_IMAGE="grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8"
scenario="${1:-sweep}"
shift || true
env_args=(-e SCENARIO="$scenario")
for kv in "$@"; do env_args+=(-e "$kv"); done
url="${PATHOS_URL:-$(grep -E '^PATHOS_PUBLIC_URL=' .env | cut -d= -f2- || true)}"
url="${url:-https://localhost}"
cookie="$(python3 - <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("smoke", "scripts/smoke-test.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.Client()
ok, why = m.login(c, m.ADMIN, [m.TEMP_PW, m.NEW_PW])
if not ok:
    sys.exit("login failed: " + why)
for ck in c.jar:
    if ck.name.endswith("pathos_session"):
        print(f"{ck.name}={ck.value}")
PY
)"
out="reports/load/$(date -u +%Y%m%dT%H%M%SZ)-$scenario"
mkdir -p "$out" && chmod 777 "$out"
set +e
docker run --rm --network host -v "$ROOT/scripts/load:/scripts:ro" -v "$ROOT/$out:/out" \
  -e PATHOS_URL="$url" -e PATHOS_COOKIE="$cookie" "${env_args[@]}" \
  "$K6_IMAGE" run --quiet --summary-export /out/summary.json /scripts/k6-scale.js 2>&1 | tee "$out/k6.txt"
status=${PIPESTATUS[0]}
set -e
echo "report: $out (k6 exit $status)"
exit "$status"
