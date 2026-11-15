#!/usr/bin/env bash
# k6 load test against a running PATHOS stack.
#
#   scripts/load/run.sh [--seed] [--cleanup] [--rate 20] [--duration 60s]
#
# --seed     adds 300 repositories / 100,000 findings first (seed.sql)
# --cleanup  removes the seeded data afterwards (cleanup.sql)
# The bootstrap administrator logs in (same credentials as the smoke test);
# results land in reports/load/<timestamp>/. The default rate stays below
# the per-user read limit (25 req/s); for higher rates set
# PATHOS_RATE_LIMIT_SCALE on the api service.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
K6_IMAGE="grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8"
seed=0 cleanup=0 rate=20 duration=60s
while [ $# -gt 0 ]; do
  case "$1" in
    --seed) seed=1; shift ;;
    --cleanup) cleanup=1; shift ;;
    --rate) rate="$2"; shift 2 ;;
    --duration) duration="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
if [ "$seed" = 1 ]; then
  echo "seeding synthetic data"
  docker compose exec -T postgres psql -q -U postgres -d pathos -f - < scripts/load/seed.sql
fi
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
out="reports/load/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out" && chmod 777 "$out"
set +e
docker run --rm --network host -v "$ROOT/scripts/load:/scripts:ro" -v "$ROOT/$out:/out" \
  -e PATHOS_URL="${PATHOS_URL:-https://localhost}" -e PATHOS_COOKIE="$cookie" -e RATE="$rate" -e DURATION="$duration" \
  "$K6_IMAGE" run --summary-export /out/summary.json /scripts/k6.js | tee "$out/k6.txt"
status=${PIPESTATUS[0]}
set -e
if [ "$cleanup" = 1 ]; then
  echo "removing synthetic data"
  docker compose exec -T postgres psql -q -U postgres -d pathos -f - < scripts/load/cleanup.sql
fi
echo "report: $out (k6 exit $status)"
exit "$status"
