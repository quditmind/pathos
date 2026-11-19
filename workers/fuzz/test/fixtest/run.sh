#!/usr/bin/env bash
# Checks pathos-fixtest (AI fix verification test runs) in a built
# worker-fuzz image, without network access:
#   workers/fuzz/test/fixtest/run.sh [image]   (default pathos-worker-fuzz:dev)
# Expected exit codes: 0 tests pass, 1 tests fail, 2 runner does not apply.
set -euo pipefail
IMAGE="${1:-pathos-worker-fuzz:dev}"
HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0
for case in "go go-ok 0" "go go-broken 1" "go none 2" "python py-ok 0" "python py-broken 1" "python none 2"; do
  set -- $case
  rc=0
  docker run --rm --network none --entrypoint /opt/pathos/fuzz/bin/pathos-fixtest -v "$HERE":/t:ro \
    --tmpfs /work:exec,uid=10001 "$IMAGE" "$1" "/t/$2" /work/log /work >/dev/null 2>&1 || rc=$?
  if [ "$rc" = "$3" ]; then echo "ok   $1 $2 (exit $rc)"; else echo "FAIL $1 $2: exit $rc, want $3"; fail=1; fi
done
exit $fail
