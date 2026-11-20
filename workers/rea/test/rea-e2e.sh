#!/usr/bin/env bash
# End-to-end test of the worker-rea image (reverse engineering, static tier).
#
#   workers/rea/test/rea-e2e.sh [image]   (default pathos-worker-rea:dev)
#
# Builds the fixtures (workers/rea/test/fixtures: a tiny C program and a Go
# service with a planted net/http/pprof import, compiled in throw-away
# containers, i.e. our own builds; a firmware blob made from test data),
# then sets up what docker-compose.yml does for worker-rea, on throw-away
# networks and a throw-away volume:
#   - "egress" (port 3128) and "api" (port 8081): HTTP listeners on two
#     internal networks, standing in for the egress proxy and the API;
#   - the sandbox runner: the image with `sandbox-runner`, network none,
#     IPC none, UID 10002:10001, read-only, no capabilities, pids limit 256;
#   - the worker: the image as 10001:10001 on both networks, running the Go
#     test TestREAE2E (backend/internal/worker/rea_e2e_test.go, build tag
#     rea_e2e), which analyses the three artifacts with the real pathos-rea
#     through the runner, checks the facts, and runs `pathos-rea selftest`
#     through the runner to check its isolation.
# Everything is removed afterwards. Docker resources: REA_E2E_PREFIX (m10-rea-e2e).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${1:-pathos-worker-rea:dev}"
P="${REA_E2E_PREFIX:-m10-rea-e2e}-$$"
WORK="$ROOT/.rea-e2e-$$"
mkdir -p "$WORK/bin"
cleanup() {
  docker rm -f "$P-worker" "$P-runner" "$P-services" "$P-build" >/dev/null 2>&1 || true
  docker network rm "$P-scan" "$P-api" >/dev/null 2>&1 || true
  docker volume rm "$P-sandbox" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
GO_IMAGE="golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d"
PY_IMAGE="python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"

echo "== fixtures (our own builds, no network)"
docker run --rm --name "$P-build" --network none -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOFLAGS=-mod=mod \
  -v "$ROOT/workers/rea/test/fixtures:/f:ro" -v "$WORK/bin:/out" "$GO_IMAGE" sh -c '
    set -e
    gcc -O1 -o /out/hello /f/hello-c/hello.c
    cd /f/pprof-go && go build -trimpath -o /out/payments ./cmd/server
    /f/make-firmware.sh /out/hello /out/firmware.bin'
ls -l "$WORK/bin"

echo "== test binary"
GOFLAGS="-tags=rea_e2e" GO_DOCKER_ARGS="-e CGO_ENABLED=0" \
  "$ROOT/scripts/go.sh" test -c -o "/repo/.rea-e2e-$$/worker.test" ./internal/worker
chmod 0755 "$WORK" "$WORK/bin" "$WORK/worker.test"
chmod 0644 "$WORK"/bin/*

echo "== networks, services, volume"
docker network create --internal "$P-scan" >/dev/null
docker network create --internal "$P-api" >/dev/null
docker create --name "$P-services" --network "$P-scan" --network-alias egress --read-only --cap-drop ALL \
  --entrypoint python "$PY_IMAGE" -c '
import http.server, threading
for port in (3128, 8081):
    s = http.server.ThreadingHTTPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=s.serve_forever).start()
' >/dev/null
docker network connect --alias api "$P-api" "$P-services"
docker start "$P-services" >/dev/null
docker volume create --driver local --opt type=tmpfs --opt device=tmpfs \
  --opt o=size=2g,uid=10001,gid=10001,mode=0750 "$P-sandbox" >/dev/null

echo "== sandbox runner"
docker run -d --name "$P-runner" --network none --ipc none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user 10002:10001 --pids-limit 256 --memory 3g --memory-swap 3g --cpus 2 \
  -e PATHOS_SANDBOX_DIR=/sandbox -v "$P-sandbox:/sandbox" "$IMAGE" sandbox-runner >/dev/null

echo "== worker (runs TestREAE2E)"
docker create --name "$P-worker" --network "$P-scan" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user 10001:10001 --pids-limit 1024 --memory 1g \
  --tmpfs /work:size=1g,mode=0700,uid=10001,gid=10001 --tmpfs /tmp:size=512m,mode=1777 \
  -e PATHOS_WORKER_BOOTSTRAP_TOKEN="rea-e2e-marker-$$-not-a-real-token" -e PATHOS_API_URL=http://api:8081 \
  -e PATHOS_SANDBOX_DIR=/sandbox -e E2E_TEST_DIR=/e2e/bin -e TMPDIR=/work -e HOME=/tmp \
  -v "$P-sandbox:/sandbox" -v "$WORK/worker.test:/e2e/worker.test:ro" -v "$WORK/bin:/e2e/bin:ro" \
  --entrypoint /e2e/worker.test "$IMAGE" -test.run '^TestREAE2E$' -test.v -test.timeout 40m >/dev/null
docker network connect "$P-api" "$P-worker"
rc=0
docker start -a "$P-worker" || rc=$?
echo "== processes left in the runner (only the runner itself may remain)"
docker top "$P-runner" -o pid,user,args
n="$(docker top "$P-runner" -o pid | tail -n +2 | wc -l)"
if [ "$n" -ne 1 ]; then echo "FAIL: $n processes in the runner after the runs"; rc=1; fi
echo "== runner log"
docker logs "$P-runner" 2>&1 | tail -n 10
exit "$rc"
