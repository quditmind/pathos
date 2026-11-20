#!/usr/bin/env bash
# End-to-end test of the worker-fuzz sandbox in the built image.
#
#   workers/fuzz/test/sandbox-e2e.sh [image]   (default pathos-worker-fuzz:dev)
#
# Sets up what docker-compose.yml does for worker-fuzz, on throw-away
# networks and a throw-away volume:
#   - "egress" (port 3128) and "api" (port 8081): HTTP listeners on two
#     internal networks, standing in for the egress proxy and the API;
#   - the sandbox runner: the image with `sandbox-runner`, network none,
#     IPC none, UID 10002:10001, read-only, no capabilities, pids limit 256;
#   - the worker: the image as 10001:10001 on both networks, with a marker
#     value as its token, running the Go test TestSandboxE2E
#     (backend/internal/worker/sandbox_e2e_test.go, build tag sandbox_e2e).
# The test runs the real go-fuzz and atheris manifests through the runner on
# the fuzz sample plus a malicious probe (workers/fuzz/test/sandbox-probe)
# and checks that every escape attempt failed and the planted bugs were
# still reported. Everything is removed afterwards.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${1:-pathos-worker-fuzz:dev}"
P="${SANDBOX_E2E_PREFIX:-pathos-sbx-e2e}-$$"
# The test binary is built by scripts/go.sh, which sees only the repository.
WORK="$ROOT/.sandbox-e2e-$$"
mkdir -p "$WORK"
cleanup() {
  docker rm -f "$P-worker" "$P-runner" "$P-services" >/dev/null 2>&1 || true
  docker network rm "$P-scan" "$P-api" >/dev/null 2>&1 || true
  docker volume rm "$P-sandbox" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== test binary"
GOFLAGS="-tags=sandbox_e2e" GO_DOCKER_ARGS="-e CGO_ENABLED=0" \
  "$ROOT/scripts/go.sh" test -c -o "/repo/.sandbox-e2e-$$/worker.test" ./internal/worker
chmod 0755 "$WORK" "$WORK/worker.test"

echo "== networks, services, volume"
docker network create --internal "$P-scan" >/dev/null
docker network create --internal "$P-api" >/dev/null
docker create --name "$P-services" --network "$P-scan" --network-alias egress --read-only --cap-drop ALL \
  --entrypoint /opt/pathos/fuzz/bin/python "$IMAGE" -c '
import http.server, threading
for port in (3128, 8081):
    s = http.server.ThreadingHTTPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=s.serve_forever).start()
' >/dev/null
docker network connect --alias api "$P-api" "$P-services"
docker start "$P-services" >/dev/null
# Wait until both listeners accept connections: the test's control step
# fails if it dials them before the server threads are up.
for i in $(seq 1 60); do
  docker exec "$P-services" /opt/pathos/fuzz/bin/python -c 'import socket
for p in (3128, 8081): socket.create_connection(("127.0.0.1", p), 1).close()' 2>/dev/null && break
  [ "$i" -eq 60 ] && { echo "FAIL: services did not start listening"; docker logs "$P-services"; exit 1; }
  sleep 0.5
done
docker volume create --driver local --opt type=tmpfs --opt device=tmpfs \
  --opt o=size=2g,uid=10001,gid=10001,mode=0750 "$P-sandbox" >/dev/null

echo "== sandbox runner"
docker run -d --name "$P-runner" --network none --ipc none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user 10002:10001 --pids-limit 256 --memory 4g --memory-swap 4g --cpus 2 \
  -e PATHOS_SANDBOX_DIR=/sandbox -v "$P-sandbox:/sandbox" "$IMAGE" sandbox-runner >/dev/null

echo "== worker (runs TestSandboxE2E)"
docker create --name "$P-worker" --network "$P-scan" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user 10001:10001 --pids-limit 1024 --memory 4g \
  --tmpfs /work:size=2g,mode=0700,uid=10001,gid=10001 --tmpfs /tmp:size=1g,mode=1777 \
  -e PATHOS_WORKER_BOOTSTRAP_TOKEN="sandbox-e2e-marker-$$-not-a-real-token" -e PATHOS_API_URL=http://api:8081 \
  -e HTTPS_PROXY=http://egress:3128 -e HTTP_PROXY=http://egress:3128 -e PATHOS_SANDBOX_DIR=/sandbox \
  -e E2E_TEST_DIR=/e2e/test -e TMPDIR=/work -e HOME=/tmp \
  -v "$P-sandbox:/sandbox" -v "$WORK/worker.test:/e2e/worker.test:ro" -v "$ROOT/workers/fuzz/test:/e2e/test:ro" \
  --entrypoint /e2e/worker.test "$IMAGE" -test.run "${SANDBOX_E2E_RUN:-^TestSandboxE2E\$}" -test.v -test.timeout 30m >/dev/null
docker network connect "$P-api" "$P-worker"
rc=0
docker start -a "$P-worker" || rc=$?
echo "== processes left in the runner (only the runner itself may remain)"
docker top "$P-runner" -o pid,user,args
n="$(docker top "$P-runner" -o pid | tail -n +2 | wc -l)"
if [ "$n" -ne 1 ]; then echo "FAIL: $n processes in the runner after the runs"; rc=1; fi
echo "== runner log"
docker logs "$P-runner" 2>&1 | tail -n 20
exit "$rc"
