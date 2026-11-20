#!/usr/bin/env bash
# Our own build for the reverse-engineering end-to-end test
# (e2e/tests/reverse-engineering.spec.ts): compiles the test-data service
# e2e/tests/fixtures-data/rea-svc with the pinned Go image (no network) and
# attests its SLSA provenance with the cosign of the core worker image and a
# throw-away key. Output in e2e/.rea-build (git-ignored): server,
# provenance.sigstore.json, cosign.pub. scripts/e2e.sh runs it first
# (the Playwright container has no Docker).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/e2e/tests/fixtures-data/rea-svc"
OUT="$ROOT/e2e/.rea-build"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d}"
COSIGN_IMAGE="${E2E_COSIGN_IMAGE:-${PATHOS_IMAGE_PREFIX:-}pathos-worker-core:${PATHOS_VERSION:-dev}}"
CACHE="${PATHOS_GO_CACHE:-$HOME/.cache/pathos-go}"
mkdir -p "$CACHE"
rm -rf "$OUT"
mkdir -p "$OUT"
docker run --rm --network none -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/cache/build -e GOTOOLCHAIN=local -e CGO_ENABLED=0 \
  -v "$CACHE":/cache -v "$SRC":/src:ro -v "$OUT":/out -w /src "$GO_IMAGE" \
  go build -trimpath -buildvcs=false -o /out/server ./cmd/server
cat > "$OUT/predicate.json" <<'JSON'
{"buildDefinition":{"buildType":"https://pathos.example.test/e2e/go-build@v1","externalParameters":{"source":"e2e/tests/fixtures-data/rea-svc"},
 "resolvedDependencies":[{"uri":"git+https://git.example.test/e2e/rea-svc","digest":{"gitCommit":"0000000000000000000000000000000000000000"}}]},
 "runDetails":{"builder":{"id":"https://pathos.example.test/e2e/builder"}}}
JSON
cosign() {
  docker run --rm --network none -u "$(id -u):$(id -g)" -e COSIGN_PASSWORD= -e HOME=/w -v "$OUT":/w -w /w \
    --entrypoint /usr/local/bin/cosign "$COSIGN_IMAGE" "$@"
}
cosign generate-key-pair >/dev/null
cosign attest-blob --yes --key cosign.key --type slsaprovenance1 --predicate predicate.json \
  --bundle provenance.sigstore.json --use-signing-config=false --tlog-upload=false server >/dev/null 2>&1
rm -f "$OUT/cosign.key"
echo "own build: $(sha256sum "$OUT/server" | cut -c1-16)… with provenance in $OUT"
