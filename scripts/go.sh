#!/usr/bin/env bash
# Run the Go toolchain in a container (no local Go install required).
# Usage: scripts/go.sh test ./...    |   scripts/go.sh mod tidy
# Set GO_DOCKER_ARGS for extra docker flags (e.g. mounting the Docker socket
# for testcontainers-based integration tests).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO_IMAGE="${GO_IMAGE:-golang:1.27.4}"
CACHE="${PATHOS_GO_CACHE:-$HOME/.cache/pathos-go}"
mkdir -p "$CACHE"
TTY=(); [ -t 1 ] && TTY=(-t)
# shellcheck disable=SC2086
exec docker run --rm "${TTY[@]}" -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod -e GOFLAGS="${GOFLAGS:-}" \
  -v "$CACHE":/cache -v "$ROOT":/repo -w /repo/backend ${GO_DOCKER_ARGS:-} \
  "$GO_IMAGE" go "$@"
