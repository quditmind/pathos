#!/usr/bin/env bash
# Run npm in a container (no local Node install required).
# Usage: scripts/npm.sh ci | scripts/npm.sh test | scripts/npm.sh run build
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODE_IMAGE="${NODE_IMAGE:-node:26.13.1-alpine}"
CACHE="${PATHOS_NPM_CACHE:-$HOME/.cache/pathos-npm}"
mkdir -p "$CACHE"
TTY=(); [ -t 1 ] && TTY=(-t)
exec docker run --rm "${TTY[@]}" -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/cache \
  -v "$CACHE":/cache -v "$ROOT/frontend":/web -w /web "$NODE_IMAGE" npm "$@"
