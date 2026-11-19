#!/usr/bin/env bash
# Run the Gradle wrapper of ide/jetbrains in a container (no local JDK or
# Gradle install required). The JDK image is pinned by digest; Gradle, the
# IntelliJ Platform and the plugin verifier IDEs are cached in
# PATHOS_GRADLE_CACHE (a host directory or a docker volume name).
# Usage: scripts/gradle-jetbrains.sh build | scripts/gradle-jetbrains.sh test
#        scripts/gradle-jetbrains.sh verifyPlugin
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JDK_IMAGE="${JDK_IMAGE:-eclipse-temurin:21.0.13_9-jdk-noble@sha256:a2e61ec9e2e4d5c7aa885412400319f9299abe4d8189f42ec3bec48708c576a6}"
CACHE="${PATHOS_GRADLE_CACHE:-$HOME/.cache/pathos-gradle}"
case "$CACHE" in /*) mkdir -p "$CACHE" ;; esac
TTY=(); [ -t 1 ] && TTY=(-t)
exec docker run --rm "${TTY[@]}" -u "$(id -u):$(id -g)" -e HOME=/tmp -e GRADLE_USER_HOME=/gradle \
  -v "$CACHE":/gradle -v "$ROOT/ide/jetbrains":/work -w /work "$JDK_IMAGE" ./gradlew --no-daemon "$@"
