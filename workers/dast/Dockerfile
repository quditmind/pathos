# syntax=docker/dockerfile:1
# PATHOS worker-dast: the core worker image plus the DAST family tools for
# authorized web application (url) and API (api) scan targets: OWASP ZAP
# (baseline, full active scan, API scan), Wapiti, Dalfox, ffuf, testssl.sh,
# SSLyze, Schemathesis and Arjun; sqlmap and Nikto only in an opt-in build
# (licence terms, see below). The tools are defined only by manifests
# (workers/dast/tools.d, installed read-only at /opt/pathos/tools.d) and run
# through /opt/pathos/dast/bin/dast-run, which confines them to the target
# host, the egress proxy and the target's rate limit.
# Build context: repository root.
#
# CORE_IMAGE is the worker-core image of the same PATHOS version (CI and
# docker compose pass it); see workers/sast/Dockerfile for why a family image
# extends the core image.
#
# Every download is pinned: Python packages by version and SHA-256
# (pip --require-hashes), ffuf through the Go checksum database, release
# archives and ZAP add-ons and libraries by SHA-256. Nothing from a scan
# target is ever executed.
#
# Opt-in tools (not in the published image):
#   WITH_SQLMAP=true  sqlmap (GPL-2.0-or-later). Its licence states that
#                     software which executes sqlmap and parses its results
#                     is a derived work; check that this fits how you
#                     distribute PATHOS before enabling it.
#   WITH_NIKTO=true   Nikto (GPL-3.0; its databases may be distributed only
#                     with the full Nikto package and used only with Nikto).

ARG CORE_IMAGE=pathos-worker-core:dev

# Wapiti, SSLyze, Schemathesis and Arjun (and sqlmap when enabled) in their
# own virtual environment (CPython 3.13, the interpreter of the core image).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
ARG WITH_SQLMAP=false
COPY workers/dast/requirements.txt workers/dast/requirements-build.txt workers/dast/requirements-sqlmap.txt /tmp/
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/dast; \
    pip=/opt/pathos/dast/bin/pip; \
    # Build backend for the packages published only as source archives.
    $pip install --no-compile --require-hashes --no-deps -r /tmp/requirements-build.txt; \
    $pip install --no-compile --require-hashes --no-deps --no-build-isolation -r /tmp/requirements.txt; \
    if [ "$WITH_SQLMAP" = true ]; then $pip install --no-compile --require-hashes --no-deps -r /tmp/requirements-sqlmap.txt; fi; \
    /opt/pathos/dast/bin/wapiti --version; \
    /opt/pathos/dast/bin/sslyze --help >/dev/null; \
    /opt/pathos/dast/bin/schemathesis --version; \
    /opt/pathos/dast/bin/python -c 'import arjun'; \
    # Wapiti installs Playwright for its optional headless browser mode; no
    # browser is installed, and its bundled Node.js driver is not needed.
    rm -rf /opt/pathos/dast/lib/python3.13/site-packages/playwright/driver/node \
           /opt/pathos/dast/lib/python3.13/site-packages/playwright/driver/package; \
    # pip, setuptools and wheel are only needed to build the image.
    /opt/pathos/dast/bin/python -m pip uninstall -y pip setuptools wheel; \
    find /opt/pathos/dast -name '__pycache__' -prune -exec rm -rf {} +

# OWASP ZAP 2.17.0 (core release archive) with a reviewed set of add-ons
# (build/zap-addons.txt). The add-ons bundle netty, Jackson and Guava
# versions with fixed HIGH/CRITICAL CVEs; build/patch-zap-addons.py replaces
# them with patched releases (build/zap-maven-jars.txt).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS zap
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
ARG ZAP=2.17.0 ZAP_SHA=0cb73b7f72d12c263fb61de304edb82a455d7aa4e1813c216c061765c306f5b7
COPY workers/dast/build/ /build/
RUN set -eux; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch /tmp/zap.zip "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP}/ZAP_${ZAP}_Core.zip" "$ZAP_SHA"; \
    unzip -q /tmp/zap.zip -d /tmp/zap; mv "/tmp/zap/ZAP_${ZAP}" /out; \
    # Only the reviewed add-ons (the archive's own are older or not needed).
    rm -f /out/plugin/*.zap; \
    grep -v '^#' /build/zap-addons.txt | while read -r file sha; do \
      id="${file%%-*}"; rest="${file#*-}"; version="${rest#*-}"; version="${version%.zap}"; \
      fetch "/out/plugin/$file" "https://github.com/zaproxy/zap-extensions/releases/download/${id}-v${version}/${file}" "$sha"; \
    done; \
    mkdir /tmp/jars; \
    grep -v '^#' /build/zap-maven-jars.txt | while read -r path sha; do \
      fetch "/tmp/jars/${path##*/}" "https://repo1.maven.org/maven2/${path}" "$sha"; \
    done; \
    python -I /build/patch-zap-addons.py /out/plugin /tmp/jars; \
    # The desktop launchers, Windows files and the bundled licence texts of
    # the removed add-ons are not needed; ZAP's own licence files stay.
    rm -f /out/zap.bat /out/zap.ico; \
    find /out -type d -exec chmod 0755 {} +; find /out -type f -exec chmod 0644 {} +; chmod 0755 /out/zap.sh

# ffuf, built from its Go module (integrity: Go checksum database) with the
# current toolchain and a patched dependency: ffuf v2.3.0 requires
# golang.org/x/net v0.7.0 (fixable HIGH CVEs), raised to v0.62.0. (ffuf
# v2.3.0 still prints "2.1.0-dev" as its version; the module version is
# checked instead.)
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gotools
ARG FFUF=2.3.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    dir="$(go mod download -json "github.com/ffuf/ffuf/v2@v${FFUF}" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"; \
    cp -r "$dir" /src; chmod -R u+w /src; cd /src; \
    go get golang.org/x/net@v0.62.0; \
    mkdir /out; CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/ffuf .; \
    go version -m /out/ffuf | grep -q "golang.org/x/net[[:space:]]*v0.62.0"; \
    /out/ffuf -V | grep -q "ffuf version"

# Dalfox (release binary, statically linked), testssl.sh and, when enabled,
# Nikto (GitHub source archives of the release tags). Hashes computed when
# the versions were pinned (Dalfox: also published with the release).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS downloads
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
ARG DALFOX=3.3.0 DALFOX_SHA=26e979d0f681d280fcf5121b7e59396c5c495c161ffddf411e4baec9fae8bcb4
ARG TESTSSL=3.2.5 TESTSSL_SHA=23bb53d50ae093b89631e9fff547c087f632bf35f7a3d7dc78dd4ffff56cd779
ARG NIKTO=2.6.1 NIKTO_SHA=d1ca1acb05d81a5a6f374c0afdd76b33afa0089278631a20673c0210a71d992f
ARG WITH_NIKTO=false
RUN set -eux; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    mkdir -p /out/bin /out/testssl /out/nikto; \
    fetch dalfox.tgz "https://github.com/hahwul/dalfox/releases/download/v${DALFOX}/dalfox-v${DALFOX}-linux-x86_64-musl.tar.gz" "$DALFOX_SHA"; \
    tar -xzf dalfox.tgz -C /out/bin --strip-components=1 "dalfox-v${DALFOX}-linux-x86_64-musl/dalfox"; \
    /out/bin/dalfox --version | grep -q "${DALFOX}"; \
    fetch testssl.tgz "https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL}.tar.gz" "$TESTSSL_SHA"; \
    # testssl.sh with its data files; the bundled legacy OpenSSL binaries are
    # not installed (the system OpenSSL is used).
    tar -xzf testssl.tgz -C /out/testssl --strip-components=1 \
      "testssl.sh-${TESTSSL}/testssl.sh" "testssl.sh-${TESTSSL}/etc" "testssl.sh-${TESTSSL}/LICENSE"; \
    if [ "$WITH_NIKTO" = true ]; then \
      fetch nikto.tgz "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO}.tar.gz" "$NIKTO_SHA"; \
      tar -xzf nikto.tgz -C /out/nikto --strip-components=1 "nikto-${NIKTO}/program" "nikto-${NIKTO}/COPYING" "nikto-${NIKTO}/COPYING.LibWhisker"; \
    fi; \
    find /out -type d -exec chmod 0755 {} +; find /out -type f -exec chmod 0644 {} +; \
    chmod 0755 /out/bin/dalfox /out/testssl/testssl.sh; \
    if [ -f /out/nikto/program/nikto.pl ]; then chmod 0755 /out/nikto/program/nikto.pl; fi

FROM ${CORE_IMAGE}
USER root
ARG WITH_SQLMAP=false WITH_NIKTO=false
# Java for ZAP; OpenSSL and the DNS and text utilities testssl.sh needs;
# Perl modules for Nikto (opt-in).
RUN set -eux; \
    mkdir -p /usr/share/man/man1; \
    apt-get update; \
    apt-get install -y --no-install-recommends openjdk-21-jre-headless openssl bsdextrautils bind9-host procps; \
    if [ "$WITH_NIKTO" = true ]; then \
      apt-get install -y --no-install-recommends perl libnet-ssleay-perl libio-socket-ssl-perl libjson-perl libxml-writer-perl; \
    fi; \
    apt-get upgrade -y; \
    rm -rf /var/lib/apt/lists/*
COPY --from=python-tools /opt/pathos/dast/ /opt/pathos/dast/
COPY --from=zap /out/ /opt/pathos/zap/
COPY --from=gotools /out/ffuf /opt/pathos/dast/bin/ffuf
ARG FFUF=2.3.0
COPY --from=downloads /out/bin/dalfox /opt/pathos/dast/bin/dalfox
COPY --from=downloads /out/testssl/ /opt/pathos/testssl/
COPY --from=downloads /out/nikto/ /opt/pathos/nikto/
COPY --chmod=0755 workers/dast/bin/dast-run /opt/pathos/dast/bin/dast-run
COPY workers/dast/share/ /opt/pathos/dast/share/
COPY workers/dast/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    # The manifests of tools that are not part of this build are removed
    # (a manifest whose command is missing is not loaded).
    if [ "$WITH_SQLMAP" != true ]; then rm -f /opt/pathos/tools.d/sqlmap.yaml; fi; \
    if [ "$WITH_NIKTO" != true ]; then rm -f /opt/pathos/tools.d/nikto.yaml; rm -rf /opt/pathos/nikto; fi; \
    echo "$FFUF" > /opt/pathos/dast/share/ffuf.version; \
    chmod -R go-w /opt/pathos/dast /opt/pathos/zap /opt/pathos/testssl /opt/pathos/tools.d; \
    for t in wapiti sslyze schemathesis arjun ffuf dalfox dast-run; do test -x "/opt/pathos/dast/bin/$t"; done; \
    java -version 2>&1 | grep -q 'version "21'; \
    for t in zap-baseline zap-full-scan zap-api-scan wapiti dalfox ffuf testssl sslyze schemathesis arjun; do \
      /opt/pathos/dast/bin/dast-run "$t" --version; \
    done; \
    if [ "$WITH_SQLMAP" = true ]; then /opt/pathos/dast/bin/dast-run sqlmap --version; fi; \
    if [ "$WITH_NIKTO" = true ]; then /opt/pathos/dast/bin/dast-run nikto --version; fi
USER 10001:10001
# The virtual environment comes last in PATH, so it never shadows the core
# image's commands.
ENV PATHOS_WORKER_FAMILY=dast PATHOS_TOOLS_DIR=/opt/pathos/tools.d \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/pathos/dast/bin
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
