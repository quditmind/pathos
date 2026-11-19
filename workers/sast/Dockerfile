# syntax=docker/dockerfile:1
# PATHOS worker-sast: the core worker image plus the SAST family tools.
# SAST: Bandit, njsscan, gosec, Flawfinder, cppcheck, PHPStan, Psalm (taint
# analysis), Ruff (S rules), ESLint with eslint-plugin-security, Semgrep CE
# (PATHOS rules only) and Bearer. Secrets: TruffleHog, detect-secrets,
# Kingfisher and Talisman. Code-quality security: ShellCheck, Pylint and
# golangci-lint. The tools are defined only by manifests
# (workers/sast/tools.d, installed read-only at /opt/pathos/tools.d).
# Build context: repository root.
#
# A scan job runs on a single worker, and every repository scan includes
# the core tools (Gitleaks is mandatory), so a family image extends the
# core image instead of replacing it: a family worker can run every job
# the core worker runs, plus the jobs that use its family's tools.
# CORE_IMAGE is the worker-core image of the same PATHOS version (CI and
# docker compose pass it); its agent stage builds the pathos-worker binary.
#
# Every download is pinned: Python packages by version and SHA-256
# (pip --require-hashes), npm packages by package-lock.json integrity
# hashes (npm ci), Go modules by the Go checksum database, and every other
# archive by version and SHA-256 (computed when the version was pinned).
# Repository code is never built or executed by this image: gosec and
# golangci-lint type-check Go code with the Go toolchain but run no
# build, test or generate step.

ARG CORE_IMAGE=pathos-worker-core:dev

# Python tools in their own virtual environment (CPython 3.13, the
# interpreter of the core image): Bandit, njsscan, Flawfinder, Ruff,
# detect-secrets, Pylint and Semgrep CE (njsscan's dependency).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/sast/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/sast; \
    /opt/pathos/sast/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/requirements.txt; \
    for t in bandit njsscan flawfinder ruff detect-secrets pylint semgrep; do /opt/pathos/sast/bin/$t --version; done; \
    # pip is only needed to build the image.
    /opt/pathos/sast/bin/python -m pip uninstall -y pip; \
    find /opt/pathos/sast -name '__pycache__' -prune -exec rm -rf {} +

# Go tools, built from source with the current toolchain (the upstream
# binaries are built with older Go releases). gosec, golangci-lint and
# TruffleHog: Go modules (integrity: Go checksum database). Talisman's
# module path is not its repository path, so it is built from the GitHub
# source archive of the release tag (SHA-256 pinned; its dependencies are
# checked against its go.sum and the checksum database).
# Patched dependencies: gosec v2.30.0 requires golang.org/x/net v0.61.0 and
# Talisman v1.37.0 golang.org/x/text v0.23.0 (fixable HIGH CVEs).
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gotools
RUN apk add --no-cache curl
ARG GOSEC=2.30.0 GOLANGCI_LINT=2.15.0 TRUFFLEHOG=3.99.9 \
    TALISMAN=1.37.0 TALISMAN_SHA=40f9ab7d43fadf75abe7a4d71fac5ff083f71b63afada282146827725460d2d1
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    export CGO_ENABLED=0; \
    moddir() { go mod download -json "$1" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p'; }; \
    src() { rm -rf /src; cp -r "$1" /src; chmod -R u+w /src; cd /src; }; \
    src "$(moddir "github.com/securego/gosec/v2@v${GOSEC}")"; \
    go get golang.org/x/net@v0.62.0; \
    go build -trimpath -ldflags "-s -w -X main.Version=${GOSEC}" -o /out/gosec ./cmd/gosec; \
    src "$(moddir "github.com/golangci/golangci-lint/v2@v${GOLANGCI_LINT}")"; \
    go build -trimpath -ldflags "-s -w -X main.version=${GOLANGCI_LINT} -X main.commit=v${GOLANGCI_LINT} -X main.date=module" -o /out/golangci-lint ./cmd/golangci-lint; \
    src "$(moddir "github.com/trufflesecurity/trufflehog/v3@v${TRUFFLEHOG}")"; \
    go build -trimpath -ldflags "-s -w -X github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion=${TRUFFLEHOG}" -o /out/trufflehog .; \
    cd /; curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o talisman.tgz "https://github.com/thoughtworks/talisman/archive/refs/tags/v${TALISMAN}.tar.gz"; \
    echo "${TALISMAN_SHA}  talisman.tgz" | sha256sum -c -; \
    rm -rf /src; mkdir /src; tar -xzf talisman.tgz -C /src --strip-components=1; cd /src; \
    go get golang.org/x/text@v0.43.0; \
    go build -trimpath -ldflags "-s -w -X main.Version=v${TALISMAN}" -o /out/talisman ./cmd; \
    for t in gosec golangci-lint trufflehog talisman; do go version "/out/$t" | grep -q "go1.27.4"; done; \
    /out/gosec -version 2>&1 | grep -q "Version: ${GOSEC}"; /out/golangci-lint --version 2>&1 | grep -q "${GOLANGCI_LINT}"; \
    /out/trufflehog --version 2>&1 | grep -q "${TRUFFLEHOG}"; /out/talisman --version 2>&1 | grep -q "${TALISMAN}"; \
    go version -m /out/gosec | grep -q "golang.org/x/net[[:space:]]*v0.62.0"; \
    go version -m /out/talisman | grep -q "golang.org/x/text[[:space:]]*v0.43.0"; \
    # The Go toolchain gosec and golangci-lint load packages with (go list
    # and the standard library sources). Left out: the toolchain's own
    # sources, tests and documentation, and tools they do not call.
    mkdir -p /out/go; cp -a /usr/local/go/. /out/go/; cd /out/go; \
    rm -rf src/cmd test api doc misc; find src -type d -name testdata -prune -exec rm -rf {} +; \
    rm -f pkg/tool/linux_amd64/fix pkg/tool/linux_amd64/cover pkg/tool/linux_amd64/preprofile pkg/tool/linux_amd64/doc \
      pkg/tool/linux_amd64/pprof pkg/tool/linux_amd64/trace pkg/tool/linux_amd64/test2json pkg/tool/linux_amd64/covdata; \
    /out/go/bin/go version | grep -q "go1.27.4"

# Bearer CLI (Elastic-2.0, catalogued as optional) needs cgo (tree-sitter),
# so it is built on Debian like the runtime image, from the GitHub source
# archive of the release tag (SHA-256 pinned; dependencies checked against
# its go.sum and the checksum database). Its rules (Bearer/bearer-rules,
# Elastic-2.0) are release archives pinned by SHA-256 and installed as an
# external rule directory: Bearer would otherwise download them at scan
# time. Patched dependency: golang.org/x/net v0.61.0 (fixable HIGH CVE).
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS bearer
ARG BEARER=2.1.3 BEARER_SHA=c6cf4b0c46253fb63320cab158761b7bb343df757e73020f89b960eab81e63fd BEARER_RULES=0.48.4
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    fetch() { curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch bearer.tgz "https://github.com/Bearer/bearer/archive/refs/tags/v${BEARER}.tar.gz" "$BEARER_SHA"; \
    mkdir /src; tar -xzf bearer.tgz -C /src --strip-components=1; cd /src; \
    go get golang.org/x/net@v0.62.0; \
    CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X github.com/bearer/bearer/cmd/bearer/build.Version=${BEARER}" -o /out/bearer ./cmd/bearer; \
    /out/bearer version 2>&1 | grep -q "${BEARER}"; \
    go version -m /out/bearer | grep -q "golang.org/x/net[[:space:]]*v0.62.0"; \
    cd /; r="https://github.com/Bearer/bearer-rules/releases/download/v${BEARER_RULES}"; \
    fetch go.tgz "$r/go.tar.gz" 0d406d5295d3bcc408c856ba80a2fcfb29e28e3f316afb68d0d3bc2aab103643; \
    fetch java.tgz "$r/java.tar.gz" 0b0c2ccfd10fa2b8d9df792274dc162fa9b058614bf2203449817c0ab5ee4bc3; \
    fetch javascript.tgz "$r/javascript.tar.gz" 08c12673a8bdcf0cb0332aac93c1657baba1d2d27503e954f564268f76482688; \
    fetch php.tgz "$r/php.tar.gz" 4197647742328a32c0b4cd00feaa33ff125cf41ce8842369523346a722411ab0; \
    fetch python.tgz "$r/python.tar.gz" 771bf56a12e6abbf36549174f32b93d83244e879dc36247e2281f9e755cc6208; \
    fetch ruby.tgz "$r/ruby.tar.gz" 86dd93dd2fe0ab95cc5bafd0ab4722aa60733c8722774b2029e4b1f81b42dfa0; \
    mkdir -p /out/bearer-rules; for l in go java javascript php python ruby; do tar -xzf "$l.tgz" -C /out/bearer-rules; done; \
    find /out/bearer-rules -type d -exec chmod 0755 {} +; find /out/bearer-rules -type f -exec chmod 0644 {} +

# cppcheck, built from the GitHub source archive of the release tag
# (SHA-256 pinned): the Debian package depends on a second Python
# interpreter.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS cppcheck
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl g++ cmake make && rm -rf /var/lib/apt/lists/*
ARG CPPCHECK=2.19.0 CPPCHECK_SHA=c6cff9d3bbcb3da941bf7f525ae974b6c7af3d610c4c5519fcd1be3f21f5ae09
RUN set -eux; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o cppcheck.tgz "https://github.com/danmar/cppcheck/archive/refs/tags/${CPPCHECK}.tar.gz"; \
    echo "${CPPCHECK_SHA}  cppcheck.tgz" | sha256sum -c -; \
    mkdir /src; tar -xzf cppcheck.tgz -C /src --strip-components=1; \
    cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DUSE_MATCHCOMPILER=ON -DHAVE_RULES=OFF -DBUILD_GUI=OFF -DBUILD_TESTS=OFF \
      -DCMAKE_INSTALL_PREFIX=/opt/pathos/sast/cppcheck -DFILESDIR=/opt/pathos/sast/cppcheck/share; \
    cmake --build /build -j"$(nproc)"; cmake --install /build --strip; \
    /opt/pathos/sast/cppcheck/bin/cppcheck --version | grep -q "Cppcheck ${CPPCHECK}"

# Downloaded release files: ShellCheck, Kingfisher, PHPStan, Psalm and
# Node.js (for ESLint).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS downloads
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils && rm -rf /var/lib/apt/lists/*
ARG SHELLCHECK=0.11.0 SHELLCHECK_SHA=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 \
    KINGFISHER=2.19.1 KINGFISHER_SHA=3449ba41007df91e6774a816dd64cc9385900a304ef3cbb58ab61e0a83448e1c \
    PHPSTAN=2.3.6 PHPSTAN_SHA=bd5af896c8eb831e10873a4407c37ac33118dcd88de4ea77e13cd6e6702a41cc \
    PSALM=7.11.0 PSALM_SHA=7c87fe6fa6d886737dfcd6f37d40edb96a8d74b970cb6430e52d9c4b0b97051f \
    NODE=24.22.3 NODE_SHA=4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb
RUN set -eux; \
    fetch() { curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch shellcheck.tar.xz "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK}/shellcheck-v${SHELLCHECK}.linux.x86_64.tar.xz" "$SHELLCHECK_SHA"; \
    fetch kingfisher.tgz "https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER}/kingfisher-linux-x64.tgz" "$KINGFISHER_SHA"; \
    fetch phpstan.phar "https://github.com/phpstan/phpstan/releases/download/${PHPSTAN}/phpstan.phar" "$PHPSTAN_SHA"; \
    fetch psalm.phar "https://github.com/vimeo/psalm/releases/download/${PSALM}/psalm.phar" "$PSALM_SHA"; \
    fetch node.tar.xz "https://nodejs.org/dist/v${NODE}/node-v${NODE}-linux-x64.tar.xz" "$NODE_SHA"; \
    mkdir -p /out/bin /out/node /tmp/kf; \
    tar -xJf shellcheck.tar.xz -C /out/bin --strip-components=1 "shellcheck-v${SHELLCHECK}/shellcheck"; \
    tar -xzf kingfisher.tgz -C /tmp/kf; install -m 0755 /tmp/kf/kingfisher /out/bin/kingfisher; \
    install -m 0755 phpstan.phar /out/bin/phpstan; install -m 0755 psalm.phar /out/bin/psalm; \
    tar -xJf node.tar.xz -C /out/node --strip-components=1; \
    /out/bin/shellcheck --version | grep -q "version: ${SHELLCHECK}"; \
    /out/bin/kingfisher --version | grep -q "${KINGFISHER}"; \
    /out/node/bin/node --version | grep -q "v${NODE}"

# ESLint with eslint-plugin-security and the TypeScript parser, installed
# from package-lock.json (npm ci checks every package's integrity hash;
# install scripts are not run).
FROM downloads AS eslint
COPY workers/sast/eslint/package.json workers/sast/eslint/package-lock.json /opt/pathos/sast/eslint/
RUN --mount=type=cache,target=/root/.npm set -eux; \
    cd /opt/pathos/sast/eslint; \
    PATH="/out/node/bin:$PATH" npm ci --ignore-scripts --no-audit --no-fund --omit=dev; \
    /out/node/bin/node node_modules/eslint/bin/eslint.js --version

FROM ${CORE_IMAGE}
USER root
# PHP CLI for PHPStan and Psalm (Debian packages, verified by apt).
RUN apt-get update && apt-get install -y --no-install-recommends php8.4-cli php8.4-xml php8.4-mbstring \
    && rm -rf /var/lib/apt/lists/*
COPY --from=python-tools /opt/pathos/sast/ /opt/pathos/sast/
COPY --from=downloads /out/bin/ /opt/pathos/sast/bin/
# Only the node binary of the Node.js distribution (npm is not needed).
COPY --from=downloads /out/node/bin/node /opt/pathos/sast/node/bin/node
COPY --from=downloads /out/node/LICENSE /opt/pathos/sast/node/LICENSE
COPY --from=eslint /opt/pathos/sast/eslint/ /opt/pathos/sast/eslint/
COPY --from=gotools /out/gosec /out/golangci-lint /out/trufflehog /out/talisman /opt/pathos/sast/bin/
COPY --from=gotools /out/go/ /opt/pathos/sast/go/
COPY --from=bearer /out/bearer /opt/pathos/sast/bin/bearer
COPY --from=bearer /out/bearer-rules/ /opt/pathos/sast/bearer-rules/
COPY --from=cppcheck /opt/pathos/sast/cppcheck/ /opt/pathos/sast/cppcheck/
COPY --chmod=0755 workers/sast/bin/ /opt/pathos/sast/bin/
COPY workers/sast/eslint/eslint.config.mjs /opt/pathos/sast/eslint/eslint.config.mjs
COPY workers/sast/config/ /opt/pathos/sast/config/
COPY workers/sast/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    ln -s /opt/pathos/sast/bin/shellcheck /usr/local/bin/shellcheck; \
    ln -s /opt/pathos/sast/cppcheck/bin/cppcheck /opt/pathos/sast/bin/cppcheck; \
    chmod -R go-w /opt/pathos/sast /opt/pathos/tools.d; \
    for t in bandit njsscan flawfinder ruff detect-secrets pylint semgrep shellcheck-tree gosec gosec-tree golangci-lint golangci-lint-tree \
      trufflehog talisman talisman-tree kingfisher bearer phpstan psalm psalm-taint eslint-tree cppcheck; do test -x "/opt/pathos/sast/bin/$t"; done; \
    /opt/pathos/sast/bin/shellcheck-tree --version | grep -q "version: 0.11.0"; \
    /opt/pathos/sast/bin/phpstan --version | grep -q "2.3.6"; \
    /opt/pathos/sast/bin/psalm --version | grep -q "7.11.0"; \
    /opt/pathos/sast/bin/eslint-tree --version | grep -q "10.15.0"; \
    /opt/pathos/sast/bin/bearer version 2>&1 | grep -q "2.1.3"; \
    /opt/pathos/sast/bin/cppcheck --version | grep -q "2.19.0"
USER 10001:10001
# libsast (njsscan) runs "semgrep" from PATH; the virtual environment comes
# last, so it never shadows the core image's commands.
ENV PATHOS_WORKER_FAMILY=sast PATHOS_TOOLS_DIR=/opt/pathos/tools.d \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/pathos/sast/bin
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
