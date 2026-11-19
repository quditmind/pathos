# syntax=docker/dockerfile:1
# PATHOS worker-sca: the core worker image plus the SCA family tools
# govulncheck, pip-audit, cargo-audit, bundler-audit, Retire.js, npm audit,
# yarn audit, pnpm audit, Composer audit, OWASP Dependency-Check, GuardDog,
# pathos-depcheck (dependency confusion and typosquatting), cdxgen
# (CycloneDX SBOM) and pathos-reach (function-level reachability). The
# tools are defined only by manifests (workers/sca/tools.d, installed
# read-only at /opt/pathos/tools.d) and run through the pathos-sca helper
# (workers/sca/bin/pathos-sca).
# Build context: repository root.
#
# A family image extends the core image instead of replacing it (see
# workers/sast/Dockerfile). CORE_IMAGE is the worker-core image of the same
# PATHOS version.
#
# Every download is pinned: Python packages by version and SHA-256
# (pip --require-hashes), npm packages by package-lock.json integrity
# (npm ci), Ruby gems, Node.js, cargo-audit, Composer, the Temurin JRE,
# Dependency-Check and the advisory database snapshots by SHA-256, Go
# modules by the Go checksum database, Debian packages by apt signatures.
# Repository code is never built or executed by this image: the helper
# disables package-manager plugins, scripts and toolchain switching, and
# cdxgen runs under the Node.js permission model without child processes.

ARG CORE_IMAGE=pathos-worker-core:dev

# pip-audit and GuardDog in their own virtual environment (CPython 3.13, the
# interpreter of the core image).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/sca/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/sca; \
    /opt/pathos/sca/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/requirements.txt; \
    /opt/pathos/sca/bin/pip-audit --version; \
    # pip is only needed to build the image (pip-audit runs with
    # --disable-pip). Its vendored packages carry fixable CVEs, so it is
    # removed; pip-audit reads a pip version from the pip-version helper
    # (PIPAPI_PYTHON_LOCATION).
    /opt/pathos/sca/bin/python -m pip uninstall -y pip; \
    # GuardDog's popular-package lists (typosquatting rules) are refreshed
    # from third-party sites when older than 30 days. The copies used by
    # the worker (GUARDDOG_TOP_PACKAGES_CACHE_LOCATION) carry a timestamp in
    # the future, so the lists of the pinned release are always used and
    # nothing is downloaded.
    mkdir -p /opt/pathos/sca/guarddog-top; \
    /opt/pathos/sca/bin/python -I -c 'import glob, json, os, sys; [json.dump(dict(json.load(open(f)), downloaded_timestamp=4102444800), open(os.path.join(sys.argv[1], os.path.basename(f)), "w")) for f in glob.glob(os.path.join(sys.argv[2], "*.json"))]' \
      /opt/pathos/sca/guarddog-top /opt/pathos/sca/lib/python3.13/site-packages/guarddog/analyzer/metadata/resources; \
    ls /opt/pathos/sca/guarddog-top/top_pypi_packages.json /opt/pathos/sca/guarddog-top/top_npm_packages.json; \
    find /opt/pathos/sca -name '__pycache__' -prune -exec rm -rf {} +

# govulncheck, pathos-depcheck and pathos-reach, built with Go 1.27.4
# (integrity: Go checksum database; pathos-depcheck and pathos-reach are
# this repository's code and use the standard library only).
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gotools
ARG GOVULNCHECK=1.10.0
# PATHOS release version for the PATHOS-built helpers (pathos-depcheck,
# pathos-reach); the release workflow and Compose pass it.
ARG VERSION=dev
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
COPY backend/internal/depcheck/ ./internal/depcheck/
COPY backend/cmd/pathos-depcheck/ ./cmd/pathos-depcheck/
COPY backend/internal/reachscan/ ./internal/reachscan/
COPY backend/cmd/pathos-reach/ ./cmd/pathos-reach/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    GOBIN=/out CGO_ENABLED=0 go install -trimpath -ldflags "-s -w" "golang.org/x/vuln/cmd/govulncheck@v${GOVULNCHECK}"; \
    /out/govulncheck -version | grep -q "v${GOVULNCHECK}"; \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pathos-depcheck ./cmd/pathos-depcheck; \
    /out/pathos-depcheck --version; \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pathos-reach ./cmd/pathos-reach; \
    /out/pathos-reach --version

# Downloads (hashes computed when the versions were pinned).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS downloads
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils unzip && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
ARG NODE=24.22.3 NODE_SHA=4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb
ARG CARGO_AUDIT=0.23.0 CARGO_AUDIT_SHA=4f01c74ed84b2dffd0b1d37012a62cdf2a92c96e25bdf8eec7fcc0d4d3eb7811
ARG COMPOSER=2.11.2 COMPOSER_SHA=dd158c0afd41d15fac89e1b4e47b5d42911fe316c3687cd5edac98319b25d028
ARG JRE=21.0.13.1_2 JRE_TAG=jdk-21.0.13.1%2B2 JRE_SHA=18f44fab9065217f3ba61d0eef8a7b5f3c3713aa7293001b0d4ac10ede3850f0
ARG DEPCHECK=13.0.0 DEPCHECK_SHA=44d920d1ec03e948df862a253f0912782a31b9beee8a7c8895b9cb95760176ed
# Patched Dependency-Check libraries (Maven Central): 13.0.0 ships
# jackson-core and jackson-databind 2.22.1, Guava 33.6.0 and jsoup 1.23.1
# (fixable HIGH CVEs). The patched jars replace them under the original
# file names, which the CLI jar's manifest class path lists.
ARG JACKSON=2.22.3 JACKSON_CORE_SHA=8a501126a385b25841915d839508f8a66e2a0dbc8a6709d055ef3b3e852b094c \
    JACKSON_DATABIND_SHA=556db5439e206114346043f68d200497dc96a0bca62a360a81784092ebd0e0a9 \
    GUAVA=33.7.2-jre GUAVA_SHA=b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c \
    JSOUP=1.23.2 JSOUP_SHA=e9d8c856856680427f096d156f02a414289985c930998fcb519ce5be39b42003
ARG BUNDLER_AUDIT=0.9.3 BUNDLER_AUDIT_SHA=81c8766c71e47d0d28a0f98c7eed028539f21a6ea3cd8f685eb6f42333c9b4e9
ARG THOR=1.5.0 THOR_SHA=e3a9e55fe857e44859ce104a84675ab6e8cd59c650a49106a05f55f136425e73
# Advisory database snapshots (GitHub source archives of a commit): the
# RustSec advisory database for cargo-audit, the Ruby advisory database for
# bundler-audit and the Retire.js repository. They are as current as the
# image; rebuild the image to refresh them.
ARG RUSTSEC_DB=472a4c9a785030434f15d7da84964d60fbe789ab RUSTSEC_DB_SHA=d881db6c5326ee7d674a59be5176c97831eab1c9a65f9eec30299eb6cce871e7
ARG RUBY_DB=49bb1fbb35476f27f8cfbfcb943790633836dc1c RUBY_DB_SHA=aeeb858600ad520858f29a8ae91dabc7ec5eb9acb9fea1fbe5c38ffedbbb824b
ARG RETIRE_REPO=8d814f3c023a909b26be6a35a45b54163c2d95fe RETIRE_REPO_SHA=3602c6e405f1a32b62b92fee54b53d741e8eae0831fdcb3e8febb2155dcd3bfe
RUN set -eux; \
    fetch() { curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch node.tar.xz "https://nodejs.org/dist/v${NODE}/node-v${NODE}-linux-x64.tar.xz" "$NODE_SHA"; \
    fetch cargo-audit.tgz "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv${CARGO_AUDIT}/cargo-audit-x86_64-unknown-linux-musl-v${CARGO_AUDIT}.tgz" "$CARGO_AUDIT_SHA"; \
    fetch composer.phar "https://getcomposer.org/download/${COMPOSER}/composer.phar" "$COMPOSER_SHA"; \
    fetch jre.tgz "https://github.com/adoptium/temurin21-binaries/releases/download/${JRE_TAG}/OpenJDK21U-jre_x64_linux_hotspot_${JRE}.tar.gz" "$JRE_SHA"; \
    fetch dc.zip "https://github.com/dependency-check/DependencyCheck/releases/download/v${DEPCHECK}/dependency-check-${DEPCHECK}-release.zip" "$DEPCHECK_SHA"; \
    fetch bundler-audit.gem "https://rubygems.org/downloads/bundler-audit-${BUNDLER_AUDIT}.gem" "$BUNDLER_AUDIT_SHA"; \
    fetch thor.gem "https://rubygems.org/downloads/thor-${THOR}.gem" "$THOR_SHA"; \
    fetch rustsec.tgz "https://github.com/rustsec/advisory-db/archive/${RUSTSEC_DB}.tar.gz" "$RUSTSEC_DB_SHA"; \
    fetch ruby-db.tgz "https://github.com/rubysec/ruby-advisory-db/archive/${RUBY_DB}.tar.gz" "$RUBY_DB_SHA"; \
    fetch jsrepository.json "https://raw.githubusercontent.com/RetireJS/retire.js/${RETIRE_REPO}/repository/jsrepository-v4.json" "$RETIRE_REPO_SHA"; \
    o=/opt/pathos/sca; mkdir -p $o/node $o/jre $o/bin $o/db/advisory-db $o/db/ruby-advisory-db /gems; \
    tar -xJf node.tar.xz -C $o/node --strip-components=1 --no-same-owner; \
    # npm comes from package-lock.json (newer than the bundled copy, whose
    # dependencies carry fixable CVEs); corepack is not used.
    rm -rf $o/node/include $o/node/share $o/node/lib/node_modules $o/node/bin/npm $o/node/bin/npx $o/node/bin/corepack; \
    tar -xzf cargo-audit.tgz --strip-components=1 -C $o/bin "cargo-audit-x86_64-unknown-linux-musl-v${CARGO_AUDIT}/cargo-audit"; \
    install -m 0644 composer.phar $o/composer.phar; \
    tar -xzf jre.tgz -C $o/jre --strip-components=1 --no-same-owner; \
    unzip -q dc.zip -d $o; \
    m=https://repo1.maven.org/maven2; lib=$o/dependency-check/lib; \
    fetch "$lib/jackson-core-2.22.1.jar" "$m/com/fasterxml/jackson/core/jackson-core/${JACKSON}/jackson-core-${JACKSON}.jar" "$JACKSON_CORE_SHA"; \
    fetch "$lib/jackson-databind-2.22.1.jar" "$m/com/fasterxml/jackson/core/jackson-databind/${JACKSON}/jackson-databind-${JACKSON}.jar" "$JACKSON_DATABIND_SHA"; \
    fetch "$lib/guava-33.6.0-jre.jar" "$m/com/google/guava/guava/${GUAVA}/guava-${GUAVA}.jar" "$GUAVA_SHA"; \
    fetch "$lib/jsoup-1.23.1.jar" "$m/org/jsoup/jsoup/${JSOUP}/jsoup-${JSOUP}.jar" "$JSOUP_SHA"; \
    tar -xzf rustsec.tgz -C $o/db/advisory-db --strip-components=1 --no-same-owner; \
    tar -xzf ruby-db.tgz -C $o/db/ruby-advisory-db --strip-components=1 --no-same-owner; \
    install -m 0644 jsrepository.json $o/db/jsrepository.json; \
    cp bundler-audit.gem thor.gem /gems/; \
    $o/bin/cargo-audit --version | grep -q "${CARGO_AUDIT}"; \
    $o/jre/bin/java -version; \
    $o/node/bin/node --version | grep -q "v${NODE}"

# Retire.js, yarn (1.x), pnpm and cdxgen from package-lock.json (integrity
# checked by npm ci; install scripts are not run).
FROM downloads AS node-tools
COPY workers/sca/npm/package.json workers/sca/npm/package-lock.json /opt/pathos/sca/npm/
RUN --mount=type=cache,target=/root/.npm set -eux; \
    export PATH=/opt/pathos/sca/node/bin:$PATH; \
    cd /opt/pathos/sca/npm; \
    # Bootstrap: npm ci with the npm of the lockfile, unpacked from the
    # registry tarball checked against the lockfile's integrity.
    url="$(node -e 'const l=require("./package-lock.json").packages["node_modules/npm"];console.log(l.resolved+" "+l.integrity)')"; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o /tmp/npm.tgz "${url%% *}"; \
    test "sha512-$(node -e 'process.stdout.write(require("crypto").createHash("sha512").update(require("fs").readFileSync("/tmp/npm.tgz")).digest("base64"))')" = "${url#* }"; \
    mkdir -p /tmp/npm && tar -xzf /tmp/npm.tgz -C /tmp/npm --strip-components=1; \
    node /tmp/npm/bin/npm-cli.js ci --ignore-scripts --omit=optional --no-audit --no-fund; \
    rm -rf /tmp/npm /tmp/npm.tgz; \
    node node_modules/npm/bin/npm-cli.js --version; \
    node_modules/.bin/retire --version; node_modules/.bin/yarn --version; node_modules/.bin/pnpm --version; \
    node node_modules/@cyclonedx/cdxgen/bin/cdxgen.js --version

FROM ${CORE_IMAGE}
ARG BUNDLER_AUDIT=0.9.3
USER root
# Ruby (bundler-audit) and PHP (Composer audit) from Debian.
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-bundler php-cli \
    && rm -rf /var/lib/apt/lists/*
COPY --from=downloads /gems/ /tmp/gems/
RUN set -eux; \
    # Into the system gem directory, where Debian's bundler is found.
    gem install --local --no-document /tmp/gems/thor.gem /tmp/gems/bundler-audit.gem; \
    rm -rf /tmp/gems; \
    bundle-audit version | grep -q "${BUNDLER_AUDIT}"
COPY --from=python-tools /opt/pathos/sca/ /opt/pathos/sca/
COPY --from=downloads /opt/pathos/sca/ /opt/pathos/sca/
COPY --from=node-tools /opt/pathos/sca/npm/ /opt/pathos/sca/npm/
# The Go toolchain for govulncheck (package loading and call graphs).
COPY --from=golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d /usr/local/go/ /opt/pathos/sca/go/
COPY --from=gotools /out/ /opt/pathos/sca/bin/
COPY --chmod=0755 workers/sca/bin/pathos-sca workers/sca/bin/pip-version /opt/pathos/sca/bin/
COPY workers/sca/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    rm -rf /opt/pathos/sca/go/test /opt/pathos/sca/go/doc /opt/pathos/sca/go/api; \
    chown -R root:root /opt/pathos/sca; \
    chmod -R go-w /opt/pathos/sca /opt/pathos/tools.d; \
    for t in govulncheck pip-audit cargo-audit bundler-audit retire npm-audit yarn-audit pnpm-audit composer-audit dependency-check guarddog depcheck cdxgen reach; do \
      /opt/pathos/sca/bin/pathos-sca "$t" --version; \
    done
USER 10001:10001
ENV PATHOS_WORKER_FAMILY=sca PATHOS_TOOLS_DIR=/opt/pathos/tools.d
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
