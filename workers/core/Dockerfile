# syntax=docker/dockerfile:1
# PATHOS worker-core: Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov,
# zizmor and actionlint (GitHub Actions), Nuclei (DAST for authorized URL/API targets)
# and cosign (Sigstore signature and attestation verification of image and artifact targets).
# Build context: repository root.
#
# Every downloaded binary is pinned by version and SHA-256. Repository code
# is never built or executed by this image.

FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS agent
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY backend/ ./
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pathos-worker ./cmd/pathos-worker

# Gitleaks is built from its Go module (integrity: Go checksum database) with
# the current toolchain and patched dependencies, because the upstream
# v8.30.1 binary was built with Go 1.24.11 and carries fixable CVEs in
# x/crypto, x/text and klauspost/compress.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gitleaks
ARG GITLEAKS=8.30.1
RUN --mount=type=cache,target=/go/pkg/mod set -eux; \
    dir="$(go mod download -json "github.com/zricethezav/gitleaks/v8@v${GITLEAKS}" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"; \
    cp -r "$dir" /src; chmod -R u+w /src; cd /src; \
    go get golang.org/x/crypto@v0.55.0 golang.org/x/text@v0.41.0 github.com/klauspost/compress@v1.18.7; \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS}" -o /out/gitleaks .; \
    /out/gitleaks version

# Nuclei is built from its Go module (integrity: Go checksum database) with
# the current toolchain and patched dependencies, because the upstream
# v3.11.1 binary was built with Go 1.26.5 and carries fixable CVEs
# (kin-openapi, go-git, go-jose, grpc, x/crypto, x/mod, x/net, x/text).
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS nuclei
ARG NUCLEI=3.11.1
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    dir="$(go mod download -json "github.com/projectdiscovery/nuclei/v3@v${NUCLEI}" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"; \
    cp -r "$dir" /src; chmod -R u+w /src; cd /src; \
    go get github.com/getkin/kin-openapi@v0.149.0 github.com/go-git/go-git/v5@v5.19.2 github.com/go-jose/go-jose/v4@v4.1.6 \
      golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.83.2; \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/nuclei ./cmd/nuclei; \
    /out/nuclei -version 2>&1 | grep -q "v${NUCLEI}"

# cosign (Sigstore signature and attestation verification), built from its Go
# module with the current toolchain. Integrity: the module hash is pinned below
# (h1 sum, as recorded in the Go checksum database) and checked before building.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS cosign
ARG COSIGN=3.1.4 COSIGN_SUM=h1:d3UHS8oJebMf6XUhPtWv9weU1ZYRyXq9HJ7QPccmqvY=
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    sum="$(go mod download -json "github.com/sigstore/cosign/v3@v${COSIGN}" | sed -n 's/^[[:space:]]*"Sum": "\(.*\)",$/\1/p')"; \
    test "$sum" = "$COSIGN_SUM"; \
    GOBIN=/out CGO_ENABLED=0 go install -trimpath -ldflags "-s -w" "github.com/sigstore/cosign/v3/cmd/cosign@v${COSIGN}"; \
    /out/cosign version 2>&1 | grep -q "v${COSIGN}"

# actionlint (GitHub Actions workflow checks), built from its Go module
# (integrity: Go checksum database) with the current toolchain.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS actionlint
ARG ACTIONLINT=1.7.12
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    GOBIN=/out CGO_ENABLED=0 go install -trimpath -ldflags "-s -w" "github.com/rhysd/actionlint/cmd/actionlint@v${ACTIONLINT}"; \
    /out/actionlint -version | grep -q "${ACTIONLINT}"

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
ARG TRIVY=0.76.2   TRIVY_SHA=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
ARG SYFT=1.57.1    SYFT_SHA=bf52519eb57f675d47c07d43213cb6dff6449f3d6d1147ff6701ed91f44eef0c
ARG GRYPE=0.121.3  GRYPE_SHA=e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85
ARG OSV=2.7.1      OSV_SHA=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8
ARG OPENGREP=2.0.0 OPENGREP_SHA=37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0
ARG ZIZMOR=1.32.0  ZIZMOR_SHA=bb110cc765eca9cd7efb2e284a956be5974c60027b0970f16397d86208a9957b
# Nuclei templates: GitHub source archive of the release tag (hash computed
# when the version was pinned).
# Only a reviewed subset is installed. Left out: osint and token-spray
# (contact third-party sites), default-logins and credential-stuffing (log-in
# attempts), fuzzing, iot, honeypot and technologies (fingerprinting).
ARG NUCLEI_TEMPLATES=10.5.1 NUCLEI_TEMPLATES_SHA=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb
RUN set -eux; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY}/trivy_${TRIVY}_Linux-64bit.tar.gz" "$TRIVY_SHA"; \
    fetch syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT}/syft_${SYFT}_linux_amd64.tar.gz" "$SYFT_SHA"; \
    fetch grype.tgz "https://github.com/anchore/grype/releases/download/v${GRYPE}/grype_${GRYPE}_linux_amd64.tar.gz" "$GRYPE_SHA"; \
    fetch osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV}/osv-scanner_linux_amd64" "$OSV_SHA"; \
    fetch opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP}/opengrep_linux_x86" "$OPENGREP_SHA"; \
    fetch zizmor.tgz "https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR}/zizmor-x86_64-unknown-linux-gnu.tar.gz" "$ZIZMOR_SHA"; \
    fetch templates.tgz "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES}.tar.gz" "$NUCLEI_TEMPLATES_SHA"; \
    mkdir -p /out /templates; \
    for t in trivy syft grype; do tar -xzf "$t.tgz" -C /out "$t"; done; \
    tar -xzf zizmor.tgz -C /out zizmor; \
    install -m 0755 osv-scanner opengrep /out/; \
    chmod 0755 /out/*; \
    t="nuclei-templates-${NUCLEI_TEMPLATES}"; \
    tar -xzf templates.tgz -C /templates --strip-components=1 \
      "$t/http/cves" "$t/http/misconfiguration" "$t/http/vulnerabilities" "$t/http/exposures" "$t/http/exposed-panels" \
      "$t/http/takeovers" "$t/http/miscellaneous" "$t/ssl" "$t/dast" "$t/helpers" "$t/LICENSE.md"; \
    find /templates -type d -exec chmod 0755 {} +; find /templates -type f -exec chmod 0644 {} +

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ARG CHECKOV=3.4.5
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-compile "checkov==${CHECKOV}" \
    && checkov --version \
    # pip is only needed to build the image; removing it also removes its
    # vendored (and CVE-flagged) urllib3/msgpack copies from the runtime.
    && python -m pip uninstall -y pip \
    && find /usr/local/lib/python3.13 -name '__pycache__' -prune -exec rm -rf {} +
COPY --from=tools /out/ /usr/local/bin/
COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
COPY --from=actionlint /out/actionlint /usr/local/bin/actionlint
COPY --from=cosign /out/cosign /usr/local/bin/cosign
COPY --from=agent /out/pathos-worker /usr/local/bin/pathos-worker
COPY workers/rules/ /opt/pathos/rules/
COPY --from=tools /templates/ /opt/pathos/nuclei-templates/
RUN useradd --uid 10001 --create-home --home-dir /tmp/home --shell /usr/sbin/nologin pathos \
    && mkdir -p /work /cache /rules && chown pathos:pathos /work /cache \
    && for t in gitleaks trivy syft grype osv-scanner opengrep checkov git zizmor nuclei actionlint cosign; do command -v "$t" >/dev/null; done
USER 10001:10001
ENV PATHOS_WORK_DIR=/work PATHOS_CACHE_DIR=/cache PATHOS_RULES_DIRS=/opt/pathos/rules:/rules \
    PYTHONDONTWRITEBYTECODE=1 HOME=/tmp/home
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
