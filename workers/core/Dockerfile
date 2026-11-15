# syntax=docker/dockerfile:1
# PATHOS worker-core: Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov.
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

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
ARG TRIVY=0.76.2   TRIVY_SHA=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
ARG SYFT=1.57.1    SYFT_SHA=bf52519eb57f675d47c07d43213cb6dff6449f3d6d1147ff6701ed91f44eef0c
ARG GRYPE=0.121.3  GRYPE_SHA=e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85
ARG OSV=2.7.1      OSV_SHA=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8
ARG OPENGREP=2.0.0 OPENGREP_SHA=37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0
RUN set -eux; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY}/trivy_${TRIVY}_Linux-64bit.tar.gz" "$TRIVY_SHA"; \
    fetch syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT}/syft_${SYFT}_linux_amd64.tar.gz" "$SYFT_SHA"; \
    fetch grype.tgz "https://github.com/anchore/grype/releases/download/v${GRYPE}/grype_${GRYPE}_linux_amd64.tar.gz" "$GRYPE_SHA"; \
    fetch osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV}/osv-scanner_linux_amd64" "$OSV_SHA"; \
    fetch opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP}/opengrep_linux_x86" "$OPENGREP_SHA"; \
    mkdir -p /out; \
    for t in trivy syft grype; do tar -xzf "$t.tgz" -C /out "$t"; done; \
    install -m 0755 osv-scanner opengrep /out/; \
    chmod 0755 /out/*

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
COPY --from=agent /out/pathos-worker /usr/local/bin/pathos-worker
COPY workers/rules/ /opt/pathos/rules/
RUN useradd --uid 10001 --create-home --home-dir /tmp/home --shell /usr/sbin/nologin pathos \
    && mkdir -p /work /cache /rules && chown pathos:pathos /work /cache \
    && for t in gitleaks trivy syft grype osv-scanner opengrep checkov git; do command -v "$t" >/dev/null; done
USER 10001:10001
ENV PATHOS_WORK_DIR=/work PATHOS_CACHE_DIR=/cache PATHOS_RULES_DIRS=/opt/pathos/rules:/rules \
    PYTHONDONTWRITEBYTECODE=1 HOME=/tmp/home
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
