# syntax=docker/dockerfile:1
# PATHOS worker-graph: the core worker image plus CodeGraph discovery
# (pathos-graph). pathos-graph reads a repository's source files and
# writes its code graph (pathos.codegraph/v1): Go is parsed with the Go
# parser, Java, Python, JavaScript/TypeScript, C#, PHP and Ruby with
# tree-sitter (grammars compiled into the binary), languages are detected
# with go-enry, OpenAPI documents are read with kin-openapi, and the
# Opengrep and Syft binaries of the core image run as separate processes:
# Opengrep with the PATHOS graph rules (workers/graph/rules: routes, data
# access, queues, outbound HTTP calls), Syft for SBOM components. The tool
# is defined only by its manifest (workers/graph/tools.d, installed
# read-only at /opt/pathos/tools.d). Build context: repository root.
#
# Repository code is never built or executed by this image, and the graph
# build needs no network (the manifest declares network: none, so the
# proxy settings are removed from the tool's environment).
#
# The family image extends the core image (CORE_IMAGE, the worker-core
# image of the same PATHOS version), so it also runs every core tool.
# Every download is pinned: the Go toolchain by image digest, Go modules
# by go.sum and the Go checksum database.

ARG CORE_IMAGE=pathos-worker-core:dev

# pathos-graph needs cgo (tree-sitter is a C library): built with the
# Debian trixie Go image, the same Debian release as the core image's
# runtime (glibc).
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG VERSION=dev
WORKDIR /src
COPY workers/graph/discover/go.mod workers/graph/discover/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY workers/graph/discover/*.go ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.Version=${VERSION}" -o /out/pathos-graph .; \
    /out/pathos-graph version

FROM ${CORE_IMAGE}
USER root
COPY --from=build --chmod=0755 /out/pathos-graph /opt/pathos/graph/bin/pathos-graph
COPY workers/graph/rules/ /opt/pathos/graph/rules/
COPY workers/graph/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    chmod -R go-w /opt/pathos/graph /opt/pathos/tools.d; \
    /opt/pathos/graph/bin/pathos-graph version; \
    test -x /usr/local/bin/opengrep; test -x /usr/local/bin/syft
USER 10001:10001
ENV PATHOS_WORKER_FAMILY=graph PATHOS_TOOLS_DIR=/opt/pathos/tools.d
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
