# syntax=docker/dockerfile:1
# PATHOS worker-fuzz: the core worker image plus coverage-guided fuzzing of
# the fuzz harnesses a repository contains: Go native fuzzing (the Go
# toolchain) and Atheris (Python). The tools are defined only by manifests
# (workers/fuzz/tools.d, installed read-only at /opt/pathos/tools.d).
# Build context: repository root.
#
# These tools build and run repository code. They run only in this worker's
# sandbox, only when a scan profile selects them, without network access
# and under CPU, memory, file size and time limits (bin/pathos-fuzz). The
# compose service adds CPU and memory limits for the whole container.
#
# The family image extends the core image (CORE_IMAGE, the worker-core
# image of the same PATHOS version), so it also runs every core tool.
# Every download is pinned: the Go toolchain by image digest, Atheris by
# version and SHA-256 (pip --require-hashes).

ARG CORE_IMAGE=pathos-worker-core:dev

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/fuzz/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/fuzz; \
    /opt/pathos/fuzz/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/requirements.txt; \
    /opt/pathos/fuzz/bin/python -c "import atheris"; \
    /opt/pathos/fuzz/bin/python -m pip uninstall -y pip; \
    find /opt/pathos/fuzz -name '__pycache__' -prune -exec rm -rf {} +

# The Go toolchain of the official image (the version PATHOS is built
# with), without its test data and API files.
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS go
RUN set -eux; \
    cp -a /usr/local/go /out-go; \
    rm -rf /out-go/test /out-go/api /out-go/doc /out-go/misc; \
    /out-go/bin/go version | grep -q 'go1.27.4 linux/amd64'

FROM ${CORE_IMAGE}
USER root
COPY --from=python-tools /opt/pathos/fuzz/ /opt/pathos/fuzz/
COPY --from=go /out-go/ /opt/pathos/fuzz/go/
COPY --chmod=0755 workers/fuzz/bin/pathos-fuzz /opt/pathos/fuzz/bin/pathos-fuzz
COPY workers/fuzz/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    chmod -R go-w /opt/pathos/fuzz /opt/pathos/tools.d; \
    for t in /opt/pathos/fuzz/bin/pathos-fuzz /opt/pathos/fuzz/go/bin/go; do test -x "$t"; done; \
    for t in go atheris; do /opt/pathos/fuzz/bin/pathos-fuzz version "$t"; done
USER 10001:10001
ENV PATHOS_WORKER_FAMILY=fuzz PATHOS_TOOLS_DIR=/opt/pathos/tools.d \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/pathos/fuzz/bin
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
