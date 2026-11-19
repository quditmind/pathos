# syntax=docker/dockerfile:1
# PATHOS worker-sast: the core worker image plus the SAST family tools
# Bandit, njsscan and ShellCheck. The tools are defined only by manifests
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
# (pip --require-hashes), ShellCheck by version and SHA-256. Repository
# code is never built or executed by this image.

ARG CORE_IMAGE=pathos-worker-core:dev

# Bandit and njsscan in their own virtual environment (CPython 3.13, the
# interpreter of the core image).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/sast/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/sast; \
    /opt/pathos/sast/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/requirements.txt; \
    /opt/pathos/sast/bin/bandit --version; \
    /opt/pathos/sast/bin/njsscan --version; \
    # pip is only needed to build the image.
    /opt/pathos/sast/bin/python -m pip uninstall -y pip; \
    find /opt/pathos/sast -name '__pycache__' -prune -exec rm -rf {} +

# ShellCheck: GitHub release archive (hash computed when the version was
# pinned).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS shellcheck
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils && rm -rf /var/lib/apt/lists/*
ARG SHELLCHECK=0.11.0 SHELLCHECK_SHA=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
RUN set -eux; \
    curl -fsSL --retry 3 -o shellcheck.tar.xz "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK}/shellcheck-v${SHELLCHECK}.linux.x86_64.tar.xz"; \
    echo "${SHELLCHECK_SHA}  shellcheck.tar.xz" | sha256sum -c -; \
    mkdir -p /out; \
    tar -xJf shellcheck.tar.xz -C /out --strip-components=1 "shellcheck-v${SHELLCHECK}/shellcheck"; \
    chmod 0755 /out/shellcheck; \
    /out/shellcheck --version | grep -q "version: ${SHELLCHECK}"

FROM ${CORE_IMAGE}
USER root
COPY --from=python-tools /opt/pathos/sast/ /opt/pathos/sast/
COPY --from=shellcheck /out/shellcheck /usr/local/bin/shellcheck
COPY --chmod=0755 workers/sast/bin/shellcheck-tree /opt/pathos/sast/bin/shellcheck-tree
COPY workers/sast/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    chmod -R go-w /opt/pathos/sast /opt/pathos/tools.d; \
    for t in /opt/pathos/sast/bin/bandit /opt/pathos/sast/bin/njsscan /opt/pathos/sast/bin/shellcheck-tree /usr/local/bin/shellcheck; do test -x "$t"; done; \
    /opt/pathos/sast/bin/shellcheck-tree --version | grep -q "version: 0.11.0"
USER 10001:10001
# libsast (njsscan) runs "semgrep" from PATH; the virtual environment comes
# last, so it never shadows the core image's commands.
ENV PATHOS_WORKER_FAMILY=sast PATHOS_TOOLS_DIR=/opt/pathos/tools.d \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/pathos/sast/bin
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
