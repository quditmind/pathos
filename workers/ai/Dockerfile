# syntax=docker/dockerfile:1
# PATHOS worker-ai: the core worker image plus AI security tools: ModelScan
# (unsafe operators in model files) and the LLM red-teaming tools garak and
# promptfoo, which run only for authorized LLM endpoint targets with
# intrusive testing authorized. The tools are defined only by manifests
# (workers/ai/tools.d, installed read-only at /opt/pathos/tools.d). The
# AI-BOM is built into every worker. Build context: repository root.
#
# The family image extends the core image (CORE_IMAGE, the worker-core
# image of the same PATHOS version), so it also runs every core tool.
#
# Every download is pinned: Python packages by version and SHA-256 (pip
# --require-hashes), Node.js by version and SHA-256, promptfoo and its
# dependencies by the npm lockfile (integrity hashes, npm ci). No install
# script of an npm package runs.

ARG CORE_IMAGE=pathos-worker-core:dev

# ModelScan and garak in their own virtual environment (CPython 3.13, the
# core image's interpreter). langdetect (a garak dependency) is a source
# archive; it is built without build isolation with the pinned setuptools.
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/ai/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/ai; \
    grep -A1 -E '^(setuptools|wheel)==' /tmp/requirements.txt | grep -v '^--$' > /tmp/build.txt; \
    /opt/pathos/ai/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/build.txt; \
    /opt/pathos/ai/bin/pip install --no-compile --require-hashes --no-deps --no-build-isolation --ignore-requires-python -r /tmp/requirements.txt; \
    /opt/pathos/ai/bin/modelscan --version; \
    XDG_DATA_HOME=/tmp/g XDG_CONFIG_HOME=/tmp/g XDG_CACHE_HOME=/tmp/g /opt/pathos/ai/bin/python -m garak --version; \
    rm -rf /tmp/g; \
    /opt/pathos/ai/bin/python -m pip uninstall -y pip; \
    find /opt/pathos/ai -name '__pycache__' -prune -exec rm -rf {} +

# Node.js (official release archive) and promptfoo from the lockfile.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS promptfoo
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils libatomic1 && rm -rf /var/lib/apt/lists/*
ARG NODE=26.13.1 NODE_SHA=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864
RUN set -eux; \
    curl -fsSL --retry 3 -o node.tar.xz "https://nodejs.org/dist/v${NODE}/node-v${NODE}-linux-x64.tar.xz"; \
    echo "${NODE_SHA}  node.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/node /out/node/bin; \
    tar -xJf node.tar.xz -C /opt/node --strip-components=1; \
    cp /opt/node/bin/node /out/node/bin/node; \
    cp /opt/node/LICENSE /out/node/LICENSE
COPY workers/ai/promptfoo/package.json workers/ai/promptfoo/package-lock.json /out/promptfoo/
RUN --mount=type=cache,target=/root/.npm set -eux; \
    cd /out/promptfoo; \
    PATH=/opt/node/bin:$PATH npm ci --omit=dev --ignore-scripts --no-audit --no-fund; \
    /out/node/bin/node -e "console.log(require('/out/promptfoo/node_modules/promptfoo/package.json').version)" | grep -qx 0.126.0

FROM ${CORE_IMAGE}
USER root
# Node.js needs libatomic (Debian package).
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 && rm -rf /var/lib/apt/lists/*
COPY --from=python-tools /opt/pathos/ai/ /opt/pathos/ai/
COPY --from=promptfoo /out/node/ /opt/pathos/ai/node/
COPY --from=promptfoo /out/promptfoo/ /opt/pathos/ai/promptfoo/
COPY workers/ai/promptfoo/redteam-tests.yaml /opt/pathos/ai/promptfoo/redteam-tests.yaml
COPY --chmod=0755 workers/ai/bin/pathos-ai /opt/pathos/ai/bin/pathos-ai
COPY workers/ai/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    chmod -R go-w /opt/pathos/ai /opt/pathos/tools.d; \
    for t in /opt/pathos/ai/bin/pathos-ai /opt/pathos/ai/bin/modelscan /opt/pathos/ai/node/bin/node; do test -x "$t"; done; \
    for t in modelscan garak promptfoo; do /opt/pathos/ai/bin/pathos-ai version "$t"; done
USER 10001:10001
ENV PATHOS_WORKER_FAMILY=ai PATHOS_TOOLS_DIR=/opt/pathos/tools.d \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/pathos/ai/bin
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
