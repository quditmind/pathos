# syntax=docker/dockerfile:1
# PATHOS worker-binary: the core worker image plus binary and firmware
# analysis tools: CVE Binary Tool (known vulnerable components), capa
# (capabilities of executables) and YARA-X (YARA rules). The checksec-style
# binary hardening checks are built into every worker. The tools are defined
# only by manifests (workers/binary/tools.d, installed read-only at
# /opt/pathos/tools.d). Build context: repository root.
#
# The family image extends the core image (CORE_IMAGE, the worker-core
# image of the same PATHOS version), so it also runs every core tool.
#
# Every download is pinned: Python packages by version and SHA-256 (pip
# --require-hashes), YARA-X, the rule sets and capa's signatures by version
# or commit and SHA-256. CVE Binary Tool's vulnerability database is not in
# the image: an operator installs it in the worker's cache volume
# (docs/OPERATIONS.md). Nothing from a scanned file is executed.

ARG CORE_IMAGE=pathos-worker-core:dev

# capa and CVE Binary Tool in their own virtual environment (CPython 3.13,
# the core image's interpreter). CVE Binary Tool is a source archive; it is
# built without build isolation, with the pinned setuptools and wheel.
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/binary/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/binary; \
    grep -A1 -E '^(setuptools|wheel)==' /tmp/requirements.txt | grep -v '^--$' > /tmp/build.txt; \
    /opt/pathos/binary/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/build.txt; \
    /opt/pathos/binary/bin/pip install --no-compile --require-hashes --no-deps --no-build-isolation -r /tmp/requirements.txt; \
    /opt/pathos/binary/bin/capa --version; \
    /opt/pathos/binary/bin/cve-bin-tool --version; \
    /opt/pathos/binary/bin/python -m pip uninstall -y pip; \
    find /opt/pathos/binary -name '__pycache__' -prune -exec rm -rf {} +

# YARA-X and the rules: the ReversingLabs YARA rules (MIT) and PATHOS' own,
# compiled once here. capa's rule set (capa-rules, Apache-2.0) and its
# library signatures (sigs/ of the capa source, Apache-2.0).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS rules
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
ARG YARAX=1.23.0 YARAX_SHA=da0c17f23fc743dcd44ad6d3135c906a4c0d197685b661c4cdc923c2f8967a64
ARG RL_RULES=e0a0be54aa1e11ccfd6854e4f19e9476f328fd84 RL_RULES_SHA=0fd2319ed56875772fe843e542520ca4c84e91c72857ed1ac3274a8685ebb4a3
ARG CAPA=10.0.0 CAPA_SHA=d3f6006ad61e6591896f524566c191eca89c6220611969e1bd485bd9a1098180 \
    CAPA_RULES_SHA=3d14dbdaf5b71731e42395ed5fa4d287418e6a2e5d6b0a348c7fd9fbe1699611
COPY workers/binary/yara/ /tmp/pathos-yara/
RUN set -eux; \
    mkdir -p /out/yara /out/capa/rules /out/capa/sigs /tmp/rl; \
    curl -fsSL --retry 3 -o yarax.tar.gz "https://github.com/VirusTotal/yara-x/releases/download/v${YARAX}/yara-x-v${YARAX}-x86_64-unknown-linux-gnu.tar.gz"; \
    echo "${YARAX_SHA}  yarax.tar.gz" | sha256sum -c -; \
    tar -xzf yarax.tar.gz -C /out/yara yr; \
    chmod 0755 /out/yara/yr; \
    /out/yara/yr --version | grep -q "${YARAX}"; \
    curl -fsSL --retry 3 -o rl.tar.gz "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/${RL_RULES}.tar.gz"; \
    echo "${RL_RULES_SHA}  rl.tar.gz" | sha256sum -c -; \
    tar -xzf rl.tar.gz -C /tmp/rl --strip-components=1; \
    cp /tmp/rl/LICENSE /out/yara/LICENSE.reversinglabs; \
    /out/yara/yr compile -w -o /out/yara/rules.yarc rl:/tmp/rl/yara pathos:/tmp/pathos-yara; \
    curl -fsSL --retry 3 -o capa-rules.tar.gz "https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA}.tar.gz"; \
    echo "${CAPA_RULES_SHA}  capa-rules.tar.gz" | sha256sum -c -; \
    tar -xzf capa-rules.tar.gz -C /out/capa/rules --strip-components=1; \
    curl -fsSL --retry 3 -o capa.tar.gz "https://github.com/mandiant/capa/archive/refs/tags/v${CAPA}.tar.gz"; \
    echo "${CAPA_SHA}  capa.tar.gz" | sha256sum -c -; \
    tar -xzf capa.tar.gz -C /out/capa/sigs --strip-components=2 "capa-${CAPA}/sigs"; \
    rm -rf /out/capa/rules/.github /out/capa/rules/.gitignore

FROM ${CORE_IMAGE}
USER root
COPY --from=python-tools /opt/pathos/binary/ /opt/pathos/binary/
COPY --from=rules /out/yara/ /opt/pathos/binary/yara/
COPY --from=rules /out/capa/ /opt/pathos/binary/capa/
COPY --chmod=0755 workers/binary/bin/pathos-binary /opt/pathos/binary/bin/pathos-binary
COPY workers/binary/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    chmod -R go-w /opt/pathos/binary /opt/pathos/tools.d; \
    for t in /opt/pathos/binary/bin/pathos-binary /opt/pathos/binary/bin/capa /opt/pathos/binary/bin/cve-bin-tool /opt/pathos/binary/yara/yr; do test -x "$t"; done; \
    for t in yara capa cve-bin-tool; do /opt/pathos/binary/bin/pathos-binary version "$t"; done
USER 10001:10001
ENV PATHOS_WORKER_FAMILY=binary PATHOS_TOOLS_DIR=/opt/pathos/tools.d \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/pathos/binary/bin
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
