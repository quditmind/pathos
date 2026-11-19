# syntax=docker/dockerfile:1
# PATHOS worker-mobile: the core worker image plus the mobile application
# security tools mobsfscan, APKLeaks, Quark-Engine and the PATHOS mobile app
# checks (androguard), with jadx (decompiler) on a Temurin JRE. The tools
# are defined only by manifests (workers/mobile/tools.d, installed
# read-only at /opt/pathos/tools.d) and run for mobile app targets
# (uploaded APK, AAB or IPA packages). Build context: repository root.
#
# The family image extends the core image (CORE_IMAGE, the worker-core
# image of the same PATHOS version), so it also runs every core tool.
#
# Every download is pinned: Python packages by version and SHA-256 (pip
# --require-hashes), the JRE and jadx by version and SHA-256. Nothing from a
# scanned package is executed: jadx and androguard read it.

ARG CORE_IMAGE=pathos-worker-core:dev

# mobsfscan (with Semgrep CE), APKLeaks, Quark-Engine and androguard in
# their own virtual environment (CPython 3.13, the core image's interpreter).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/mobile/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/mobile; \
    /opt/pathos/mobile/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/requirements.txt; \
    /opt/pathos/mobile/bin/mobsfscan --version; \
    /opt/pathos/mobile/bin/python -c "import androguard, apkleaks, quark"; \
    # pip is only needed to build the image.
    /opt/pathos/mobile/bin/python -m pip uninstall -y pip; \
    find /opt/pathos/mobile -name '__pycache__' -prune -exec rm -rf {} +

# Eclipse Temurin JRE 21 and jadx: release archives, hashes computed when
# the versions were pinned.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS java
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip zip && rm -rf /var/lib/apt/lists/*
ARG JRE=21.0.13.1_2 JRE_TAG=jdk-21.0.13.1%2B2 JRE_SHA=18f44fab9065217f3ba61d0eef8a7b5f3c3713aa7293001b0d4ac10ede3850f0
ARG JADX=1.5.7 JADX_SHA=1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3
# jadx 1.5.7 bundles Guava 31.1-android (CVE-2026-102554, fixed in 33.7.2):
# its classes and Maven metadata in the jar are replaced with Guava
# 33.8.0-android from Maven Central (same API for jadx; the decompilation
# fixtures are produced with the patched jar).
ARG GUAVA=33.8.0-android GUAVA_SHA=c88b3bd93382316b00a387b629d2cc2620119e16c46554b07fa14e9aa07f990e
RUN set -eux; \
    curl -fsSL --retry 3 -o jre.tar.gz "https://github.com/adoptium/temurin21-binaries/releases/download/${JRE_TAG}/OpenJDK21U-jre_x64_linux_hotspot_${JRE}.tar.gz"; \
    echo "${JRE_SHA}  jre.tar.gz" | sha256sum -c -; \
    mkdir -p /out/jre /out/jadx; \
    tar -xzf jre.tar.gz -C /out/jre --strip-components=1; \
    curl -fsSL --retry 3 -o jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX}/jadx-${JADX}.zip"; \
    echo "${JADX_SHA}  jadx.zip" | sha256sum -c -; \
    unzip -q jadx.zip -d /out/jadx; \
    rm -f /out/jadx/bin/*.bat; \
    chmod 0755 /out/jadx/bin/jadx; \
    curl -fsSL --retry 3 -o guava.jar "https://repo1.maven.org/maven2/com/google/guava/guava/${GUAVA}/guava-${GUAVA}.jar"; \
    echo "${GUAVA_SHA}  guava.jar" | sha256sum -c -; \
    mkdir /tmp/guava; \
    unzip -q guava.jar 'com/google/common/*' 'com/google/thirdparty/*' 'META-INF/maven/com.google.guava/guava/*' -d /tmp/guava; \
    jar="/out/jadx/lib/jadx-${JADX}-all.jar"; \
    zip -q -d "$jar" 'META-INF/maven/com.google.guava/guava/*'; \
    (cd /tmp/guava && zip -q -r "$jar" com META-INF); \
    unzip -p "$jar" META-INF/maven/com.google.guava/guava/pom.properties | grep -qx "version=${GUAVA}"; \
    JAVA_HOME=/out/jre /out/jadx/bin/jadx --version | grep -qx "${JADX}"

FROM ${CORE_IMAGE}
USER root
COPY --from=python-tools /opt/pathos/mobile/ /opt/pathos/mobile/
COPY --from=java /out/jre/ /opt/pathos/mobile/jre/
COPY --from=java /out/jadx/ /opt/pathos/mobile/jadx/
COPY --chmod=0755 workers/mobile/bin/pathos-mobile /opt/pathos/mobile/bin/pathos-mobile
COPY workers/mobile/bin/pathos_mobile_checks.py /opt/pathos/mobile/share/pathos_mobile_checks.py
COPY workers/mobile/quark-rules/ /opt/pathos/mobile/quark-rules/
COPY workers/mobile/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    # APKLeaks looks for jadx on PATH (it would download one otherwise).
    ln -s /opt/pathos/mobile/jadx/bin/jadx /usr/local/bin/jadx; \
    chmod -R go-w /opt/pathos/mobile /opt/pathos/tools.d; \
    for t in /opt/pathos/mobile/bin/pathos-mobile /opt/pathos/mobile/bin/mobsfscan /opt/pathos/mobile/bin/apkleaks /opt/pathos/mobile/bin/quark; do test -x "$t"; done; \
    for t in mobsfscan apkleaks quark checks; do /opt/pathos/mobile/bin/pathos-mobile version "$t"; done
USER 10001:10001
# The virtual environment comes last on PATH, so it never shadows the core
# image's commands (libsast runs "semgrep" from PATH).
ENV PATHOS_WORKER_FAMILY=mobile PATHOS_TOOLS_DIR=/opt/pathos/tools.d JAVA_HOME=/opt/pathos/mobile/jre \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/pathos/mobile/bin
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
