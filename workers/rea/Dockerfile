# syntax=docker/dockerfile:1
# PATHOS worker-rea: reverse engineering, static tier (PATHOS 3.0 M10,
# ADR-009). pathos-rea (workers/rea/analyse) analyses an uploaded build
# artifact and writes normalised facts (pathos.rea/v1: sections, functions,
# imports, strings with secrets redacted, the call graph): radare2 for
# triage, references and disassembly, binwalk for firmware extraction,
# ILSpy (ilspycmd) for .NET assemblies, and, when built with WITH_GHIDRA or
# WITH_JADX, Ghidra headless (decompiled pseudo-C, call graph) and Jadx
# (Android packages, Java archives). Build context: repository root.
#
# The artifact is never executed. pathos-rea never runs in the worker
# container either: the same image also runs as the sandbox runner
# (`pathos-worker sandbox-runner`, compose service worker-rea-sandbox:
# network_mode none, UID 10002, no worker token, read-only root filesystem,
# no capabilities, its own CPU, memory and pids limits), which runs
# pathos-rea for the worker through a shared volume. The worker itself is
# only on the internal worker-api network.
#
# Unlike the other family images this one does not extend worker-core (no
# scanners are needed): it is Debian trixie with the pathos-worker agent
# built from this repository with the same build metadata as worker-core.
# Every download is pinned: images by digest, radare2, Ghidra, Jadx and
# ilspycmd by version and SHA-256, binwalk by crate version, SHA-256 and Cargo.lock
# (crates.io checksums, cargo install --locked).

# The worker agent (as in workers/core/Dockerfile).
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS agent
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY backend/ ./
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    BI=pathos/internal/platform/buildinfo; \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X ${BI}.Version=${VERSION} -X ${BI}.Commit=${COMMIT} -X ${BI}.BuildDate=${BUILD_DATE}" -o /out/pathos-worker ./cmd/pathos-worker

# pathos-rea: pure Go, no cgo.
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG VERSION=dev
WORKDIR /src
COPY workers/rea/analyse/go.mod ./
COPY workers/rea/analyse/*.go ./
COPY workers/rea/analyse/ghidra/ ./ghidra/
RUN --mount=type=cache,target=/root/.cache/go-build set -eux; \
    rm -f ./*_test.go; \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.Version=${VERSION}" -o /out/pathos-rea .; \
    /out/pathos-rea version

# binwalk 3 (Rust, MIT) from crates.io with its locked dependencies. The
# crate is pinned by its crates.io SHA-256 and patched before the build:
# binwalk 3.1.0's main loop waits on ThreadPool::active_count(), which does
# not count a job that no pool thread has picked up yet nor a result still in
# the channel, so on a busy CPU it could exit 0 with nothing analysed, logged
# or extracted (binwalk-worker-pool-race.patch; upstream main still has it).
FROM rust:1.100.0-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS binwalk
ARG BINWALK=3.1.0
ARG BINWALK_SHA256=99d5dc70f5021c55624f098adae4d1de9c1c07d000475664704b675aad7e0811
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libfontconfig1-dev liblzma-dev libbz2-dev zlib1g-dev curl patch \
    && rm -rf /var/lib/apt/lists/*
COPY workers/rea/binwalk-worker-pool-race.patch /tmp/binwalk.patch
RUN --mount=type=cache,target=/usr/local/cargo/registry set -eux; \
    curl -fsSL -o /tmp/binwalk.crate "https://static.crates.io/crates/binwalk/binwalk-${BINWALK}.crate"; \
    echo "${BINWALK_SHA256}  /tmp/binwalk.crate" | sha256sum -c -; \
    mkdir /tmp/binwalk; tar -xzf /tmp/binwalk.crate -C /tmp/binwalk --strip-components 1; \
    patch -d /tmp/binwalk -p1 --forward < /tmp/binwalk.patch; \
    cargo install --locked --path /tmp/binwalk --root /out; \
    /out/bin/binwalk -V | grep -q "${BINWALK}"; \
    mkdir -p /out/licenses; \
    cp /tmp/binwalk/LICENSE /out/licenses/binwalk-LICENSE

# The JDK for the optional Ghidra and Jadx (Eclipse Temurin 25, GPL-2.0
# with Classpath Exception); copied only when one of them is built in.
FROM eclipse-temurin:25-jdk-noble@sha256:8599ea2d8f71696f00dcdf46213a4b65fa97ceeaa318671fccba6b0af2727792 AS jdk

# Pinned downloads.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS downloads
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
COPY --from=jdk /opt/java/openjdk /jdk-src
ARG R2=6.2.6 R2_SHA=0dddf90e217e38a6a658881b9ec7e217198487c75b7f82a332b3cbd30834636f
ARG WITH_ILSPY=true ILSPY=11.2.0.10050 ILSPY_SHA=5be3af86839e93075d103e5b4fec73a637b8d70e49c97eaf043ebe55b7c7800d
ARG WITH_GHIDRA=false GHIDRA=12.2 GHIDRA_DATE=20261016 GHIDRA_SHA=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67 \
    GUAVA=33.7.2-jre GUAVA_SHA=b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c
ARG WITH_JADX=false JADX=1.5.7 JADX_SHA=1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3
RUN set -eux; \
    mkdir -p /out/rea/licenses /out/rea/versions /out/rea/bin /out/deb; \
    curl -fsSL --retry 3 -o /out/deb/radare2.deb "https://github.com/radareorg/radare2/releases/download/${R2}/radare2_${R2}_amd64.deb"; \
    echo "${R2_SHA}  /out/deb/radare2.deb" | sha256sum -c -; \
    if [ "${WITH_ILSPY}" = true ]; then \
      # ilspycmd for linux-x64 is a native ahead-of-time build (no .NET runtime needed).
      curl -fsSL --retry 3 -o ilspy.nupkg "https://api.nuget.org/v3-flatcontainer/ilspycmd.linux-x64/${ILSPY}/ilspycmd.linux-x64.${ILSPY}.nupkg"; \
      echo "${ILSPY_SHA}  ilspy.nupkg" | sha256sum -c -; \
      unzip -q -o ilspy.nupkg 'tools/any/linux-x64/ilspycmd' -d /tmp/ilspy; \
      install -m 0755 /tmp/ilspy/tools/any/linux-x64/ilspycmd /out/rea/bin/ilspycmd; \
      DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 /out/rea/bin/ilspycmd --version | grep -q "${ILSPY}"; \
      echo "${ILSPY}" > /out/rea/versions/ilspy; \
      printf 'ILSpy / ilspycmd %s: MIT (https://github.com/icsharpcode/ILSpy, NuGet licence expression MIT)\n' "${ILSPY}" > /out/rea/licenses/ilspy-LICENSE.txt; \
    fi; \
    if [ "${WITH_GHIDRA}" = true ]; then \
      curl -fsSL --retry 3 -o ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA}_build/ghidra_${GHIDRA}_PUBLIC_${GHIDRA_DATE}.zip"; \
      echo "${GHIDRA_SHA}  ghidra.zip" | sha256sum -c -; \
      unzip -q ghidra.zip -d /tmp/ghidra; \
      mv /tmp/ghidra/ghidra_${GHIDRA}_PUBLIC /out/rea/ghidra; \
      # Headless analysis only: no documentation, GUI-only extensions or server.
      rm -rf /out/rea/ghidra/docs /out/rea/ghidra/Extensions /out/rea/ghidra/server /out/rea/ghidra/Ghidra/Debug /out/rea/ghidra/GPL/DemanglerGnu/os/win_x86_64 \
        /out/rea/ghidra/Ghidra/Features/*/os/win_x86_64 /out/rea/ghidra/Ghidra/Features/*/os/mac_* /out/rea/ghidra/Ghidra/Features/*/os/linux_arm_64; \
      # The Ghidra Server service wrapper (bundles an outdated Netty) is not
      # needed headless; Guava is updated to a release without known
      # vulnerabilities (same API, Maven Central, SHA-256 pinned).
      rm -rf /out/rea/ghidra/Ghidra/Features/GhidraServer/data/yajsw-*; \
      find /out/rea/ghidra -name '*-src.zip' -delete; \
      curl -fsSL --retry 3 -o guava.jar "https://repo1.maven.org/maven2/com/google/guava/guava/${GUAVA}/guava-${GUAVA}.jar"; \
      echo "${GUAVA_SHA}  guava.jar" | sha256sum -c -; \
      g=/out/rea/ghidra/Ghidra/Framework/Generic; old="$(basename "$(ls $g/lib/guava-*.jar)")"; \
      rm "$g/lib/$old"; install -m 0644 guava.jar "$g/lib/guava-${GUAVA}.jar"; \
      sed -i "s/$old/guava-${GUAVA}.jar/" "$g/Module.manifest"; \
      cp /out/rea/ghidra/LICENSE /out/rea/licenses/ghidra-LICENSE; \
      echo "${GHIDRA}" > /out/rea/versions/ghidra; \
    fi; \
    if [ "${WITH_JADX}" = true ]; then \
      curl -fsSL --retry 3 -o jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX}/jadx-${JADX}.zip"; \
      echo "${JADX_SHA}  jadx.zip" | sha256sum -c -; \
      unzip -q jadx.zip -d /out/rea/jadx; \
      rm -f /out/rea/jadx/bin/*.bat /out/rea/jadx/bin/jadx-gui; \
      cp /out/rea/jadx/LICENSE /out/rea/licenses/jadx-LICENSE; \
      echo "${JADX}" > /out/rea/versions/jadx; \
    fi; \
    if [ "${WITH_GHIDRA}" = true ] || [ "${WITH_JADX}" = true ]; then \
      cp -a /jdk-src /out/rea/jdk; \
      rm -rf /out/rea/jdk/jmods /out/rea/jdk/lib/src.zip /out/rea/jdk/demo /out/rea/jdk/man; \
      cp /out/rea/jdk/legal/java.base/LICENSE /out/rea/licenses/temurin-jdk-LICENSE; \
    fi

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# Runtime libraries of binwalk (fontconfig is linked for its entropy plot).
RUN --mount=type=bind,from=downloads,source=/out/deb,target=/deb set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libfontconfig1 liblzma5 libbz2-1.0 zlib1g; \
    dpkg -i /deb/radare2.deb; \
    rm -rf /var/lib/apt/lists/* /usr/share/doc/radare2/examples; \
    r2 -v | grep -q 'radare2 6.2.6'; \
    groupadd -g 10001 pathos; useradd -u 10001 -g 10001 -M -d /tmp/home -s /usr/sbin/nologin pathos
COPY --from=agent /out/pathos-worker /usr/local/bin/pathos-worker
COPY --from=downloads /out/rea/ /opt/pathos/rea/
COPY --from=binwalk /out/bin/binwalk /usr/local/bin/binwalk
COPY --from=binwalk /out/licenses/ /opt/pathos/rea/licenses/
COPY --from=build /out/pathos-rea /opt/pathos/rea/bin/pathos-rea
RUN set -eux; \
    cp /usr/share/doc/radare2/copyright /opt/pathos/rea/licenses/radare2-copyright 2>/dev/null || true; \
    if [ -d /opt/pathos/rea/ghidra ]; then ln -s /opt/pathos/rea/jdk/bin/java /opt/pathos/rea/bin/java; fi; \
    chown -R root:root /opt/pathos; chmod -R go-w /opt/pathos; \
    /opt/pathos/rea/bin/pathos-rea version | tee /dev/stderr | grep -q '^pathos-rea .*; radare2 6.2.6; binwalk 3.1.0;'; \
    /usr/local/bin/pathos-worker --help >/dev/null 2>&1 || test -x /usr/local/bin/pathos-worker
USER 10001:10001
ENV PATHOS_WORKER_FAMILY=rea \
    PATH=/opt/pathos/rea/bin:/opt/pathos/rea/jdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    JAVA_HOME=/opt/pathos/rea/jdk \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
