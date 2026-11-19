# syntax=docker/dockerfile:1
# PATHOS worker-iac: the core worker image plus the infrastructure-as-code
# and CI/CD pipeline family tools KICS, KubeLinter, Kubescape, TFLint,
# Conftest (PATHOS policy bundle), Hadolint, cfn-lint, cfn_nag, Polaris,
# kube-score, Trivy (config mode, the core image's binary) and OpenSSF
# Scorecard (--local). The tools are defined only by manifests
# (workers/iac/tools.d, installed read-only at /opt/pathos/tools.d).
# Build context: repository root.
#
# A family image extends the core image (see workers/sast/Dockerfile): a
# family worker runs every job the core worker runs, plus the jobs that use
# its family's tools. CORE_IMAGE is the worker-core image of the same PATHOS
# version (CI and docker compose pass it).
#
# Every download is pinned: Go tools by module version (integrity: Go
# checksum database) or by the SHA-256 of the source archive (Polaris),
# rule and framework data by SHA-256, Hadolint by version and SHA-256,
# Python packages by version and SHA-256 (pip --require-hashes), Ruby gems
# by version and SHA-256 (Gemfile.lock CHECKSUMS). Every tool runs offline
# (network: none); repository code is never built or executed.

ARG CORE_IMAGE=pathos-worker-core:dev

# Go tools, built from their modules with the current toolchain (the
# upstream release binaries are built with older Go releases). Patched
# dependencies (Go checksum database), for fixable HIGH/CRITICAL CVEs in the
# versions the releases require: KubeLinter 0.8.3 (containerd,
# klauspost/compress, x/crypto, x/net, x/text, grpc, oras-go), Conftest
# 0.71.1 (go-jose, x/net), kube-score 1.20.0 (x/net, x/text) and Polaris
# 10.2.6 (x/net).
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gotools
ARG KICS=2.2.1 KUBE_LINTER=0.8.3 KUBESCAPE=4.0.21 TFLINT=0.66.0 CONFTEST=0.71.1 KUBE_SCORE=1.20.0 SCORECARD=5.7.0
ARG POLARIS=10.2.6 POLARIS_SHA=80cb945283bf2c50856054fd07c924d68b755d9f52fdb39b2a009ed360c5420c
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build set -eux; \
    # build <module@version> <package> <ldflags> <name> [dependency upgrades]
    build() { \
      dir="$(go mod download -json "$1" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"; \
      rm -rf /src; cp -r "$dir" /src; chmod -R u+w /src; cd /src; \
      shift; pkg="$1" ld="$2" name="$3"; shift 3; \
      if [ "$#" -gt 0 ]; then go get "$@"; fi; \
      CGO_ENABLED=0 go build -trimpath -ldflags "-s -w $ld" -o "/out/$name" "$pkg"; cd /; \
      go version "/out/$name" | grep -q "go1.27.4"; \
    }; \
    build "github.com/Checkmarx/kics/v2@v${KICS}" ./cmd/console "-X github.com/Checkmarx/kics/v2/internal/constants.Version=v${KICS}" kics; \
    # KICS queries and Rego libraries of the same release (module source).
    mkdir -p /data/kics/assets; cp -r /src/assets/queries /src/assets/libraries /data/kics/assets/; \
    build "golang.stackrox.io/kube-linter@v${KUBE_LINTER}" ./cmd/kube-linter "-X golang.stackrox.io/kube-linter/internal/version.version=${KUBE_LINTER}" kube-linter \
      github.com/containerd/containerd@v1.7.33 github.com/klauspost/compress@v1.18.7 golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.62.0 \
      golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.83.2 oras.land/oras-go/v2@v2.6.2; \
    build "github.com/kubescape/kubescape/v4@v${KUBESCAPE}" . "-X main.version=v${KUBESCAPE}" kubescape; \
    build "github.com/terraform-linters/tflint@v${TFLINT}" . "" tflint; \
    build "github.com/open-policy-agent/conftest@v${CONFTEST}" . "-X github.com/open-policy-agent/conftest/internal/version.Version=${CONFTEST}" conftest \
      github.com/go-jose/go-jose/v4@v4.1.6 golang.org/x/net@v0.62.0; \
    build "github.com/zegl/kube-score@v${KUBE_SCORE}" ./cmd/kube-score "-X main.version=${KUBE_SCORE}" kube-score \
      golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0; \
    build "github.com/ossf/scorecard/v5@v${SCORECARD}" . "-X sigs.k8s.io/release-utils/version.gitVersion=v${SCORECARD}" scorecard; \
    # Polaris' module path has no major version suffix, so its v10 releases
    # cannot be fetched as a module: GitHub source archive by SHA-256; its
    # dependencies are verified against go.sum and the checksum database.
    wget -q -O /tmp/polaris.tgz "https://github.com/FairwindsOps/polaris/archive/refs/tags/v${POLARIS}.tar.gz"; \
    echo "${POLARIS_SHA}  /tmp/polaris.tgz" | sha256sum -c -; \
    rm -rf /src; mkdir /src; tar -xzf /tmp/polaris.tgz -C /src --strip-components=1; cd /src; \
    go get golang.org/x/net@v0.62.0; \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${POLARIS}" -o /out/polaris .; cd /; \
    go version /out/polaris | grep -q "go1.27.4"

# Kubescape frameworks, exceptions, attack tracks and control inputs
# (offline scans with --use-artifacts-from; nothing is downloaded or uploaded
# at scan time): the assets of a pinned kubescape/regolibrary release,
# verified against the release's checksums.txt, whose SHA-256 is pinned.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS kubescape-artifacts
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
ARG REGOLIBRARY=2.0.39 REGOLIBRARY_SUMS=3298400566bfd42670ba16c40556169d6bd59a1e80ab11c54ce041c6325ad8cc
RUN set -eux; \
    mkdir -p /dl /data/kubescape; cd /dl; \
    base="https://github.com/kubescape/regolibrary/releases/download/v${REGOLIBRARY}"; \
    curl -fsSL --retry 3 -o checksums.txt "$base/checksums.txt"; \
    echo "${REGOLIBRARY_SUMS}  checksums.txt" | sha256sum -c -; \
    frameworks="agentruntimehardening allcontrols armobest cis-aks-t1.2.0 cis-aks-t1.8.0 cis-eks-t1.7.0 cis-eks-t1.8.0 cis-gke-v1.9.0 \
      cis-v1.10.0 cis-v1.12.0 clusterscan devopsbest ism mitre nsa soc2 workloadscan"; \
    for a in $frameworks exceptions attack_tracks default_config_inputs; do \
      curl -fsSL --retry 3 -o "$a" "$base/$a"; \
      grep -E "^[0-9a-f]{64}  $a\$" checksums.txt | sha256sum -c -; \
    done; \
    for a in $frameworks exceptions; do cp "$a" "/data/kubescape/$a.json"; done; \
    cp attack_tracks /data/kubescape/attack-tracks.json; cp default_config_inputs /data/kubescape/controls-inputs.json; \
    chmod 0644 /data/kubescape/*

# Hadolint: GitHub release binary (statically linked; SHA-256 from the
# release's checksums.sha256).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS hadolint
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
ARG HADOLINT=2.15.1 HADOLINT_SHA=c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507
RUN set -eux; \
    mkdir -p /out; \
    curl -fsSL --retry 3 -o /out/hadolint "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT}/hadolint-linux-x86_64"; \
    echo "${HADOLINT_SHA}  /out/hadolint" | sha256sum -c -; \
    chmod 0755 /out/hadolint; /out/hadolint --version | grep -q "${HADOLINT}"

# cfn-lint in its own virtual environment (CPython 3.13, the interpreter of
# the core image).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python-tools
COPY workers/iac/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip set -eux; \
    python -m venv /opt/pathos/iac/venv; \
    /opt/pathos/iac/venv/bin/pip install --no-compile --require-hashes --no-deps -r /tmp/requirements.txt; \
    /opt/pathos/iac/venv/bin/cfn-lint --version; \
    /opt/pathos/iac/venv/bin/python -m pip uninstall -y pip; \
    find /opt/pathos/iac/venv -name '__pycache__' -prune -exec rm -rf {} +

# cfn_nag (Ruby): gems installed by Bundler from the checksummed lockfile;
# native extensions are compiled here, the runtime image only gets Ruby.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS ruby-tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates ruby ruby-dev ruby-bundler build-essential libyaml-dev \
    && rm -rf /var/lib/apt/lists/*
COPY workers/iac/ruby/Gemfile workers/iac/ruby/Gemfile.lock /opt/pathos/iac/ruby/
WORKDIR /opt/pathos/iac/ruby
RUN set -eux; \
    bundle config set --local deployment true; \
    bundle config set --local path /opt/pathos/iac/ruby/gems; \
    bundle config set --local without development:test; \
    bundle install --jobs 4; \
    bundle binstubs cfn-nag --path /opt/pathos/iac/ruby/bin; \
    /opt/pathos/iac/ruby/bin/cfn_nag_scan --version; \
    rm -rf /opt/pathos/iac/ruby/gems/ruby/*/cache

FROM ${CORE_IMAGE}
USER root
# Ruby for cfn_nag (Debian package of the same release as the builder).
RUN apt-get update && apt-get install -y --no-install-recommends ruby && rm -rf /var/lib/apt/lists/*
COPY --from=gotools /out/ /opt/pathos/iac/bin/
COPY --from=gotools /data/kics/ /opt/pathos/iac/kics/
COPY --from=kubescape-artifacts /data/kubescape/ /opt/pathos/iac/kubescape/
COPY --from=hadolint /out/hadolint /opt/pathos/iac/bin/hadolint
COPY --from=python-tools /opt/pathos/iac/venv/ /opt/pathos/iac/venv/
COPY --from=ruby-tools /opt/pathos/iac/ruby/ /opt/pathos/iac/ruby/
COPY --chmod=0755 workers/iac/bin/ /opt/pathos/iac/bin/
COPY workers/iac/policy/ /opt/pathos/iac/policy/
COPY workers/iac/polaris.yaml workers/iac/tflint.hcl /opt/pathos/iac/
COPY workers/iac/tools.d/ /opt/pathos/tools.d/
RUN set -eux; \
    chmod 0644 /opt/pathos/iac/bin/iacfiles.py; \
    # The policy bundle's unit tests run here and are not installed.
    /opt/pathos/iac/bin/conftest verify --no-color --policy /opt/pathos/iac/policy; \
    rm /opt/pathos/iac/policy/*_test.rego; \
    chmod -R go-w /opt/pathos/iac /opt/pathos/tools.d; \
    for t in kics kics-scan kube-linter kubescape kubescape-scan tflint conftest conftest-tree kube-score scorecard polaris hadolint \
             hadolint-tree cfn-lint-tree cfn-nag-tree kube-score-tree; do test -x "/opt/pathos/iac/bin/$t"; done; \
    /opt/pathos/iac/bin/cfn-nag-tree --version; /opt/pathos/iac/bin/hadolint-tree --version | grep -q 2.15.1; \
    # A repository without Kubernetes manifests is an empty result, not a
    # failure (the bundled Kubescape's wording is matched by kubescape-scan).
    mkdir /tmp/ks-empty; echo 'foo: bar' > /tmp/ks-empty/config.yml; \
    /opt/pathos/iac/bin/kubescape-scan /tmp/ks-empty /tmp/ks-empty.json; test ! -s /tmp/ks-empty.json; rm -rf /tmp/ks-empty /tmp/ks-empty.json
USER 10001:10001
ENV PATHOS_WORKER_FAMILY=iac PATHOS_TOOLS_DIR=/opt/pathos/tools.d
ENTRYPOINT ["/usr/local/bin/pathos-worker"]
