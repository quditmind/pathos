# syntax=docker/dockerfile:1
# PATHOS API image: pathos (api|jobs roles) + pathosctl on distroless static.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# Build metadata (docs/OPERATIONS.md, "Build metadata"): served by
# GET /api/v1/meta and printed by `pathosctl version`.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    BI=pathos/internal/platform/buildinfo; \
    LDFLAGS="-s -w -X ${BI}.Version=${VERSION} -X ${BI}.Commit=${COMMIT} -X ${BI}.BuildDate=${BUILD_DATE}"; \
    CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o /out/pathos ./cmd/pathos && \
    CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o /out/pathosctl ./cmd/pathosctl && \
    mkdir -p /out/state/sources /out/state/work

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/pathos /out/pathosctl /usr/local/bin/
# Mount points for the encrypted source store and import scratch space;
# named volumes inherit this ownership on first use.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/state /var/lib/pathos
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pathos"]
