# syntax=docker/dockerfile:1
# PATHOS API image: pathos (api|jobs roles) + pathosctl on distroless static.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X pathos/internal/server.Version=${VERSION}" -o /out/pathos ./cmd/pathos && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/pathosctl ./cmd/pathosctl

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/pathos /out/pathosctl /usr/local/bin/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pathos"]
