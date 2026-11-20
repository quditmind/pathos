# Example shop API image (test fixture).
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/api"]
