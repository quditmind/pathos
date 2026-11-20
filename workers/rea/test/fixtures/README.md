# Reverse-engineering test fixtures (test data only)

Built by `workers/rea/test/rea-e2e.sh` in throw-away containers, never shipped:

- `hello-c/hello.c`: a tiny C program (ELF with imports from libc and a planted
  fake AWS access key string that the analyser must redact).
- `pprof-go/`: a Go service that blank-imports `net/http/pprof` (registers
  `/debug/pprof/*` on the default mux) next to its declared `/api/orders` route:
  the source-versus-binary diff must report the pprof handlers as only in the binary.
- `make-firmware.sh`: writes a firmware-like blob (header, gzip stream, embedded ELF,
  padding) from test data only.

The AWS key `AKIAIOSFODNN7EXAMPLE` is AWS's documented example key, not a credential.
