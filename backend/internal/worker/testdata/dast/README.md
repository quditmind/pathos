# worker-dast fixtures

Real reports of the worker-dast tools, used by `manifests_dast_test.go`.
They were produced by running each manifest's command (`dast-run <tool> …`)
in the worker-dast image built with `WITH_SQLMAP=true WITH_NIKTO=true`,
against the deliberately vulnerable application in `vulnapp/` (never deploy
it). Nothing else was scanned; no network had a route to the internet.

Setup (Docker; every name has the `b3-` prefix and was removed afterwards):

```sh
docker build -t b3-vulnapp:dev backend/internal/worker/testdata/dast/vulnapp
docker network create --internal b3-scan     # scanner + egress proxy
docker network create --internal b3-target   # egress proxy + application
docker run -d --name b3-vulnapp --network b3-target b3-vulnapp:dev
# Squid with deploy/egress/squid.conf, allowlist "b3-vulnapp" and a conf.d
# override for its private address (acl … dstdomain b3-vulnapp; http_access allow …)
docker run -d --name b3-egress --network b3-scan \
  -v $PWD/deploy/egress/squid.conf:/etc/squid/squid.conf:ro \
  -v <allowlist>:/etc/squid/allowlist.txt:ro -v <conf.d>:/etc/squid/conf.d:ro ubuntu/squid:7.2-26.04_edge
docker network connect b3-target b3-egress
```

Each run (the worker's container restrictions; the scanner reaches the
application only through the egress proxy):

```sh
docker run --rm --network b3-scan --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -u 10001:10001 -e HOME=/tmp/home -e HTTP_PROXY=http://b3-egress:3128 -e HTTPS_PROXY=http://b3-egress:3128 \
  -e PATHOS_TARGET_RATE_LIMIT=20 -v $PWD/out:/out --entrypoint /opt/pathos/dast/bin/dast-run pathos-worker-dast \
  <tool> <target URL> /out/<report> /tmp/work [/out/openapi.json]
```

| Fixture | Tool | Target URL |
|---|---|---|
| `zap-baseline.json` | `zap-baseline` | `http://b3-vulnapp/` |
| `zap-full-scan.json` | `zap-full-scan` (manifest `zap`) | `http://b3-vulnapp/` |
| `zap-api-scan.json` | `zap-api-scan` | `http://b3-vulnapp/` with `openapi.json` |
| `wapiti.json` | `wapiti` | `http://b3-vulnapp/` |
| `dalfox.json` | `dalfox` | `http://b3-vulnapp/search?q=apple` |
| `ffuf.json` | `ffuf` | `http://b3-vulnapp/` |
| `sqlmap.csv` | `sqlmap` | `http://b3-vulnapp/item?id=1` |
| `nikto.json` | `nikto` | `http://b3-vulnapp/` |
| `testssl.json` | `testssl` | `https://b3-vulnapp/` |
| `sslyze.json` | `sslyze` | `https://b3-vulnapp/` |
| `schemathesis.json` | `schemathesis` | `http://b3-vulnapp/` with `openapi.json` |
| `arjun.json` | `arjun` | `http://b3-vulnapp/hidden` |

`openapi.json` is the application's `/openapi.json` with its `servers` set
to the absolute URL, as PATHOS requires for API targets.
