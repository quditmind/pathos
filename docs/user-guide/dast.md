---
title: DAST tools (worker-dast)
section: user-guide
order: 15
version: "2.0"
updated: 2026-11-19
summary: The worker-dast family image (OWASP ZAP, Wapiti, Dalfox, ffuf, testssl.sh, SSLyze, Schemathesis, Arjun, and opt-in sqlmap and Nikto) for web application and API scan targets; safety, authorization, rate limits and what each tool reports.
---
# DAST tools (worker-dast)

The `worker-dast` family worker adds dynamic testing tools to **web application** (`url`) and **API** (`api`) [scan targets](scanning.md). They test a running application over the network, so they are off until an administrator starts the worker, someone adds them to a target, and the target is authorized for them.

## Safety and authorization

Read this before you select a tool.

- **Only systems you may test.** Every worker-dast tool sends requests to the target. A target needs an **authorization statement** (*I am authorized to test this application*; your user and the time are recorded) before any of them can run. A changed address needs a new statement.
- **Intrusive testing is a second, separate authorization.** Tools marked *intrusive* send attacks: injection payloads, XSS probes, fuzzed input, content discovery requests, active scan rules. They can change or delete data, fill logs, trigger alerts, lock accounts or slow the application down. They run only when the target's **intrusive testing authorized** flag is set (who, when and a reference such as a test window or ticket are recorded and audited as `scan_target.intrusive_authorize` and `scan_target.intrusive_revoke`). A scan that includes an intrusive tool is refused (`409`) without the flag, and the worker checks the flag again before it starts each intrusive tool. Changing the target's address withdraws the flag.
- **Prefer test and staging systems.** Run intrusive tools against production only in an agreed window, with a backup, and with the owners informed.
- **Only the target host.** Each tool runs through the image's `dast-run` helper. It starts a local proxy that forwards only requests and TLS connections to the target's host (on the target's port, 80 or 443) and refuses every other host, including third-party services, update servers and out-of-band callback servers; refused attempts are listed in the scan log. Everything goes on through the worker's egress proxy, so the host must also be on the egress allowlist (`deploy/egress/allowlist.txt`; private addresses need an override in `deploy/egress/conf.d`). The egress access log records every request.
- **Rate limit.** The target's rate limit (*Rate limit*, 1–100 requests per second, default 20) is enforced by that proxy for every new request and TLS connection, and is also passed to each tool's own rate option (ZAP's rate limit rule, Dalfox, ffuf, Schemathesis and Arjun `--rate-limit`, sqlmap and Nikto delays). Requests inside a kept-alive TLS connection are limited by the tool's own option.
- **No credentials.** Target credentials (basic or header authentication) are **not** passed to these tools yet: their reports can contain request headers, and raw reports are stored unchanged. They test what an anonymous visitor can reach. Nuclei (built in) still uses the target's credentials.
- **Fixed options.** The tools run with reviewed options only; nothing in the target or in PATHOS can add command-line options. Modules or options that contact third parties are never used (for example Wapiti's SSRF and Log4Shell modules, Arjun's passive sources, Dalfox's remote payloads and blind XSS callbacks, ZAP's out-of-band service and telemetry, Nikto's version check and submissions). In the test runs the scope proxy refused, among others, Nikto's requests for its telemetry server and for the cloud metadata address `169.254.169.254` (Nikto's open-proxy checks).
- **Time limits.** Each tool has a timeout (manifest), and the scan profile's timeout also applies.

## Tools

| Tool (key) | Target kinds | Intrusive | What it does |
|---|---|---|---|
| OWASP ZAP baseline scan (`zap-baseline`) | URL, API | no | Spiders the application for up to 5 minutes and runs the passive scan rules (headers, cookies, information disclosure). No attacks |
| OWASP ZAP full scan (`zap`) | URL, API | yes | Spider, passive rules and the active scan rules (SQL and command injection, XSS, path traversal, and more), at most 60 minutes |
| OWASP ZAP API scan (`zap-api-scan`) | API | yes | Imports the target's OpenAPI document and runs the passive and active rules on every operation. Findings are recorded as *API security* |
| Wapiti (`wapiti`) | URL, API | yes | Crawls the target's folder and runs its attack modules (injection, XSS, open redirect, CRLF, file upload, CSRF, backup files, HTTP methods, Shellshock) |
| Dalfox (`dalfox`) | URL, API | yes | XSS in the parameters of the target URL and the parameters it finds on that page. It does not crawl: give the target URL of a page with parameters (for example `https://app.example.com/search?q=x`) |
| ffuf (`ffuf`) | URL, API | yes | Requests about 130 well-known paths below the target URL (exposed `.git` and `.env` files, backups, admin and debug endpoints) |
| testssl.sh (`testssl`) | https URL, API | no | TLS protocols, cipher suites, certificate and known TLS vulnerabilities. Findings are recorded as *misconfiguration*. An http target gives no findings |
| SSLyze (`sslyze`) | https URL, API | no | TLS configuration checked against Mozilla's intermediate profile, certificate validation, known TLS vulnerabilities. *misconfiguration* |
| Schemathesis (`schemathesis`) | API | yes | Generated requests for every operation of the OpenAPI document (examples, coverage, fuzzing and stateful phases); reports server errors and responses that do not match the schema. *API security* |
| Arjun (`arjun`) | URL, API | yes | Finds hidden query parameters of the target URL (informational findings) |
| sqlmap (`sqlmap`) | URL, API | yes | SQL injection detection (batch mode, `--risk=1 --level=1`, the target URL, its forms and a crawl of depth 2). It never dumps data, reads or writes files or runs commands. *Database security*. **Opt-in build only** |
| Nikto (`nikto`) | URL, API | yes | Web server checks (dangerous files, outdated software, misconfiguration), all categories except denial of service. **Opt-in build only** |

## Using them

1. An administrator starts the worker ([operations guide](../OPERATIONS.md#family-worker-images): `COMPOSE_PROFILES=dast`, then `docker compose up -d worker-dast`) and adds the application's host to the egress allowlist.
2. Create or edit a web application or API target (**Scanning → Scan targets**), confirm the authorization statement and choose the tools under **Additional tools**. Intrusive tools are marked *intrusive*.
3. For intrusive tools, tick **Intrusive testing authorized** and record the reference (test window, ticket).
4. Scan the target. The tools run after the built-in scanners on the `worker-dast` worker; each tool's raw report is kept with the scan, and findings show the tool under *Detected by*.

A scan that needs a worker-dast tool waits for a `worker-dast` worker; if none is online, another worker runs the scan and marks the tool as skipped.

## Opt-in tools: sqlmap and Nikto

They are not in the published image because of their licence terms: sqlmap's licence treats software that runs sqlmap and parses its results as a derived work, and Nikto's databases may be distributed only with the full Nikto package and used only with Nikto. An administrator who has checked that these terms fit their use can build the image with them: set `PATHOS_DAST_WITH_SQLMAP=true` and/or `PATHOS_DAST_WITH_NIKTO=true` in `.env` and run `docker compose --profile dast build worker-dast`. Their catalog entries are *restricted*.
