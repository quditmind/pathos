# Performance at scale

This page reports how PATHOS behaves with a large dataset: how the data was generated, what was measured, the bottlenecks found, what was changed and the numbers before and after. Every number below was measured on the machine described here, with the command shown. Nothing is extrapolated silently: the one estimate is labelled, and the sizing advice is marked as derived from the measurements.

## Test machine

| | |
|---|---|
| CPU | 13th Gen Intel Core i7-13800H, 14 cores / 20 threads (`nproc` = 20) |
| Memory | 30 GiB, 7.4 GiB swap |
| Disk | KIOXIA KXG80ZNV1T02 NVMe SSD, 1 TB (ext4, about 560 GB free) |
| Software | Linux 7.0.0-42, Docker 29.9.3, PostgreSQL 18.7, Go 1.27.4, k6 2.3.0 |

The machine is a developer laptop and was **shared**: another PATHOS stack and other build jobs ran at the same time, the host swap was full and about 12 GiB of memory was available. Absolute numbers on a dedicated server will differ; the before/after comparisons were run back to back on the same stack.

The stack was the normal Compose deployment with the production override, under its own project name, plus a small overlay that adds `pg_stat_statements` (`scripts/load/docker-compose.load.yml`). Resource limits are those of `docker-compose.prod.yml`: API 2 CPUs / 1 GB, jobs 1 CPU / 768 MB, PostgreSQL 4 GB with `shared_buffers=1GB`, `work_mem=16MB`. Rate limiting was off (`PATHOS_RATE_LIMIT_SCALE=0`). No scan workers ran; the ingest test plays the workers itself.

```bash
COMPOSE_PROJECT_NAME=d2 docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f scripts/load/docker-compose.load.yml up -d proxy api jobs scheduler
```

## Tools

| Tool | What it does |
|---|---|
| `backend/cmd/pathos-loadgen` | Development-only Go command (not built into any image). `seed` fills the database, `ingest` drives the worker API, `recompute` times risk re-scoring, `sizes` prints table sizes, `cleanup` removes the synthetic data. |
| `scripts/load/loadgen.sh` | Builds the command and runs it in a container on the stack's internal `data` and `worker-api` networks, as the PostgreSQL superuser from `.env`. |
| `scripts/load/k6-scale.js`, `scripts/load/scale.sh` | k6 test of the read paths (signs in as the bootstrap administrator). Scenarios: `sweep` (one user calls each endpoint in turn: latency without contention), `mixed` (weighted mix at a constant arrival rate), `users` (concurrent users clicking through pages with 1–3 s think time). |
| `scripts/load/summary.py` | Turns a k6 summary into the tables below. |

### How the data gets in

- **Direct SQL** (`pathos-loadgen seed`): repositories, applications, business units, scan history, findings, occurrences, status history and SBOM components. A million findings cannot go through scans in reasonable time on one machine (see the ingest rate below), so they are written with `INSERT … SELECT generate_series`. The database triggers still run (repository and scan keys, SLA deadlines).
- **Real ingest path** (`pathos-loadgen ingest`): scans are queued with the API's own enqueue function, then fake workers register, lease, upload Opengrep SARIF and complete through the worker API, exactly like `pathos-worker`. These findings are created by the real parser, deduplication, auto-resolution and post-scan hooks.
- **Intelligence feeds**: the `jobs` service downloaded the real EPSS (411,421 rows) and CISA KEV (1,838 rows) feeds by itself. The seed adds 5,000 OSV records for the synthetic CVE pool (`intel_vulns`).

Synthetic repositories belong to an archived SCM connection named `loadgen` (or are uploaded repositories with a snapshot record and no stored archive), are not scan-enabled and point at `example.invalid`, so schedules, webhooks and SCM sync never contact anything.

### Dataset (1 million findings)

```bash
COMPOSE_PROJECT_NAME=d2 scripts/load/loadgen.sh seed -repos 10000 -findings 1000000
```

Seeding took **304 s** (5 min 5 s wall clock); the PostgreSQL volume grew to **5.1 GB** (`du -sh` of the volume; database size 4,184 MB).

| Table | Rows | Table + indexes |
|---|---:|---:|
| findings | 1,000,000 | 1,696 MB |
| finding_occurrences | 2,998,673 | 1,056 MB |
| sbom_components | 1,506,044 | 622 MB |
| sbom_dependencies | 1,496,044 | 385 MB |
| scan_results | 400,000 | 130 MB |
| finding_status_history | 529,731 | 123 MB |
| scan_jobs | 100,000 | 66 MB |
| repositories | 10,000 | 12 MB |

Distributions (deterministic, from `seed.go`):

- **Repositories**: 10,000 in 500 applications and 12 business units; 10 % uploaded, 90 % SCM. Findings per repository follow a power law (measured after the ingest tests had added 99,000 findings: median 68, mean 110, largest 15,199).
- **Severity**: critical 3 %, high 17 %, medium 40 %, low 30 %, info 10 %.
- **Category**: SCA 42 %, SAST 22 % (plus code quality 1.5 %), container 12 %, IaC 9 %, secrets 5 %, licence 3 %, misconfiguration, DAST and API 2 % each.
- **Status**: open 50 %, in progress 3 %, needs review 2 %, fixed 32 %, false positive 6 %, accepted risk 7 %; 3 % of open findings were reopened.
- **Duplicates**: CVEs and rules come from shared pools with skewed popularity (5,000 CVEs across 420,000 SCA findings); half of the SCA findings were reported by two scanners (210,465 findings have two scanner keys); 0.5 % carry the human disposition *duplicate*.
- **History**: 10 scans per repository over 10 weeks, 4 scanner results per scan, 1–5 sightings per finding (3 on average), first-seen dates over 14 months.
- **SBOM**: 150 components per repository on average from a pool of 2,400 packages, with licences (MIT 50 %, Apache-2.0 25 %, BSD 10 %, ISC 4 %, GPL-3.0 3 %, AGPL-3.0 1 %, LGPL 2 %, none 5 %) and dependency edges.

## Results with 1 million findings

### Per-endpoint latency, one user (`sweep`)

```bash
COMPOSE_PROJECT_NAME=d2 scripts/load/scale.sh sweep ITER=20
```

20 requests per endpoint, one after another (5 for the last six endpoints before the changes; the SBOM inventory timed out at k6's 120 s limit, so the "before" run was stopped after 3 of its requests). Times are milliseconds; errors are non-2xx responses or timeouts. The executive report's 20 errors before the changes are HTTP 500 responses (change 8 below); its time is the time until the failure.

| Endpoint | Before p50 | p95 | p99 | Errors | After p50 | p95 | p99 | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| dashboard 30d | 6,946 | 8,431 | 8,796 | 0/20 | 2,445 | 2,565 | 2,640 | 0/20 |
| dashboard 365d | 7,275 | 10,593 | 11,162 | 0/20 | 2,518 | 2,564 | 2,565 | 0/20 |
| executive | 15,045 | 15,976 | 18,763 | 20/20 | 2,926 | 2,982 | 3,015 | 0/20 |
| export report csv | 300 | 321 | 323 | 0/5 | 206 | 215 | 220 | 0/20 |
| export sbom spdx | 6 | 8 | 8 | 0/5 | 5 | 7 | 13 | 0/20 |
| finding detail | 4 | 5 | 9 | 0/20 | 3 | 7 | 10 | 0/20 |
| finding history | 2 | 3 | 5 | 0/20 | 2 | 2 | 3 | 0/20 |
| finding risk | 2 | 2 | 3 | 0/20 | 3 | 3 | 4 | 0/20 |
| findings big repository | 87 | 94 | 95 | 0/20 | 74 | 86 | 124 | 0/20 |
| findings by application | 11 | 27 | 29 | 0/20 | 19 | 29 | 35 | 0/20 |
| findings by repository | 7 | 11 | 11 | 0/20 | 8 | 16 | 19 | 0/20 |
| findings kev | 46 | 66 | 67 | 0/20 | 47 | 66 | 146 | 0/20 |
| findings lifecycle new | 514 | 611 | 691 | 0/20 | 21 | 33 | 34 | 0/20 |
| findings list | 1,948 | 2,411 | 3,362 | 0/20 | 6 | 10 | 10 | 0/20 |
| findings page 5 | 2,185 | 2,526 | 2,598 | 0/20 | 10 | 14 | 16 | 0/20 |
| findings severity category | 174 | 302 | 548 | 0/20 | 8 | 16 | 25 | 0/20 |
| findings sla breached | 1,420 | 1,672 | 1,838 | 0/20 | 6 | 11 | 11 | 0/20 |
| findings sort risk | 1,818 | 2,097 | 2,350 | 0/20 | 6 | 10 | 18 | 0/20 |
| findings status all | 3,038 | 3,315 | 3,667 | 0/20 | 5 | 7 | 9 | 0/20 |
| findings summary | 206 | 225 | 226 | 0/20 | 56 | 59 | 59 | 0/20 |
| findings text search | 565 | 729 | 1,133 | 0/20 | 13 | 127 | 283 | 0/20 |
| global search | 5 | 20 | 22 | 0/20 | 7 | 10 | 10 | 0/20 |
| posture aggregate | 1,835 | 1,938 | 1,971 | 0/20 | 1,563 | 1,604 | 1,606 | 0/20 |
| posture applications | 1,825 | 2,059 | 2,127 | 0/20 | 1,565 | 1,590 | 1,592 | 0/20 |
| posture coverage | 159 | 179 | 182 | 0/20 | 135 | 140 | 141 | 0/20 |
| report group by repository | 356 | 575 | 611 | 0/5 | 97 | 104 | 105 | 0/20 |
| report run json | 318 | 1,959 | 2,282 | 0/5 | 197 | 225 | 299 | 0/20 |
| repositories list | 57 | 66 | 71 | 0/20 | 56 | 60 | 64 | 0/20 |
| repositories search | 24 | 35 | 35 | 0/20 | 23 | 31 | 33 | 0/20 |
| repository detail | 4 | 7 | 8 | 0/20 | 4 | 9 | 10 | 0/20 |
| sbom components | 72,789 | 115,283 | 119,061 | 3/3 | 7,879 | 7,933 | 8,136 | 0/20 |
| sbom license violations | 72,233 | 110,472 | 118,096 | 5/5 | 4,310 | 4,344 | 4,389 | 0/20 |
| scans list | 26 | 257 | 304 | 0/5 | 48 | 54 | 67 | 0/20 |

### Throughput under load (`mixed`)

A weighted mix of the main read paths (findings list variants 50 %, summary 8 %, detail and history 11 %, dashboard 6 %, posture 2 %, search, repositories, scans) at a constant arrival rate for 120 s:

```bash
COMPOSE_PROJECT_NAME=d2 scripts/load/scale.sh mixed RATE=5 DURATION=120s ONLY=<the 18 endpoints of the mix>
```

| Run (PostgreSQL memory) | Target req/s | Achieved req/s | p50 | p95 | p99 | Failed | Findings list p50 / p95 | Finding detail p50 / p95 | Dashboard p50 / p95 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Before, 4 GB | 5 | 3.3 | 5,895 | 13,501 | 18,765 | 0.18 % | 9,573 / 12,143 | 7,161 / 10,094 | 21,608 / 66,713 |
| After, 4 GB | 5 | 4.8 | 89 | 16,163 | 23,867 | 0.00 % | 26 / 2,750 | 20 / 4,061 | 16,519 / 24,560 |
| After, 4 GB | 20 | 6.9 | 31,260 | 59,573 | 120,001 | 4.63 % | 28,216 / 42,869 | 24,905 / 62,281 | 119,999 / 120,001 |
| After, 4 GB | 50 | 7.7 | 32,441 | 119,998 | 120,001 | 9.01 % | 28,880 / 48,310 | 31,349 / 120,001 | 120,000 / 120,001 |
| After, 6 GB (`shared_buffers=3GB`) | 5 | 5.0 | 13 | 2,721 | 3,408 | 0.00 % | 9 / 15 | 8 / 15 | 2,862 / 4,271 |
| After, 6 GB (`shared_buffers=3GB`) | 20 | 13.8 | 10,230 | 29,792 | 56,027 | 0.00 % | 8,439 / 18,413 | 13,777 / 29,231 | 33,516 / 57,661 |

Times in milliseconds. Failures are k6 timeouts (120 s). The 6 GB runs were made with `PG_SHARED_BUFFERS=3GB PG_EFFECTIVE_CACHE=5GB PG_MEMORY=6G` (variables of the load overlay) and the same code as the "After, 4 GB" runs; the covering summary index (change 2) was added after these runs. During the 20 req/s runs PostgreSQL used about 16 CPU cores and waited on reads while the API container used about 1 % CPU and 50 MB: the database, not the API, is the limit.

### Concurrent users (`users`)

Each virtual user opens the dashboard, the findings list and its summary, a filtered list, a finding with its history, a repository's findings, a text search, the repositories list, the global search, page 5 of the list and the posture page, with 1–3 s between pages; users ramp up over 30 s and stay for 90 s.

```bash
COMPOSE_PROJECT_NAME=d2 scripts/load/scale.sh users USERS=20 RAMP=30s DURATION=90s
```

| Run (PostgreSQL 4 GB) | Requests | Achieved req/s | p50 | p95 | p99 | Failed | Findings list p50 / p95 | Finding detail p50 / p95 | Dashboard p50 / p95 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Before, 20 users | 568 | 3.4 | 811 | 16,105 | 26,441 | 0.00 % | 4,547 / 6,101 | 10 / 30 | 18,252 / 28,640 |
| After, 20 users | 1,157 | 8.1 | 18 | 3,466 | 4,501 | 0.00 % | 12 / 15 | 8 / 14 | 3,571 / 4,744 |
| After, 50 users | 1,718 | 11.4 | 268 | 11,543 | 17,135 | 0.00 % | 293 / 3,157 | 14 / 4,035 | 12,414 / 18,058 |

With the same think time, the 20 users completed twice as many pages after the changes. Posture took 2.5 s (p50) with 20 users and 8.0 s with 50.

### Scan ingest (worker API)

```bash
COMPOSE_PROJECT_NAME=d2 scripts/load/loadgen.sh ingest -workers 8 -jobs 100 -findings-per-upload 50 -repo-offset 4020 -stride 4
COMPOSE_PROJECT_NAME=d2 scripts/load/loadgen.sh ingest -workers 16 -jobs 50 -findings-per-upload 500 -repo-offset 20 -stride 4
```

Each job runs the default profile (10 scanners): one Opengrep SARIF upload with 50 or 500 results, nine empty results, then *complete*. Round 1 is the first scan of the repositories, round 2 a rescan in which 10 % of the results changed (new and fixed findings). "Before" and "after" used different but comparable repositories (alternate ones from the same range). Before the changes, the jobs service was re-scoring risk at the same time (see below), which explains the slow SARIF upload tail in round 2.

| Run | Workers × results per SARIF | Round | Jobs | Seconds | Jobs/s | Uploads/s | Findings/s | SARIF upload p50 / p95 / p99 ms | Complete p50 / p95 / p99 ms | Errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Before | 8 × 50 | 1 | 100 | 22.3 | 4.5 | 45 | 224 | 33 / 81 / 90 | 1,603 / 1,795 / 1,834 | 0 |
| Before | 8 × 50 | 2 | 100 | 23.8 | 4.2 | 42 | 210 | 39 / 2,973 / 2,992 | 1,471 / 1,599 / 4,467 | 0 |
| After | 8 × 50 | 1 | 100 | 3.3 | 30.3 | 303 | 1,515 | 33 / 89 / 111 | 143 / 292 / 298 | 0 |
| After | 8 × 50 | 2 | 100 | 2.5 | 40.3 | 403 | 2,016 | 35 / 50 / 52 | 99 / 142 / 150 | 0 |
| Before | 16 × 500 | 1 | 50 | 8.6 | 5.8 | 58 | 2,918 | 400 / 500 / 509 | 1,667 / 1,874 / 1,979 | 0 |
| Before | 16 × 500 | 2 | 50 | 16.4 | 3.1 | 31 | 1,529 | 426 / 1,035 / 15,035 | 1,607 / 1,815 / 2,231 | 0 |
| After¹ | 16 × 500 | 1 | 50 | 2.3 | 21.7 | 217 | 10,840 | 315 / 451 / 513 | 189 / 353 / 431 | 0 |
| After¹ | 16 × 500 | 2 | 50 | 2.3 | 21.8 | 218 | 10,893 | 390 / 572 / 600 | 133 / 182 / 195 | 0 |
| After | 32 × 50 | 1 | 100 | 1.7 | 58.9 | 589 | 2,946 | 58 / 85 / 96 | 214 / 340 / 361 | 0 |
| After | 32 × 50 | 2 | 100 | 1.4 | 69.9 | 699 | 3,493 | 77 / 100 / 106 | 158 / 247 / 270 | 0 |

¹ Measured before changes 2 and 4 (summary index, re-scoring batch from the partial index); the other "After" rows are the final code. The "After" runs are short (1.4–4 s), so their rates are less precise than the "Before" ones. Writing findings (the SARIF upload) did not get slower with the four new indexes: 33–35 ms p50 for 50 results before and after. Before the changes, *complete* took 1.5–1.7 s whatever the scan, and that bounded throughput at about 4–6 jobs/s.

### Risk re-scoring

A risk-model change marks every finding for re-scoring; the `jobs` service then re-scores them in batches. Measured directly with `pathos-loadgen recompute` (jobs service stopped) and end to end (all findings marked, jobs service running):

```bash
COMPOSE_PROJECT_NAME=d2 scripts/load/loadgen.sh recompute -limits 500,2000,5000 -findings 100000
```

| Code | Batch | Findings | Seconds | Findings/s | Longest batch |
|---|---:|---:|---:|---:|---:|
| Before (direct) | 2,000 | 20,000 | 43.6 | 459 | 4.60 s |
| Alias lookups fixed (direct, run 1) | 500 / 2,000 / 5,000 / 10,000 | 100,000 each | 29.2 / 36.1 / 45.7 / 35.9 | 3,429 / 2,769 / 2,189 / 2,786 | 0.18 / 1.71 / 2.61 / 3.92 s |
| Alias lookups fixed (direct, run 2) | 2,000 / 500 / 1,000 / 2,000 / 500 | 100,000 each | 36.9 / 31.6 / 36.7 / 40.2 / 39.1 | 2,711 / 3,163 / 2,725 / 2,489 / 2,555 | 0.92 / 0.24 / 0.48 / 1.28 / 0.38 s |
| Final (direct) | 500 / 2,000 / 5,000 / 500 / 2,000 / 5,000 | 100,000 each | 33.6 / 33.0 / 46.3 / 34.0 / 34.3 / 43.3 | 2,979 / 3,028 / 2,158 / 2,943 / 2,916 / 2,308 | 0.27 / 0.71 / 2.64 / 0.23 / 0.84 / 2.25 s |
| Alias lookups fixed, jobs service end to end, batch 2,000 | 2,000 | 1,096,980 | stopped after 552 s with 461,980 left | about 2,900 for the first 450,000, then 450–600 | — |
| Final, jobs service end to end | 500 | 1,045,500 | 371 | 2,816 | — |

Marking all findings for re-scoring (the `UPDATE` a risk-model change runs) took 89 s and 74 s in the two end-to-end runs. Before the changes the end-to-end run was not measured; at the measured 459 findings/s, 1 million findings would take about 36 minutes (an estimate from the direct rate).

## What was changed

Each change keeps the API responses and stored data the same; integration tests compare the new queries with the old definitions where the query was rewritten.

1. **Keyset indexes for the findings list** (migration 00038). The list orders by `(severity rank or risk rank, last_seen_at, id)` and pages with a cursor on the same columns, but no index matched, so every page sorted all open findings (2–3 s at 1 million, external merge sort on disk). Three expression indexes (open findings by severity rank, all findings by severity rank, open findings by risk rank) turn a page into an index range scan: the default list went from 1,948 ms to 6 ms (p50). A unit test fails if the ORDER BY expressions and the indexed expressions drift apart. The migration builds the indexes `CONCURRENTLY` (3.4 s on 1 million findings).
2. **Covering index for the list summary** (migration 00038). The severity counts above the list read every open finding; `(organization_id, status, severity, repository_id)` allows an index-only scan: 417 ms → 79 ms in `EXPLAIN ANALYZE` (after `VACUUM`; the gain shrinks while many rows were changed since the last vacuum).
3. **Vulnerability-intelligence lookups use the GIN index**. `x = ANY(aliases)` cannot use the `intel_vulns` GIN index, so the risk re-scoring query scanned every OSV record twice per finding. `aliases @> ARRAY[x]` is equivalent for non-null values and uses the index: selecting a batch of 2,000 findings went from 3,874 ms to 60 ms. The same rewrite was applied to the OSV enrichment queries.
4. **Risk re-scoring batch** picked from the `risk_dirty` partial index first. Joined directly, the planner walked repositories and their findings looking for dirty rows, which slowed down to about 500 findings/s as the remaining dirty findings thinned out (35 ms instead of 650 ms per batch of 500). The batch size went from 2,000 to 500: the same throughput, but each transaction holds its row locks for about 0.25 s instead of 0.7–0.8 s, so scans and triage touching the same findings wait less.
5. **Human Eye auto-queue after each scan**. After every scan, a query evaluated two correlated subqueries for every open finding of the organization (2.3 s at 1 million), inside the worker's *complete* call. Unless the *new findings* trigger is on, only findings that need review or have an AI review can qualify, so only those are read now (0.1–0.4 s). This was the main limit on scan throughput.
6. **SBOM inventory** (`GET /api/v1/sbom/components`): licences of each (name, version) were collected by a subquery over all components, for every group: quadratic in the inventory size (over 120 s, timed out). Licences and open-vulnerability counts are now computed for the 500 groups on the page only.
7. **Executive report trend**: three correlated counts per week (42 full scans for 90 days) became one pass with a running sum, like the dashboard trend before it: 14.4 s → 1.5 s for that query. An integration test compares every week with the per-week definition, for 30 and 180 days.
8. **Executive report error**: `max(risk_score)` of the top applications and business units was scanned into an integer, so the report failed with HTTP 500 as soon as any risk score had decimals (risk scores have two). It is rounded to an integer in SQL; the ordering still uses the exact value.
9. **Dashboard**: the open, critical, high, secrets, SLA-breach and vulnerable-dependency KPIs and the severity chart share one pass over the open findings instead of six; *resolved* and *mean time to remediate* share one query instead of running it twice; the SBOM component count uses `count(*)` over a `DISTINCT` subquery (hashed) instead of `count(DISTINCT …)` (sorted): 2.5 s → 0.65 s for that query; the independent queries run four at a time. 6.9 s → 2.4 s (p50).
10. **Partial index for open SCA findings by package** (migration 00038). The SBOM inventory counts each component's open vulnerabilities; at 10 million findings that read the repositories' findings and the page timed out (136 s in `EXPLAIN ANALYZE`). `(package_name, package_version, repository_id)` for open SCA findings makes it an index-only lookup: 8.6 s, the cost of grouping the components themselves. Found in the 10 million run; not re-measured at 1 million.
11. **JIT off for the application's connections**. PostgreSQL's JIT compiler spent 0.6–0.8 s compiling the large aggregate queries (posture: 2.7 s with JIT, 1.7–2.2 s without). The API, jobs and scheduler connections set `jit=off`; a `jit` parameter in the database URL overrides it.

## Findings not fixed

- **Heavy aggregate pages share the database with everything else.** The dashboard (2.4 s), executive report (2.7 s), posture pages (1.5 s) and SBOM inventory without a filter (8 s; 4.2 s for licence violations) each read most of the findings or components. Under load they occupy database connections and CPU, and cheap requests queue behind them: in the `mixed` test the instance stops keeping up somewhere between 5 and 20 requests/s. Admission control (a separate, small connection budget for these pages) or precomputed rollups would be the next step; neither was built.
- **Memory is the main lever.** With the default 4 GB limit the findings table, its indexes and the SBOM tables do not stay cached; giving PostgreSQL 6 GB with `shared_buffers=3GB` changed the 5 requests/s mix from p95 16.2 s to 2.7 s (see the `mixed` table).
- **Marking every finding for re-scoring** (a risk-model change) is one `UPDATE` of all findings in the request: 74–89 s at 1 million. Not changed.
- **Free-text search** (`q=`) uses `LIKE '%…%'` on five columns. It is fast for common terms because the list stops after 100 matches in index order (13 ms p50, 127 ms p95 for the five test terms at 1 million), but a term that matches nothing reads every open finding: 139.8 s with 10 million findings (not timed with 1 million). A trigram index was not added.
- **Posture** recomputes coverage per repository with a correlated subquery (about 0.5 s of its 1.5 s).
- **Human Eye auto-queue with many findings in *needs review*.** Change 5 reads every finding in *needs review* after each scan. With 10 million findings, 200,000 of them in that status, the query still took 4.1 s on average and *complete* 1.3–1.7 s (most of those findings had no review yet, so the queue was also busy creating them).

## Recommended sizing (derived from these measurements)

These are derived from the runs above on the test machine and are marked as estimates; they are not separate measurements of each size.

| Installation | Findings (open about half) | Repositories | Concurrent users | PostgreSQL | API | Basis |
|---|---|---|---|---|---|---|
| Small | up to about 100,000 | up to 1,000 | up to 10 | Production override defaults: 4 GB, `shared_buffers=1GB`, 2–4 cores | 1 replica, 2 CPU, 1 GB | At 1 million findings this configuration answered list, detail and search requests in under 20 ms for one user; a tenth of the data fits in its cache. The phase P8 test (earlier code) served 80 req/s at p95 < 500 ms with 100,000 findings. |
| Medium | about 1 million | about 10,000 | up to 20 | 6–8 GB with `shared_buffers` at a third to a half of it, 8 or more cores | 1 replica, 2 CPU, 1 GB (it used about 50 MB and 1 % CPU under load) | Measured at 1 million: 20 users at p50 18 ms / p95 3.5 s (4 GB); a 5 req/s mix at p95 2.7 s with 6 GB against 16.2 s with 4 GB. With 50 users or 20 req/s the database saturated (p95 11.5–30 s). |
| Large | 10 million | 10,000+ | more than a handful | Considerably more memory than 6 GB (the database is 29 GB) on a dedicated server, fast NVMe | 1 replica is enough for the API itself | Measured at 10 million with 6 GB: list pages stay fast, but dashboard (32 s), posture (23 s) and executive report (48 s) are too slow for interactive use and time out under 20 users. This size needs the not-yet-built work listed under "Findings not fixed" (rollups or admission control for aggregate pages); more hardware alone was not measured. |

Scan workers are not the limit for the PATHOS side of ingest: 32 simulated workers completed 59–70 jobs/s with 1 million findings. Size workers by the tools they run (1–4 GB each, see [OPERATIONS.md](OPERATIONS.md#scaling)).

## Graph rendering

The budget of prompt §4 is a first render under 2 s for 2,000 nodes. ADR-005 sets the plan: synthetic graphs labelled as test data, Chromium, 10 runs per case, median and p95, from data received to all nodes laid out and placed.

```bash
scripts/graph-bench.sh        # BENCH_RUNS=10; results in e2e/perf/results/graph-render.json
```

The harness (`frontend/bench`, never part of the product bundle) renders the shared graph component (`frontend/src/components/graph`) with `generateGraph()` (seed 42: example nodes of 11 types, 30 % in three trust boundaries, mostly forward edges spanning up to 60 nodes, 10 % back edges). "Total" runs from handing the data to the component to two animation frames after `fitView`, with every node placed. Playwright 1.65.1, Chromium, 1440×900, on the test machine above (shared, other stacks running).

**ELK layered does not scale to the budget.** Timed alone in Node 26 (`node frontend/bench/elk-node.mts <n>`), cold, ELK 0.12.1 layered with `INCLUDE_CHILDREN` (trust boundaries as containers) took 0.5 s for 150 nodes, 1.2 s for 250, 4.5 s for 500 and 28.6 s for 1,000; without containers 2.9 s for 1,000. Cheaper settings (longest-path layering, no greedy switch, simple node placement) were slower (19.9 s for 500), because they produce more layers and more dummy nodes. The browser run of 2,000 nodes with ELK did not finish within 120 s.

**What the component does instead** (decided here, recorded in ADR-005): the layout still runs in the web worker; graphs up to 250 nodes and 500 edges use ELK layered (best quality, and the server's default view stays at 500 nodes or fewer by aggregation); larger graphs use a linear-time layered layout (`fastLayout.ts`: longest-path layers, barycentre ordering in four sweeps, one band per trust boundary so a boundary box holds only its children). React Flow renders only the visible elements and draws plain boxes below 45 % zoom.

| Nodes | Edges | Layout | Layout median / p95 | Total median / p95 | Within 2 s |
|---:|---:|---|---:|---:|---|
| 200 | 299 | ELK | 742 / 792 ms | 807 / 850 ms | yes |
| 500 | 750 | fast layered | 115 / 124 ms | 245 / 272 ms | yes |
| 1,000 | 1,500 | fast layered | 120 / 131 ms | 385 / 427 ms | yes |
| **2,000** | **2,998** | fast layered | 127 / 142 ms | **666 / 774 ms** | **yes (budget)** |
| 2,000 | 5,998 | fast layered | 132 / 141 ms | 899 / 930 ms | yes |
| 5,000 | 7,499 | fast layered | 152 / 187 ms | 1,209 / 1,317 ms | yes (1,234 nodes in view after fit, the rest culled) |
| 2,000, CPU ×4 throttled | 2,998 | fast layered | 150 / 173 ms | 2,261 / 3,275 ms | no (pessimistic case of ADR-005) |

Layout time includes starting the worker, which loads the ELK bundle (1.5 MB) even when the fast layout runs. Not measured yet: the real CodeGraph of the PATHOS repository (needs the M4 engine stack), interaction frame rate while panning, and a reference client defined by the owner.

## Not measured

- Scans with real tools (the ingest test uploads synthetic SARIF; tool run time, cloning and worker memory are not included). Only Opengrep-style SARIF uploads were tested, not SBOM uploads or imports.
- More than one API or jobs replica, PgBouncer, a dedicated database server, object storage for artifacts.
- Scoped (non-administrator) users: every request ran as the bootstrap administrator with an organization-wide role; scope filters add conditions that were not timed.
- Personal API tokens (each token request updates `last_used_at` on the token row; concurrent requests with one token were not tested).
- Write paths other than scan ingest (bulk triage, imports, report schedules, notifications at volume), the frontend, and the worker-side tools.
- Long runs (hours), autovacuum behaviour under sustained writes, and backup/restore time of a large database.
- Numbers on a quiet, dedicated machine.

## 10 million findings

The same generator with ten times the findings (same 10,000 repositories and SBOM size), on a fresh stack that already had migration 00038, with PostgreSQL given 6 GB and `shared_buffers=3GB`:

```bash
COMPOSE_PROJECT_NAME=d2 PG_SHARED_BUFFERS=3GB PG_EFFECTIVE_CACHE=5GB PG_MEMORY=6G docker compose \
  -f docker-compose.yml -f docker-compose.prod.yml -f scripts/load/docker-compose.load.yml up -d proxy api jobs scheduler
COMPOSE_PROJECT_NAME=d2 scripts/load/loadgen.sh seed -repos 10000 -findings 10000000 -chunk 250000
```

- **Time**: 4,291 s (1 h 11 min 34 s). Chunks of 250,000 findings took 48 s at the start and 145–212 s after 7 million, waiting on index reads (the unique `(repository_id, fingerprint)` index takes random inserts). The `jobs` service ran its usual background work during the seed (SLA notifications, Human Eye auto-queue: 70,000 reviews were created).
- **Disk**: the PostgreSQL volume holds **29.8 GB** (database 29 GB): findings 17 GB (12 GB table, 5.7 GB indexes), 30.0 million occurrences 9.1 GB, 5.3 million status-history rows 1.3 GB, SBOM 1.0 GB.

Per-endpoint latency, one user, 5 requests each (`scale.sh sweep ITER=5`), ms:

| Endpoint | p50 | p95 | p99 | Errors | Note |
|---|---:|---:|---:|---:|---|
| dashboard 30d | 32,671 | 36,246 | 36,867 | 0/5 |  |
| dashboard 365d | 31,396 | 31,827 | 31,883 | 0/5 |  |
| executive | 48,470 | 51,369 | 51,494 | 0/5 |  |
| export report csv | 14,976 | 15,348 | 15,352 | 0/5 |  |
| export sbom spdx | 3 | 9 | 10 | 0/5 |  |
| finding detail | 6 | 12 | 13 | 0/5 |  |
| finding history | 2 | 3 | 3 | 0/5 |  |
| finding risk | 2 | 2 | 2 | 0/5 |  |
| findings big repository | 20 | 378 | 449 | 0/5 |  |
| findings by application | 831 | 918 | 920 | 0/5 |  |
| findings by repository | 94 | 240 | 261 | 0/5 |  |
| findings kev | 25 | 30 | 30 | 0/5 |  |
| findings lifecycle new | 33 | 36 | 37 | 0/5 |  |
| findings list | 6 | 8 | 8 | 0/5 |  |
| findings page 5 | 14 | 17 | 17 | 0/5 |  |
| findings severity category | 16 | 149 | 176 | 0/5 |  |
| findings sla breached | 11 | 14 | 15 | 0/5 |  |
| findings sort risk | 16 | 40 | 44 | 0/5 |  |
| findings status all | 9 | 13 | 14 | 0/5 |  |
| findings summary | 762 | 11,625 | 13,701 | 0/5 | 349 / 701 in a later run after autovacuum (3 requests) |
| findings text search | 36 | 872 | 1,038 | 0/5 |  |
| global search | 3 | 15 | 17 | 0/5 |  |
| posture aggregate | 22,787 | 23,455 | 23,482 | 0/5 |  |
| posture applications | 22,745 | 23,381 | 23,465 | 0/5 |  |
| posture coverage | 143 | 150 | 152 | 0/5 |  |
| report group by repository | 970 | 5,594 | 6,519 | 0/5 |  |
| report run json | 15,154 | 17,588 | 18,022 | 0/5 |  |
| repositories list | 58 | 61 | 62 | 0/5 |  |
| repositories search | 26 | 37 | 38 | 0/5 |  |
| repository detail | 5 | 7 | 7 | 0/5 |  |
| sbom components | 117,682 | 119,901 | 119,982 | 5/5 | timed out; 7,842 / 7,868 after the package index (3 requests) |
| sbom license violations | 109,472 | 118,910 | 119,441 | 5/5 | timed out; 4,177 / 4,191 after the package index (3 requests) |
| scans list | 161 | 4,455 | 5,313 | 0/5 |  |

- The findings list and its variants, finding detail, history, search and repository pages stay at 2–40 ms (p50) with ten times the data: the keyset indexes keep a page an index range scan. Filters that the indexes do not cover (application, a large repository) are slower (0.1–0.9 s).
- Everything that aggregates over all findings grows roughly with the data: dashboard 32 s, executive report 48 s, posture 23 s, a saved report 15 s. With 20 concurrent users (`users USERS=20`) every dashboard request hit the 120 s k6 timeout (20 of 20), while list, detail, search and repository requests stayed at 4–90 ms p50 and the list summary at 1.0 s (211 requests in 2 min; most users were waiting on the dashboard).
- The SBOM inventory timed out at 120 s because counting each component's open vulnerabilities read the repositories' findings; a partial index on open SCA findings by package (now in migration 00038) brought it to 7.8 s.
- Scan ingest (8 workers, 50 results): 2.9 jobs/s on the first scan and 5.1 jobs/s on the rescan; *complete* p50 1.3–1.7 s. The time is the Human Eye auto-queue query (4.1 s mean): the dataset has 200,000 findings in *needs review* (2 %), and most were still waiting for their review to be created by the background queue.
- Risk re-scoring (direct, batch 500, 100,170 findings): 2,467 findings/s, longest batch 0.40 s.
- Free-text search for a term that matches nothing (the worst case; the list query's conditions and order run in `psql` with `\timing`): 139.8 s.

