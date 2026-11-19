# Benchmarks

How well does PATHOS detect what it should, and how much does it report that it should not? This page describes a reproducible harness that measures it on suites with known answers, and the results of its first run. The numbers are PATHOS's: the scanners ran in the PATHOS worker images with the manifests and arguments a scan job uses, and their reports were parsed and merged by PATHOS's own code. They are not the numbers of the tools run by hand with their best settings.

Contents: [Method](#method) · [Suites and licences](#suites-and-licences) · [Results (2026-11-19)](#results-2026-11-19) · [After the fixes](#after-the-fixes-2026-11-19) · [Where PATHOS does badly](#where-pathos-does-badly) · [Limitations](#limitations) · [Reproducing](#reproducing) · [Follow-ups](#follow-ups)

## Method

1. **Run.** `benchmarks/run.sh` copies a suite's code into a scan directory and starts the worker images (`pathos-worker-core`, `-sast`, `-sca`) with `pathos-worker run-local -src … -out … -scanners …`. `run-local` builds the same tool table as the worker agent (built-in tools and the first-party manifests in `/opt/pathos/tools.d`) and runs each tool exactly as a job would. The difference is that it writes each report and a `results.json` (version, status, duration, manifest parser) to a directory instead of uploading them. Containers run with `--read-only`, `--cap-drop ALL`, `no-new-privileges` and `--network none`. The SCA suite is the exception: its vulnerability databases and registry lookups need the network.
2. **Parse.** `pathos-bench score` (`backend/cmd/pathos-bench`, package `internal/bench`) parses each report the way the API parses a worker upload (`scans.Ingest`): with the manifest's parser (`import:<format>`, `jsonmap`), or by scanner key for built-in tools. The default profile threshold is `info`, so no finding is filtered by severity.
3. **Merge.** Findings of all tools are merged by fingerprint, as the findings table merges them (one row per repository and fingerprint). Non-dependency fingerprints include the tool, so for SAST and secrets the merged result is the union of the tools' findings. Dependency findings of the same package, version and vulnerability merge across tools.
4. **Score.** Every tool and the merged result ("PATHOS combined") are scored against the suite's labelled cases. For each case, the tool detects it or it does not:

   | Case | Detected | Not detected |
   |---|---|---|
   | real vulnerability (positive) | TP | FN |
   | not a vulnerability (negative) | FP | TN |

   Precision = TP / (TP + FP); recall (true positive rate, TPR) = TP / (TP + FN); false positive rate (FPR) = FP / (FP + TN); F1 = 2·P·R / (P + R); **score = TPR − FPR**, the OWASP Benchmark score (0 is what random guessing gets; 100 is perfect). For the OWASP suites the report also gives the **category average**, the mean of the per-category TPR, FPR and score. The OWASP scorecards use this as their summary, so every vulnerability class weighs the same. Tables give rates as percentages and scores in percentage points.
5. **Match rules** (per suite):
   - OWASP Benchmark: a finding in the test case's file (`BenchmarkTestNNNNN.java` / `.py`) whose CWE list contains the case's CWE, as in the OWASP scorecard. Findings without a CWE, or with a different one, do not count. A second table shows "any finding in the file" for comparison.
   - Secrets: any finding of category `secrets` in the case's file (one labelled item per file).
   - SCA: a dependency finding for the case's package (any of the names tools use), in the case's project directory, whose CVE or rule ID is one of the vulnerability's identifiers (CVE, GHSA, GO, PYSEC).
   - "Unrelated" counts findings outside any labelled file or package. They are not scored.
6. A tool that failed or was skipped is shown as such and gets no score, never zeros.

## Suites and licences

| Suite | What | Size | Source and version | Licence | Stored in this repository |
|---|---|---|---|---|---|
| owasp-java | OWASP Benchmark for Java, SAST mode | 2,740 test cases (1,415 vulnerable) in 11 CWE categories | [OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) commit `c6717ea2`, `expectedresults-1.2.csv` | GPL-2.0 | No: downloaded by `run.sh`, SHA-256 pinned in `benchmarks/suites.lock` |
| owasp-python | OWASP Benchmark for Python 0.1, SAST mode | 1,230 test cases (452 vulnerable) in 14 categories | [OWASP-Benchmark/BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) commit `f1291485`, `expectedresults-0.1.csv` | GPL-3.0 | No (as above) |
| secrets-selfmade | **Self-made**: generated files, one labelled item each | 103 files: 64 credentials in 16 formats, 39 look-alikes in 12 kinds | `pathos-bench gen-secrets`, seed 20261119 (`internal/bench/secrets.go`) | Apache-2.0 | The generator only; the files are generated at run time, so no secret-shaped string is committed |
| sca-pinned-versions | **Self-made**: 8 projects (npm lockfile, `requirements.txt`, `pom.xml`, `go.mod`), each in a vulnerable and a fixed version | 7 packages; 70 cases (57 vulnerable, 13 fixed) | `benchmarks/suites/sca`; answer key from api.osv.dev on 2026-11-19 (`osv-labels.py`) | Apache-2.0 | Yes |
| reach | Function-level reachability benchmark of wave C | 12 cases, 4 languages | `backend/internal/reach/bench_test.go` | Apache-2.0 | Yes |

The secrets corpus contains the published formats of AWS keys, GitHub classic and fine-grained tokens, GitLab, Slack, Stripe, Google, SendGrid, npm and Twilio keys, RSA and PKCS#8 private keys, a Postgres URL with a password, a JWT, an Azure storage connection string and a generic password. Each format appears in four file types. The look-alikes are environment variable references, placeholders, the AWS documentation example key, SHA-256 hashes, commit IDs, UUIDs, lockfile integrity values, SSH and PEM public keys, data URIs, UI strings and calls that read a secret from a vault. All values are random: none is a working credential, and no tool can or does verify them.

In the SCA answer key, every vulnerability that OSV lists for a pinned version is a positive case in the "vulnerable" project. A vulnerability fixed by the newer version is a negative case in the "fixed" project, and one that affects both versions is positive in both. Aliases are one case.

Suites considered and **not** done in this round:
- **IaC.** The candidate is KICS's own query test cases (Apache-2.0), which have per-file expected results. They are labelled for KICS's queries only. Scoring Checkov or Trivy on them needs a reviewed mapping of each check to the other tools' rule IDs, which was not written. Scoring KICS against its own unit tests would show nothing.
- **DAST.** OWASP Benchmark has a web mode and Juice Shop has a challenge list. Neither was run: both need a running target and authorized intrusive scans, and scoring Juice Shop's challenges against ZAP alerts needs a mapping that does not exist.
- **Container images**, mobile, binary, AI and fuzzing: no suite with an answer key was chosen yet.

## Results (2026-11-19)

These are the results of the first run, before the defects it found were fixed. The [next section](#after-the-fixes-2026-11-19) has the run after the fixes.

Machine: Intel Core i7-13800H, `nproc` 20, 31,933,004 KiB memory (30.5 GiB), Linux 7.0.0-42-generic, Docker 29.9.3. Images: `d1-pathos-worker-{core,sast,sca}:dev`, built from this branch (commit `c40af82`; the worker code has not changed since). Harness commit `87b40d1`. Command:

```sh
PATHOS_BENCH_IMAGE_PREFIX=d1- benchmarks/run.sh
```

Run time: 167 s for all suites (owasp-java 73 s, owasp-python 62 s, secrets 11 s, sca 19 s, reach 1 s), with the suite archives and vulnerability databases already downloaded. The first run, which downloaded the Trivy and Grype databases, took 273 s (sca 119 s). Image builds are not included. Vulnerability databases: Trivy DB updated 2026-11-19T07:06Z; Grype DB v6.1.10 built 2026-11-19T00:22Z; OSV-Scanner, pip-audit, npm audit and govulncheck queried their services during the run.

Raw results: [`benchmarks/results/2026-11-19/`](../benchmarks/results/2026-11-19/). [`results.md`](../benchmarks/results/2026-11-19/results.md) has every per-category table, the `*.json` files every count, and `env.json` the environment.

Tool versions (as recorded by the worker): Opengrep 2.0.0, Semgrep CE 1.172.0*, Bearer 2.1.3, Bandit 1.9.4, Ruff 0.17.5, Gitleaks 8.30.1, TruffleHog 3.99.9, Kingfisher 2.19.1, detect-secrets 1.5.0, Talisman 1.37.0, Trivy 0.76.2, Grype 0.121.3, OSV-Scanner 2.7.1, pip-audit 2.10.1, npm 12.2.3, govulncheck 1.10.0. *In this first run the worker recorded an empty version for Semgrep CE (item 7 [below](#where-pathos-does-badly)); 1.172.0 is the version pinned in the image, and the version the worker records after the fix.

### OWASP Benchmark for Java (SAST)

| Tool | Findings | TP | FP | FN | TN | Precision | Recall | FPR | Score | Category average score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Opengrep (PATHOS rules) | 449 | 241 | 206 | 1174 | 1119 | 53.9% | 17.0% | 15.6% | +1.5 | +0.0 |
| Semgrep CE (PATHOS rules) | 449 | 241 | 206 | 1174 | 1119 | 53.9% | 17.0% | 15.6% | +1.5 | +0.0 |
| Bearer | 2194 | 980 | 382 | 435 | 943 | 72.0% | 69.3% | 28.8% | +40.4 | +38.1 |
| **PATHOS combined** | 3092 | 1033 | 434 | 382 | 891 | 70.4% | 73.0% | 32.8% | +40.2 | +37.8 |

- Opengrep and Semgrep CE run the same PATHOS rule files and give identical results. For Java those rules cover only SQL injection: 88.6% recall at 88.8% FPR. In the other ten categories they find nothing.
- Bearer carries the result. It does well on weak randomness, cookies and cryptography (100% recall; 0% FPR for weakrand and securecookie, 23.3% for crypto) and on weak hashes (69.0% recall, 0% FPR). Trust boundary is at 94.0% / 90.7% and SQL injection at 78.7% / 73.7%. It finds no path traversal with CWE-22.
- Combining tools adds little in Java (score +40.2 against Bearer's +40.4). The opengrep SQL findings add true positives and almost as many false positives.

### OWASP Benchmark for Python (SAST)

| Tool | Findings | TP | FP | FN | TN | Precision | Recall | FPR | Score | Category average score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Opengrep (PATHOS rules) | 184 | 101 | 30 | 351 | 748 | 77.1% | 22.4% | 3.9% | +18.5 | +8.6 |
| Semgrep CE (PATHOS rules) | 184 | 101 | 30 | 351 | 748 | 77.1% | 22.4% | 3.9% | +18.5 | +8.6 |
| Bearer | 314 | 84 | 7 | 368 | 771 | 92.3% | 18.6% | 0.9% | +17.7 | +10.9 |
| Bandit | 536 | 108 | 25 | 344 | 753 | 81.2% | 23.9% | 3.2% | +20.7 | +9.3 |
| Ruff (S rules) | 348 | 85 | 14 | 367 | 764 | 85.9% | 18.8% | 1.8% | +17.0 | +14.8 |
| **PATHOS combined** | 1566 | 184 | 30 | 268 | 748 | 86.0% | 40.7% | 3.9% | +36.9 | +17.5 |

- Combining helps in Python: recall goes from at most 23.9% for one tool to 40.7%, with no more false positives than Opengrep alone (3.9% FPR).
- Detected categories: weak hashing (100% recall, 0% FPR, Opengrep and Bearer), weak randomness (77.8%, 0%, Bandit), deserialization (100% recall at 33.3% FPR), command injection (100% recall at 100% FPR) and SQL injection (5 positive cases, 100% recall at 100% FPR).
- **Not detected at all** (0% recall for every tool) in nine of 14 categories: code injection, LDAP injection, path traversal, open redirect, insecure cookie, trust boundary, XPath injection, XSS and XXE.
- With "any finding in the file" the combined recall is 57.5% at 24.7% FPR. Tools often flag the right file with a CWE other than the benchmark's.

### Secrets (self-made corpus)

| Tool | Findings | TP | FP | FN | TN | Precision | Recall | FPR | Score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Gitleaks | 60 | 56 | 0 | 8 | 39 | 100.0% | 87.5% | 0.0% | +87.5 |
| TruffleHog (no verification) | 40 | 40 | 0 | 24 | 39 | 100.0% | 62.5% | 0.0% | +62.5 |
| Kingfisher (no validation) | 44 | 44 | 0 | 20 | 39 | 100.0% | 68.8% | 0.0% | +68.8 |
| detect-secrets | 89 | 64 | 12 | 0 | 27 | 84.2% | 100.0% | 30.8% | +69.2 |
| Talisman | 406 | 52 | 33 | 12 | 6 | 61.2% | 81.2% | 84.6% | −3.4 |
| **PATHOS combined** | 639 | 64 | 33 | 0 | 6 | 66.0% | 100.0% | 84.6% | +15.4 |
| **PATHOS combined without Talisman** | 233 | 64 | 12 | 0 | 27 | 84.2% | 100.0% | 30.8% | +69.2 |

- Gitleaks, the default secrets tool, has no false positives here. It misses the generic password assignments (0 of 4) and the Postgres URLs with a password (0 of 4).
- TruffleHog misses the generic passwords, private keys, Google API keys, JWTs and Twilio keys in this corpus. Kingfisher misses the generic passwords, private keys, Postgres URLs and Twilio keys. With verification or validation off, both still report unverified matches; the misses come from their detectors.
- detect-secrets finds everything, but also flags hashes, commit IDs, lockfile integrity values, the AWS documentation key and UI strings (12 of 39 look-alikes).
- Talisman flags 33 of 39 look-alike files (406 findings in total; the causes were not analysed). With all secrets tools enabled, it alone moves PATHOS's merged FPR from 30.8% to 84.6%.

### SCA (pinned versions)

| Tool | Findings | TP | FP | FN | TN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| Trivy (fs) | 60 | 57 | 0 | 0 | 13 | 100.0% | 0.0% |
| Grype | 57 | 57 | 0 | 0 | 13 | 100.0% | 0.0% |
| OSV-Scanner | 112 | 57 | 0 | 0 | 13 | 100.0% | 0.0% |
| pip-audit | 0 | 0 | 0 | 57 | 13 | 0.0% | 0.0% |
| npm audit | 0 | 0 | 0 | 57 | 13 | 0.0% | 0.0% |
| govulncheck | 6 | 0 | 0 | 57 | 13 | 0.0% | 0.0% |
| **PATHOS combined** | 84 | 57 | 0 | 0 | 13 | 100.0% | 0.0% |

(Recall and FPR here are over all 70 cases. pip-audit, npm audit and govulncheck only read Python, npm and Go projects respectively, so their per-ecosystem rows in `results.md` are the fairer view; they are 0% there too, for the reasons below.)

- Trivy, Grype and OSV-Scanner find every labelled vulnerability, including those that also affect the fixed versions, and report none of the fixed ones in the fixed projects. The answer key comes from OSV, so this mostly shows that the three tools' databases agree with OSV on well-known packages. It does not measure coverage of obscure packages.
- The 84 merged findings include **18 duplicates**: the same vulnerability reported twice because tools name the package or version differently. Grype names the Maven package `log4j-core`, Trivy and OSV-Scanner `org.apache.logging.log4j:log4j-core` (12 duplicates). OSV-Scanner reports Go versions without the `v` (`0.3.5` against `v0.3.5`; 6 duplicates).
- The other extra findings are real but not in the answer key, so they are not scored: `log4j-api` (CVE-2026-49844, a transitive dependency of `log4j-core`; the 2 "unrelated" findings of Trivy and OSV-Scanner) and Trivy's `NSWG-ECO-516` for lodash 4.17.15, an advisory ID without a CVE.

### Reachability (wave C)

All 12 cases are answered as expected: reachable 4/4, not reachable 4/4, unknown for dynamic dispatch 4/4, and no false "not reachable" ([`reach.txt`](../benchmarks/results/2026-11-19/reach.txt)). This benchmark is a Go test on sample projects with hand-written function lists for the npm, PyPI and Maven advisories and recorded govulncheck output for Go. It does not run the worker images, and 12 cases are too few to estimate an error rate.

## After the fixes (2026-11-19)

The first run exposed five defects (numbered 3–7 under [Where PATHOS does badly](#where-pathos-does-badly)). Each now has a fix and a regression test, and the whole harness was run again on the same machine with images rebuilt from the fixed code (`d1-pathos-worker-{core,sast,sca}:dev`, commit `93d80ca`) and the **same vulnerability databases** (Trivy DB updated 2026-11-19T07:06Z, Grype DB built 2026-11-19T00:22Z). Raw results: [`benchmarks/results/2026-11-19-after-fixes/`](../benchmarks/results/2026-11-19-after-fixes/). The three images pass the Trivy gate of `scripts/security-scan.sh` (0 fixable HIGH/CRITICAL: core 119, sast 129 and sca 129 unfixable).

**SCA, per ecosystem.** pip-audit, npm audit and govulncheck read one ecosystem each, so their recall is given over that ecosystem's cases. Over all 70 cases it is 31/57, 8/57 and 6/57.

| Tool | Ecosystem | Before: TP / FN / FP | After: TP / FN / FP | Before → after |
|---|---|---|---|---|
| pip-audit | PyPI (31 positive, 3 negative) | 0 / 31 / 0, recorded as **succeeded** | 31 / 0 / 0 | recall 0% → 100% |
| npm audit | npm (8 positive, 4 negative) | 0 / 8 / 0, recorded as **succeeded** | 8 / 0 / 0 | recall 0% → 100% |
| govulncheck | Go (6 positive, 2 negative) | 0 / 6 / 0 (findings in `go.mod`, no module) | 6 / 0 / 0 (in `go-vulnerable/go.mod`, `go-fixed/go.mod`) | recall 0% → 100% |
| Trivy, Grype, OSV-Scanner | all | 57 / 0 / 0 each | 57 / 0 / 0 each | unchanged |
| **PATHOS combined** | all (57 positive, 13 negative) | 57 / 0 / 0 | 57 / 0 / 0 | unchanged |

**Merged SCA findings.**

| | Before | After |
|---|---:|---:|
| Findings after merging | 84 | 68 |
| Duplicates (the same package, version and vulnerability twice) | 18: 12 Maven (Grype `log4j-core` against `org.apache.logging.log4j:log4j-core`), 6 Go (`0.3.5` against `v0.3.5`) | 8, all from npm audit (below) |
| Tools contributing findings | Trivy, Grype, OSV-Scanner, govulncheck (wrong file) | the same plus pip-audit and npm audit |

The 68 are 57 labelled vulnerabilities, 3 real but unlabelled findings (`log4j-api` twice, Trivy's `NSWG-ECO-516`) and the 8 npm audit findings. npm audit's JSON names neither the installed version nor a CVE, only the advisory (GHSA) and a vulnerable range. Its findings therefore have a different identity from Trivy's, Grype's and OSV-Scanner's for the same advisory and do not merge. That is a follow-up, not something the normalization can fix. The duplicates were counted by listing the merged findings (`bench.Merge`) and grouping them by project, package and vulnerability.

**Semgrep CE.**

| | Before | After |
|---|---|---|
| Version recorded | (empty) | 1.172.0 |
| Run time on OWASP Java | 29.1 s | 12.7 s |
| Run time on OWASP Python | 25.5 s | 8.5 s |

The ~17 s saved per scan is the version command's timeout. Findings are unchanged: OWASP Java score +1.5, OWASP Python +18.5.

**Unchanged.** The OWASP Java and Python, secrets and reachability results are identical to the first run, as expected, because the fixes do not touch those tools' detection. The SCA suite took 260 s this time because the database cache volume had been removed and the databases were downloaded again; the whole run took 379 s.

**Regression tests:**
- `workers/sca/test/test_pathos_sca.py` (run in CI's backend job): per-file pip-audit with a package pinned in two files; a pip-audit or npm audit error fails the tool and names the file; every lockfile is audited except under `node_modules` and `vendor`; govulncheck module directories. All but the "nothing to audit" test fail on the old wrapper.
- `backend/internal/scanners`:
  - `TestPathosEnvelope`: per-lockfile reports for npm, yarn, pnpm and Composer audit and pip-audit; findings in their files; evidence located; the report stored unchanged.
  - `TestGovulncheckModuleDirectories`
  - `TestLegacyPathFingerprints`
  - `TestFingerprintV2PackageIdentity`
  - `TestGrypeMavenGroupFromPURL`
- `backend/internal/worker`: `TestPluginVersionEnvAndTimeout`.
- `backend/test/integration/fingerprint_v2_test.go`: a Grype finding stored by 2.0 (old fingerprint, `accepted_risk`) is re-keyed on the next scan and keeps its id and status, and Trivy's finding for the same package merges into it. The test fails without the re-keying.

## Where PATHOS does badly

Stated plainly. Items 3–7 were found by the first run and are fixed ([After the fixes](#after-the-fixes-2026-11-19)); they stay listed with what was wrong.

1. **Java SAST depends on one optional tool.** Without Bearer (Elastic-2.0, off by default), PATHOS's Java SAST is the PATHOS Opengrep rules: category-average score 0, SQL injection only. A default PATHOS install has no Java SAST beyond that.
2. **Python SAST misses most injection classes.** Every tool scores 0% recall on code injection, LDAP, path traversal, open redirect, insecure cookies, trust boundary, XPath, XSS and XXE. Combined recall is 40.7%.
3. **Fixed:** pip-audit silently reported nothing in a repository with two `requirements*.txt` files that pin the same package. The `pathos-sca` wrapper passed every requirements file to one pip-audit run. pip-audit refuses duplicate requirements and exits with status 1, which the wrapper accepted as "vulnerabilities found", so the empty report was recorded as a successful run with 0 findings. Verified by running the wrapper by hand: `ERROR:pip_audit._cli:package PyYAML has duplicate requirements`. Now: one run per file. Any run whose exit status is not "vulnerabilities found", or that writes no valid report, fails the tool with the file and the error. The same rule now applies to every `pathos-sca` tool, including cargo-audit, bundler-audit, GuardDog and govulncheck, which used to report success when only some of their runs failed.
4. **Fixed:** npm audit (and yarn, pnpm and Composer audit) read only the repository root's lockfile. Lockfiles in subdirectories (monorepos) were not audited, and the run was recorded as successful with 0 findings. Now every lockfile is audited (outside `node_modules`, `vendor` and the other skipped directories), and each finding is located in its lockfile.
5. **Fixed:** govulncheck findings lost their module directory. The import parser set the file to `go.mod`, not `<module dir>/go.mod`, so in a repository with several Go modules findings pointed to the wrong file. Now the wrapper records each module's directory and findings are located in that module's `go.mod`: 6 of 6 Go positives.
6. **Fixed:** cross-tool deduplication of dependency findings failed on naming differences (Maven group ID, Go `v` prefix): 18 of 84 merged SCA findings were duplicates. Fingerprint version 2 normalizes package identity, and stored findings are re-keyed rather than replaced ([DATABASE.md](DATABASE.md#fingerprinting)). 0 of those 18 remain; npm audit's 8 findings still do not merge (see above).
7. **Fixed:** Semgrep CE's version was never recorded offline. `semgrep --version` takes about 99 s without network (it waits for the version check; `--metrics off` alone does not change that). The worker's 20 s version timeout gave up, so every scan with Semgrep CE lost 20 s and stored an empty version. The manifest's `SEMGREP_ENABLE_VERSION_CHECK=0` applied to the scan, not to the version command. Now version commands run with the manifest's env (and a new `version_timeout`), and Semgrep CE's version takes about 3 s.
8. **Talisman is too noisy for the merged result** on this corpus (84.6% FPR). It is not in the default profile (no family tool is), and its catalog note now says it is high-noise. There are no other recommended profiles in PATHOS.

## Limitations

- OWASP Benchmark is synthetic: small servlet and Flask test cases, one weakness each, with simple data flow. Scores on it do not predict results on real code. BenchmarkPython 0.1 is young and some categories have few cases (SQL injection: 5 positive, 11 negative).
- The strict CWE match penalizes tools that report a related CWE (for example CWE-73 or CWE-23 for path traversal). The "any finding in the file" table shows the other extreme. PATHOS does not map CWEs between tools.
- The secrets corpus and the SCA projects are self-made. The secret formats were chosen knowing which tools look for them, so recall on the corpus is an upper bound for real repositories. Real leaks are also in history, in binary files and in formats not covered. The SCA answer key is OSV's view on 2026-11-19. Database updates change the expected and the reported vulnerabilities, and tools that use OSV (OSV-Scanner) have an advantage.
- Each file holds one labelled item, and a detection is "any secrets finding in the file". The location within the file and the secret type are not checked.
- The SCA suite needs the network. Its results depend on the day's databases and registries.
- Tools that are not off by default are included. The merged result is "every applicable tool enabled", not PATHOS's default profile, which has only the core tools.
- Not measured: IaC, DAST, container, mobile, binary, AI and fuzzing detection; results on real-world repositories; triage features (risk scores, AI triage, Human Eye); scan performance on large repositories; variance between runs (one run; the SAST and secrets tools are deterministic on fixed input, the SCA results are not).

## Reproducing

Requirements: Docker, `curl`, `sha256sum`, network access for the downloads and the SCA suite, and about 10 GB of disk for the images. No local Go is needed; `scripts/go.sh` builds the scorer in a container.

```sh
benchmarks/run.sh --build              # build core, sast and sca images, then run every suite
benchmarks/run.sh owasp-python secrets # selected suites, with images already built
benchmarks/run.sh --smoke              # CI subset: secrets suite with Gitleaks, reachability; no downloads
PATHOS_BENCH_IMAGE_PREFIX=d1- benchmarks/run.sh   # use images named d1-pathos-worker-*:dev
```

- Downloads, scan copies and results go to `~/.cache/pathos-benchmarks` (`PATHOS_BENCH_DIR`). Each run writes `results/<UTC time>/` with `results.md`, one JSON and one text summary per suite, `env.json` and `sca-databases.txt`.
- The OWASP archives are downloaded once and checked against `benchmarks/suites.lock` before every use. A changed archive stops the run.
- `benchmarks/suites/sca/osv-labels.py` regenerates the SCA answer key from api.osv.dev (run by hand; commit the result with the date it records).
- Adding a suite: write a labels file (`internal/bench` `Labels`: a match mode and cases), add a `run_suite` branch in `run.sh` that prepares `src/`, runs the tools with `scan` and calls `score`.

**CI.** The **Benchmarks** workflow (`.github/workflows/benchmarks.yml`) runs on manual dispatch only. By default it runs the smoke subset: it builds `worker-core`, generates the secrets corpus, runs Gitleaks and the reachability test, and fails if Gitleaks' recall drops below 50%. Nothing is downloaded. With `full: true` it builds the images and runs every suite, which downloads the pinned archives and the vulnerability databases. The results are uploaded as an artifact.

## Follow-ups

Done since the first run: the fixes for items 3–7 above, and the Talisman catalog note.

1. Java and Python SAST coverage: add PATHOS Opengrep rules for path traversal, XSS, LDAP, XPath, XXE, open redirect, code injection and cookies (Java and Python), each with tests. Consider shipping a FindSecBugs/SpotBugs run for Java (needs a build). Re-run the benchmark after each pack.
2. npm audit findings: take the installed version from the lockfile and the CVE from the advisory, so they merge with the other tools' findings (8 duplicates remain).
3. Map related CWEs (for example 22/23/73, 327/328) when scoring, and report both strict and mapped scores.
4. Find out why Talisman flags most look-alike files and tune it. detect-secrets' false positives are on high-entropy values (hashes, commit IDs, integrity values) and on UI strings that contain the word "password"; review its plugin settings.
5. Pull request checks: compare dependency findings by the version 1 fingerprint too, until the base branch has been scanned once with 2.1.
6. Add an IaC suite: KICS query tests with a reviewed mapping to Checkov and Trivy rule IDs.
7. Add a DAST suite: OWASP Benchmark web mode or Juice Shop in a local container on an internal network, with a ZAP-alert-to-challenge mapping.
8. Run the full suite in CI on a schedule and keep a history of results so regressions show.
