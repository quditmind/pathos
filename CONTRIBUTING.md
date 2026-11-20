# Contributing to PATHOS

Thanks for helping! This guide gets you from clone to pull request.

## Development setup

The only requirement is Docker with the Compose plugin. Go and Node run in containers, so you don't need them installed locally.

```bash
git clone https://github.com/quditmind/pathos.git && cd pathos
./deploy/scripts/install.sh       # creates .env with generated secrets
docker compose up -d --wait       # https://localhost
```

## Tests

| Command | What it runs |
|---|---|
| `make test` | Go vet and unit tests, frontend typecheck and unit tests |
| `make test-integration` | Go integration tests against a throwaway PostgreSQL |
| `make smoke` | ~90 end-to-end API checks against the running stack |
| `make e2e` | Playwright browser tests against the running stack |
| `make security` | gosec, govulncheck, npm audit, Trivy on our images, ZAP baseline |

CI (`.github/workflows/ci.yml`) runs all of these on every pull request, starting from a fresh install.

### CodeGraph and threat-model browser tests

`e2e/tests/codegraph.spec.ts` builds the CodeGraph of a real application through the discovery worker, and `e2e/tests/threatmodels.spec.ts` generates a threat model from one. Both need the `graph` Compose profile; without it they skip with the reason. To run them locally:

```bash
docker compose --profile graph up -d --wait worker-graph
export E2E_CODEGRAPH_APP=$(python3 scripts/seed-e2e-app.py | tail -1)
scripts/e2e.sh -g "CodeGraph|threat model"
```

`scripts/seed-e2e-app.py` signs in like `scripts/smoke-test.py`, creates the application `PATHOS` (`--name` to change it), uploads a zip of this repository (`git archive HEAD`, or `--zip <file>`) as a Local PC source and imports it without a scan. It is idempotent (an application that already has a repository is left alone) and prints the application id on the last line; `--github-env` also appends `E2E_CODEGRAPH_APP=<id>` to `$GITHUB_ENV`. The threat-model test uploads its own fixture (`e2e/tests/fixtures-data/threat-model-repo`) and only needs the worker. `E2E_CODEGRAPH_WAIT_S` (default 900) bounds the wait for the graph build.

The CI `stack` job does this before the browser tests (`E2E_CODEGRAPH_WAIT_S=600`). Measured cost: the archive of HEAD is ~29 MB as tar, ~11.5 MB as zip (~2,300 files); `pathos-graph discover` on it took 23 s with 4 CPUs / 4 GiB and 32 s with 2 CPUs / 1 GiB (1,237 source files, 12,650 nodes, 32,357 edges, 13.6 MB graph), well inside the worker's 4 GiB limit. The worker image is already built in that job, so the addition (worker start, upload and import, graph build, the two specs) is estimated at 3-5 minutes on a GitHub-hosted runner, under the 10-minute budget. If it ever grows past that, remove the two steps before *Browser tests*: both specs then skip again.

## Pull requests

- Use one topic per pull request, and link the issue it closes (`Closes #123`).
- Add or update tests with every behaviour change. Bug fixes should include a test that fails without the fix.
- Format the code: Go with `gofmt` (CI checks it, including files behind the `integration` build tag); the frontend follows the existing style.
- Update the docs when behaviour or configuration changes: `docs/` and `CHANGELOG.md` (under *Unreleased*).
- Security-relevant changes: explain the threat in the description, and keep [docs/SECURITY.md](docs/SECURITY.md) accurate.
- Dependencies: pin exact versions (images by digest). We adopt releases that are at least two weeks old.

## Commit identity

Commits are public. To keep your email private, use your GitHub noreply address (`git config user.email <id>+<username>@users.noreply.github.com`).

## Errors found in logs

After a manual test session, run `make triage` (optionally `SINCE=6h`). It collects errors, warnings, HTTP 5xx responses and panics from all services, groups repeats, and redacts emails, IP addresses, IDs, tokens and secrets. Review the draft, then file issues with `make triage-create`. They are labelled `bug` and `from-logs`; a recurring error gets a "seen again" comment instead of a duplicate. Known harmless lines belong in `scripts/log-triage-ignore.txt`, each with a reason.

## Reporting bugs and security issues

Use the issue templates for bugs and feature requests. Report **security vulnerabilities privately**: see [SECURITY.md](SECURITY.md).

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE) and that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).
