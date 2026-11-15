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
