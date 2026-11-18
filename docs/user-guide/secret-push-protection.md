---
title: Secret push protection
section: user-guide
order: 17
version: "1.1"
updated: 2026-11-19
summary: Keep secrets out of Git with a pre-commit hook, a server-side pre-receive hook and PATHOS push-event scanning that alerts on secrets in pushed commits.
---
# Secret push protection

A credential committed to Git stays in the history, in every clone and often
in CI logs. PATHOS offers three layers that work together; use as many as
your platform allows.

| Layer | Where it runs | Blocks the push? | Platforms |
|---|---|---|---|
| Pre-commit hook | Developer machine | Blocks the commit (can be bypassed with `--no-verify`) | Any |
| Pre-receive hook | Your Git server | Yes | Self-hosted GitLab, Gitea / Forgejo, Bitbucket Server / Data Center (with a hook add-on) |
| Push-event scanning | PATHOS | No, it alerts within seconds | GitHub, GitHub Enterprise Server, GitLab (cloud and self-managed) |

Scheduled and on-demand PATHOS scans (Gitleaks, optionally over the full
history) remain the safety net for everything else.

All three use the same idea: only what a change **adds** is checked, and
secret values are **never shown or stored** — messages name the rule, the
file, the line and the commit.

## Pre-commit hook (developer machines)

The `integrations/pre-commit/` directory of the PATHOS source contains:

- `pathos-gitleaks.toml`: the PATHOS baseline Gitleaks configuration (all
  default Gitleaks rules, plus allowlists for lockfiles, vendored and
  generated files and published documentation placeholders). Copy it to the
  root of each repository as `.gitleaks.toml`.
- A `.pre-commit-config.yaml` example for the [pre-commit](https://pre-commit.com)
  framework, using Gitleaks v8.30.1 (the version PATHOS scans with), and
  hook definitions (`pathos-gitleaks`, `pathos-gitleaks-docker`) for an
  internal hook repository.
- `hooks/pre-commit`: a plain Git hook for teams without the framework.

Quick start with the framework:

```sh
cp integrations/pre-commit/pathos-gitleaks.toml  my-repo/.gitleaks.toml
cp integrations/pre-commit/pre-commit-config.example.yaml my-repo/.pre-commit-config.yaml
cd my-repo && pre-commit install
```

Or the plain hook: `cp integrations/pre-commit/hooks/pre-commit my-repo/.git/hooks/ && chmod +x my-repo/.git/hooks/pre-commit`.
It needs `gitleaks` on `PATH` or Docker (`PATHOS_GITLEAKS_DOCKER=1`), and
fails closed when neither is available unless `PATHOS_GITLEAKS_OPTIONAL=1`.

When a commit is blocked: unstage the file, move the value to a secret
store or environment variable, and **rotate the credential** if it was ever
real. False positives get the narrowest possible entry in `.gitleaks.toml`
or a `gitleaks:allow` comment. `git commit --no-verify` skips the hook;
your policy may forbid it, and the server-side layers still apply.

These hooks do not need PATHOS or any network access.

## Pre-receive hook (self-hosted Git servers)

`integrations/pre-receive/pathos-pre-receive` rejects pushes whose new
commits add secrets. It scans only commits that are new to the repository,
ignores deletions, resolves annotated tags, and is bounded by a time limit
(`PATHOS_PRERECEIVE_TIMEOUT`, default 60 s) and a commit limit
(`PATHOS_PRERECEIVE_MAX_COMMITS`, default 2000). A push that could not be
checked is accepted with a warning, or rejected with
`PATHOS_PRERECEIVE_STRICT=1`.

Installation, step by step for GitLab server hooks, Gitea / Forgejo and
Bitbucket Server, is in `integrations/pre-receive/README.md`. Gitleaks
v8.30.1 must be installed on the Git server (or every Gitaly node).
GitHub.com and GitLab.com do not run custom pre-receive hooks; use
push-event scanning there.

## Push-event scanning in PATHOS

For repositories imported from GitHub, GitHub Enterprise Server or GitLab,
PATHOS can check every push it receives through the repository's webhook.

1. Make sure the repository's SCM connection has a webhook (see
   [Provider integrations](provider-integrations.md)); push events must be
   enabled.
2. Open the repository (**Repositories** → the repository → **Security**
   tab) and tick **Scan pushes for secrets** in *Secret push protection*.
   This needs `repos.manage` on the repository.

From then on, each verified push event queues a push scan. Within seconds
the PATHOS jobs service reads the commits of the push through the provider
API (no clone; repository code is never executed), checks the lines they
add against high-confidence patterns (cloud keys, GitHub / GitLab / Slack /
Stripe / npm / PyPI tokens, Google API keys, Azure storage keys, private
keys) and, for every likely secret:

- records an alert with the commit, file, line and kind of secret,
- sends the **Secret pushed** notification (`secret.pushed`, built-in rule
  *Secrets pushed to repositories*: security managers and the repository's
  owners; administrators can change it under **Administration →
  Notifications**), which is also available to outbound webhooks,
- writes an audit log entry.

The *Secret push protection* panel lists recent pushes (scanned, failed,
not supported) and the alerts. Alerts are visible with `findings.read`.

What push scanning does not do:

- It cannot block a push: it runs after the push is accepted. Use the
  hooks above to block.
- A new branch is compared with the default branch; a push of more than 50
  commits is checked as one combined diff attributed to the head commit,
  and very large files are read only up to 1 MiB.
- Bitbucket Cloud and Azure DevOps are not supported (use scheduled scans,
  and the pre-receive hook on Bitbucket Server).

Responding to an alert: **revoke and rotate** the credential first — once
pushed, it is in the history of every clone — then remove it from the code
and, if your policy requires, rewrite the history. The next scheduled scan
reports any remaining occurrence as a regular secrets finding.
