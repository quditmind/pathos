# PATHOS secret check before commit

Stops secrets before they reach a commit, on the developer's machine, with
[Gitleaks](https://github.com/gitleaks/gitleaks) (MIT licence) — the same
scanner the PATHOS worker runs (v8.30.1). Nothing here contacts PATHOS or
any other service, and nothing depends on a PATHOS command-line tool.

| File | Purpose |
|---|---|
| `pathos-gitleaks.toml` | PATHOS baseline Gitleaks configuration: all default rules, plus allowlists for lockfiles, vendored/generated files and published documentation placeholders. Copy it to a repository root as `.gitleaks.toml`. |
| `.pre-commit-hooks.yaml` | Hook definitions for the [pre-commit](https://pre-commit.com) framework (`pathos-gitleaks`, `pathos-gitleaks-docker`). |
| `pre-commit-config.example.yaml` | A ready `.pre-commit-config.yaml` using the upstream Gitleaks hook pinned to v8.30.1. |
| `hooks/pre-commit` | A plain Git hook (POSIX `sh`) for teams that do not use the pre-commit framework. |

All variants scan **only the staged changes**, print findings with the
value **redacted**, and read `.gitleaks.toml` from the repository root.

## Option 1: pre-commit framework (upstream hook)

```sh
cp pathos-gitleaks.toml  /path/to/repo/.gitleaks.toml
cp pre-commit-config.example.yaml /path/to/repo/.pre-commit-config.yaml
cd /path/to/repo && pre-commit install
```

pre-commit builds Gitleaks v8.30.1 from source (Go required; integrity
through the Go checksum database).

## Option 2: pre-commit framework (PATHOS hook repository)

pre-commit reads `.pre-commit-hooks.yaml` from the root of a hook
repository, so mirror this directory as its own Git repository inside your
organization (for example `security/pathos-hooks`) and tag it. Then:

```yaml
repos:
  - repo: https://git.example.com/security/pathos-hooks
    rev: v2.1.0
    hooks:
      - id: pathos-gitleaks          # gitleaks on PATH
      # - id: pathos-gitleaks-docker # or: Docker only, pinned official image
```

## Option 3: plain Git hook

```sh
cp hooks/pre-commit /path/to/repo/.git/hooks/pre-commit
chmod +x /path/to/repo/.git/hooks/pre-commit
```

For every repository on a machine: copy it to a directory such as
`~/.config/git/hooks/` and run `git config --global core.hooksPath ~/.config/git/hooks`.

Settings (environment variables):

| Variable | Effect |
|---|---|
| `PATHOS_GITLEAKS_CONFIG` | Configuration file to use instead of `.gitleaks.toml`. |
| `PATHOS_GITLEAKS_DOCKER=1` | Run the pinned `zricethezav/gitleaks:v8.30.1` image instead of a local binary. |
| `PATHOS_GITLEAKS_OPTIONAL=1` | Let commits through (with a warning) when Gitleaks is not installed. By default the hook fails closed. |

## When a commit is blocked

1. Unstage the file, remove the secret and load it from a secret store or
   environment variable instead.
2. If the secret was ever valid, **revoke and rotate it**.
3. For a false positive, add the narrowest possible allowlist entry to
   `.gitleaks.toml`, or a `gitleaks:allow` comment on the line.

`git commit --no-verify` skips client-side hooks. Your organization's policy
may forbid this, and the server-side checks still apply: the
[pre-receive hook](../pre-receive/README.md), PATHOS push-event scanning and
scheduled PATHOS scans all see the commit.

See the user guide page *Secret push protection* for the full picture.
