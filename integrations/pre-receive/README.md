# PATHOS secret check on the Git server (pre-receive)

`pathos-pre-receive` is a server-side `pre-receive` hook for self-hosted Git
servers. It rejects a push when the commits it adds contain a secret, using
[Gitleaks](https://github.com/gitleaks/gitleaks) (MIT licence, v8.30.1 — the
version the PATHOS worker runs). It cannot be skipped with
`git commit --no-verify`.

How it works:

- Reads the updated refs from standard input; deleted refs are ignored.
- Scans only commits that are **new to the repository**
  (`git rev-list <new tips> --not --all`): a branch created from existing
  history, or a tag on an existing commit, costs nothing; annotated tags are
  resolved to their commit.
- Runs `gitleaks git --redact --log-opts="<tips> --not --all"`, so values are
  redacted in the messages shown to the pusher.
- Bounded: pushes with more than `PATHOS_PRERECEIVE_MAX_COMMITS` new commits
  (default 2000) are not scanned, and a scan stops after
  `PATHOS_PRERECEIVE_TIMEOUT` seconds (default 60, needs `timeout` from
  coreutils or BusyBox).
- When the push could not be checked (Gitleaks missing, too large, timeout,
  Gitleaks error) it is accepted with a warning, unless
  `PATHOS_PRERECEIVE_STRICT=1`, which rejects it instead.
- Uses `pathos-gitleaks.toml` placed next to the script (copy it from
  `../pre-commit/`), or `PATHOS_GITLEAKS_CONFIG`; otherwise the Gitleaks
  defaults. `PATHOS_GITLEAKS` sets the binary path.

Install Gitleaks v8.30.1 on the Git server (or every Gitaly node) from the
[official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1),
checking the published SHA-256 checksum.

The hook logic (new branches, deletions, tags, rejection, strict and lax
modes) was exercised against a bare repository with a stub scanner; run it
in a test project on your server before enabling it globally.

## GitLab (self-managed)

GitLab runs [server hooks](https://docs.gitlab.com/administration/server_hooks/)
from Gitaly.

- **All repositories:** set `custom_hooks_dir` in the Gitaly configuration
  (Linux package: `gitaly['configuration'] = { hooks: { custom_hooks_dir: '/var/opt/gitlab/gitaly/custom_hooks' } }`),
  then install
  `/var/opt/gitlab/gitaly/custom_hooks/pre-receive.d/pathos-pre-receive` and
  `pathos-gitleaks.toml` next to it, owned by the `git` user and executable.
- **One repository:** upload a tarball containing `custom_hooks/pre-receive`
  with `gitaly hooks set` (GitLab 15.11 and later), as described in the
  GitLab documentation.

GitLab shows the hook's messages to the pusher (`remote: PATHOS: …`).

## Gitea and Forgejo

- **One repository:** *Settings → Git Hooks → pre-receive* (requires
  `DISABLE_GIT_HOOKS = false` in `app.ini` and users allowed to edit Git
  hooks; only grant this to administrators, since hooks run on the server).
  Paste the script.
- **Server-wide:** place the script in each repository's
  `hooks/pre-receive.d/` directory (Gitea runs every executable there), for
  example with a provisioning script; Gitea has no global hook directory.

## Bitbucket Server / Data Center

Bitbucket Server does not run hook scripts natively. Use an add-on that runs
external pre-receive scripts (for example *External Hooks*), and point it at
`pathos-pre-receive`; check the add-on's licence and support status yourself.
PATHOS neither ships nor requires such an add-on. Without one, rely on the
client-side hook and PATHOS scans.

## GitHub and GitLab.com

Hosted services do not run custom pre-receive hooks. Use the client-side
hook (`../pre-commit/`) and enable **secret push protection** on the
repository in PATHOS: it scans the commits of every push received through
the webhook and alerts (it cannot block a push that already happened).
