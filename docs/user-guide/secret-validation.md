---
title: Live secret validation
section: user-guide
order: 20
version: "2.0"
updated: 2026-11-19
summary: Optional check of detected secrets against their provider (active, revoked or not checked), off by default and enabled per provider by an administrator; the secret never leaves the worker.
---
# Live secret validation

A secret scanner tells you that a string looks like a credential. It cannot
tell you whether the credential still works. Live secret validation asks the
credential's own provider, with one read-only "who am I" request, so a secret
finding can say:

| Verdict | Meaning | What PATHOS does |
|---|---|---|
| **Active** | The provider accepted the credential. | The finding becomes **critical** (the previous severity is kept as evidence), its risk likelihood is set to the maximum, and the drawer asks you to rotate the key now. |
| **Revoked or invalid** (`inactive`) | The provider rejected it: revoked, expired or never valid. | A severity raised by an earlier *Active* verdict goes back to the scanner's severity. Remove the value from the code and history anyway. |
| **Check failed** (`error`) | No answer, rate limit, unexpected status, or the egress proxy refused the host. | Nothing else changes. An earlier *Active* or *Revoked* verdict is kept; the failure is shown as the last attempt. |
| **Not checked** | Validation is off, the provider is not enabled, the credential type cannot be checked, or the secret is not in the scanned files. | The reason is shown. |

Validation is **off by default**. It contacts third-party services, so an
administrator enables it provider by provider (see
[Administration](administration.md#secret-validation)).

## How it works

1. A repository scan runs the secret scanners as usual. Gitleaks, TruffleHog
   and Kingfisher keep their own verification off, and secret values are
   removed from stored reports and findings.
2. If providers are enabled, the **worker** (never the API server) reads each
   secret finding's line from its checkout (for secrets found in the Git
   history, from the commit that added them), recognizes the credential (for
   pairs such as an AWS key ID and secret, within three lines) and sends it
   once to that provider's endpoint, through the egress proxy.
3. The worker uploads only the verdict, the request it made, the HTTP status,
   a short explanation and, for active credentials, a non-secret identity
   (account ID, user name or organization ID). The secret itself is never
   sent to PATHOS, never stored and never logged.

Checks are spaced at the configured rate (1 per second by default) and
limited per scan (50 by default); each request times out after 10 seconds,
redirects are not followed, and the worker refuses any host that is not the
provider's own.

Pull request scans, scan targets and installations running with
`PATHOS_OFFLINE=true` are never validated.

## Providers

| Provider | Request | Identity shown |
|---|---|---|
| AWS access key | `POST https://sts.amazonaws.com/` `GetCallerIdentity` (Signature Version 4) | Account ID and ARN |
| GitHub token | `GET https://api.github.com/user` (then `/rate_limit` for token types that cannot read `/user`) | User login |
| GitLab token (gitlab.com) | `GET https://gitlab.com/api/v4/user` | User name |
| Slack token | `POST https://slack.com/api/auth.test` | Team and user IDs |
| Stripe secret or restricted key | `GET https://api.stripe.com/v1/balance` | Live or test mode |
| OpenAI API key | `GET https://api.openai.com/v1/models` | Organization ID (response header) |
| Anthropic API key | `GET https://api.anthropic.com/v1/models` | Organization ID (response header, when sent) |
| SendGrid API key | `GET https://api.sendgrid.com/v3/scopes` | — (number of scopes) |
| Twilio account SID and auth token | `GET https://api.twilio.com/2010-04-01/Accounts/{AccountSid}.json` | Account SID |
| npm access token | `GET https://registry.npmjs.org/-/whoami` | User name |
| Google API key | `GET https://generativelanguage.googleapis.com/v1beta/models` (model list, no billable call; key sent in a header) | — |
| Azure Storage account key | `GET https://{account}.blob.core.windows.net/?restype=service&comp=properties` (Shared Key) | Storage account name |

Not checked, with the reason shown on the finding:

- **PyPI tokens**: PyPI has no read-only endpoint that checks a token (only
  uploads use it).
- **AWS temporary keys** (`ASIA…`): they need a session token.
- **Slack webhook URLs**: the only test is posting a message.
- Tokens of self-managed GitLab instances, and any credential PATHOS does not
  recognize on the finding's line.

How a provider's answer maps to a verdict:

- HTTP 200 (Slack: `ok: true`) is **active**; HTTP 401 (Slack: `invalid_auth`,
  `token_revoked`, `account_inactive`…; AWS: `InvalidClientTokenId`; Google:
  `API_KEY_INVALID`; Azure: `AuthenticationFailed`) is **inactive**.
- Some 403 answers prove that the credential exists: a Stripe restricted key
  without balance access, a GitLab token without the `read_user` scope, a
  Google key restricted to other APIs. They are **active**, with the reason as
  evidence.
- Everything else (429, 5xx, an AWS `SignatureDoesNotMatch` for a secret found
  next to a key ID it does not belong to) is **error**.

The checks are built from each provider's published API documentation and are
tested against local stand-ins of each provider; they have not been run
against the live services in this release.

## In the findings

- **Finding drawer → Live secret validation**: the verdict, the provider, when
  it was checked, the request and HTTP status, the explanation, the last
  inconclusive attempt and, for active keys, the identity and the severity
  before it was raised.
- **Re-check** (permission `scans.run`): PATHOS keeps no secret, so it queues a
  scan of the repository; the verdict is updated when that scan finishes. It
  is refused while validation is off.
- **Findings → Secret check** filter: active, revoked or invalid, check
  failed, not checked. The hidden **Secret check** column adds the verdict to
  CSV exports, and active keys get an *Active key* badge next to the risk.
- **Contextual risk**: an active credential sets the exploit likelihood to the
  maximum ("leaked credential validated as active").
- The security gate counts new critical findings, so a newly found active
  secret fails a gate that fails on critical findings.

## What to do

1. **Active**: rotate or revoke the credential at the provider first, then
   remove it from the code and the Git history, and check the provider's logs
   for use you do not recognize.
2. **Revoked or invalid**: remove it from the code and history; nothing is
   urgent at the provider.
3. **Check failed**: read the evidence. A refusal by the egress proxy means the
   provider's host is not on the allowlist yet.

See also [Secret push protection](secret-push-protection.md) to stop secrets
before they reach the repository.
