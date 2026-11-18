---
title: Material changes and developer insights
section: user-guide
order: 24
version: "1.0"
updated: 2026-11-19
summary: Security-material change detection between scanned commits (authentication, new endpoints, dependencies, cryptography, infrastructure exposure, secrets handling, CI/CD, sensitive data), the change.material notification and policy condition, and opt-in developer attribution with its privacy controls.
---
# Material changes and developer insights

PATHOS gives developer context in two ways:

- **Material changes**: on every branch scan of a Git repository, PATHOS compares the scanned commit with the commit of the previous scan of the same branch and lists the changes that matter for security, with the rule that matched and why it matters.
- **Developer insights** (opt-in, off by default): who introduced and who fixed findings, per git author, per linked user and per team.

Neither needs AI. Both are computed by deterministic rules you can read below.

## Material changes

### What is compared

When a worker scans a repository at a new commit, it also fetches the commit of the previous successful scan of the **same ref** and computes the diff between the two commits (only those two commits; full-history repositories use their existing clone). The rules run on the changed lines of that diff in the worker; only the matches are sent to PATHOS. The dependency rule compares the scan's SBOM (Syft) with the SBOM of the previous scan.

Each scan records how the comparison went:

| Status | Meaning |
|---|---|
| Computed | The two commits were compared. Very large diffs (over 32 MB) are analysed partially and marked as such. |
| Baseline | The first scan of a branch; it is what the next scan is compared with. |
| Unchanged | Same commit as the previous scan. |
| Unavailable | The comparison could not run, with the reason: for example the previous commit no longer exists (rewritten history), the server does not serve commits by ID, or the repository is an upload (no Git history). |

Pull request checks, uploaded repositories (snapshots) and scan targets (images, URLs, APIs, SBOMs) have no material changes.

### Rules

| Category | What is detected | Frameworks |
|---|---|---|
| Authentication / authorization | Added, changed or removed authentication and authorization code; files whose path names authentication, sessions, permissions, OAuth, SAML, JWT or SSO | Spring Security (`SecurityFilterChain`, `@PreAuthorize`, `requestMatchers`, `permitAll` …), Django and Django REST framework (`@login_required`, `permission_classes`, `AUTHENTICATION_BACKENDS` …), Flask/FastAPI (`@jwt_required`, `Depends(get_current_user)` …), Express/Passport/NestJS (`passport.use`, `jwt.verify`, `@UseGuards` …), Go middleware (gin/echo/chi basic auth and JWT), ASP.NET (`[Authorize]`, `[AllowAnonymous]`, `AddAuthorization` …) |
| New API endpoint | New HTTP routes | Express/Fastify/Koa/NestJS, Flask/FastAPI/Django URL patterns, Spring `@RequestMapping`/`@GetMapping` and JAX-RS, Go net/http, gin, echo, chi, gorilla, ASP.NET controllers and minimal APIs |
| New dependency | A package in this scan's SBOM that the previous SBOM did not have | Every ecosystem Syft catalogs |
| Cryptography | Added, changed or removed encryption, hashing, signing, key generation, randomness and TLS configuration (including `InsecureSkipVerify`, `verify=False`) | Java, Node.js, Python, Go, .NET and others |
| Infrastructure exposure | Rules open to the internet (`0.0.0.0/0`, `::/0`), public buckets and ACLs, disabled public access blocks, public network access, `"Principal": "*"`, Kubernetes `LoadBalancer`, `privileged` and `hostNetwork` | Terraform, CloudFormation, Bicep, Kubernetes YAML |
| Secrets handling | New code that reads credentials from the environment, vaults or key stores, or private key material | Any language |
| CI/CD pipeline | Changed pipeline definitions; privileged GitHub Actions triggers and permissions (`pull_request_target`, `workflow_run`, `write-all`, `id-token: write`, `secrets: inherit`) | GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI, Bitbucket, Buildkite, Tekton, Drone, Travis, Cloud Build |
| Sensitive data model | New fields named like personal or sensitive data (national IDs, passport, date of birth, payment card, IBAN, health data …) in models, schemas and SQL | Any language, SQL, Prisma, GraphQL, Protobuf, Avro |

Vendored and generated code (`node_modules/`, `vendor/`, `dist/`, lock files …) is ignored; test code is ignored except for pipelines; commented-out lines do not count. Every rule has a level (high or medium); the full list with explanations is in the API (`GET /api/v1/material-changes/rules`).

A material change is a **prompt for a closer look, not a finding**: it never creates, changes or closes a finding.

### Where you see them

- **Scans → an execution → Material changes**: the comparison summary and every change with its rule, location (file and lines), the matched line (secrets redacted) and "Why this is material".
- **Repositories → a repository → Material changes**: the changes of the repository's recent scans, filterable by category and period, with a link to each scan.

Both need `scans.read` on the repository. The author of the last commit that touched the file is shown only when developer attribution is on and you hold `insights.people`.

### Notifications and webhooks

The event **Security-material change** (`change.material`) fires once per scan that found material changes. Its severity is *high* when a high-level rule matched, otherwise *medium*, so a notification rule with minimum severity *high* only fires for changes such as Spring Security configuration, open ingress or privileged workflow triggers. Choose it in **Administration → Notifications** (rules and templates) and for outbound webhooks; the webhook payload lists the changes as `findings` items (`title`, `severity` = level, `location`).

### Security policy condition

A security policy can match findings that **landed with a material change**: in the policy editor, tick categories under *Landed with a security-material change*. A finding matches when its file had a material change of one of those categories in the scan that first reported it. For example "category Authentication / authorization → Require a Human Eye review" queues every finding that arrives together with an authentication change for a manual review. The condition applies to the scan branch only, not to pull request checks.

## Developer insights (attribution)

### Privacy first: off by default

Developer attribution is **off** until an administrator turns it on, because data about individual people needs a deliberate decision (and, in many organizations and jurisdictions, informing employees or their representatives). While it is off:

- workers are not asked for commit authors, and nothing about people is stored;
- material changes do not show authors.

When it is on, workers send the **author names** of the commits between two scans (never e-mail addresses). A git author name is associated with a PATHOS user only when an administrator links them. **Turning attribution off erases** every stored author name, attribution and identity link at once.

### Turning it on

**Administration → Developer attribution** (`settings.manage` at organization scope) → *Turn on developer attribution*. Attribution starts with the next branch scans: the first scan after turning it on only records the commit to compare with. The change is audited (`insights.settings.update`).

### How a finding is attributed

From the commits between the previous and the current scanned commit:

- a **new** finding is attributed to the author of the newest commit in that range that touched the finding's file;
- a **fixed** finding (one the scan no longer reports) to the author of the newest commit in the range that touched its file;
- findings whose file no commit in the range touched stay unattributed.

This is an inference from commit history, not proof of who wrote a line. Use it for coaching and planning, not for individual performance ratings.

### Linking git authors to users

On the same page, users with `users.manage` link an author name seen in scans to a PATHOS user (case-insensitive). Links group attribution per user and per team (the user's teams in **Administration → Users**). Linking and unlinking are audited (`insights.identity.link`, `insights.identity.unlink`).

### Views

**Overview → Developer insights** needs the organization-wide permission `insights.people` (granted to Super Administrator and Security Manager; grant it to others through a custom role). For a period of 30 days to a year:

- **Developers**: per git author: findings introduced (and how many critical/high), still open, fixed, mean time to fix (first detection to fix, for the findings the author fixed) and repositories involved;
- **Teams**: the same per team of the linked users, plus rows for linked users without a team and for authors not linked to a user;
- **Secure-coding trend**: findings introduced and fixed per week, for everyone or one developer.

## Related

- [Running scans](scanning.md) for executions and their tabs
- [Security policies and compliance](policies-and-compliance.md)
- [Administration](administration.md) for notification rules, users and teams
- API: [Material changes and developer insights](../api-reference/developer-context.md)
