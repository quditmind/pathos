---
title: IDE integration (VS Code)
section: user-guide
group: connect
order: 24
version: "1.0"
updated: 2026-11-19
summary: The PATHOS extension for Visual Studio Code: installation, API token, repository detection, findings in the Problems panel and the Findings view, details, triage actions, privacy and troubleshooting.
---
# IDE integration (VS Code)

The PATHOS extension for Visual Studio Code shows the open findings of your repository where you write the code:

- in the **Problems** panel and as squiggles at the reported file and line
- in a **Findings** view in the activity bar, grouped by severity and file
- in a **details** page with description, remediation, risk score and code snippet

From the editor you can also open a finding in PATHOS, change its status and request a [Human Eye](human-review.md) review, with exactly the permissions of your PATHOS account.

The extension is in `ide/vscode` of the PATHOS repository. It needs VS Code 1.90 or later. For IntelliJ IDEA, GoLand, PyCharm, WebStorm and the other JetBrains IDEs, see [IDE integration (JetBrains)](ide-integration-jetbrains.md).

## Install

Build or download the `.vsix` file (each CI run publishes it as the `pathos-vscode-vsix` artifact; to build it yourself run `npm ci && npm run package` in `ide/vscode`), then install it:

```bash
code --install-extension pathos-vscode-0.1.0.vsix
```

Or in VS Code: **Extensions** → **…** → **Install from VSIX…**.

## Connect to PATHOS

1. **Create a REST API token.** In PATHOS, open the user menu → **API tokens (MCP)** ([REST API tokens](reporting-and-integrations.md#rest-api-tokens)). Choose what it **Allows**:
   - **REST API: read** (`api:read`) is enough to see findings.
   - **REST API: read and write** (`api:write`) is needed to change a status or request a review.

   Copy the token; it is shown only once. It expires after 7, 30 or 90 days.
2. **Set the URL.** In VS Code, open **Settings** and set **PATHOS: Url** (`pathos.url`) to the address of PATHOS, for example `https://pathos.example.com`. It must use `https://`; plain `http://` is accepted only for `localhost` and `127.0.0.1`. This is a user setting: a workspace's `.vscode/settings.json` cannot change it, so a cloned repository cannot redirect your token to another server.
3. **Set the token.** Run **PATHOS: Set API token** from the Command Palette and paste it. VS Code stores it in its secret storage, which uses the operating system's keychain (macOS Keychain, Windows Credential Manager, the Secret Service on Linux). It is never written to `settings.json`. The token is stored for this PATHOS URL only; after changing the URL, set a token again. **PATHOS: Clear API token** removes it.

The PATHOS icon in the activity bar shows these steps as links until both are done.

## Repository detection

The extension reads the git remotes of your workspace folders (through VS Code's built-in Git extension, or `.git/config` when that is not available) and compares them with the repositories in PATHOS:

- It first compares the remote with the repository's URL. HTTPS, SSH and `git@host:org/repo` forms are treated as the same address; letter case, credentials, ports and a trailing `.git` are ignored, and Azure DevOps URL variants are unified.
- If no URL matches, a repository whose full name (for example `example-org/payments-api`) equals the remote's path is used.

When exactly one repository matches, it is selected. Otherwise, or to choose another one, run **PATHOS: Select repository**: the list shows the detected repositories first, then every repository you can see. With several workspace folders, you also choose the folder the repository is checked out in. The choice is remembered for the workspace.

Seeing the repository list needs `repos.read`; seeing its findings needs `findings.read` on the repository.

## Findings in the editor

The extension loads the repository's **open** findings (status *Open*, *In progress* and *Needs review*), highest severity first, up to `pathos.maxFindings` (default 5,000). It loads them when VS Code starts, on **PATHOS: Refresh findings** (also the refresh button of the view and the status bar item), and every `pathos.refreshIntervalMinutes` minutes when that setting is above 0.

### Problems panel

Each finding with a file location becomes a problem at its line, with the source **PATHOS**:

| PATHOS severity | VS Code |
|---|---|
| Critical, High | Error |
| Medium | Warning |
| Low | Information |
| Info | Hint |

The message shows the severity, title, CWE and risk score. The code is the scanner's rule ID; clicking it opens the finding in PATHOS. The light bulb (**Quick Fix**) on the line offers **Show details** and **Open in PATHOS**.

Paths are taken relative to the workspace folder of the repository. Findings without a file (for example container or URL findings) and findings whose file does not exist in your checkout are not shown as problems, but they are listed in the Findings view.

### Findings view

The **PATHOS → Findings** view groups the findings by severity, then by file. The **Toggle grouping** button switches to grouping by file only. The view's description shows the selected repository.

- Click a finding to open its file at the reported line (or its details when the file is not in your checkout).
- The inline buttons show the details or open the finding in PATHOS.
- The context menu also has **Change finding status** and **Request Human Eye review**.

### Details

**PATHOS: Show finding details** opens a page with the title, severity, status, risk score, CWE, CVE, CVSS, EPSS, KEV, reachability, scanner and rule, location, package and fixed version, assignee, SLA, Human Eye review, description, remediation and the code snippet the scanner captured, plus a link to the finding in PATHOS. The page runs no scripts and loads nothing from the network; all scanner text is shown as plain text.

## Actions and permissions

| Action | Command | PATHOS permission | Token |
|---|---|---|---|
| See findings | Refresh findings | `repos.read`, `findings.read` | `api:read` |
| Open in PATHOS | Open finding in PATHOS | (signed in to the web UI) | — |
| Change the status | Change finding status | `findings.triage`; closing a **Critical** finding as false positive also needs `findings.accept_risk` | `api:write` |
| Request a Human Eye review | Request Human Eye review | `reviews.assign` | `api:write` |

**Change finding status** offers the manual changes PATHOS allows from the current status ([Working with findings](findings.md)): *Open*, *In progress*, *Needs review*, *False positive* and *Fixed*. *False positive* and *Fixed* need a reason of at least 5 characters; for the others it is optional. Both are recorded in the finding's status history and the audit log, with the token's id. *Accepted risk* is not offered: it needs the risk acceptance workflow in PATHOS.

**Request Human Eye review** adds the finding to the Human Eye queue with an optional reason. If the finding already has a review, nothing is added.

When PATHOS refuses an action, the extension says why: your role does not permit it, or the token is read-only and you need a token that allows **REST API: read and write**.

## Privacy

- **No telemetry.** The extension collects and sends no usage data.
- It only talks to the configured PATHOS URL, over HTTPS (or plain HTTP on localhost). It sends the token only in the `Authorization` header of those requests, never follows redirects (so the token cannot be forwarded to another host) and never logs it.
- The token is kept in VS Code's secret storage (the OS keychain), not in settings files.
- Findings are held in memory only. Nothing about your code is sent to PATHOS: the extension only reads findings and sends the status changes and review requests you make.

## Troubleshooting

| Problem | What to do |
|---|---|
| "PATHOS rejected the API token" | The token is invalid, expired or revoked. Create a new one and run **PATHOS: Set API token**. |
| "Refusing plain http://" | Use the `https://` address of PATHOS. Plain HTTP is only allowed for `localhost`. |
| "The PATHOS URL … is not a valid URL" or no findings load | Check `pathos.url`: the address you open PATHOS with in the browser, without a path such as `/findings`. |
| "returned invalid JSON (is pathos.url the PATHOS address?)" | The URL points to something else, for example a sign-in proxy page. |
| "this token only has api:read" | Create a token that allows **REST API: read and write**. |
| "your PATHOS role does not permit this" | Ask your administrator for the permission in the table above. |
| No repository is detected | Check `git remote -v` in the folder and the repository's URL in PATHOS, or pick it with **PATHOS: Select repository**. |
| Findings are in the view but not in the Problems panel | The finding has no file location, or the file does not exist in your checkout (another branch, a moved file or a path outside the repository). |
| "Showing the first N findings" | Raise `pathos.maxFindings` (at most 20,000) or work through the highest severities first. |
| Anything else | **View → Output → PATHOS** shows the extension's log, with PATHOS request IDs to quote to your administrator. |
