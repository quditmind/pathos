---
title: IDE integration (JetBrains)
section: user-guide
order: 24
version: "1.0"
updated: 2026-11-19
summary: The PATHOS plugin for JetBrains IDEs (IntelliJ IDEA, GoLand, PyCharm, WebStorm and the other IntelliJ-based IDEs): installation, API token, repository detection, findings in the editor and the PATHOS tool window, details, triage actions, privacy and troubleshooting.
---
# IDE integration (JetBrains)

The PATHOS plugin for JetBrains IDEs shows the open findings of your repository where you write the code:

- as **editor annotations** at the reported file and line, with the severity's highlighting
- in a **PATHOS** tool window, grouped by severity and file
- in a **details** window with description, remediation, risk score and code snippet

From the IDE you can also open a finding in PATHOS, change its status and request a [Human Eye](human-review.md) review, with exactly the permissions of your PATHOS account. It works like the [VS Code extension](ide-integration-vscode.md): same repository detection, same severity mapping, same permissions.

The plugin is in `ide/jetbrains` of the PATHOS repository. It depends only on the IntelliJ Platform, so it runs in IntelliJ IDEA, GoLand, PyCharm, WebStorm, PhpStorm, RubyMine, CLion, Rider and the other IDEs built on it, version **2025.3 to 2026.3** (builds 253 to 263).

## Install

Build or download the plugin ZIP file (each CI run publishes it as the `pathos-jetbrains-plugin` artifact; to build it yourself run `scripts/gradle-jetbrains.sh buildPlugin` from the repository root, which needs only Docker, or `./gradlew buildPlugin` in `ide/jetbrains` with JDK 21). The file is `ide/jetbrains/build/distributions/pathos-jetbrains-0.1.0.zip`.

In the IDE: **Settings** → **Plugins** → the gear icon → **Install Plugin from Disk…**, choose the ZIP file and restart the IDE when asked.

## Connect to PATHOS

1. **Create a REST API token.** In PATHOS, open the user menu → **API tokens (MCP)** ([REST API tokens](reporting-and-integrations.md#rest-api-tokens)). Choose what it **Allows**:
   - **REST API: read** (`api:read`) is enough to see findings.
   - **REST API: read and write** (`api:write`) is needed to change a status or request a review.

   Copy the token; it is shown only once. It expires after 7, 30 or 90 days.
2. **Open the settings.** **Settings** → **Tools** → **PATHOS** (also **Tools** → **PATHOS** → **PATHOS Settings…**, or the gear in the PATHOS tool window).
3. **Set the server URL** to the address of PATHOS, for example `https://pathos.example.com`. It must use `https://`; plain `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`. This is an IDE-wide setting, not a project setting: a project you open cannot change where your token is sent.
4. **Paste the token** into **API token** and click **OK** or **Apply**. The IDE stores it in its password safe, which uses the operating system's keychain by default (macOS Keychain, Windows Credential Manager, the Secret Service on Linux) or KeePass if you chose that under **Settings** → **Appearance & Behavior** → **System Settings** → **Passwords**. It is never written to the IDE's settings files. The token is stored for this PATHOS URL only; after changing the URL, set a token again. **Clear Stored Token** (or **Tools** → **PATHOS** → **Clear API Token**) removes it. **Tools** → **PATHOS** → **Set API Token…** is a shortcut for pasting a new token.

Until both are set, the PATHOS tool window shows a link to the settings.

## Repository detection

The plugin reads the git remotes of the project's git checkouts (the IDE's version control roots and the content roots that contain a `.git` directory, or a `.git` file for worktrees and submodules) from their `.git/config` and compares them with the repositories in PATHOS:

- It first compares the remote with the repository's URL. HTTPS, SSH and `git@host:org/repo` forms are treated as the same address; letter case, credentials, ports and a trailing `.git` are ignored, and Azure DevOps URL variants are unified.
- If no URL matches, a repository whose full name (for example `example-org/payments-api`) equals the remote's path is used.

When exactly one repository matches, it is selected. Otherwise, or to choose another one, use **Select Repository…** (tool window toolbar, or **Tools** → **PATHOS**): the list shows the detected repositories first, then every repository you can see. With several git checkouts in the project, you also choose the checkout the repository is in. Finding paths are taken relative to that checkout. The choice is remembered for the project (in `.idea/workspace.xml`, which is not shared through version control).

Seeing the repository list needs `repos.read`; seeing its findings needs `findings.read` on the repository.

## Findings in the editor

The plugin loads the repository's **open** findings (status *Open*, *In progress* and *Needs review*), highest severity first, up to **Max findings** (default 5,000, at most 20,000). It loads them when the project opens, on **Refresh Findings** (tool window toolbar or **Tools** → **PATHOS**), after you change the settings, and every **Refresh every** minutes when that setting is above 0.

### Editor annotations

Each finding with a file location becomes an annotation on its line:

| PATHOS severity | JetBrains IDE |
|---|---|
| Critical, High | Error (red underline, error stripe) |
| Medium | Warning |
| Low | Weak warning |
| Info | Information (gray dotted underline) |

The message shows the severity, title, CWE and risk score. **Alt+Enter** on the line offers **PATHOS: Show details** and **PATHOS: Open in PATHOS**. The annotations work in every file type, including plain text and configuration files. An *Info* finding on the same line as a *Critical* or *High* finding is hidden by the IDE under the error highlighting; it is still listed in the tool window.

Paths are taken relative to the git checkout of the repository. Findings without a file (for example container or URL findings) and findings whose file does not exist in your checkout are not shown in the editor, but they are listed in the tool window.

### PATHOS tool window

The **PATHOS** tool window (bottom) groups the findings by severity, then by file. **Toggle Grouping** switches to grouping by file only. The line above the tree shows the selected repository and the number of open findings, or the last error.

- Double-click a finding (or press **Enter**) to open its file at the reported line, or its details when the file is not in your checkout.
- The context menu has **Open Finding Location**, **Show Finding Details**, **Open Finding in PATHOS**, **Change Finding Status…** and **Request Human Eye Review…**.

The same actions are in **Tools** → **PATHOS** and in **Find Action** (**Ctrl+Shift+A** / **Cmd+Shift+A**); without a selected finding they show a list of the loaded findings, those of the current file first.

### Details

**Show Finding Details** opens a window with the title, severity, status, risk score, CWE, CVE, CVSS, EPSS, KEV, reachability, scanner and rule, location, package and fixed version, assignee, SLA, Human Eye review, description, remediation and the code snippet the scanner captured. Its buttons open the finding in PATHOS, change its status or request a review. All scanner text is shown as plain text; the window loads nothing from the network.

## Actions and permissions

| Action | Command | PATHOS permission | Token |
|---|---|---|---|
| See findings | Refresh Findings | `repos.read`, `findings.read` | `api:read` |
| Open in PATHOS | Open Finding in PATHOS | (signed in to the web UI) | — |
| Change the status | Change Finding Status… | `findings.triage`; closing a **Critical** finding as false positive also needs `findings.accept_risk` | `api:write` |
| Request a Human Eye review | Request Human Eye Review… | `reviews.assign` | `api:write` |

**Change Finding Status…** offers the manual changes PATHOS allows from the current status ([Working with findings](findings.md)): *Open*, *In progress*, *Needs review*, *False positive* and *Fixed*. *False positive* and *Fixed* need a reason of at least 5 characters; for the others it is optional. Both are recorded in the finding's status history and the audit log, with the token's id. *Accepted risk* is not offered: it needs the risk acceptance workflow in PATHOS.

**Request Human Eye Review…** adds the finding to the Human Eye queue with an optional reason. If the finding already has a review, nothing is added.

When PATHOS refuses an action, the plugin says why in a notification: your role does not permit it, or the token is read-only and you need a token that allows **REST API: read and write**.

## Privacy

- **No telemetry.** The plugin collects and sends no usage data.
- It only talks to the configured PATHOS URL, over HTTPS (or plain HTTP on localhost), through the IDE's HTTP proxy settings (a proxy that needs a password is not supported). It sends the token only in the `Authorization` header of those requests, never follows redirects (so the token cannot be forwarded to another host) and never logs it.
- The token is kept in the IDE's password safe, not in settings files.
- Findings are held in memory only. Nothing about your code is sent to PATHOS: the plugin only reads findings and sends the status changes and review requests you make.

## Troubleshooting

| Problem | What to do |
|---|---|
| "PATHOS rejected the API token" | The token is invalid, expired or revoked. Create a new one and paste it in **Settings** → **Tools** → **PATHOS**. |
| "Refusing plain http://" | Use the `https://` address of PATHOS. Plain HTTP is only allowed for `localhost`. |
| "The PATHOS URL … is not a valid URL" or no findings load | Check the server URL: the address you open PATHOS with in the browser, without a path such as `/findings`. |
| "PATHOS answered with a redirect" | The URL is not the final address (for example `http` redirected to `https`, or a different host name). Use the address PATHOS is served at. |
| "returned invalid JSON (is the PATHOS URL the PATHOS address?)" | The URL points to something else, for example a sign-in proxy page. |
| "Cannot reach PATHOS" | The server is down or not reachable from your machine; check the URL, VPN and the IDE's proxy settings (**Settings** → **Appearance & Behavior** → **System Settings** → **HTTP Proxy**). |
| "this token only has api:read" | Create a token that allows **REST API: read and write**. |
| "your PATHOS role does not permit this" | Ask your administrator for the permission in the table above. |
| No repository is detected | Check `git remote -v` in the checkout and the repository's URL in PATHOS, or pick it with **Select Repository…**. |
| Findings are in the tool window but not in the editor | The finding has no file location, or the file does not exist in your checkout (another branch, a moved file or a path outside the repository). |
| "Showing the first N findings" | Raise **Max findings** (at most 20,000) or work through the highest severities first. |
| Anything else | **Help** → **Show Log in Files** (`idea.log`) contains the plugin's messages (category `io.github.quditmind.pathos`), with PATHOS request IDs to quote to your administrator. |
