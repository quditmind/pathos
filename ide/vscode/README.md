# PATHOS for VS Code

Shows the open findings that [PATHOS](https://github.com/quditmind/pathos) (open-source ASPM) holds for your repository, right in the editor:

- **Problems panel**: findings appear as diagnostics at their file and line (critical/high as errors, medium as warnings, low as information, info as hints). The diagnostic code links to the finding in PATHOS.
- **Findings view** (PATHOS icon in the activity bar): grouped by severity and file, or by file only. Click a finding to open its location.
- **Details**: title, severity, status, CWE, risk score, scanner, description, remediation, location and code snippet.
- **Triage**: change the status (with a reason) and request a Human Eye review, with the permissions of your PATHOS account.

## Setup

1. Set **`pathos.url`** in your user settings, for example `https://pathos.example.com` (https is required; http only for `localhost`).
2. In PATHOS, open the user menu → **API tokens (MCP)** and create a token that allows **REST API: read** (view findings) or **REST API: read and write** (also change statuses and request reviews).
3. Run **PATHOS: Set API token** and paste it. The token is stored in VS Code's SecretStorage (the OS keychain), never in settings.
4. The repository is detected from the workspace's git remote. If it is not, run **PATHOS: Select repository**.

Commands: *Set API token*, *Clear API token*, *Select repository*, *Refresh findings*, *Open finding in PATHOS*, *Show finding details*, *Request Human Eye review*, *Change finding status*, *Toggle grouping*.

Settings: `pathos.url`, `pathos.refreshIntervalMinutes` (0 = off), `pathos.maxFindings` (default 5000).

## Privacy

No telemetry. The extension only talks to the configured PATHOS URL, sends the token only in the `Authorization` header of those requests, never follows redirects and never logs the token.

Full documentation: the "IDE integration (VS Code)" page of the PATHOS user guide.

## License

Apache-2.0
