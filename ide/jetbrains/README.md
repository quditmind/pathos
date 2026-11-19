# PATHOS for JetBrains IDEs

Shows the open findings that [PATHOS](https://github.com/quditmind/pathos) (open-source ASPM) holds for your repository in IntelliJ IDEA, GoLand, PyCharm, WebStorm and the other IDEs built on the IntelliJ Platform (2025.3 to 2026.3). Same features and rules as the [VS Code extension](../vscode/README.md):

- **Editor annotations** at the finding's file and line: critical/high as errors, medium as warnings, low as weak warnings, info as information (gray dotted underline). **Alt+Enter** offers *Show details* and *Open in PATHOS*.
- **PATHOS tool window**: findings grouped by severity and file, or by file only. Double-click opens the location.
- **Details**: title, severity, status, CWE, risk score, scanner, description, remediation, location and code snippet.
- **Triage**: change the status (with a reason) and request a Human Eye review, with the permissions of your PATHOS account.

## Setup

1. Install the ZIP: **Settings → Plugins → ⚙ → Install Plugin from Disk…** (CI publishes it as the `pathos-jetbrains-plugin` artifact; releases attach it).
2. In PATHOS, open the user menu → **API tokens (MCP)** and create a token that allows **REST API: read** (view findings) or **REST API: read and write** (also change statuses and request reviews).
3. **Settings → Tools → PATHOS**: set the server URL (https required; http only for `localhost`) and paste the token. The token is stored in the IDE's password safe (OS keychain or KeePass) for that URL only, never in settings files.
4. The repository is detected from the project's git remotes. If it is not, use **Select Repository…** in the tool window or **Tools → PATHOS**.

Actions (tool window, **Tools → PATHOS**, Find Action): *Refresh Findings*, *Toggle Grouping*, *Select Repository…*, *Show Finding Details*, *Open Finding in PATHOS*, *Change Finding Status…*, *Request Human Eye Review…*, *Set API Token…*, *Clear API Token*, *PATHOS Settings…*.

Settings: server URL, API token, refresh interval in minutes (0 = off), max findings (default 5000, at most 20000).

## Privacy

No telemetry. The plugin only talks to the configured PATHOS URL (through the IDE's HTTP proxy settings), sends the token only in the `Authorization` header of those requests, never follows redirects and never logs the token. Untrusted scanner text is never rendered as HTML.

## Build and test

Everything runs in a container (`eclipse-temurin` JDK 21, pinned by digest); only Docker is needed on the host:

```bash
scripts/gradle-jetbrains.sh build          # compile, unit and platform tests, plugin ZIP
scripts/gradle-jetbrains.sh verifyPlugin   # JetBrains Plugin Verifier against IntelliJ IDEA 2025.3 and 2026.3
```

To try the plugin in a sandbox IDE, run `./gradlew runIde` in `ide/jetbrains` with a local JDK 21 (it needs a display, so not in the container).

The ZIP is `build/distributions/pathos-jetbrains-<version>.zip`. Gradle and the IntelliJ Platform are cached in `~/.cache/pathos-gradle` (`PATHOS_GRADLE_CACHE` sets another directory or a Docker volume); the first build downloads about 3 GB, the verifier IDEs about 3 GB more.

Versions are pinned: Gradle 9.9.1 (wrapper with `distributionSha256Sum`), Kotlin 2.4.21, IntelliJ Platform Gradle Plugin 2.20.1, IntelliJ IDEA 2025.3 as build platform (`gradle.properties`). The plugin uses the Kotlin standard library bundled with the IDE (API version 2.2) and has no third-party runtime dependencies (its JSON parser is built in). Every downloaded artifact is checked against the SHA-256 in `gradle/verification-metadata.xml`; the IntelliJ IDEA archives there are the Linux ones and match the SHA-256 that JetBrains publishes next to each download, so builds verify in the container (Linux); a `./gradlew` run on macOS or Windows downloads other archives and needs `--dependency-verification lenient` or its own entries. After changing a dependency, regenerate the file with `scripts/gradle-jetbrains.sh --write-verification-metadata sha256 build verifyPlugin` and review the diff. The `localIde`, `bundledModule` and `bundledPlugin` entries are generated locally from the verified IDE archive and are trusted.

Tests:

- `PathosClientTest`: the API client against a local JDK `HttpServer`: pagination, caps, request bodies, error mapping (401, 403 variants, 404, 409, 400/422, 429, 5xx), invalid JSON, unreachable server, timeout, redirects not followed (the redirect target receives nothing), token never in errors.
- `MappingTest`: remote URL normalization and repository matching (same cases as the VS Code extension), severity mapping, paths, status transitions, grouping.
- `DetailsAndGitTest`: HTML escaping of scanner text, `.git/config` and worktree remotes, JSON parser.
- `PathosExternalAnnotatorTest` (`BasePlatformTestCase`, headless IDE): annotations, severities, ranges and quick fixes in text and XML files.

Full documentation: the "IDE integration (JetBrains)" page of the PATHOS user guide.

## License

Apache-2.0
