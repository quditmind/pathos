---
title: Scan types and tool manifests
section: api-reference
order: 23
version: "2.0"
updated: 2026-11-19
summary: The 25 scan types with their tools, import formats and live workers (GET /api/v1/scan-types), and the tool manifest format (v2) with its parsers sarif, import and jsonmap.
---
# Scan types and tool manifests

PATHOS reports on 25 **scan types** (SAST, DAST, SCA, secrets, IaC, container, API security, IAST, mobile, fuzzing, licence, SBOM, malware, code-quality security, supply chain, cryptography, configuration, CI/CD pipeline, binary, AI/LLM, runtime, compliance, licence policy, database security, manual review). Tools are added with **tool manifests**: first-party manifests shipped in family worker images, and operator plugins on a worker host. How to write one is described in the scanner catalog (`docs/SCANNER_CATALOG.md`, "Adding a tool"); this page lists the API and the formats.

## List scan types

`GET /api/v1/scan-types` — permission `scanners.read` at any scope (like the [scanner catalog](scan-configuration.md#scanner-catalog)).

```json
{
  "workers_online": 2,
  "generic_import_formats": [ { "id": "sarif", "label": "SARIF 2.1", "tool": "" }, { "id": "pathos", "label": "PATHOS findings JSON", "tool": "" } ],
  "items": [
    {
      "id": "sast",
      "name": "SAST",
      "kind_of_check": "sast-deep",
      "description": "Static analysis of source code for security weaknesses",
      "categories": ["sast"],
      "tools": [
        { "key": "opengrep", "name": "Opengrep", "category": "sast", "license_spdx": "LGPL-2.1", "source": "catalog",
          "adapter_available": true, "runnable": true, "workers": 2, "network": "none", "intrusive": false,
          "targets": ["repository"], "decision": "use" },
        { "key": "bandit", "name": "Bandit", "category": "sast", "license_spdx": "Apache-2.0", "source": "catalog",
          "adapter_available": true, "runnable": false, "workers": 0, "network": "none", "intrusive": false,
          "targets": ["repository"], "decision": "use" }
      ],
      "import_formats": [ { "id": "semgrep", "label": "Semgrep / Opengrep JSON", "tool": "Semgrep" } ],
      "runnable_tools": 1,
      "runnable": true,
      "importable": true
    }
  ]
}
```

| Field | Description |
|---|---|
| `id`, `name`, `description` | The scan type. Ids: `sast`, `dast`, `sca`, `secrets`, `iac`, `container`, `api`, `iast`, `mobile`, `fuzzing`, `license`, `sbom`, `malware`, `code-quality`, `supply-chain`, `crypto`, `configuration`, `cicd`, `binary`, `ai`, `runtime`, `compliance`, `license-policy`, `database`, `manual` |
| `categories` | The finding categories its findings are recorded under (for example `cicd` also lists `iac`, the category of zizmor and actionlint findings; `sbom` and `manual` list none) |
| `note` | Explains a mapping that is not obvious (optional) |
| `tools[]` | The catalog tools that cover the type, plus operator plugins that online workers advertise for it |
| `tools[].source` | `catalog`, `plugin` (operator plugin) or `server` (evaluated by PATHOS itself: licence policy, end-of-life feed) |
| `tools[].adapter_available` | A PATHOS worker image or manifest can run the tool |
| `tools[].runnable`, `tools[].workers` | An online, non-revoked worker of this deployment advertises the tool, and how many do. For `server` tools: the check is active (the end-of-life feed only when it is enabled) |
| `tools[].network`, `tools[].intrusive`, `tools[].targets` | What the tool contacts, whether it sends attack traffic, and what it scans ([manifests](#tool-manifests)) |
| `import_formats` | [Result import formats](result-imports.md) specific to the type: the formats whose default category is the type's first category, and the formats the type names because their findings keep their own categories (for example `gitlab`, `asff`, `gcp-scc`, the linters with `code-quality` rules) or are recorded under another category (DAST tools under API security, TLS scanners under cryptography). The generic ones, listed once in `generic_import_formats` (SARIF, PATHOS findings JSON, CSV), apply to every type |
| `runnable_tools`, `runnable` | How many tools are runnable now; `true` when at least one is |
| `importable` | At least one specific import format exists |
| `kind_of_check` | The kind of check the scan type is grouped under (PATHOS 3.0 M6, a display grouping; every scan type has exactly one) |
| `kinds[]` | The 20 [kinds of check](../user-guide/security-scanning.md#tool-names-and-kinds-of-check), then `ai`, `manual` and `other` (`outside_kinds: true`): `id`, `name`, `phase`, `after_v2`, `scan_types`, `tools` (the kind's 10 reference tools: `name`, `key` when catalogued, `source` `catalog` \| `feed` \| `pathos` \| `gap`, `mode` for a mode of a catalogued tool that is not wired, `after_v2`, `runnable`), `extra_tools` (other catalogued tools of its scan types), `catalogued`, `runnable` and `gaps` counts |

Nothing in the response is fixed text: workers, plugins and formats come from the database and the registered parsers when the request is made.

## Tool manifests

A manifest is a YAML or JSON file read by the worker (never sent to the API). The fields, the placeholders and the trust model are listed in the scanner catalog. What the API sees of a manifest:

- **Registration** ([worker protocol](worker-protocol.md#register)): the worker advertises each manifest tool in `tools` with `name`, `category`, `scan_types`, `license_spdx`, `homepage`, `family`, `targets`, `network`, `intrusive`, `requires_build`, `parser` and `first_party`. Operator plugins get a catalog row (`worker_family: "plugin"`) through a database function that accepts only `plugin-<category>-<name>` keys; it never lowers a tool's `network: target` or `intrusive` declaration. First-party manifests use the catalog entry of their key.
- **Routing**: a scan job that uses manifest tools is leased only by a worker that advertises all of them, unless no online worker does.
- **Results** ([worker protocol](worker-protocol.md#results)): the worker uploads the tool's own output with the manifest's `parser`. The parser is stored with the raw report (`scan_artifacts.parser`) and is used again to locate a finding in it (for example when a Human Eye review captures the original output).
- **Authorization**: tools with `network: target` run only for [web application, API and LLM endpoint targets](scan-targets.md) with an authorization statement; `intrusive` tools also need the target's intrusive testing flag (`intrusive_authorized`). Repository scan profiles refuse both.
- **Rate limit**: a tool with `network: target` gets the target's rate limit (`config.rate_limit`, 1–100 requests per second, 20 when not set) in the environment variable `PATHOS_TARGET_RATE_LIMIT` (manifest `env` cannot set `PATHOS_` variables). The `worker-dast` tools pass it on to their own rate options and to the scope proxy of their `dast-run` helper ([DAST tools](../user-guide/dast.md)).

### Parsers

| `parser` | Upload form | Meaning |
|---|---|---|
| `sarif` (default) | no `parser` field | SARIF 2.1.0, parsed like every SARIF scanner |
| `import:<format>` | `{ "kind": "import", "format": "<format>" }` | Any [result import format](result-imports.md#supported-formats) id, e.g. `import:bandit` for `bandit -f json`. The same parser as imports, so the same fingerprints |
| `jsonmap` | `{ "kind": "jsonmap", "jsonmap": { … } }` | A declarative mapping of a JSON or JSON Lines report ([below](#jsonmap)) |

### jsonmap

| Key | Description |
|---|---|
| `records` | Path of the array of records; empty when the report is the array. With `lines`, the path of the array in each line; empty when each line is one record |
| `lines` | `true`: the report is JSON Lines |
| `rule_id` | **Required.** Rule or check identifier |
| `title`, `message` | Title (default: first line of the message) and description |
| `severity` | Severity value of a record |
| `severity_map` | Map from the tool's values to `critical`, `high`, `medium`, `low`, `info` (at most 50 entries). Values not in the map are recognised when they are common words (`error` → high, `warning` → medium, `note` → low, …) |
| `default_severity` | Severity when none matches (default `info`) |
| `confidence` | `high`, `medium` or `low` |
| `file`, `line`, `end_line`, `url` | Location; worker workspace prefixes are removed from paths |
| `package`, `version`, `fixed_version` | Affected package (SCA-style findings) |
| `cve`, `cwe`, `cvss` | Identifiers and a CVSS base score (0–10) |
| `category` | Finding category of every record (default: the tool's category) |
| `identity` | What tells two findings of one rule in one file apart (default: the message). Records that are still identical are told apart by their order |

A **value** is a path (`location.path`, `identifiers.0.value`), alternatives separated by `|` (`rule|id`), or a template with paths in braces (`SC{code}`; empty when every path in it is empty). Arrays of strings or numbers are read as lists for `cve` and `cwe`. Paths contain letters, digits, `_`, `$`, `@` and `-`; expressions are at most 300 characters. A record without a rule id makes the upload fail with the record number; at most 20 000 findings are read per report; secret-looking values in titles and messages are redacted.

Example: ShellCheck's `--format=json1` output, one document per line:

```json
{"comments":[{"file":"/work/j1/src/deploy.sh","line":4,"endLine":4,"column":8,"level":"warning","code":2115,"message":"Use \"${var:?}\" to ensure this never expands to /* ."}]}
```

with

```json
{ "lines": true, "records": "comments", "rule_id": "SC{code}", "title": "message", "message": "message", "severity": "level",
  "severity_map": { "error": "high", "warning": "medium", "info": "low", "style": "info" },
  "file": "file", "line": "line", "end_line": "endLine", "identity": "SC{code} {message}" }
```

gives a `code-quality` finding `SC2115` in `deploy.sh`, line 4, severity `medium`.
