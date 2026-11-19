# Scanner plugins (operator tool manifests)

Files `*.yaml`, `*.yml` or `*.json` in this directory define extra tools for the
workers (mounted read-only at `/etc/pathos/scanners.d`). An empty directory
means no plugins; at most 50 load. See docs/SCANNER_CATALOG.md, "Adding a tool
(tool manifests)": version 1 files (SARIF tools) keep working; version 2 adds
scan types, targets, network and intrusive declarations, and the parsers
`import:<format>` and `jsonmap`.

`example.yaml.disabled` shows the format; it is not loaded (wrong extension).
