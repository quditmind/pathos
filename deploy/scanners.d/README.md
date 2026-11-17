# Scanner plugins (declarative adapters)

Files `*.yaml`, `*.yml` or `*.json` in this directory define extra scanners for
`worker-core` (mounted read-only at `/etc/pathos/scanners.d`). An empty directory
means no plugins. See docs/SCANNER_CATALOG.md, "Declarative scanner adapters".

`example.yaml.disabled` shows the format; it is not loaded (wrong extension).
