Test fixtures for pathos-graph (labelled example code): tiny sample
projects per language and a combined multi-language repository
(fixture-repo). They are parsed by the tests, never built or executed.
`*.opengrep.json` and `*.cdx.json` are real outputs of Opengrep (with
workers/graph/rules) and Syft on fixture-repo, recorded with the
worker-core image (see discover_test.go).
