package scanners

// pathos-graph: CodeGraph discovery (PATHOS 3.0 M4). It runs in the
// worker-graph family image like the other family tools, reads source files
// only (never builds or runs repository code), needs no network, and its
// JSON output (pathos.codegraph/v1) is a code graph stored by the codegraph
// package, not findings. It is never part of a selectable scan profile:
// CodeGraph builds use a per-organization system profile (trigger
// "codegraph").

// PathosGraph is the CodeGraph discovery tool.
const PathosGraph = "pathos-graph"

func init() {
	iacscaUpsert(
		s(PathosGraph, "PATHOS CodeGraph discovery (pathos-graph)", "other", "Apache-2.0", "use", "graph", available, format("json"),
			home("https://github.com/quditmind/pathos"),
			note("worker-graph image (tool manifest; JSON graph stored in the CodeGraph store, no findings): modules, files, functions, "+
				"calls and imports (Go parser, tree-sitter), routes, database and queue access (PATHOS Opengrep rules), OpenAPI "+
				"operations, containers and infrastructure as code, SBOM components (Syft); reads source files only, offline")),
	)
}

// IsGraphTool reports whether a scanner's output is a CodeGraph (stored in
// the graph store, not parsed into findings).
func IsGraphTool(key string) bool { return key == PathosGraph }
