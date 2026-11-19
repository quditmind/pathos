package scanners

// pathos-reach: function-level reachability of dependency vulnerabilities
// for JavaScript/TypeScript, Python and Java (Go: govulncheck). It runs in
// the worker-sca image like the other SCA tools; its report is
// reachability evidence for the repository's dependency findings, not
// findings.

// PathosReach is the pathos-reach analysis.
const PathosReach = "pathos-reach"

func init() {
	iacscaUpsert(
		s(PathosReach, "PATHOS function-level reachability (pathos-reach)", "sca", "Apache-2.0", "use", "sca", available, format("json"),
			home("https://github.com/quditmind/pathos"),
			note("worker-sca image (tool manifest; JSON report stored as reachability evidence, no findings): calls to the vulnerable functions "+
				"of dependency advisories in the repository's JavaScript/TypeScript, Python and Java code, with call paths; dynamic imports, "+
				"computed member access and reflection make the answer unknown; reads source files only, offline")),
	)
	iacscaScanTypeTools("sca", PathosReach)
}

// IsReachabilityTool reports whether a scanner's output is reachability
// evidence (stored with the repository, not parsed into findings).
func IsReachabilityTool(key string) bool { return key == PathosReach }
