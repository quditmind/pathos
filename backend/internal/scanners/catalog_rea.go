package scanners

// pathos-rea: reverse engineering, static tier (PATHOS 3.0 M10,
// docs/aspm/PATHOS_REVERSE_ENGINEERING.md). It runs in the worker-rea family
// image, always inside the sandbox runner (no network, its own UID, no
// worker token), and never executes the artifact. It analyses an uploaded
// build artifact with radare2, binwalk and, when installed and enabled,
// Ghidra (headless), Jadx and ILSpy; its JSON output (pathos.rea/v1) is a
// set of normalised facts stored as a binary graph in the CodeGraph store
// by the rea package, not findings. It is never part of a scan profile or a
// target's tool selection: analyses start from Binary analysis (trigger
// "rea", a per-organization system profile) and only for artifacts that
// pass the input policy.

// PathosREA is the reverse-engineering analysis tool.
const PathosREA = "pathos-rea"

func init() {
	iacscaUpsert(
		s(PathosREA, "PATHOS reverse engineering (pathos-rea)", "other", "Apache-2.0", "use", "rea", format("json"),
			func(sc *Scanner) { sc.AdapterAvailable, sc.TargetOnly, sc.Targets = true, true, []string{"binary"} },
			home("https://github.com/quditmind/pathos"),
			note("worker-rea image, sandbox runner only (static tier: the artifact is never executed): sections, functions, imports, "+
				"strings (secrets redacted), call graph and firmware contents with radare2 (LGPL-3.0) and binwalk (MIT); Ghidra headless "+
				"(Apache-2.0), Jadx (Apache-2.0) and ILSpy (MIT) when built in. Output is stored as a binary graph, no findings")),
	)
}

// IsREATool reports whether a scanner's output is a reverse-engineering
// document (stored by the rea package, not parsed into findings).
func IsREATool(key string) bool { return key == PathosREA }
