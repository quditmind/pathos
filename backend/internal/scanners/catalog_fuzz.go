package scanners

// worker-fuzz (workers/fuzz): coverage-guided fuzzing of the fuzz harnesses
// a repository already contains. The tools build and run repository code,
// so they run only in the worker sandbox, only when a scan profile selects
// them, without network access and with CPU, memory and time limits.

func init() {
	fuzz := func(sc *Scanner) { sc.AdapterAvailable, sc.RequiresBuild = true, true }
	Catalog = append(Catalog,
		s("go-fuzz", "Go native fuzzing", "fuzz", "BSD-3-Clause", "use", "fuzz", fuzz, format("json"), home("https://go.dev/doc/security/fuzz/"),
			note("worker-fuzz image (tool manifest): `go test -fuzz` for each Fuzz* target, time-bounded; crashes become findings with the reproducer input (size-limited) as evidence. Needs vendored or no module dependencies (no network)")),
		s("atheris", "Atheris", "fuzz", "Apache-2.0", "use", "fuzz", fuzz, format("json"), home("https://github.com/google/atheris"),
			note("worker-fuzz image (tool manifest): Python fuzz harnesses in the repository (files that import atheris), time-bounded; only the Python standard library and the repository's own modules are importable")),
		s("jazzer", "Jazzer", "fuzz", "Apache-2.0", "optional", "fuzz", build, home("https://github.com/CodeIntelligenceTesting/jazzer"),
			note("Not shipped: JVM harnesses need the project built with Maven or Gradle, which downloads dependencies; import Jazzer crash logs with the libfuzzer format")),
	)
	mbafAddScanTypeTools("fuzzing", "go-fuzz", "atheris", "jazzer")
}
