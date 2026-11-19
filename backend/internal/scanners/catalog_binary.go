package scanners

// worker-binary (workers/binary): build artifacts and firmware. The tools
// are defined by manifests in workers/binary/tools.d; the checksec-style
// binary hardening checks are built into every worker (BinaryHardening).

func init() {
	artifact := func(sc *Scanner) {
		sc.AdapterAvailable, sc.TargetOnly, sc.Targets = true, true, []string{"binary"}
	}
	Catalog = append(Catalog,
		s("cve-bin-tool", "CVE Binary Tool", "sca", "GPL-3.0-or-later", "use", "binary", artifact, format("json"),
			home("https://github.com/intel/cve-bin-tool"),
			note("worker-binary image (tool manifest): known vulnerable components in binaries and firmware (version signatures). Runs offline on a database the operator provides (see docs/OPERATIONS.md); never downloads it itself")),
		s("capa", "capa", "binary", "Apache-2.0", "use", "binary", artifact, format("json"), home("https://github.com/mandiant/capa"),
			note("worker-binary image (tool manifest): capabilities of executables (PE, ELF, .NET) with the capa-rules set (Apache-2.0), mapped to MITRE ATT&CK and MBC")),
		s("yara-x", "YARA-X", "malware", "BSD-3-Clause", "use", "binary", available,
			func(sc *Scanner) { sc.Targets = []string{"repository", "binary", "mobile-app"} }, format("json"), home("https://github.com/VirusTotal/yara-x"),
			note("worker-binary image (tool manifest): YARA rules on build artifacts, mobile packages and (when a profile selects it) repositories. Bundled rules: ReversingLabs YARA rules (MIT) and a PATHOS test rule")),
	)
	mbafAddScanTypeTools("binary", "cve-bin-tool", "capa", "yara-x")
	mbafAddScanTypeTools("sca", "cve-bin-tool")
	mbafAddScanTypeTools("malware", "capa", "yara-x")
}
