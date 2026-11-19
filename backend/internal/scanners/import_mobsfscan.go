package scanners

// mobsfscan JSON (`mobsfscan --json`): results by rule id with files[]
// and metadata (cwe, description, masvs, owasp-mobile, reference,
// severity ERROR / WARNING / INFO), the structure of njsscan (see
// njsscanParse). App-level checks (for example missing root detection)
// have no files and are findings without a location.

func init() {
	registerImportFormat(ImportFormat{ID: "mobsfscan", Label: "mobsfscan JSON", Tool: "mobsfscan", Category: "sast", Media: "json", Order: 153,
		match: func(p *importProbe) bool { return p.kind == "object" && p.has("mobsfscan_version", "results") },
		parse: func(raw []byte) ([]importRecord, error) { return njsscanParse("mobsfscan", raw, "results") }})
}
