package scanners

// ClusterFuzzLite / CIFuzz (`output-sarif: true`) writes the crashes it
// finds as SARIF 2.1 (results.sarif, one result per crash with the
// sanitizer crash type as rule and the crashing source line); it is parsed
// by the SARIF importer.

func init() {
	registerImportFormat(ImportFormat{ID: "clusterfuzzlite", Label: "ClusterFuzzLite / CIFuzz crashes (SARIF)", Tool: "ClusterFuzzLite", Category: "other",
		Media: "sarif", Parser: "sarif", Order: 377})
}
