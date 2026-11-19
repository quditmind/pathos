package scanners

// NowSecure mobile application assessments are exported as SARIF 2.1 by
// NowSecure's own converter (nowsecure/nowsecure-action, convert-sarif);
// they are parsed by the SARIF importer. Findings without a source mapping
// carry NowSecure's placeholder location "Unknown".

func init() {
	registerImportFormat(ImportFormat{ID: "nowsecure", Label: "NowSecure (SARIF)", Tool: "NowSecure", Category: "mobile",
		Media: "sarif", Parser: "sarif", Order: 376})
}
