package scanners

// Docker Scout (`docker scout cves --format sarif --output report.sarif
// <image>`) reports image vulnerabilities as SARIF 2.1; it is parsed by the
// SARIF importer with the container category.

func init() {
	registerImportFormat(ImportFormat{ID: "docker-scout", Label: "Docker Scout (SARIF)", Tool: "Docker Scout", Category: "container",
		Media: "sarif", Parser: "sarif", Order: 378})
}
