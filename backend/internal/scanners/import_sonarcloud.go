package scanners

// SonarQube Cloud (SonarCloud) issues JSON (`/api/issues/search`, also
// `/api/hotspots/search`) is the SonarQube Web API format (issues with
// rule, component, severity, textRange, impacts; issues also name their
// organization), so it is parsed and detected as sonarqube; this alias
// names the tool.

func init() {
	registerImportFormat(ImportFormat{ID: "sonarcloud", Label: "SonarQube Cloud (SonarCloud) issues JSON", Tool: "SonarQube Cloud",
		Category: "sast", Media: "json", Parser: "sonarqube", Order: 165})
}
