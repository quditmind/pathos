package scanners

import "encoding/json"

// Snyk Container JSON (`snyk container test <image> --json`) has the layout
// of Snyk Open Source JSON (one project, or an array with --app-vulns)
// with the image details in "docker" and "platform"; it is parsed by the
// Snyk Open Source parser with the container category.

func isSnykContainer(m map[string]json.RawMessage) bool {
	return hasKeys(m, "docker") || hasKeys(m, "platform")
}

func init() {
	registerImportFormat(ImportFormat{ID: "snyk-container", Label: "Snyk Container JSON", Tool: "Snyk Container", Category: "container", Media: "json",
		Parser: "snyk", Order: 600,
		match: func(p *importProbe) bool {
			return (p.kind == "object" || p.kind == "array") && isSnykProject(p.keys) && isSnykContainer(p.keys)
		}})
}
