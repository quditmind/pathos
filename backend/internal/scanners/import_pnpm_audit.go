package scanners

// pnpm audit JSON (`pnpm audit --json`): the npm audit version 1 report
// (actions, advisories, muted, metadata) without npm's runId. Parsed like
// npm audit version 1; the lockfile is pnpm-lock.yaml.

// isPnpmAudit tells a pnpm audit report from an npm 6 one (which always has
// runId).
func isPnpmAudit(p *importProbe) bool {
	return p.kind == "object" && p.has("actions", "advisories", "muted", "metadata") && !p.has("runId")
}

func init() {
	registerImportFormat(ImportFormat{ID: "pnpm-audit", Label: "pnpm audit JSON", Tool: "pnpm audit", Category: "sca", Media: "json", Order: 212,
		match: isPnpmAudit,
		parse: func(raw []byte) ([]importRecord, error) {
			recs, err := parseNpmAudit(raw)
			for i := range recs {
				recs[i].F.FilePath = "pnpm-lock.yaml"
			}
			return recs, err
		}})
}
