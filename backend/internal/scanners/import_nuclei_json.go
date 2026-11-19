package scanners

import "fmt"

// Nuclei JSON export (`nuclei -json-export <file>`, -je): a JSON array of
// the same result objects as the JSON Lines output (-jsonl), parsed like
// them.

func init() {
	registerImportFormat(ImportFormat{ID: "nuclei-json", Label: "Nuclei JSON export (-json-export)", Tool: "Nuclei", Category: "dast", Media: "json", Order: 705,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("template-id") && p.hasAny("info", "matched-at", "host")
		},
		parse: parseNucleiJSON})
}

func parseNucleiJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("nuclei: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		f, snip, err := nucleiFinding(it, i+1)
		if err != nil {
			return out, err
		}
		out = append(out, importRecord{F: f, SnippetKey: snip, Raw: it})
	}
	return out, nil
}
