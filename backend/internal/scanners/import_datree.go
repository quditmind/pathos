package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Datree JSON (`datree test <files> -o json`): policyValidationResults[]
// (fileName, ruleResults[]: identifier, name, messageOnFailure,
// documentationUrl, occurrencesDetails[]: metadataName, kind, isSkipped,
// skipMessage, failureLocations[]: schemaPath, failedErrorLine) with
// policySummary and evaluationSummary. Every rule result is a failed
// rule; Datree has no severity: findings are medium. Skipped occurrences
// are kept with low confidence.

func init() {
	registerImportFormat(ImportFormat{ID: "datree", Label: "Datree JSON (datree test -o json)", Tool: "Datree", Category: "iac", Media: "json", Order: 703,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("policyValidationResults") && p.hasAny("policySummary", "evaluationSummary")
		},
		parse: parseDatree})
}

func parseDatree(raw []byte) ([]importRecord, error) {
	var doc struct {
		Results []struct {
			FileName string `json:"fileName"`
			Rules    []struct {
				ID      string `json:"identifier"`
				Name    string `json:"name"`
				Message string `json:"messageOnFailure"`
				DocURL  string `json:"documentationUrl"`
				Details []struct {
					MetadataName string `json:"metadataName"`
					Kind         string `json:"kind"`
					IsSkipped    bool   `json:"isSkipped"`
					SkipMessage  string `json:"skipMessage"`
					Locations    []struct {
						SchemaPath string `json:"schemaPath"`
						Line       int    `json:"failedErrorLine"`
					} `json:"failureLocations"`
				} `json:"occurrencesDetails"`
			} `json:"ruleResults"`
		} `json:"policyValidationResults"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("datree: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, fr := range doc.Results {
		for _, r := range fr.Rules {
			if r.ID == "" {
				return out, fmt.Errorf("datree: %s: rule result without identifier", fr.FileName)
			}
			for _, d := range r.Details {
				f := Finding{Category: "iac", RuleID: r.ID, Title: firstNonEmpty(r.Name, r.ID), Severity: "medium", FilePath: NormalizePath(fr.FileName),
					Description: joinText(r.Message, fmt.Sprintf("%s %s.", d.Kind, d.MetadataName), r.DocURL, "Datree reports no severity; the finding is medium.")}
				var paths []string
				for _, l := range d.Locations {
					if f.StartLine == nil {
						f.StartLine = intPtr(l.Line)
					}
					paths = append(paths, l.SchemaPath)
				}
				f.Description = joinText(f.Description, labeled("Paths", strings.Join(paths, ", ")))
				if d.IsSkipped {
					f.Confidence = "low"
					f.Description = joinText(f.Description, "Datree verdict: skipped ("+d.SkipMessage+").")
				}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(d.Kind + "/" + d.MetadataName),
					Raw: rawJSON(map[string]any{"fileName": fr.FileName, "identifier": r.ID, "name": r.Name, "occurrence": d})})
			}
		}
	}
	return out, nil
}
