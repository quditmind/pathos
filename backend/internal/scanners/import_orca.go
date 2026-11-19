package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Orca Security alerts, JSON export of the alerts view: an array of
// alerts with Title, Category, OrcaScore (0-10), Status, Source, Labels,
// CreatedAt, LastSeen, CloudAccount.Name and Inventory.Name (the asset).
// The export has no severity word: OrcaScore gives it like a CVSS score.
// Alerts that are not open (closed, dismissed) are kept with low
// confidence and their status, because the export does not say whether
// the risk was fixed. A finding is located at its asset.

type orcaAlert struct {
	Title        string   `json:"Title"`
	Category     string   `json:"Category"`
	OrcaScore    float64  `json:"OrcaScore"`
	Status       string   `json:"Status"`
	Source       string   `json:"Source"`
	Labels       []string `json:"Labels"`
	CreatedAt    string   `json:"CreatedAt"`
	LastSeen     string   `json:"LastSeen"`
	CloudAccount struct {
		Name string `json:"Name"`
	} `json:"CloudAccount"`
	Inventory struct {
		Name string `json:"Name"`
	} `json:"Inventory"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "orca", Label: "Orca Security alerts JSON export", Tool: "Orca Security", Category: "misconfiguration", Media: "json", Order: 603,
		match: func(p *importProbe) bool {
			return p.kind == "array" && hasKeys(p.keys, "Title", "OrcaScore", "Inventory")
		},
		parse: parseOrca})
}

func parseOrca(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("orca: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var a orcaAlert
		if err := json.Unmarshal(it, &a); err != nil || a.Title == "" {
			return out, fmt.Errorf("orca: alert %d: expected an object with Title", i+1)
		}
		asset := firstNonEmpty(a.Inventory.Name, a.Source)
		f := Finding{Category: "misconfiguration", RuleID: firstNonEmpty(a.Category, "orca") + ": " + a.Title, Title: a.Title, FilePath: asset,
			Severity: FromScore(a.OrcaScore), CVSS: floatPtr(a.OrcaScore),
			Description: joinText(fmt.Sprintf("Orca alert on %s in cloud account %s (OrcaScore %.1f).", asset, a.CloudAccount.Name, a.OrcaScore),
				labeled("Category", a.Category), labeled("Labels", strings.Join(a.Labels, ", ")), labeled("Created", a.CreatedAt), labeled("Last seen", a.LastSeen))}
		if a.OrcaScore <= 0 {
			f.Severity, f.CVSS = "info", nil
		}
		if st := strings.ToLower(a.Status); st != "" && st != "open" && st != "in_progress" && st != "in progress" {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "Orca status: "+a.Status+".")
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(a.CloudAccount.Name), Raw: it})
	}
	return out, nil
}
