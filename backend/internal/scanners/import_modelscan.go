package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ProtectAI ModelScan JSON (`modelscan -p <path> -r json -o report.json`):
// issues[] (unsafe operators in serialised models: pickle, PyTorch, Keras,
// TensorFlow) and errors[] (files ModelScan could not scan). One finding
// per issue, located at the model file; scan errors are kept as info
// findings so an unscanned model is never silent.

type modelscanIssue struct {
	Description string `json:"description"`
	Operator    string `json:"operator"`
	Module      string `json:"module"`
	Source      string `json:"source"`
	Scanner     string `json:"scanner"`
	Severity    string `json:"severity"`
}

type modelscanError struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "modelscan", Label: "ModelScan JSON", Tool: "ModelScan", Category: "other", Media: "json", Order: 372,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("summary", "issues") && p.headHas(`"modelscan_version"`)
		},
		parse: parseModelScan})
}

func parseModelScan(raw []byte) ([]importRecord, error) {
	var rep struct {
		Summary struct {
			InputPath string `json:"input_path"`
		} `json:"summary"`
		Issues []json.RawMessage `json:"issues"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("modelscan: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range rep.Issues {
		var is modelscanIssue
		if err := json.Unmarshal(it, &is); err != nil || (is.Operator == "" && is.Description == "") {
			return out, fmt.Errorf("modelscan: issue %d: expected an object with operator and description", i+1)
		}
		scanner := is.Scanner[strings.LastIndex(is.Scanner, ".")+1:]
		op := strings.Trim(is.Module+"."+is.Operator, ".")
		f := Finding{Category: "malware", RuleID: "modelscan:" + firstNonEmpty(scanner, "scan") + ":" + op,
			Title:    firstNonEmpty(is.Description, "Unsafe operator "+op),
			Severity: firstNonEmpty(normSeverity(is.Severity), "high"), FilePath: NormalizePath(firstNonEmpty(is.Source, rep.Summary.InputPath)),
			CWE: []string{"CWE-502"}, Confidence: "high"}
		f.Description = joinText(fmt.Sprintf("ModelScan found the operator %s in the serialised model %s. Loading the model runs it.", op, is.Source),
			labelled("Scanner", is.Scanner))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(op), Raw: it})
	}
	for i, it := range rep.Errors {
		var e modelscanError
		if err := json.Unmarshal(it, &e); err != nil {
			return out, fmt.Errorf("modelscan: error %d: expected an object", i+1)
		}
		cat := firstNonEmpty(e.Category, "scan error")
		f := Finding{Category: "other", RuleID: "modelscan:error:" + cat, Title: "ModelScan could not scan the model (" + cat + ")",
			Severity: "info", FilePath: NormalizePath(firstNonEmpty(e.Source, rep.Summary.InputPath, "model")), Confidence: "low",
			Description: joinText("The model was not scanned; review it manually.", e.Description)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("error|" + e.Description), Raw: it})
	}
	return out, nil
}
