package scanners

import (
	"encoding/json"
	"errors"
	"strings"

	"pathos/internal/platform/logging"
)

// FlowStep is one location of a SARIF thread flow (or a related location).
type FlowStep struct {
	FilePath string   `json:"file_path"`
	Line     int      `json:"line,omitempty"`
	Column   int      `json:"column,omitempty"`
	Message  string   `json:"message,omitempty"`
	Snippet  string   `json:"snippet,omitempty"`
	Kinds    []string `json:"kinds,omitempty"`
	Function string   `json:"function,omitempty"`
}

// Flow is one source-to-sink path reported by the scanner.
type Flow struct {
	Message string     `json:"message,omitempty"`
	Steps   []FlowStep `json:"steps"`
}

// Located is the scanner's own record of one finding.
type Located struct {
	// Raw is the scanner's result object (redacted).
	Raw json.RawMessage
	// Rule is the rule definition, when the report includes it (redacted).
	Rule json.RawMessage
	// Flows are code flows (taint paths) exactly as reported.
	Flows []Flow
	// Related are relatedLocations: locations the scanner associated with
	// the result without asserting a data flow between them.
	Related []FlowStep
}

// ErrNotLocated means the report does not contain the finding.
var ErrNotLocated = errors.New("finding not present in the scanner report")

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int       `json:"startLine"`
			StartColumn int       `json:"startColumn"`
			Snippet     *sarifMsg `json:"snippet"`
		} `json:"region"`
	} `json:"physicalLocation"`
	LogicalLocations []struct {
		Name               string `json:"name"`
		FullyQualifiedName string `json:"fullyQualifiedName"`
	} `json:"logicalLocations"`
	Message *sarifMsg `json:"message"`
}

type sarifFlowResult struct {
	CodeFlows []struct {
		Message     *sarifMsg `json:"message"`
		ThreadFlows []struct {
			Locations []struct {
				Location *sarifLocation `json:"location"`
				Kinds    []string       `json:"kinds"`
			} `json:"locations"`
		} `json:"threadFlows"`
	} `json:"codeFlows"`
	RelatedLocations []sarifLocation `json:"relatedLocations"`
}

const maxFlowSteps = 200

func stepOf(l *sarifLocation, kinds []string) FlowStep {
	st := FlowStep{FilePath: NormalizePath(l.PhysicalLocation.ArtifactLocation.URI), Line: l.PhysicalLocation.Region.StartLine,
		Column: l.PhysicalLocation.Region.StartColumn, Kinds: kinds}
	if l.Message != nil {
		st.Message = truncate(logging.RedactString(l.Message.Text), 1000)
	}
	if l.PhysicalLocation.Region.Snippet != nil {
		st.Snippet = truncate(logging.RedactString(l.PhysicalLocation.Region.Snippet.Text), 2000)
	}
	if len(l.LogicalLocations) > 0 {
		st.Function = truncate(firstNonEmpty(l.LogicalLocations[0].FullyQualifiedName, l.LogicalLocations[0].Name), 300)
	}
	return st
}

// LocateSARIF finds the result whose fingerprint is fingerprint in a SARIF
// report produced by scanner key. Results are matched by recomputing the
// same fingerprint the ingest pipeline stored, so nothing is guessed.
func LocateSARIF(key string, raw []byte, fingerprint string) (*Located, error) {
	fs, err := ParseSARIF(key, raw)
	if err != nil && len(fs) == 0 {
		return nil, err
	}
	idx := -1
	for i, f := range fs {
		if f.Matches(fingerprint) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrNotLocated
	}
	// ParseSARIF visits runs and results in document order without
	// skipping, so the n-th parsed finding is the n-th result.
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	n := idx
	for _, run := range doc.Runs {
		if n >= len(run.Results) {
			n -= len(run.Results)
			continue
		}
		res := run.Results[n]
		out := &Located{Raw: redactJSON(res)}
		var meta struct {
			RuleID    string `json:"ruleId"`
			RuleIndex *int   `json:"ruleIndex"`
		}
		_ = json.Unmarshal(res, &meta)
		for i, r := range run.Tool.Driver.Rules {
			var rid struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(r, &rid)
			if (meta.RuleID != "" && rid.ID == meta.RuleID) || (meta.RuleID == "" && meta.RuleIndex != nil && *meta.RuleIndex == i) {
				out.Rule = redactJSON(r)
				break
			}
		}
		var fr sarifFlowResult
		if err := json.Unmarshal(res, &fr); err == nil {
			steps := 0
			for _, cf := range fr.CodeFlows {
				for _, tf := range cf.ThreadFlows {
					fl := Flow{}
					if cf.Message != nil {
						fl.Message = truncate(logging.RedactString(cf.Message.Text), 1000)
					}
					for _, loc := range tf.Locations {
						if loc.Location == nil || steps >= maxFlowSteps {
							continue
						}
						fl.Steps = append(fl.Steps, stepOf(loc.Location, loc.Kinds))
						steps++
					}
					if len(fl.Steps) > 0 {
						out.Flows = append(out.Flows, fl)
					}
				}
			}
			for i := range fr.RelatedLocations {
				if i >= maxFlowSteps {
					break
				}
				out.Related = append(out.Related, stepOf(&fr.RelatedLocations[i], nil))
			}
		}
		return out, nil
	}
	return nil, ErrNotLocated
}

// redactJSON re-encodes v with credential patterns redacted in every string
// and a bounded size.
func redactJSON(v json.RawMessage) json.RawMessage {
	var x any
	if err := json.Unmarshal(v, &x); err != nil {
		return json.RawMessage(`null`)
	}
	x = redactAny(x)
	b, err := json.Marshal(x)
	if err != nil || len(b) > 256<<10 {
		return json.RawMessage(`{"truncated": true}`)
	}
	return b
}

func redactAny(x any) any {
	switch t := x.(type) {
	case string:
		return logging.RedactString(t)
	case []any:
		for i := range t {
			t[i] = redactAny(t[i])
		}
		return t
	case map[string]any:
		for k, v := range t {
			// Scanner-provided secret material never leaves PATHOS.
			if strings.EqualFold(k, "secret") || strings.EqualFold(k, "match") {
				t[k] = "[REDACTED]"
				continue
			}
			t[k] = redactAny(v)
		}
		return t
	}
	return x
}

// Locate finds a finding in a raw report of scanner key (any format).
func Locate(key string, raw []byte, fingerprint string) (*Located, error) {
	if IsImportKey(key) {
		return LocateImport(key, "", raw, fingerprint)
	}
	if key == Grype {
		return locateGrype(key, raw, fingerprint)
	}
	return LocateSARIF(key, raw, fingerprint)
}

// locateGrype finds a finding in a Grype JSON report.
func locateGrype(key string, raw []byte, fingerprint string) (*Located, error) {
	var fs []Finding
	var err error
	if IsImportKey(key) {
		fs, err = ParseImport(key, "grype", raw)
	} else {
		fs, err = ParseGrypeJSON(raw)
	}
	if err != nil && len(fs) == 0 {
		return nil, err
	}
	var doc struct {
		Matches []json.RawMessage `json:"matches"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	for i, f := range fs {
		if f.Matches(fingerprint) && i < len(doc.Matches) {
			return &Located{Raw: redactJSON(doc.Matches[i])}, nil
		}
	}
	return nil, ErrNotLocated
}
