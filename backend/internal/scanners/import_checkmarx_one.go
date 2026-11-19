package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Checkmarx One results JSON (`cx results show --report-format json`, or
// the results API): {"results": [...], "totalCount", "scanID"} with one
// entry per result: type (sast, sca, kics), id, similarityId, status,
// state (TO_VERIFY, CONFIRMED, URGENT, NOT_EXPLOITABLE,
// PROPOSED_NOT_EXPLOITABLE), severity, description, data and
// vulnerabilityDetails (cweId, cveName, cvssScore). SAST data has
// queryName and nodes[] (fileName, line, method): the first node is the
// source, the last the sink, where the finding is located. SCA data has
// packageIdentifier (Type-name-version) and recommendedVersion. KICS data
// has queryName, filename, line, expectedValue and value. Results marked
// not exploitable are kept with low confidence.

type cxOneResult struct {
	Type         string `json:"type"`
	ID           string `json:"id"`
	SimilarityID string `json:"similarityId"`
	Status       string `json:"status"`
	State        string `json:"state"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
	Data         struct {
		QueryName     string      `json:"queryName"`
		Group         string      `json:"group"`
		Language      string      `json:"languageName"`
		PackageID     string      `json:"packageIdentifier"`
		Recommended   string      `json:"recommendedVersion"`
		FileName      string      `json:"filename"`
		Line          looseString `json:"line"`
		Platform      string      `json:"platform"`
		ExpectedValue string      `json:"expectedValue"`
		Value         string      `json:"value"`
		Nodes         []struct {
			FileName string `json:"fileName"`
			Line     int    `json:"line"`
			Method   string `json:"method"`
			Name     string `json:"name"`
		} `json:"nodes"`
	} `json:"data"`
	Details struct {
		CWE       looseString `json:"cweId"`
		CVE       string      `json:"cveName"`
		CVSSScore float64     `json:"cvssScore"`
	} `json:"vulnerabilityDetails"`
}

// cxPackage splits a Checkmarx package identifier ("Npm-lodash-4.17.20").
func cxPackage(id string) (string, string) {
	typ, rest, ok := strings.Cut(id, "-")
	if !ok || typ == "" {
		return id, ""
	}
	i := strings.LastIndex(rest, "-")
	if i <= 0 {
		return rest, ""
	}
	return rest[:i], rest[i+1:]
}

func init() {
	registerImportFormat(ImportFormat{ID: "checkmarx-one", Label: "Checkmarx One results JSON (SAST, SCA, KICS)", Tool: "Checkmarx One", Media: "json", Order: 614,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("results"), "type", "similarityId", "severity") && p.hasAny("totalCount", "scanID")
		},
		parse: parseCheckmarxOne})
}

func parseCheckmarxOne(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("checkmarx one: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r cxOneResult
		if err := json.Unmarshal(it, &r); err != nil || r.Type == "" {
			return out, fmt.Errorf("checkmarx one: result %d: expected an object with type", i+1)
		}
		f := Finding{Severity: r.Severity, CWE: []string{string(r.Details.CWE)}, Description: r.Description}
		switch strings.ToLower(r.Type) {
		case "sca", "sca-container":
			f.Category = "sca"
			f.PackageName, f.PackageVersion = cxPackage(r.Data.PackageID)
			f.FixedVersion, f.CVE, f.CVSS = r.Data.Recommended, firstNonEmpty(r.Details.CVE, r.ID), floatPtr(r.Details.CVSSScore)
			f.RuleID = firstNonEmpty(r.Details.CVE, r.ID)
			f.Title = fmt.Sprintf("%s in %s %s", f.RuleID, f.PackageName, f.PackageVersion)
			f.FilePath = r.Data.PackageID
		case "kics":
			f.Category = "iac"
			f.RuleID, f.Title = firstNonEmpty(r.Data.QueryName, r.ID), firstNonEmpty(r.Data.QueryName, r.ID)
			f.FilePath, f.StartLine = NormalizePath(r.Data.FileName), intPtr(atoiLoose(string(r.Data.Line)))
			f.Description = joinText(f.Description, labeled("Platform", r.Data.Platform), labeled("Expected", r.Data.ExpectedValue), labeled("Actual", r.Data.Value))
		default:
			f.Category = "sast"
			f.RuleID, f.Title = firstNonEmpty(r.Data.QueryName, r.ID), strings.ReplaceAll(firstNonEmpty(r.Data.QueryName, r.ID), "_", " ")
			if n := len(r.Data.Nodes); n > 0 {
				sink := r.Data.Nodes[n-1]
				f.FilePath, f.StartLine = NormalizePath(sink.FileName), intPtr(sink.Line)
				src := r.Data.Nodes[0]
				f.Description = joinText(f.Description, fmt.Sprintf("Source: %s:%d (%s %s). Sink: %s:%d (%s %s).", src.FileName, src.Line, src.Method, src.Name,
					sink.FileName, sink.Line, sink.Method, sink.Name), labeled("Query group", r.Data.Group))
			}
		}
		f.Description = joinText(f.Description, fmt.Sprintf("Checkmarx One %s result, status %s, state %s.", r.Type, r.Status, r.State))
		if strings.Contains(strings.ToUpper(r.State), "NOT_EXPLOITABLE") {
			f.Confidence = "low"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(r.SimilarityID), Raw: it})
	}
	return out, nil
}
