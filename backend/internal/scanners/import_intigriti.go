package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Intigriti submissions JSON (the external company API's submissions
// export, {"records": [...]}, each with an optional "detail" carrying the
// report). Severity "Exceptional" is critical. Submissions closed as
// resolved are fixed and not imported; other closed submissions
// (duplicate, out of scope, ...) are kept with low confidence. The proof
// of concept is researcher-written HTML that may hold credentials: it is
// reduced to text and redacted, and the stored report is redacted too.

type intigritiSeverity struct {
	Value  string `json:"value"`
	Vector string `json:"vector"`
}

type intigritiState struct {
	Status struct {
		Value string `json:"value"`
	} `json:"status"`
	CloseReason struct {
		Value string `json:"value"`
	} `json:"closeReason"`
}

type intigritiRecord struct {
	Code     string            `json:"code"`
	Title    string            `json:"title"`
	Severity intigritiSeverity `json:"severity"`
	State    intigritiState    `json:"state"`
	WebLinks struct {
		Details string `json:"details"`
	} `json:"webLinks"`
	Detail struct {
		Title    string            `json:"title"`
		Severity intigritiSeverity `json:"severity"`
		Report   struct {
			Type struct {
				Name     string `json:"name"`
				Category string `json:"category"`
				Cwe      string `json:"cwe"`
			} `json:"type"`
			Domain struct {
				Name string `json:"name"`
			} `json:"domain"`
			Endpoint            string `json:"endpointVulnerableComponent"`
			PocDescription      string `json:"pocDescription"`
			Impact              string `json:"impact"`
			RecommendedSolution string `json:"recommendedSolution"`
		} `json:"report"`
	} `json:"detail"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "intigriti", Label: "Intigriti submissions JSON", Tool: "Intigriti", Category: "other", Media: "json", Order: 483,
		match: func(p *importProbe) bool {
			r := p.firstOf("records")
			return p.kind == "object" && hasKeys(r, "code", "title", "severity", "state") && (hasKeys(r, "originators") || hasKeys(r, "webLinks") || hasKeys(r, "detail"))
		},
		parse:    parseIntigriti,
		sanitize: sanitizeHTTPJSON})
}

func parseIntigriti(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "records")
	if err != nil {
		return nil, fmt.Errorf("intigriti: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r intigritiRecord
		if err := json.Unmarshal(it, &r); err != nil || r.Code == "" {
			return out, fmt.Errorf("intigriti: record %d: expected a submission with code", i+1)
		}
		reason := r.State.CloseReason.Value
		skip, note := bountyVerdict("Intigriti", reason)
		if skip {
			continue
		}
		rep := r.Detail.Report
		sev := firstNonEmpty(r.Severity.Value, r.Detail.Severity.Value)
		f := Finding{Category: "other", RuleID: firstNonEmpty(rep.Type.Name, "intigriti-submission"), Title: firstNonEmpty(r.Title, r.Detail.Title, r.Code),
			Severity: normSeverity(sev), CVSSVector: firstNonEmpty(r.Severity.Vector, r.Detail.Severity.Vector), CWE: []string{rep.Type.Cwe}}
		if strings.EqualFold(sev, "exceptional") {
			f.Severity = "critical"
		}
		loc := rep.Domain.Name
		if ep := strings.TrimSpace(rep.Endpoint); ep != "" {
			loc = strings.TrimRight(loc, "/") + "/" + strings.TrimLeft(ep, "/")
			if strings.Contains(ep, "://") {
				loc = ep
			}
		}
		f.FilePath = locationOf("", redactHTTP(firstNonEmpty(strings.Trim(loc, "/"), r.WebLinks.Details, "intigriti:"+r.Code)))
		if note != "" {
			f.Confidence = "low"
		}
		f.Description = joinText(note, labelled("Proof of concept", clipText(redactHTTP(markupToText(rep.PocDescription)), 3000)),
			labelled("Impact", redactHTTP(markupToText(rep.Impact))), labelled("Recommended solution", markupToText(rep.RecommendedSolution)),
			labelled("Type", strings.Trim(rep.Type.Category+" / "+rep.Type.Name, " /")), labelled("Status", strings.Trim(r.State.Status.Value+" "+reason, " ")),
			labelled("Submission", firstNonEmpty(r.WebLinks.Details, r.Code)))
		out = append(out, importRecord{F: f, SnippetKey: hashOf("intigriti|" + r.Code), Raw: sanitizeHTTPJSON(it)})
	}
	return out, nil
}
