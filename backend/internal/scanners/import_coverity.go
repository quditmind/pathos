package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Coverity JSON (`cov-format-errors --json-output-v7` or `-v10`, and the
// `coverity scan` CLI's JSON): {"type": "Coverity issues", "formatVersion",
// "issues": [...]} with checkerName, mergeKey (the identity),
// strippedMainEventFilePathname, mainEventLineNumber, functionDisplayName,
// events (the main event is the message) and checkerProperties
// (category, cweCategory, impact High/Medium/Low, issueKinds). Issues of
// kind SECURITY are sast; QUALITY-only issues are code quality (other).
// When the report was produced with server state, a triage
// classification of False Positive or Intentional is noted and imported
// with low confidence.

type coverityIssue struct {
	MergeKey       string `json:"mergeKey"`
	CheckerName    string `json:"checkerName"`
	Type           string `json:"type"`
	Subcategory    string `json:"subcategory"`
	Domain         string `json:"domain"`
	MainFile       string `json:"mainEventFilePathname"`
	StrippedFile   string `json:"strippedMainEventFilePathname"`
	MainLine       int    `json:"mainEventLineNumber"`
	FunctionName   string `json:"functionDisplayName"`
	OccurrenceInMK int    `json:"occurrenceNumberInMK"`
	Events         []struct {
		Description string `json:"eventDescription"`
		Main        bool   `json:"main"`
	} `json:"events"`
	State *struct {
		CID    int `json:"cid"`
		Triage struct {
			Classification string `json:"classification"`
			Action         string `json:"action"`
		} `json:"triage"`
	} `json:"stateOnServer"`
	Props struct {
		Category    string      `json:"category"`
		CWE         looseString `json:"cweCategory"`
		IssueKinds  []string    `json:"issueKinds"`
		Impact      string      `json:"impact"`
		Effect      string      `json:"subcategoryLocalEffect"`
		Short       string      `json:"subcategoryShortDescription"`
		Long        string      `json:"subcategoryLongDescription"`
		Description string      `json:"categoryDescription"`
	} `json:"checkerProperties"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "coverity", Label: "Coverity JSON (v7, v10)", Tool: "Coverity", Media: "json", Order: 102,
		match: func(p *importProbe) bool {
			if p.kind != "object" || !p.has("issues") {
				return false
			}
			if m := p.firstOf("issues"); m != nil {
				return hasKeys(m, "checkerName", "mergeKey")
			}
			return p.has("formatVersion") && string(p.keys["type"]) == `"Coverity issues"`
		},
		parse: parseCoverityJSON})
}

func parseCoverityJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "issues")
	if err != nil {
		return nil, fmt.Errorf("coverity: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var c coverityIssue
		if err := json.Unmarshal(it, &c); err != nil || c.CheckerName == "" {
			return out, fmt.Errorf("coverity: issue %d: expected an object with checkerName", i+1)
		}
		msg := ""
		for _, e := range c.Events {
			if e.Main {
				msg = e.Description
			}
		}
		cat := "other"
		if slices.ContainsFunc(c.Props.IssueKinds, func(k string) bool { return strings.EqualFold(k, "SECURITY") }) {
			cat = "sast"
		}
		sev := normSeverity(c.Props.Impact)
		if sev == "" {
			sev = "medium"
		}
		f := Finding{Category: cat, RuleID: c.CheckerName, Severity: sev, CWE: []string{string(c.Props.CWE)},
			Title:    firstNonEmpty(c.Props.Short, c.Props.Category, c.CheckerName) + " (" + c.CheckerName + ")",
			FilePath: NormalizePath(firstNonEmpty(c.StrippedFile, c.MainFile)), StartLine: intPtr(c.MainLine),
			Description: joinText(msg, c.Props.Long, labelled("Effect", c.Props.Effect), labelled("Function", c.FunctionName))}
		if c.State != nil {
			switch cl := c.State.Triage.Classification; cl {
			case "False Positive", "Intentional":
				f.Confidence = "low"
				f.Description = joinText("Coverity triage: "+cl+"; kept for review.", f.Description)
			}
		}
		key := c.MergeKey
		if key == "" {
			key = c.CheckerName + "|" + c.FunctionName + "|" + msg
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("coverity|%s|%d", key, c.OccurrenceInMK)), Raw: it})
	}
	return out, nil
}
