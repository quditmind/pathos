package scanners

import (
	"fmt"
	"strings"
)

// Checkmarx CxSAST XML report: CxXMLResults / Query / Result / Path /
// PathNode. One finding per result at the result's file and line; the path
// nodes (source to sink) stay in the record. Results Checkmarx users marked
// as false positives or not exploitable are kept (low confidence, noted),
// never dismissed.

type cxNode struct {
	FileName string `xml:"FileName" json:"file_name"`
	Line     int    `xml:"Line" json:"line"`
	Column   int    `xml:"Column" json:"column"`
	NodeID   string `xml:"NodeId" json:"node_id"`
	Name     string `xml:"Name" json:"name"`
	Snippet  []struct {
		Number int    `xml:"Number" json:"number"`
		Code   string `xml:"Code" json:"code"`
	} `xml:"Snippet>Line" json:"snippet,omitempty"`
}

type cxResult struct {
	NodeID        string `xml:"NodeId,attr"`
	FileName      string `xml:"FileName,attr"`
	Status        string `xml:"Status,attr"`
	Line          int    `xml:"Line,attr"`
	Column        int    `xml:"Column,attr"`
	FalsePositive string `xml:"FalsePositive,attr"`
	Severity      string `xml:"Severity,attr"`
	State         string `xml:"state,attr"`
	Remark        string `xml:"Remark,attr"`
	DeepLink      string `xml:"DeepLink,attr"`
	Path          struct {
		ResultID     string   `xml:"ResultId,attr"`
		PathID       string   `xml:"PathId,attr"`
		SimilarityID string   `xml:"SimilarityId,attr"`
		Nodes        []cxNode `xml:"PathNode"`
	} `xml:"Path"`
}

type cxQuery struct {
	ID       string     `xml:"id,attr"`
	CWEID    string     `xml:"cweId,attr"`
	Name     string     `xml:"name,attr"`
	Group    string     `xml:"group,attr"`
	Severity string     `xml:"Severity,attr"`
	Language string     `xml:"Language,attr"`
	Results  []cxResult `xml:"Result"`
}

// cxRecord is the record kept as a finding's original output.
type cxRecord struct {
	QueryID       string   `json:"query_id"`
	Query         string   `json:"query"`
	Group         string   `json:"group,omitempty"`
	Language      string   `json:"language,omitempty"`
	CWEID         string   `json:"cwe_id,omitempty"`
	Severity      string   `json:"severity"`
	NodeID        string   `json:"node_id,omitempty"`
	FileName      string   `json:"file_name"`
	Line          int      `json:"line"`
	Column        int      `json:"column,omitempty"`
	Status        string   `json:"status,omitempty"`
	State         string   `json:"state,omitempty"`
	FalsePositive string   `json:"false_positive,omitempty"`
	Remark        string   `json:"remark,omitempty"`
	DeepLink      string   `json:"deep_link,omitempty"`
	ResultID      string   `json:"result_id,omitempty"`
	PathID        string   `json:"path_id,omitempty"`
	SimilarityID  string   `json:"similarity_id,omitempty"`
	Path          []cxNode `json:"path"`
}

var cxStates = map[string]string{"0": "To Verify", "1": "Not Exploitable", "2": "Confirmed", "3": "Urgent", "4": "Proposed Not Exploitable"}

func init() {
	registerImportFormat(ImportFormat{ID: "checkmarx", Label: "Checkmarx CxSAST XML", Category: "sast", Media: "xml", Order: 15,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "CxXMLResults" },
		parse: parseCheckmarxXML})
}

func parseCheckmarxXML(raw []byte) ([]importRecord, error) {
	var doc struct {
		Queries []cxQuery `xml:"Query"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("checkmarx: %w", err)
	}
	var out []importRecord
	for _, q := range doc.Queries {
		for _, r := range q.Results {
			if len(out) >= MaxFindingsPerReport {
				return out, nil
			}
			out = append(out, checkmarxFinding(q, r))
		}
	}
	return out, nil
}

func checkmarxFinding(q cxQuery, r cxResult) importRecord {
	title := strings.ReplaceAll(firstNonEmpty(q.Name, q.ID), "_", " ")
	f := Finding{Category: "sast", RuleID: firstNonEmpty(q.Name, q.ID), Title: title, Severity: normSeverity(firstNonEmpty(r.Severity, q.Severity)),
		FilePath: NormalizePath(r.FileName), StartLine: intPtr(r.Line), CWE: []string{q.CWEID}}
	if f.Severity == "" {
		f.Severity = "medium"
	}
	var notes []string
	if strings.EqualFold(r.FalsePositive, "true") {
		f.Confidence = "low"
		notes = append(notes, "Checkmarx marked this result as a false positive; it is kept for review.")
	}
	if st, ok := cxStates[strings.TrimSpace(r.State)]; ok && r.State != "0" {
		notes = append(notes, "Checkmarx state: "+st+".")
		if r.State == "1" || r.State == "4" {
			f.Confidence = "low"
		}
	}
	flow := ""
	if n := len(r.Path.Nodes); n > 0 {
		src, sink := r.Path.Nodes[0], r.Path.Nodes[n-1]
		flow = fmt.Sprintf("Source: %s at %s:%d. Sink: %s at %s:%d (%d steps).", src.Name, NormalizePath(src.FileName), src.Line,
			sink.Name, NormalizePath(sink.FileName), sink.Line, n)
	}
	f.Description = joinText(strings.Join(notes, " "), fmt.Sprintf("Checkmarx query %s (%s, %s).", q.Name, q.Group, q.Language), flow,
		labelled("Status", r.Status), labelled("Remark", r.Remark))
	snip := r.Path.SimilarityID
	if snip == "" || snip == "0" {
		parts := []string{}
		for _, nd := range r.Path.Nodes {
			parts = append(parts, nd.Name+"@"+NormalizePath(nd.FileName))
		}
		snip = strings.Join(parts, ">")
	}
	nodes := r.Path.Nodes
	if len(nodes) > 200 {
		nodes = nodes[:200]
	}
	rec := cxRecord{QueryID: q.ID, Query: q.Name, Group: q.Group, Language: q.Language, CWEID: q.CWEID, Severity: firstNonEmpty(r.Severity, q.Severity),
		NodeID: r.NodeID, FileName: r.FileName, Line: r.Line, Column: r.Column, Status: r.Status, State: r.State, FalsePositive: r.FalsePositive,
		Remark: clipText(r.Remark, maxEvidenceText), DeepLink: r.DeepLink, ResultID: r.Path.ResultID, PathID: r.Path.PathID,
		SimilarityID: r.Path.SimilarityID, Path: nodes}
	return importRecord{F: f, SnippetKey: hashOf("cx|" + snip), Raw: rawJSON(rec)}
}
