package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// OWASP ZAP reports: the traditional JSON report (`-J report.json`) and the
// XML report (`-x report.xml`). One finding per alert instance: the
// location is the instance URI, identity the alert reference, method and
// parameter. Alerts ZAP marked as false positives (confidence 0) are kept
// with low confidence, never dropped.

type zapInstance struct {
	URI       looseString `json:"uri" xml:"uri"`
	Method    looseString `json:"method" xml:"method"`
	Param     looseString `json:"param" xml:"param"`
	Attack    looseString `json:"attack" xml:"attack"`
	Evidence  looseString `json:"evidence" xml:"evidence"`
	OtherInfo looseString `json:"otherinfo" xml:"otherinfo"`
}

type zapAlert struct {
	PluginID   looseString   `json:"pluginid" xml:"pluginid"`
	AlertRef   looseString   `json:"alertRef" xml:"alertRef"`
	Alert      looseString   `json:"alert" xml:"alert"`
	Name       looseString   `json:"name" xml:"name"`
	RiskCode   looseString   `json:"riskcode" xml:"riskcode"`
	Confidence looseString   `json:"confidence" xml:"confidence"`
	RiskDesc   looseString   `json:"riskdesc" xml:"riskdesc"`
	Desc       looseString   `json:"desc" xml:"desc"`
	Solution   looseString   `json:"solution" xml:"solution"`
	Reference  looseString   `json:"reference" xml:"reference"`
	CWEID      looseString   `json:"cweid" xml:"cweid"`
	WASCID     looseString   `json:"wascid" xml:"wascid"`
	Instances  []zapInstance `json:"instances" xml:"instances>instance"`
}

type zapSite struct {
	Name   string     `json:"@name" xml:"name,attr"`
	Alerts []zapAlert `json:"alerts" xml:"alerts>alertitem"`
}

type zapReport struct {
	Sites []zapSite `json:"site" xml:"site"`
}

// zapRecord is the record kept as a finding's original output.
type zapRecord struct {
	Site       string      `json:"site"`
	PluginID   string      `json:"pluginid"`
	AlertRef   string      `json:"alertRef,omitempty"`
	Name       string      `json:"name"`
	RiskCode   string      `json:"riskcode"`
	Confidence string      `json:"confidence"`
	RiskDesc   string      `json:"riskdesc,omitempty"`
	Desc       string      `json:"desc,omitempty"`
	Solution   string      `json:"solution,omitempty"`
	Reference  string      `json:"reference,omitempty"`
	CWEID      string      `json:"cweid,omitempty"`
	WASCID     string      `json:"wascid,omitempty"`
	Instance   zapInstance `json:"instance"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "zap", Label: "OWASP ZAP report (JSON or XML)", Category: "dast", Media: "json", Order: 50,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return p.has("site") && p.hasAny("@version", "@programName", "@generated")
			case "xml":
				return p.root == "OWASPZAPReport"
			}
			return false
		},
		parse: parseZAPReport})
}

func parseZAPReport(raw []byte) ([]importRecord, error) {
	var rep zapReport
	if b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM)); len(b) > 0 && b[0] == '<' {
		if err := decodeXML(b, &rep); err != nil {
			return nil, fmt.Errorf("zap: %w", err)
		}
	} else if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("zap: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, site := range rep.Sites {
		for _, a := range site.Alerts {
			insts := a.Instances
			if len(insts) == 0 {
				// An alert without instances still is a finding (of the site).
				insts = []zapInstance{{URI: looseString(site.Name)}}
			}
			for _, in := range insts {
				out = append(out, zapFinding(site.Name, a, in))
			}
		}
	}
	return out, nil
}

func zapFinding(site string, a zapAlert, in zapInstance) importRecord {
	name := firstNonEmpty(string(a.Name), string(a.Alert), string(a.PluginID))
	f := Finding{Category: "dast", RuleID: firstNonEmpty(string(a.AlertRef), string(a.PluginID), name), Title: name,
		FilePath: locationOf("", firstNonEmpty(string(in.URI), site)), CWE: []string{string(a.CWEID)}}
	switch strings.TrimSpace(string(a.RiskCode)) {
	case "3":
		f.Severity = "high"
	case "2":
		f.Severity = "medium"
	case "1":
		f.Severity = "low"
	default:
		f.Severity = "info"
	}
	fp := false
	switch strings.TrimSpace(string(a.Confidence)) {
	case "0":
		f.Confidence, fp = "low", true
	case "1":
		f.Confidence = "low"
	case "2":
		f.Confidence = "medium"
	case "3", "4":
		f.Confidence = "high"
	}
	where := strings.TrimSpace(string(in.Method) + " " + string(in.URI))
	if in.Param != "" {
		where += fmt.Sprintf(" (parameter %q)", string(in.Param))
	}
	note := ""
	if fp {
		note = "ZAP marked this alert as a false positive (confidence 0); it is kept for review."
	}
	f.Description = joinText(note, markupToText(string(a.Desc)), where,
		labelled("Attack", string(in.Attack)), labelled("Evidence", clipText(string(in.Evidence), 500)),
		labelled("Solution", markupToText(string(a.Solution))))
	rec := zapRecord{Site: site, PluginID: string(a.PluginID), AlertRef: string(a.AlertRef), Name: name, RiskCode: string(a.RiskCode),
		Confidence: string(a.Confidence), RiskDesc: string(a.RiskDesc), Desc: clipText(string(a.Desc), maxEvidenceText),
		Solution: clipText(string(a.Solution), maxEvidenceText), Reference: clipText(string(a.Reference), maxEvidenceText),
		CWEID: string(a.CWEID), WASCID: string(a.WASCID), Instance: in}
	rec.Instance.Evidence = looseString(clipText(string(in.Evidence), maxEvidenceText))
	rec.Instance.OtherInfo = looseString(clipText(string(in.OtherInfo), maxEvidenceText))
	return importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(string(in.Method)) + "|" + string(in.Param)), Raw: rawJSON(rec)}
}

// labelled returns "label: v", or "" for an empty v.
func labelled(label, v string) string {
	if v = strings.TrimSpace(v); v == "" {
		return ""
	}
	return label + ": " + v
}
