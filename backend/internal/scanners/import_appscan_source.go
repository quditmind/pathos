package scanners

import (
	"fmt"
	"strings"
)

// HCL AppScan Source assessment XML (.ozasmt): AssessmentRun with pools
// that findings reference by id: StringPool (String id/value), FilePool
// (File id/value), SitePool (Site: file_id, ln, method, caller, cxt = the
// code) and FindingDataPool (FindingData: vtype = the vulnerability type
// string, sev 0 High, 1 Medium, 2 Low, 3 Info, conf 0 Definitive (high),
// 1 Suspect (medium), 2 Scan Coverage (low), site_id, rec = the
// recommendation string, cwe). One finding per FindingData. Identity is
// the type, the calling method and the API called.

type appscanFindingData struct {
	ID     string `xml:"id,attr"`
	VType  string `xml:"vtype,attr"`
	Sev    string `xml:"sev,attr"`
	Conf   string `xml:"conf,attr"`
	SiteID string `xml:"site_id,attr"`
	Rec    string `xml:"rec,attr"`
	CWE    string `xml:"cwe,attr"`
}

type appscanDoc struct {
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr"`
	Strings []struct {
		ID    string `xml:"id,attr"`
		Value string `xml:"value,attr"`
	} `xml:"StringPool>String"`
	Files []struct {
		ID    string `xml:"id,attr"`
		Value string `xml:"value,attr"`
	} `xml:"FilePool>File"`
	Sites []struct {
		ID     string `xml:"id,attr"`
		FileID string `xml:"file_id,attr"`
		Line   int    `xml:"ln,attr"`
		Method string `xml:"method,attr"`
		Caller string `xml:"caller,attr"`
		Cxt    string `xml:"cxt,attr"`
		Sig    string `xml:"sig,attr"`
	} `xml:"SitePool>Site"`
	Findings []appscanFindingData `xml:"FindingDataPool>FindingData"`
}

// appscanRecord is the record kept as a finding's original output.
type appscanRecord struct {
	FindingDataID  string `json:"finding_data_id"`
	Type           string `json:"vulnerability_type"`
	Severity       string `json:"sev"`
	Classification string `json:"conf"`
	CWE            string `json:"cwe,omitempty"`
	File           string `json:"file,omitempty"`
	Line           int    `json:"line,omitempty"`
	Caller         string `json:"caller,omitempty"`
	API            string `json:"api,omitempty"`
	Code           string `json:"code,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

var (
	appscanSeverity = map[string]string{"0": "high", "1": "medium", "2": "low", "3": "info"}
	appscanConf     = map[string]string{"0": "high", "1": "medium", "2": "low"}
	appscanConfName = map[string]string{"0": "Definitive", "1": "Suspect", "2": "Scan Coverage"}
)

func init() {
	registerImportFormat(ImportFormat{ID: "appscan-source", Label: "HCL AppScan Source assessment XML (.ozasmt)", Tool: "AppScan Source",
		Category: "sast", Media: "xml", Order: 103,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "AssessmentRun" },
		parse: parseAppScanSource})
}

func parseAppScanSource(raw []byte) ([]importRecord, error) {
	var doc appscanDoc
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("appscan-source: %w", err)
	}
	str := map[string]string{}
	for _, s := range doc.Strings {
		str[s.ID] = s.Value
	}
	files := map[string]string{}
	for _, f := range doc.Files {
		files[f.ID] = f.Value
	}
	sites := map[string]int{}
	for i, s := range doc.Sites {
		sites[s.ID] = i
	}
	var out []importRecord
	for i, fd := range doc.Findings {
		vtype := str[fd.VType]
		if vtype == "" {
			return out, fmt.Errorf("appscan-source: finding data %d: vtype %q is not in the string pool", i+1, fd.VType)
		}
		rec := appscanRecord{FindingDataID: fd.ID, Type: vtype, Severity: fd.Sev, Classification: appscanConfName[fd.Conf], CWE: fd.CWE,
			Recommendation: str[fd.Rec]}
		if si, ok := sites[fd.SiteID]; ok {
			s := doc.Sites[si]
			rec.File, rec.Line, rec.Caller, rec.API, rec.Code = files[s.FileID], s.Line, str[s.Caller], str[s.Method], str[s.Cxt]
		}
		sev, ok := appscanSeverity[fd.Sev]
		if !ok {
			sev = "medium"
		}
		title := strings.ReplaceAll(vtype, ".", " / ")
		f := Finding{Category: "sast", RuleID: vtype, Title: title, Severity: sev, Confidence: appscanConf[fd.Conf],
			FilePath: NormalizePath(rec.File), StartLine: intPtr(rec.Line), CWE: []string{fd.CWE},
			Description: joinText(fmt.Sprintf("AppScan Source %s finding (%s).", vtype, firstNonEmpty(rec.Classification, "unclassified")),
				labelled("Call", rec.API), labelled("In", rec.Caller), labelled("Code", rec.Code), labelled("Recommendation", rec.Recommendation))}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("appscan|" + vtype + "|" + rec.Caller + "|" + rec.API), Raw: rawJSON(rec)})
	}
	return out, nil
}
