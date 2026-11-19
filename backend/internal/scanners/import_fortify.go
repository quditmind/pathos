package scanners

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Fortify SCA results: the FVDL XML (audit.fvdl), or the FPR file that
// carries it (a zip archive; the FPR is accepted with format "fortify",
// its content is not detected). FVDL / Vulnerabilities / Vulnerability
// with ClassInfo (ClassID, Kingdom, Type, Subtype, DefaultSeverity),
// InstanceInfo (InstanceID, InstanceSeverity, Confidence) and the primary
// trace, whose default node is the location (inline or a NodeRef into the
// UnifiedNodePool). Description elements per ClassID carry the text and
// EngineData / RuleInfo the rule metadata (Impact, Accuracy, Probability,
// altcategoryCWE).
//
// Severity is Fortify's priority: likelihood = Accuracy x Confidence x
// Probability / 25; critical when Impact and likelihood are both >= 2.5,
// high when only Impact is, medium when only likelihood is, low otherwise.
// Without rule metadata, InstanceSeverity (1-5) is used. Identity is the
// InstanceID.

type fortifyLocation struct {
	Path    string `xml:"path,attr" json:"path"`
	Line    int    `xml:"line,attr" json:"line"`
	LineEnd int    `xml:"lineEnd,attr" json:"line_end,omitempty"`
}

type fortifyNode struct {
	ID        string          `xml:"id,attr"`
	IsDefault string          `xml:"isDefault,attr"`
	Location  fortifyLocation `xml:"SourceLocation"`
	Action    string          `xml:"Action"`
}

type fortifyVuln struct {
	ClassID         string `xml:"ClassInfo>ClassID"`
	Kingdom         string `xml:"ClassInfo>Kingdom"`
	Type            string `xml:"ClassInfo>Type"`
	Subtype         string `xml:"ClassInfo>Subtype"`
	Analyzer        string `xml:"ClassInfo>AnalyzerName"`
	DefaultSeverity string `xml:"ClassInfo>DefaultSeverity"`
	InstanceID      string `xml:"InstanceInfo>InstanceID"`
	Severity        string `xml:"InstanceInfo>InstanceSeverity"`
	Confidence      string `xml:"InstanceInfo>Confidence"`
	Function        struct {
		Name  string `xml:"name,attr"`
		Class string `xml:"enclosingClass,attr"`
	} `xml:"AnalysisInfo>Unified>Context>Function"`
	Entries []struct {
		NodeRef struct {
			ID string `xml:"id,attr"`
		} `xml:"NodeRef"`
		Node *fortifyNode `xml:"Node"`
	} `xml:"AnalysisInfo>Unified>Trace>Primary>Entry"`
}

type fortifyDoc struct {
	BuildID     string        `xml:"Build>BuildID"`
	SourceBase  string        `xml:"Build>SourceBasePath"`
	Vulns       []fortifyVuln `xml:"Vulnerabilities>Vulnerability"`
	Description []struct {
		ClassID         string `xml:"classID,attr"`
		Abstract        string `xml:"Abstract"`
		Explanation     string `xml:"Explanation"`
		Recommendations string `xml:"Recommendations"`
	} `xml:"Description"`
	Nodes []fortifyNode `xml:"UnifiedNodePool>Node"`
	Rules []struct {
		ID     string `xml:"id,attr"`
		Groups []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"MetaInfo>Group"`
	} `xml:"EngineData>RuleInfo>Rule"`
}

// fortifyRecord is the record kept as a finding's original output.
type fortifyRecord struct {
	InstanceID string            `json:"instance_id"`
	ClassID    string            `json:"class_id"`
	Kingdom    string            `json:"kingdom"`
	Type       string            `json:"type"`
	Subtype    string            `json:"subtype,omitempty"`
	Analyzer   string            `json:"analyzer,omitempty"`
	Severity   string            `json:"instance_severity,omitempty"`
	Confidence string            `json:"confidence,omitempty"`
	Priority   string            `json:"priority"`
	Function   string            `json:"function,omitempty"`
	Rule       map[string]string `json:"rule,omitempty"`
	Trace      []fortifyLocation `json:"trace"`
}

var fortifyCWERe = regexp.MustCompile(`(?i)CWE\s*(?:ID)?\s*-?\s*(\d{1,5})`)

// fortifyMaxFVDL bounds the decompressed FVDL of an FPR archive.
const fortifyMaxFVDL = maxXMLBytes

func init() {
	registerImportFormat(ImportFormat{ID: "fortify", Label: "Fortify FVDL XML / FPR", Tool: "Fortify SCA", Category: "sast", Media: "xml", Order: 100,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "FVDL" },
		parse: parseFortify})
}

// fortifyFVDL returns the FVDL of an FPR archive (raw when it is not one).
func fortifyFVDL(raw []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, []byte("PK\x03\x04")) {
		return raw, nil
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("fortify: invalid FPR archive: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != "audit.fvdl" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("fortify: FPR: %w", err)
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, fortifyMaxFVDL+1))
		if err != nil {
			return nil, fmt.Errorf("fortify: FPR: %w", err)
		}
		if len(b) > fortifyMaxFVDL {
			return nil, errors.New("fortify: FPR: audit.fvdl is too large")
		}
		return b, nil
	}
	return nil, errors.New("fortify: the FPR archive has no audit.fvdl")
}

func parseFortify(raw []byte) ([]importRecord, error) {
	fvdl, err := fortifyFVDL(raw)
	if err != nil {
		return nil, err
	}
	var doc fortifyDoc
	if err := decodeXML(fvdl, &doc); err != nil {
		return nil, fmt.Errorf("fortify: %w", err)
	}
	pool := map[string]fortifyNode{}
	for _, n := range doc.Nodes {
		pool[n.ID] = n
	}
	desc := map[string]string{}
	for _, d := range doc.Description {
		desc[d.ClassID] = joinText(d.Abstract, d.Explanation, labelled("Recommendations", d.Recommendations))
	}
	rules := map[string]map[string]string{}
	for _, r := range doc.Rules {
		m := map[string]string{}
		for _, g := range r.Groups {
			m[g.Name] = strings.TrimSpace(g.Value)
		}
		rules[r.ID] = m
	}
	var out []importRecord
	for i, v := range doc.Vulns {
		if v.ClassID == "" || v.Type == "" {
			return out, fmt.Errorf("fortify: vulnerability %d: expected ClassInfo with ClassID and Type", i+1)
		}
		// The trace: every entry's node; the location is the default node,
		// else the last one.
		var trace []fortifyLocation
		loc := -1
		for _, e := range v.Entries {
			n := e.Node
			if n == nil {
				pn, ok := pool[e.NodeRef.ID]
				if !ok {
					continue
				}
				n = &pn
			}
			trace = append(trace, n.Location)
			if n.IsDefault == "true" {
				loc = len(trace) - 1
			}
		}
		if loc < 0 {
			loc = len(trace) - 1
		}
		rule := rules[v.ClassID]
		prio := fortifyPriority(rule, v.Confidence, firstNonEmpty(v.Severity, v.DefaultSeverity))
		title := v.Type
		if v.Subtype != "" {
			title += ": " + v.Subtype
		}
		f := Finding{Category: "sast", RuleID: title, Title: title, Severity: prio,
			Description: joinText(desc[v.ClassID], fmt.Sprintf("Fortify %s (%s analyzer).", v.Kingdom, v.Analyzer))}
		for _, m := range fortifyCWERe.FindAllStringSubmatch(rule["altcategoryCWE"], -1) {
			f.CWE = append(f.CWE, "CWE-"+m[1])
		}
		if loc >= 0 {
			f.FilePath, f.StartLine, f.EndLine = NormalizePath(trace[loc].Path), intPtr(trace[loc].Line), intPtr(trace[loc].LineEnd)
		}
		if len(trace) > 200 {
			trace = trace[:200]
		}
		fn := v.Function.Name
		if v.Function.Class != "" {
			fn = v.Function.Class + "." + fn
		}
		rec := fortifyRecord{InstanceID: v.InstanceID, ClassID: v.ClassID, Kingdom: v.Kingdom, Type: v.Type, Subtype: v.Subtype, Analyzer: v.Analyzer,
			Severity: v.Severity, Confidence: v.Confidence, Priority: prio, Function: fn, Rule: rule, Trace: trace}
		key := v.InstanceID
		if key == "" {
			key = v.ClassID + "|" + fn
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("fortify|" + key), Raw: rawJSON(rec)})
	}
	return out, nil
}

// fortifyPriority computes Fortify's priority (see the top of the file).
func fortifyPriority(rule map[string]string, confidence, severity string) string {
	num := func(s string) (float64, bool) {
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, err == nil
	}
	impact, ok1 := num(rule["Impact"])
	acc, ok2 := num(rule["Accuracy"])
	prob, ok3 := num(rule["Probability"])
	conf, ok4 := num(confidence)
	if ok1 && ok2 && ok3 && ok4 {
		likely := acc * conf * prob / 25
		switch {
		case impact >= 2.5 && likely >= 2.5:
			return "critical"
		case impact >= 2.5:
			return "high"
		case likely >= 2.5:
			return "medium"
		}
		return "low"
	}
	if s, ok := num(severity); ok {
		switch {
		case s >= 4:
			return "high"
		case s >= 3:
			return "medium"
		case s >= 2:
			return "low"
		}
		return "info"
	}
	return "medium"
}
