package scanners

import "fmt"

// SpotBugs XML (`spotbugs -textui -xml:withMessages`, also with the
// FindSecBugs plugin; FindBugs' BugCollection format): BugCollection /
// BugInstance with type (the pattern), priority (1 high, 2 medium, 3 low,
// 4-5 info), rank, category, cweid, instanceHash (the identity),
// ShortMessage, LongMessage and SourceLine elements (sourcepath relative
// to the source root, start, end); BugPattern elements carry the
// pattern's description. Categories SECURITY and MALICIOUS_CODE are sast;
// the others (CORRECTNESS, BAD_PRACTICE, PERFORMANCE, STYLE, ...) are code
// quality (other).

type spotbugsSourceLine struct {
	Primary    string `xml:"primary,attr" json:"primary,omitempty"`
	Start      int    `xml:"start,attr" json:"start,omitempty"`
	End        int    `xml:"end,attr" json:"end,omitempty"`
	SourceFile string `xml:"sourcefile,attr" json:"sourcefile,omitempty"`
	SourcePath string `xml:"sourcepath,attr" json:"sourcepath,omitempty"`
	ClassName  string `xml:"classname,attr" json:"classname,omitempty"`
}

type spotbugsBug struct {
	Type          string `xml:"type,attr" json:"type"`
	Priority      string `xml:"priority,attr" json:"priority"`
	Rank          string `xml:"rank,attr" json:"rank,omitempty"`
	Abbrev        string `xml:"abbrev,attr" json:"abbrev,omitempty"`
	Category      string `xml:"category,attr" json:"category"`
	CWEID         string `xml:"cweid,attr" json:"cweid,omitempty"`
	InstanceHash  string `xml:"instanceHash,attr" json:"instance_hash,omitempty"`
	OccurrenceNum string `xml:"instanceOccurrenceNum,attr" json:"instance_occurrence_num,omitempty"`
	ShortMessage  string `xml:"ShortMessage" json:"short_message,omitempty"`
	LongMessage   string `xml:"LongMessage" json:"long_message,omitempty"`
	Class         struct {
		Name string             `xml:"classname,attr" json:"classname"`
		Line spotbugsSourceLine `xml:"SourceLine" json:"source_line"`
	} `xml:"Class" json:"class"`
	Methods []struct {
		Name  string             `xml:"name,attr" json:"name,omitempty"`
		Class string             `xml:"classname,attr" json:"classname,omitempty"`
		Role  string             `xml:"role,attr" json:"role,omitempty"`
		Line  spotbugsSourceLine `xml:"SourceLine" json:"source_line"`
	} `xml:"Method" json:"methods,omitempty"`
	Lines []spotbugsSourceLine `xml:"SourceLine" json:"source_lines,omitempty"`
}

var spotbugsPriority = map[string]string{"1": "high", "2": "medium", "3": "low", "4": "info", "5": "info"}

func init() {
	registerImportFormat(ImportFormat{ID: "spotbugs", Label: "SpotBugs / FindSecBugs XML", Tool: "SpotBugs", Media: "xml", Order: 108,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "BugCollection" },
		parse: parseSpotBugsXML})
}

func parseSpotBugsXML(raw []byte) ([]importRecord, error) {
	var doc struct {
		Bugs     []spotbugsBug `xml:"BugInstance"`
		Patterns []struct {
			Type    string `xml:"type,attr"`
			Short   string `xml:"ShortDescription"`
			Details string `xml:"Details"`
		} `xml:"BugPattern"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("spotbugs: %w", err)
	}
	details := map[string]string{}
	for _, p := range doc.Patterns {
		details[p.Type] = markupToText(p.Details)
	}
	var out []importRecord
	for i, b := range doc.Bugs {
		if b.Type == "" {
			return out, fmt.Errorf("spotbugs: bug instance %d without type", i+1)
		}
		// The location: the primary (else first) SourceLine of the bug,
		// else the method's, else the class's.
		loc := spotbugsLocation(b)
		sev, ok := spotbugsPriority[b.Priority]
		if !ok {
			sev = "medium"
		}
		cat := "other"
		if b.Category == "SECURITY" || b.Category == "MALICIOUS_CODE" {
			cat = "sast"
		}
		f := Finding{Category: cat, RuleID: b.Type, Title: firstNonEmpty(b.ShortMessage, b.Type), Severity: sev, CWE: []string{b.CWEID},
			FilePath: NormalizePath(firstNonEmpty(loc.SourcePath, loc.SourceFile)), StartLine: intPtr(loc.Start), EndLine: intPtr(loc.End),
			Description: joinText(b.LongMessage, clipText(details[b.Type], 2000), fmt.Sprintf("SpotBugs %s, category %s, rank %s.", b.Type, b.Category, b.Rank))}
		key := b.InstanceHash
		if key == "" {
			key = b.Class.Name + "|" + b.LongMessage
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("spotbugs|" + key + "|" + b.OccurrenceNum), Raw: rawJSON(b)})
	}
	return out, nil
}

// spotbugsLocation is the primary SourceLine of a bug, else its first
// one, else the method's, else the class's.
func spotbugsLocation(b spotbugsBug) spotbugsSourceLine {
	for _, l := range b.Lines {
		if l.Primary == "true" && l.SourcePath != "" {
			return l
		}
	}
	for _, l := range b.Lines {
		if l.SourcePath != "" {
			return l
		}
	}
	for _, m := range b.Methods {
		if m.Role == "" && m.Line.SourcePath != "" {
			return m.Line
		}
	}
	return b.Class.Line
}
