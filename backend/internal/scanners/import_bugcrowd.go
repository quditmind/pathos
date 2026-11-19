package scanners

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
)

// sanitizeCSVHTTP redacts HTTP evidence cell by cell and re-encodes the
// CSV, so a redacted header line can never swallow the cells after it
// (sanitizeHTTPText works on lines). Input that is not CSV is returned
// redacted as text.
func sanitizeCSVHTTP(raw []byte) []byte {
	b := bytes.TrimPrefix(raw, utf8BOM)
	line, _, _ := bytes.Cut(b, []byte("\n"))
	cr := csvReader(bytes.NewReader(b))
	cr.Comma = csvComma(line)
	var out bytes.Buffer
	cw := csv.NewWriter(&out)
	cw.Comma = cr.Comma
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return sanitizeHTTPText(raw)
		}
		for i := range rec {
			rec[i] = string(sanitizeHTTPText([]byte(rec[i])))
		}
		if cw.Write(rec) != nil {
			return sanitizeHTTPText(raw)
		}
	}
	cw.Flush()
	if cw.Error() != nil {
		return sanitizeHTTPText(raw)
	}
	return out.Bytes()
}

// Bugcrowd submissions CSV export: one row per submission with the
// priority (P1 critical to P5 informational), the VRT classification, the
// target and the researcher's description and HTTP request. Resolved
// submissions are fixed and not imported; rejected ones (duplicate, not
// applicable, out of scope, ...) are kept with low confidence. The HTTP
// request and descriptions may contain session cookies and tokens: they
// are redacted before the report is stored.

func init() {
	registerImportFormat(ImportFormat{ID: "bugcrowd", Label: "Bugcrowd submissions CSV", Tool: "Bugcrowd", Category: "other", Media: "csv", Order: 482,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && headerHas(p.header, "reference_number", "bounty_code", "title", "priority", "vrt_lineage", "substate", "bug_url")
		},
		parse:    parseBugcrowdCSV,
		sanitize: sanitizeCSVHTTP})
}

func parseBugcrowdCSV(raw []byte) ([]importRecord, error) {
	_, rows, err := csvTable(raw)
	if err != nil && len(rows) == 0 {
		return nil, fmt.Errorf("bugcrowd: %w", err)
	}
	var out []importRecord
	for _, r := range rows {
		ref, title := r.get("reference_number"), r.get("title", "caption")
		if ref == "" || title == "" {
			return out, fmt.Errorf("bugcrowd: row %d: reference_number and title are required", r.N)
		}
		skip, note := bountyVerdict("Bugcrowd", r.get("substate"))
		if skip {
			continue
		}
		f := Finding{Category: "other", RuleID: firstNonEmpty(r.get("vrt_lineage"), "bugcrowd-submission"), Title: title,
			FilePath: locationOf("", firstNonEmpty(r.get("bug_url"), r.get("target_name"), "bugcrowd:"+r.get("bounty_code"))),
			CWE:      []string{r.get("vulnerability_references")}}
		switch strings.TrimPrefix(strings.ToUpper(r.get("priority")), "P") {
		case "1":
			f.Severity = "critical"
		case "2":
			f.Severity = "high"
		case "3":
			f.Severity = "medium"
		case "4":
			f.Severity = "low"
		default:
			f.Severity = "info"
		}
		if note != "" {
			f.Confidence = "low"
		}
		f.Description = joinText(note, clipText(redactHTTP(r.get("description")), 3000), labelled("HTTP request", clipText(redactHTTP(r.get("http_request")), 2000)),
			labelled("Extra information", clipText(redactHTTP(r.get("extra_info")), 1000)), labelled("Remediation", r.get("remediation_advice")),
			labelled("VRT", r.get("vrt_lineage")), labelled("Target", strings.TrimSpace(r.get("target_name")+" "+r.get("target_category"))),
			labelled("State", strings.Trim(r.get("state")+" / "+r.get("substate"), " /")), labelled("Submitted", r.get("submitted_at")))
		rec := map[string]string{}
		for k, v := range r.Orig {
			rec[k] = redactHTTP(v)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("bugcrowd|" + ref), Raw: rawJSON(rec)})
	}
	return out, err
}
