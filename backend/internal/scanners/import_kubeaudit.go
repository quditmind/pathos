package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// kubeaudit JSON lines (`kubeaudit all -f <file> -p json`): one result
// per line with AuditResultName, level (error, warning, info), msg,
// ResourceKind, ResourceName, ResourceNamespace, ResourceApiVersion and
// auditor-specific fields (Container, MissingAnnotation, ...). error is
// medium, warning low, info info. kubeaudit does not report the file:
// findings are located at the resource (namespace/kind/name).

func init() {
	registerImportFormat(ImportFormat{ID: "kubeaudit", Label: "kubeaudit JSON lines (-p json)", Tool: "kubeaudit", Category: "iac", Media: "jsonl", Order: 702,
		match: func(p *importProbe) bool {
			return (p.kind == "jsonl" || p.kind == "object") && p.has("AuditResultName", "ResourceKind", "level")
		},
		parse: parseKubeaudit})
}

func parseKubeaudit(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := jsonLines(raw, func(n int, line []byte) error {
		var r map[string]any
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("kubeaudit: line %d: invalid JSON: %w", n, err)
		}
		str := func(k string) string { s, _ := r[k].(string); return s }
		name := str("AuditResultName")
		if name == "" {
			return fmt.Errorf("kubeaudit: line %d: expected AuditResultName", n)
		}
		res := strings.Trim(strings.Join([]string{str("ResourceNamespace"), str("ResourceKind"), str("ResourceName")}, "/"), "/")
		sev := map[string]string{"error": "medium", "warning": "low", "info": "info"}[strings.ToLower(str("level"))]
		var extra []string
		for k, v := range r {
			switch k {
			case "AuditResultName", "level", "msg", "time", "ResourceKind", "ResourceName", "ResourceNamespace", "ResourceApiVersion":
			default:
				extra = append(extra, fmt.Sprintf("%s=%v", k, v))
			}
		}
		f := Finding{Category: "iac", RuleID: name, Title: firstNonEmpty(str("msg"), name), Severity: firstNonEmpty(sev, "info"), FilePath: res,
			Description: joinText(str("msg"), labeled("Details", strings.Join(sortedStrings(extra), ", ")))}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(str("Container") + "|" + str("MissingAnnotation")), Raw: append(json.RawMessage(nil), line...)})
		return nil
	})
	return out, err
}
