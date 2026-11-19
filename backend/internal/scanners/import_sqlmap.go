package scanners

import (
	"fmt"
	"strings"
)

// sqlmap results CSV (`sqlmap -m targets.txt --batch`, or any run with
// `--results-file`): one row per injectable parameter, with the target URL,
// place (GET, POST, Cookie, URI, ...), parameter, the techniques that
// worked (letters B, E, U, S, T, Q) and notes. Every row is a confirmed SQL
// injection (high, CWE-89). sqlmap's text log is not a supported format: it
// is free text without a stable structure. Identity is the URL without its
// query, the place and the parameter.

var sqlmapTechniques = map[rune]string{
	'B': "boolean-based blind", 'E': "error-based", 'U': "UNION query", 'S': "stacked queries", 'T': "time-based blind", 'Q': "inline query",
}

func init() {
	registerImportFormat(ImportFormat{ID: "sqlmap", Label: "sqlmap results CSV", Tool: "sqlmap", Category: "dast", Media: "csv", Order: 303,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && headerHas(p.header, "target_url", "place", "parameter", "technique(s)")
		},
		parse:    parseSqlmapCSV,
		sanitize: sanitizeHTTPText,
	})
}

func parseSqlmapCSV(raw []byte) ([]importRecord, error) {
	_, rows, err := csvTable(raw)
	var out []importRecord
	for _, r := range rows {
		u, place, param := redactHTTP(r.get("target_url")), r.get("place"), r.get("parameter")
		if u == "" || param == "" {
			return out, fmt.Errorf("sqlmap: row %d: target URL and parameter are required", r.N)
		}
		var techs []string
		for _, c := range strings.ToUpper(r.get("technique(s)")) {
			if t, ok := sqlmapTechniques[c]; ok {
				techs = append(techs, t)
			}
		}
		f := Finding{Category: "dast", RuleID: "sql-injection", Title: fmt.Sprintf("SQL injection in %s parameter %q", firstNonEmpty(place, "the"), param),
			Severity: "high", Confidence: "high", FilePath: locationOf("", g1StripQuery(u)), CWE: []string{"CWE-89"}}
		f.Description = joinText("sqlmap confirmed an SQL injection.", whereText(place, u, param),
			labelled("Techniques", strings.Join(techs, ", ")), labelled("Notes", r.get("note(s)")))
		rec := map[string]string{}
		for k, v := range r.Orig {
			rec[k] = redactHTTP(v)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(place) + "|" + param), Raw: rawJSON(rec)})
	}
	if err != nil {
		return out, fmt.Errorf("sqlmap: %w", err)
	}
	return out, nil
}
