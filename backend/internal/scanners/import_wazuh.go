package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Wazuh vulnerability detection, in three shapes:
//   - alerts (alerts.json, JSON lines or an array) of the vulnerability
//     detector: rule.groups contains "vulnerability-detector" and
//     data.vulnerability holds the CVE, package, CVSS and severity (Wazuh
//     4.x; alerts of other rules are not findings);
//   - documents of the wazuh-states-vulnerabilities index (Wazuh 4.8 and
//     later), as JSON lines or an array of documents;
//   - an OpenSearch/Indexer search response over that index
//     ({"hits": {"hits": [{"_source": ...}]}}).
// One finding per agent, package and CVE; the location is the agent name
// (and IP when reported). Alerts with status "Solved" are kept with the
// status in the description (the detector reports fixes as alerts too).

type wazuhAgent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type wazuhPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Condition    string `json:"condition"`
	Type         string `json:"type"`
}

// wazuhAlertVuln is data.vulnerability of a detector alert.
type wazuhAlertVuln struct {
	CVE     string       `json:"cve"`
	Title   string       `json:"title"`
	Package wazuhPackage `json:"package"`
	CVSS    struct {
		CVSS3 struct {
			BaseScore looseString `json:"base_score"`
		} `json:"cvss3"`
		CVSS2 struct {
			BaseScore looseString `json:"base_score"`
		} `json:"cvss2"`
	} `json:"cvss"`
	Score struct {
		Base    looseString `json:"base"`
		Version string      `json:"version"`
	} `json:"score"`
	Severity     string `json:"severity"`
	Rationale    string `json:"rationale"`
	Description  string `json:"description"`
	CWEReference string `json:"cwe_reference"`
	Status       string `json:"status"`
	Reference    string `json:"reference"`
}

type wazuhAlert struct {
	Rule struct {
		ID          string   `json:"id"`
		Level       int      `json:"level"`
		Description string   `json:"description"`
		Groups      []string `json:"groups"`
	} `json:"rule"`
	Agent wazuhAgent `json:"agent"`
	Data  struct {
		Vulnerability *wazuhAlertVuln `json:"vulnerability"`
	} `json:"data"`
}

// wazuhState is a wazuh-states-vulnerabilities document.
type wazuhState struct {
	Agent         wazuhAgent   `json:"agent"`
	Package       wazuhPackage `json:"package"`
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Reference   string `json:"reference"`
		Category    string `json:"category"`
		Score       struct {
			Base    looseString `json:"base"`
			Version string      `json:"version"`
		} `json:"score"`
		UnderEvaluation bool   `json:"under_evaluation"`
		DetectedAt      string `json:"detected_at"`
	} `json:"vulnerability"`
}

func wazuhIsState(m map[string]json.RawMessage) bool {
	return hasKeys(m, "vulnerability", "package", "agent") && (hasKeys(m, "wazuh") || hasKeys(m, "host"))
}

func init() {
	registerImportFormat(ImportFormat{ID: "wazuh", Label: "Wazuh vulnerability detection JSON", Tool: "Wazuh", Category: "other", Media: "json", Order: 338,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				if h, ok := p.keys["hits"]; ok && p.headHas("wazuh-states-vulnerabilities") {
					var m map[string]json.RawMessage
					return json.Unmarshal(h, &m) == nil && hasKeys(m, "hits")
				}
				fallthrough
			case "jsonl", "array":
				if wazuhIsState(p.keys) {
					return true
				}
				return p.has("rule", "agent", "data") && p.headHas(`"vulnerability-detector"`)
			}
			return false
		},
		parse: parseWazuh})
}

func parseWazuh(raw []byte) ([]importRecord, error) {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	var docs []json.RawMessage
	switch {
	case len(b) > 0 && b[0] == '[':
		if err := json.Unmarshal(b, &docs); err != nil {
			return nil, fmt.Errorf("wazuh: invalid JSON: %w", err)
		}
	default:
		var search struct {
			Hits *struct {
				Hits []struct {
					Source json.RawMessage `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(b, &search) == nil && search.Hits != nil {
			for _, h := range search.Hits.Hits {
				docs = append(docs, h.Source)
			}
			break
		}
		err := jsonLines(b, func(n int, line []byte) error {
			if !json.Valid(line) {
				return fmt.Errorf("line %d: invalid JSON", n)
			}
			docs = append(docs, append(json.RawMessage(nil), line...))
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("wazuh: %w", err)
		}
	}
	var out []importRecord
	seen := map[string]int{}
	for i, d := range docs {
		var keys map[string]json.RawMessage
		if json.Unmarshal(d, &keys) != nil {
			return out, fmt.Errorf("wazuh: document %d: expected an object", i+1)
		}
		var f Finding
		var status string
		switch {
		case wazuhIsState(keys):
			var s wazuhState
			if err := json.Unmarshal(d, &s); err != nil || s.Vulnerability.ID == "" {
				return out, fmt.Errorf("wazuh: document %d: expected a vulnerability id", i+1)
			}
			f = wazuhFinding(s.Agent, s.Package, s.Vulnerability.ID, "", s.Vulnerability.Severity, string(s.Vulnerability.Score.Base),
				s.Vulnerability.Description, s.Vulnerability.Reference, "")
			if s.Vulnerability.UnderEvaluation {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "Wazuh marks this vulnerability as under evaluation.")
			}
		case keys["rule"] != nil:
			var a wazuhAlert
			if err := json.Unmarshal(d, &a); err != nil {
				return out, fmt.Errorf("wazuh: alert %d: %w", i+1, err)
			}
			isVD := false
			for _, g := range a.Rule.Groups {
				isVD = isVD || g == "vulnerability-detector"
			}
			v := a.Data.Vulnerability
			if !isVD || v == nil {
				continue // other alerts are not vulnerability findings
			}
			if v.CVE == "" {
				return out, fmt.Errorf("wazuh: alert %d: data.vulnerability without cve", i+1)
			}
			score := firstNonEmpty(string(v.CVSS.CVSS3.BaseScore), string(v.Score.Base), string(v.CVSS.CVSS2.BaseScore))
			f = wazuhFinding(a.Agent, v.Package, v.CVE, v.Title, v.Severity, score, firstNonEmpty(v.Description, v.Rationale), v.Reference, v.CWEReference)
			status = v.Status
			if status != "" {
				f.Description = joinText(f.Description, "Status: "+status)
			}
		default:
			return out, fmt.Errorf("wazuh: document %d: neither a vulnerability alert nor a vulnerability state", i+1)
		}
		// The detector repeats alerts; the first of each identity is kept
		// and later ones only update the status.
		id := f.FilePath + "|" + f.PackageName + "@" + f.PackageVersion + "|" + f.RuleID
		if j, dup := seen[id]; dup {
			if status != "" {
				out[j].F.Description = joinText(out[j].F.Description, "Later status: "+status)
			}
			continue
		}
		seen[id] = len(out)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(id), Raw: d})
	}
	return out, nil
}

func wazuhFinding(agent wazuhAgent, pkg wazuhPackage, id, title, sev, score, desc, ref, cwe string) Finding {
	loc := firstNonEmpty(agent.Name, agent.IP, "agent "+agent.ID)
	if agent.IP != "" && agent.Name != "" && agent.IP != "any" {
		loc += " (" + agent.IP + ")"
	}
	f := Finding{Category: "sca", RuleID: id, CVE: firstMatch(cveRe, id), Title: firstNonEmpty(title, fmt.Sprintf("%s in %s %s", id, pkg.Name, pkg.Version)),
		FilePath: loc, PackageName: pkg.Name, PackageVersion: pkg.Version, Severity: normSeverity(sev), CVSS: cvssOf(score), CWE: []string{cwe},
		Description: joinText(desc, labelled("Agent", strings.TrimSpace(agent.ID+" "+agent.Name)), labelled("Condition", pkg.Condition),
			labelled("Architecture", pkg.Architecture), labelled("Reference", ref))}
	return f
}
