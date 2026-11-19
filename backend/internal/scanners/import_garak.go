package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// garak (NVIDIA LLM vulnerability scanner) reports: the run report
// (<prefix>.report.jsonl, one JSON object per line with entry_type
// "start_run setup", "attempt", "eval", "digest", ...) and the hit log
// (<prefix>.hitlog.jsonl, one line per successful attack).
//
// From a report, one finding per eval entry with failures, that is a
// probe and detector pair where at least one attempt succeeded against
// the model; passing pairs are not findings. The attack success rate
// (fails / evaluated) sets the severity: 50% or more is high, below
// medium. Up to two successful attempts (detector score >= 0.5) are
// quoted as evidence. From a hit log, one finding per probe and detector
// (same identity as from the report). The location is the target model
// (generator type and name). Prompts and outputs pass the secret
// redaction; configuration values named like credentials are removed
// before the report is stored.

type garakEval struct {
	Probe          string `json:"probe"`
	Detector       string `json:"detector"`
	Passed         int    `json:"passed"`
	Fails          *int   `json:"fails"`
	Nones          int    `json:"nones"`
	Total          int    `json:"total"`
	TotalEvaluated int    `json:"total_evaluated"`
}

type garakProbeInfo struct {
	Description string   `json:"description"`
	Goal        string   `json:"goal"`
	DocURI      string   `json:"doc_uri"`
	Tags        []string `json:"tags"`
}

type garakHit struct {
	Probe     string  `json:"probe"`
	Detector  string  `json:"detector"`
	Score     float64 `json:"score"`
	Generator string  `json:"generator"`
	Goal      string  `json:"goal"`
	Prompt    string  `json:"-"`
	Output    string  `json:"-"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "garak", Label: "garak report or hit log (JSON Lines)", Tool: "garak", Category: "other", Media: "jsonl", Order: 370,
		match: func(p *importProbe) bool {
			if p.kind != "jsonl" && p.kind != "object" {
				return false
			}
			report := p.has("entry_type") && p.headHas(`"garak`)
			hitlog := p.has("attempt_id", "probe", "detector", "generator") && p.hasAny("triggers", "score")
			return report || hitlog
		},
		parse:    parseGarak,
		sanitize: sanitizeGarak})
}

// garakCredential reports configuration keys that hold credentials.
func garakCredential(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"api_key", "apikey", "password", "secret", "access_token", "auth_token", "bearer"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return strings.HasSuffix(k, ".key") || strings.HasSuffix(k, "_token") || k == "token"
}

func garakRedact(x any) any {
	switch t := x.(type) {
	case []any:
		for i := range t {
			t[i] = garakRedact(t[i])
		}
	case map[string]any:
		for k, v := range t {
			if s, ok := v.(string); ok && s != "" && garakCredential(k) {
				t[k] = "[REDACTED]"
				continue
			}
			t[k] = garakRedact(v)
		}
	}
	return x
}

func sanitizeGarak(raw []byte) []byte {
	var out strings.Builder
	err := jsonLines(raw, func(_ int, line []byte) error {
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			return err
		}
		b, err := json.Marshal(garakRedact(v))
		if err != nil {
			return err
		}
		out.Write(sanitizeHTTPJSON(b))
		out.WriteByte('\n')
		return nil
	})
	if err != nil {
		return sanitizeHTTPText(raw)
	}
	return []byte(out.String())
}

// garakText returns the text of a garak message (a string, or an object
// with "text"; a prompt is {"turns": [{"content": {"text"}}]}).
func garakText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["text"].(string); ok {
			return s
		}
		if turns, ok := t["turns"].([]any); ok {
			var parts []string
			for _, tr := range turns {
				if m, ok := tr.(map[string]any); ok {
					parts = append(parts, garakText(m["content"]))
				}
			}
			return strings.Join(parts, "\n")
		}
	}
	return ""
}

func parseGarak(raw []byte) ([]importRecord, error) {
	target := ""
	probes := map[string]garakProbeInfo{}
	var evals []garakEval
	evalRaw := map[string]json.RawMessage{}
	hits := map[string][]garakHit{}
	var hitOrder []string
	err := jsonLines(raw, func(n int, line []byte) error {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return fmt.Errorf("garak: line %d: invalid JSON: %w", n, err)
		}
		et, _ := m["entry_type"].(string)
		switch {
		case et == "start_run setup":
			typ := firstNonEmpty(garakStr(m["plugins.target_type"]), garakStr(m["plugins.model_type"]))
			name := firstNonEmpty(garakStr(m["plugins.target_name"]), garakStr(m["plugins.model_name"]))
			target = strings.TrimSpace(typ + " " + name)
		case et == "plugin_cache":
			var pc struct {
				Cache struct {
					Probes map[string]garakProbeInfo `json:"probes"`
				} `json:"plugin_cache"`
			}
			if json.Unmarshal(line, &pc) == nil {
				for k, v := range pc.Cache.Probes {
					probes[strings.TrimPrefix(k, "probes.")] = v
				}
			}
		case et == "eval":
			var e garakEval
			if err := json.Unmarshal(line, &e); err != nil || e.Probe == "" || e.Detector == "" {
				return fmt.Errorf("garak: line %d: eval entry without probe and detector", n)
			}
			evals = append(evals, e)
			evalRaw[e.Probe+"|"+e.Detector] = append(json.RawMessage(nil), line...)
		case et == "attempt":
			probe, _ := m["probe_classname"].(string)
			dr, _ := m["detector_results"].(map[string]any)
			outputs, _ := m["outputs"].([]any)
			for det, scores := range dr {
				list, _ := scores.([]any)
				for i, s := range list {
					if f, ok := s.(float64); ok && f >= 0.5 {
						out := ""
						if i < len(outputs) {
							out = garakText(outputs[i])
						}
						key := probe + "|" + strings.TrimPrefix(det, "detectors.")
						if len(hits[key]) < 2 {
							hits[key] = append(hits[key], garakHit{Probe: probe, Detector: det, Score: f, Prompt: garakText(m["prompt"]), Output: out})
						}
					}
				}
			}
		case et == "":
			// Hit log line.
			probe, _ := m["probe"].(string)
			det, _ := m["detector"].(string)
			if probe == "" || det == "" {
				return fmt.Errorf("garak: line %d: neither a report entry nor a hit", n)
			}
			h := garakHit{Probe: probe, Detector: det, Prompt: garakText(m["prompt"]), Output: garakText(m["output"])}
			h.Score, _ = m["score"].(float64)
			h.Generator, _ = m["generator"].(string)
			h.Goal, _ = m["goal"].(string)
			key := probe + "|" + det
			if _, seen := hits[key]; !seen {
				hitOrder = append(hitOrder, key)
			}
			hits[key] = append(hits[key], h)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []importRecord
	if len(evals) > 0 || len(hitOrder) == 0 {
		for _, e := range evals {
			evaluated := garakFirstPositive(e.TotalEvaluated, e.Total)
			fails := evaluated - e.Passed - e.Nones
			if e.Fails != nil {
				fails = *e.Fails
			}
			if fails <= 0 {
				continue
			}
			rate := 0.0
			if evaluated > 0 {
				rate = float64(fails) / float64(evaluated)
			}
			key := e.Probe + "|" + strings.TrimPrefix(e.Detector, "detectors.")
			out = append(out, garakFinding(e.Probe, e.Detector, target, probes[e.Probe], hits[key], fails, evaluated, rate, evalRaw[e.Probe+"|"+e.Detector]))
		}
		return out, nil
	}
	for _, key := range hitOrder {
		hs := hits[key]
		gen := firstNonEmpty(strings.TrimSuffix(hs[0].Generator, " None"), "model")
		info := garakProbeInfo{Goal: hs[0].Goal}
		rec := map[string]any{"probe": hs[0].Probe, "detector": hs[0].Detector, "generator": hs[0].Generator, "hits": len(hs)}
		out = append(out, garakFinding(hs[0].Probe, hs[0].Detector, gen, info, hs[:min(len(hs), 2)], len(hs), 0, -1, rawJSON(rec)))
	}
	return out, nil
}

func garakFirstPositive(v ...int) int {
	for _, n := range v {
		if n > 0 {
			return n
		}
	}
	return 0
}

func garakFinding(probe, detector, target string, info garakProbeInfo, hits []garakHit, fails, evaluated int, rate float64, raw json.RawMessage) importRecord {
	det := strings.TrimPrefix(detector, "detectors.")
	f := Finding{Category: "other", RuleID: "garak:" + probe + "/" + det,
		Title:    fmt.Sprintf("garak probe %s succeeded against the model (detector %s)", probe, det),
		FilePath: firstNonEmpty(target, "model"), Severity: "medium", Confidence: "medium"}
	if rate >= 0.5 {
		f.Severity = "high"
	}
	result := fmt.Sprintf("%d successful attack(s) in the hit log.", fails)
	if rate >= 0 {
		result = fmt.Sprintf("Attack success rate %.1f%% (%d of %d attempts).", rate*100, fails, evaluated)
	}
	var evidence []string
	for i, h := range hits {
		evidence = append(evidence, fmt.Sprintf("Example %d prompt: %s\nExample %d output: %s", i+1, redactHTTP(clipText(h.Prompt, 600)), i+1, redactHTTP(clipText(h.Output, 600))))
	}
	var owasp []string
	for _, t := range info.Tags {
		if strings.HasPrefix(t, "owasp:") || strings.HasPrefix(t, "avid-effect:") {
			owasp = append(owasp, t)
		}
	}
	f.Description = joinText(result, labelled("Goal", info.Goal), labelled("Probe", info.Description),
		labelled("Tags", strings.Join(owasp, ", ")), labelled("Reference", info.DocURI), strings.Join(evidence, "\n\n"))
	return importRecord{F: f, SnippetKey: hashOf(probe + "|" + det), Raw: sanitizeHTTPJSON(raw)}
}

func garakStr(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}
