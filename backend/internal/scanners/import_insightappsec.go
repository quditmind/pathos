package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Rapid7 InsightAppSec vulnerabilities JSON: the API's vulnerability page
// (GET /ias/v1/vulnerabilities or POST /ias/v1/search with type
// VULNERABILITY: {"data": [...], "metadata": ...}) or a bare array of
// vulnerabilities. One finding per vulnerability: the location is the root
// cause URL, identity the attack, method and parameter. Request and
// response exchanges are kept redacted. Status FALSE_POSITIVE is kept with
// low confidence. Built from the published API schema
// (insightappsec-api-v1.json); not yet verified against a real export.

type iasExchange struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

type iasVuln struct {
	ID  string `json:"id"`
	App struct {
		ID string `json:"id"`
	} `json:"app"`
	RootCause struct {
		URL       string `json:"url"`
		Parameter string `json:"parameter"`
		Method    string `json:"method"`
	} `json:"root_cause"`
	Severity        string      `json:"severity"`
	Status          string      `json:"status"`
	FirstDiscovered string      `json:"first_discovered"`
	LastDiscovered  string      `json:"last_discovered"`
	VectorString    string      `json:"vector_string"`
	Score           json.Number `json:"vulnerability_score"`
	InsightUIURL    string      `json:"insight_ui_url"`
	Variances       []struct {
		ID               string       `json:"id"`
		OriginalValue    string       `json:"original_value"`
		OriginalExchange *iasExchange `json:"original_exchange"`
		Module           struct {
			ID string `json:"id"`
		} `json:"module"`
		Attack struct {
			ID string `json:"id"`
		} `json:"attack"`
		AttackValue      string        `json:"attack_value"`
		Message          string        `json:"message"`
		Proof            string        `json:"proof"`
		ProofDescription string        `json:"proof_description"`
		AttackExchanges  []iasExchange `json:"attack_exchanges"`
	} `json:"variances"`
}

// iasRecord is the record kept as a finding's original output.
type iasRecord struct {
	ID           string   `json:"id"`
	AppID        string   `json:"app_id,omitempty"`
	URL          string   `json:"url"`
	Parameter    string   `json:"parameter,omitempty"`
	Method       string   `json:"method,omitempty"`
	Severity     string   `json:"severity"`
	Status       string   `json:"status,omitempty"`
	VectorString string   `json:"vector_string,omitempty"`
	Score        string   `json:"vulnerability_score,omitempty"`
	Attack       string   `json:"attack,omitempty"`
	Module       string   `json:"module,omitempty"`
	AttackValue  string   `json:"attack_value,omitempty"`
	Message      string   `json:"message,omitempty"`
	Proof        string   `json:"proof,omitempty"`
	Requests     []string `json:"requests,omitempty"`
	Responses    []string `json:"responses,omitempty"`
	InsightURL   string   `json:"insight_ui_url,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "insightappsec", Label: "Rapid7 InsightAppSec vulnerabilities JSON", Tool: "InsightAppSec", Category: "dast", Media: "json", Order: 404,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return p.has("data") && hasKeys(p.firstOf("data"), "root_cause", "variances", "severity")
			case "array":
				return p.has("root_cause", "variances", "severity")
			}
			return false
		},
		parse:    parseInsightAppSec,
		sanitize: sanitizeHTTPJSON})
}

func parseInsightAppSec(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "data")
	if err != nil {
		return nil, fmt.Errorf("insightappsec: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v iasVuln
		if err := json.Unmarshal(it, &v); err != nil || (v.ID == "" && v.RootCause.URL == "") {
			return out, fmt.Errorf("insightappsec: vulnerability %d: expected an object with id and root_cause", i+1)
		}
		attack, module, msg, proof := "", "", "", ""
		var reqs, resps []string
		for _, va := range v.Variances {
			attack, module = firstNonEmpty(attack, va.Attack.ID), firstNonEmpty(module, va.Module.ID)
			msg, proof = firstNonEmpty(msg, va.Message, va.ProofDescription), firstNonEmpty(proof, va.Proof)
			ex := va.AttackExchanges
			if va.OriginalExchange != nil {
				ex = append([]iasExchange{*va.OriginalExchange}, ex...)
			}
			for _, e := range ex {
				if e.Request != "" {
					reqs = append(reqs, redactHTTP(e.Request))
				}
				if e.Response != "" {
					resps = append(resps, clipText(redactHTTP(e.Response), 4000))
				}
			}
		}
		rule := firstNonEmpty(attack, module, "insightappsec")
		title := firstNonEmpty(msg, "InsightAppSec attack "+rule)
		if len(title) > 200 {
			title = "InsightAppSec attack " + rule
		}
		rc := v.RootCause
		f := Finding{Category: "dast", RuleID: rule, Title: title, FilePath: locationOf("", redactHTTP(firstNonEmpty(rc.URL, v.App.ID))),
			Severity: firstNonEmpty(map[string]string{"SAFE": "info", "INFORMATIONAL": "info"}[strings.ToUpper(v.Severity)], normSeverity(v.Severity), "info"),
			CWE:      []string{}}
		if strings.HasPrefix(v.VectorString, "CVSS:") || strings.HasPrefix(v.VectorString, "AV:") {
			f.CVSSVector = v.VectorString
		}
		if s, err := v.Score.Float64(); err == nil {
			f.CVSS = floatPtr(s)
		}
		note := ""
		switch strings.ToUpper(v.Status) {
		case "FALSE_POSITIVE":
			f.Confidence, note = "low", "InsightAppSec marked this vulnerability as a false positive; it is kept for review."
		case "VERIFIED":
			f.Confidence = "high"
		case "IGNORED", "REMEDIATED", "DUPLICATE":
			note = "InsightAppSec status: " + v.Status + "."
		}
		f.Description = joinText(note, msg, whereText(rc.Method, rc.URL, rc.Parameter), labelled("Proof", clipText(redactHTTP(proof), 1000)),
			labelled("InsightAppSec", v.InsightUIURL))
		rec := iasRecord{ID: v.ID, AppID: v.App.ID, URL: redactHTTP(rc.URL), Parameter: rc.Parameter, Method: rc.Method, Severity: v.Severity,
			Status: v.Status, VectorString: v.VectorString, Score: v.Score.String(), Attack: attack, Module: module, Message: msg,
			Proof: clipText(redactHTTP(proof), maxEvidenceText), Requests: reqs, Responses: resps, InsightURL: v.InsightUIURL}
		if len(v.Variances) > 0 {
			rec.AttackValue = redactHTTP(v.Variances[0].AttackValue)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(rc.Method) + "|" + rc.Parameter), Raw: rawJSON(rec)})
	}
	return out, nil
}
