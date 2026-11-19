package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"pathos/internal/platform/logging"
)

// Falco JSON alerts (json_output: true; one alert per line, as written to
// stdout, a file output or a program output; an array is accepted too).
// Every alert is a rule match. Alerts of the same rule, workload and
// process command line are one finding (the count and first and last time
// are in the description); the location is the Kubernetes pod
// ("namespace/pod"), else the container, else the host. Priorities:
// Emergency, Alert, Critical -> critical; Error -> high; Warning ->
// medium; Notice -> low; Informational, Debug -> info. Command lines and
// environment variables can carry credentials: environment fields are
// removed and credential-like arguments redacted before the report is
// stored.

type falcoAlert struct {
	Rule         string         `json:"rule"`
	Priority     string         `json:"priority"`
	Output       string         `json:"output"`
	Source       string         `json:"source"`
	Tags         []string       `json:"tags"`
	Time         string         `json:"time"`
	Hostname     string         `json:"hostname"`
	OutputFields map[string]any `json:"output_fields"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "falco", Label: "Falco JSON alerts", Tool: "Falco", Category: "other", Media: "jsonl", Order: 339,
		match: func(p *importProbe) bool {
			return (p.kind == "jsonl" || p.kind == "object" || p.kind == "array") && p.has("rule", "priority", "output") && p.hasAny("output_fields", "time")
		},
		parse:    parseFalco,
		sanitize: func(raw []byte) []byte { return runtimeSanitize(raw, "proc.env", "proc.aenv") }})
}

// --- runtime evidence redaction (Falco, Tetragon, Tracee) -----------------

// runtimeSecretArgRe matches credential-like command-line options and
// environment assignments: --password x, --token=x, -pSECRET (mysql),
// PASSWORD=x, AWS_SECRET_ACCESS_KEY=x.
var runtimeSecretArgRe = regexp.MustCompile(`(?i)((?:--?(?:password|passwd|pass|token|secret|api[-_]?key|access[-_]?key|client[-_]?secret|auth)(?:[= ]|\s+))|(?:\b[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*=))("[^"]*"|'[^']*'|[^\s"',}]+)`)

// runtimeMySQLPassRe matches mysql-style "-pSECRET".
var runtimeMySQLPassRe = regexp.MustCompile(`(\s-p)([^\s"',}]{3,})`)

// runtimeRedact redacts credentials in a runtime event string (command
// lines, process arguments, alert output).
func runtimeRedact(s string) string {
	s = runtimeSecretArgRe.ReplaceAllString(s, "${1}"+logging.Redacted)
	if strings.Contains(s, "mysql") || strings.Contains(s, "mariadb") {
		s = runtimeMySQLPassRe.ReplaceAllString(s, "${1}"+logging.Redacted)
	}
	return redactHTTP(s)
}

func runtimeRedactIn(x any, drop []string) any {
	switch t := x.(type) {
	case string:
		return runtimeRedact(t)
	case []any:
		for i := range t {
			t[i] = runtimeRedactIn(t[i], drop)
		}
	case map[string]any:
		for k, v := range t {
			if slices.ContainsFunc(drop, func(d string) bool { return strings.EqualFold(d, k) }) || isSensitiveHeader(k) {
				if v != nil && v != "" {
					t[k] = logging.Redacted
				}
				continue
			}
			t[k] = runtimeRedactIn(v, drop)
		}
	}
	return x
}

// runtimeSanitize redacts a JSON, JSON array or JSON Lines runtime report;
// keys named in drop (environment variables) lose their values.
func runtimeSanitize(raw []byte, drop ...string) []byte {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	var x any
	if json.Unmarshal(b, &x) == nil {
		if out, err := json.Marshal(runtimeRedactIn(x, drop)); err == nil {
			return out
		}
		return raw
	}
	var out bytes.Buffer
	err := jsonLines(b, func(_ int, line []byte) error {
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			return err
		}
		enc, err := json.Marshal(runtimeRedactIn(v, drop))
		if err != nil {
			return err
		}
		out.Write(enc)
		out.WriteByte('\n')
		return nil
	})
	if err != nil {
		return sanitizeHTTPText([]byte(runtimeRedact(string(raw))))
	}
	return out.Bytes()
}

// runtimeDocs returns the JSON objects of an array, a single object or
// JSON Lines.
func runtimeDocs(raw []byte, tool string) ([]json.RawMessage, error) {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(b) > 0 && b[0] == '[' {
		var docs []json.RawMessage
		if err := json.Unmarshal(b, &docs); err != nil {
			return nil, fmt.Errorf("%s: invalid JSON: %w", tool, err)
		}
		return docs, nil
	}
	var docs []json.RawMessage
	err := jsonLines(b, func(n int, line []byte) error {
		if !json.Valid(line) || line[0] != '{' {
			return fmt.Errorf("%s: line %d: invalid JSON", tool, n)
		}
		docs = append(docs, append(json.RawMessage(nil), line...))
		return nil
	})
	return docs, err
}

// runtimeAgg merges repeated runtime events of one identity into a finding.
type runtimeAgg struct {
	out   []importRecord
	index map[string]int
	count []int
	first []string
	last  []string
}

func (a *runtimeAgg) add(id, at string, r importRecord) {
	if a.index == nil {
		a.index = map[string]int{}
	}
	if i, ok := a.index[id]; ok {
		a.count[i]++
		if at != "" {
			a.last[i] = at
		}
		return
	}
	a.index[id] = len(a.out)
	r.SnippetKey = hashOf(id)
	a.out = append(a.out, r)
	a.count = append(a.count, 1)
	a.first = append(a.first, at)
	a.last = append(a.last, at)
}

func (a *runtimeAgg) records() []importRecord {
	for i := range a.out {
		if a.count[i] > 1 {
			a.out[i].F.Description = joinText(a.out[i].F.Description,
				fmt.Sprintf("Seen %d times between %s and %s; the original output is the first event.", a.count[i], a.first[i], a.last[i]))
		} else if a.first[i] != "" {
			a.out[i].F.Description = joinText(a.out[i].F.Description, "Time: "+a.first[i])
		}
	}
	return a.out
}

// --- Falco ------------------------------------------------------------------

func falcoField(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case nil:
		return ""
	case float64:
		return fmt.Sprint(v)
	}
	return ""
}

func parseFalco(raw []byte) ([]importRecord, error) {
	docs, err := runtimeDocs(raw, "falco")
	if err != nil {
		return nil, err
	}
	var agg runtimeAgg
	for i, d := range docs {
		var a falcoAlert
		if err := json.Unmarshal(d, &a); err != nil || a.Rule == "" {
			return agg.records(), fmt.Errorf("falco: alert %d: expected an object with rule", i+1)
		}
		of := a.OutputFields
		ns, pod := falcoField(of, "k8s.ns.name"), falcoField(of, "k8s.pod.name")
		cname, cid := falcoField(of, "container.name"), falcoField(of, "container.id")
		loc := ""
		switch {
		case pod != "":
			loc = strings.Trim(ns+"/"+pod, "/")
			if cname != "" {
				loc += " (" + cname + ")"
			}
		case cid != "" && cid != "host":
			loc = "container " + firstNonEmpty(cname, cid)
		default:
			loc = "host " + firstNonEmpty(a.Hostname, falcoField(of, "hostname"), "unknown")
		}
		sev := ""
		switch strings.ToLower(strings.TrimSpace(a.Priority)) {
		case "emergency", "alert", "critical":
			sev = "critical"
		case "error":
			sev = "high"
		case "warning":
			sev = "medium"
		case "notice":
			sev = "low"
		default:
			sev = "info"
		}
		cmd := runtimeRedact(falcoField(of, "proc.cmdline"))
		image := strings.Trim(falcoField(of, "container.image.repository")+":"+falcoField(of, "container.image.tag"), ":")
		f := Finding{Category: "other", RuleID: a.Rule, Title: a.Rule, Severity: sev, FilePath: loc, Confidence: "high",
			Description: joinText(runtimeRedact(a.Output), labelled("Process", cmd), labelled("User", falcoField(of, "user.name")),
				labelled("Image", image), labelled("Host", a.Hostname), labelled("Tags", strings.Join(a.Tags, ", ")), labelled("Source", a.Source))}
		for _, t := range a.Tags {
			if strings.HasPrefix(t, "T") && len(t) > 1 && strings.Trim(t[1:], "0123456789.") == "" {
				f.Description = joinText(f.Description, "MITRE ATT&CK: "+t)
			}
		}
		var x any
		_ = json.Unmarshal(d, &x)
		r := importRecord{F: f, Raw: rawJSON(runtimeRedactIn(x, []string{"proc.env", "proc.aenv"}))}
		agg.add(a.Rule+"|"+loc+"|"+cmd, a.Time, r)
	}
	return agg.records(), nil
}
