package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Tetragon JSON events (the export file, `tetra getevents -o json`, or
// `kubectl logs ... export-stdout`): one event per line, keyed by its type
// with node_name and time beside it. Only policy events are findings:
// process_kprobe, process_tracepoint, process_uprobe, process_usdt and process_lsm, which
// Tetragon emits when a TracingPolicy matches (they name the policy).
// process_exec and process_exit are emitted for every process as an audit
// trail, not as detections, and are not imported (the raw report is still
// stored). Tetragon has no severity: events whose policy enforced an action
// (Sigkill, Signal, Override, NotifyEnforcer) are high, other policy matches
// medium. Events of the same policy, function, workload and binary are one
// finding.

var tetragonPolicyEvents = []string{"process_kprobe", "process_tracepoint", "process_uprobe", "process_lsm", "process_usdt"}

var tetragonEventKeys = append([]string{"process_exec", "process_exit", "process_loader", "process_throttle", "rate_limit_info"}, tetragonPolicyEvents...)

type tetragonProcess struct {
	Binary    string `json:"binary"`
	Arguments string `json:"arguments"`
	UID       int    `json:"uid"`
	Pod       *struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Container *struct {
			Name  string `json:"name"`
			Image *struct {
				Name string `json:"name"`
			} `json:"image"`
		} `json:"container"`
	} `json:"pod"`
}

type tetragonPolicyEvent struct {
	Process      tetragonProcess   `json:"process"`
	Parent       *tetragonProcess  `json:"parent"`
	FunctionName string            `json:"function_name"`
	Subsys       string            `json:"subsys"`
	Event        string            `json:"event"`
	Args         []json.RawMessage `json:"args"`
	Action       string            `json:"action"`
	PolicyName   string            `json:"policy_name"`
	Message      string            `json:"message"`
	Tags         []string          `json:"tags"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "tetragon", Label: "Tetragon JSON events", Tool: "Tetragon", Category: "other", Media: "jsonl", Order: 340,
		match: func(p *importProbe) bool {
			if (p.kind != "jsonl" && p.kind != "object" && p.kind != "array") || !p.has("node_name", "time") {
				return false
			}
			return p.hasAny(tetragonEventKeys...)
		},
		parse:    parseTetragon,
		sanitize: func(raw []byte) []byte { return runtimeSanitize(raw) }})
}

func parseTetragon(raw []byte) ([]importRecord, error) {
	docs, err := runtimeDocs(raw, "tetragon")
	if err != nil {
		return nil, err
	}
	var agg runtimeAgg
	for i, d := range docs {
		var ev map[string]json.RawMessage
		if err := json.Unmarshal(d, &ev); err != nil {
			return agg.records(), fmt.Errorf("tetragon: event %d: expected an object", i+1)
		}
		kind := ""
		for _, k := range tetragonPolicyEvents {
			if ev[k] != nil {
				kind = k
			}
		}
		if kind == "" {
			continue // exec/exit audit events and other non-policy events
		}
		var p tetragonPolicyEvent
		if err := json.Unmarshal(ev[kind], &p); err != nil {
			return agg.records(), fmt.Errorf("tetragon: event %d: %w", i+1, err)
		}
		var node, at string
		_ = json.Unmarshal(ev["node_name"], &node)
		_ = json.Unmarshal(ev["time"], &at)
		hook := firstNonEmpty(p.FunctionName, strings.Trim(p.Subsys+"/"+p.Event, "/"), kind)
		policy := firstNonEmpty(p.PolicyName, "(no policy)")
		loc := "node " + firstNonEmpty(node, "unknown")
		image := ""
		if pod := p.Process.Pod; pod != nil {
			loc = strings.Trim(pod.Namespace+"/"+pod.Name, "/")
			if c := pod.Container; c != nil {
				if c.Name != "" {
					loc += " (" + c.Name + ")"
				}
				if c.Image != nil {
					image = c.Image.Name
				}
			}
		}
		sev := "medium"
		action := strings.ToUpper(p.Action)
		if slices.ContainsFunc([]string{"SIGKILL", "SIGNAL", "OVERRIDE", "NOTIFYENFORCER"}, func(a string) bool { return strings.Contains(action, a) }) {
			sev = "high"
		}
		args := make([]string, 0, len(p.Args))
		for _, a := range p.Args {
			args = append(args, clipText(runtimeRedact(string(a)), 500))
		}
		proc := strings.TrimSpace(p.Process.Binary + " " + runtimeRedact(p.Process.Arguments))
		title := firstNonEmpty(p.Message, fmt.Sprintf("%s: %s by %s", policy, hook, firstNonEmpty(p.Process.Binary, "a process")))
		f := Finding{Category: "other", RuleID: policy + "/" + hook, Title: title, Severity: sev, FilePath: loc, Confidence: "high",
			Description: joinText(fmt.Sprintf("Tetragon policy %s matched %s (%s).", policy, hook, kind), labelled("Process", proc),
				labelled("UID", fmt.Sprint(p.Process.UID)), labelled("Arguments", strings.Join(args, "\n")), labelled("Action", p.Action),
				labelled("Image", image), labelled("Node", node), labelled("Tags", strings.Join(p.Tags, ", ")))}
		var x any
		_ = json.Unmarshal(d, &x)
		agg.add(policy+"|"+hook+"|"+loc+"|"+p.Process.Binary, at, importRecord{F: f, Raw: rawJSON(runtimeRedactIn(x, nil))})
	}
	return agg.records(), nil
}
