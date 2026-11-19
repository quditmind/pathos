package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Tracee JSON events (`tracee --output json`): one event per line. Only
// detections are findings: events produced by a signature, which carry
// metadata.Properties.signatureID (or signatureName); plain system-call and
// kernel events are telemetry and are not imported (the raw report is
// still stored). Severity is the signature's 0-3 scale: 0 info, 1 low,
// 2 medium, 3 high, 4 and above critical. MITRE ATT&CK technique ids are
// kept. Events of the same signature, workload and process are one
// finding; the location is the Kubernetes pod, else the container, else
// the host.

type traceeEvent struct {
	Timestamp   json.Number `json:"timestamp"`
	ProcessName string      `json:"processName"`
	HostName    string      `json:"hostName"`
	ContainerID string      `json:"containerId"`
	Container   *struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Image string `json:"image"`
	} `json:"container"`
	Kubernetes *struct {
		PodName      string `json:"podName"`
		PodNamespace string `json:"podNamespace"`
	} `json:"kubernetes"`
	EventName string `json:"eventName"`
	Metadata  *struct {
		Description string         `json:"Description"`
		Properties  map[string]any `json:"Properties"`
	} `json:"metadata"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "tracee", Label: "Tracee JSON events (detections)", Tool: "Tracee", Category: "other", Media: "jsonl", Order: 341,
		match: func(p *importProbe) bool {
			return (p.kind == "jsonl" || p.kind == "object" || p.kind == "array") && p.has("eventName") &&
				p.hasAny("processName", "eventId", "matchedPolicies") && p.hasAny("metadata", "args")
		},
		parse:    parseTracee,
		sanitize: func(raw []byte) []byte { return runtimeSanitize(raw) }})
}

func traceeProp(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprint(v)
	}
	return ""
}

func parseTracee(raw []byte) ([]importRecord, error) {
	docs, err := runtimeDocs(raw, "tracee")
	if err != nil {
		return nil, err
	}
	var agg runtimeAgg
	for i, d := range docs {
		var e traceeEvent
		if err := json.Unmarshal(d, &e); err != nil {
			return agg.records(), fmt.Errorf("tracee: event %d: %w", i+1, err)
		}
		if e.Metadata == nil {
			continue
		}
		props := e.Metadata.Properties
		sigID, sigName := traceeProp(props, "signatureID"), traceeProp(props, "signatureName")
		if sigID == "" && sigName == "" {
			continue // telemetry events are not detections
		}
		sev := "medium"
		if s, ok := props["Severity"].(float64); ok {
			switch {
			case s >= 4:
				sev = "critical"
			case s >= 3:
				sev = "high"
			case s >= 2:
				sev = "medium"
			case s >= 1:
				sev = "low"
			default:
				sev = "info"
			}
		}
		loc := "host " + firstNonEmpty(e.HostName, "unknown")
		image := ""
		if c := e.Container; c != nil {
			image = c.Image
		}
		switch {
		case e.Kubernetes != nil && e.Kubernetes.PodName != "":
			loc = strings.Trim(e.Kubernetes.PodNamespace+"/"+e.Kubernetes.PodName, "/")
		case e.Container != nil && (e.Container.Name != "" || e.Container.ID != ""):
			loc = "container " + firstNonEmpty(e.Container.Name, e.Container.ID)
		case e.ContainerID != "":
			loc = "container " + e.ContainerID
		}
		technique := strings.TrimSpace(traceeProp(props, "Technique") + " " + traceeProp(props, "external_id"))
		f := Finding{Category: "other", RuleID: firstNonEmpty(sigID, sigName), Title: firstNonEmpty(sigName, e.EventName, sigID), Severity: sev,
			FilePath: loc, Confidence: "high",
			Description: joinText(e.Metadata.Description, labelled("Process", e.ProcessName), labelled("Event", e.EventName),
				labelled("Category", traceeProp(props, "Category")), labelled("MITRE ATT&CK", technique), labelled("Image", image),
				labelled("Host", e.HostName))}
		var x any
		_ = json.Unmarshal(d, &x)
		agg.add(f.RuleID+"|"+loc+"|"+e.ProcessName, e.Timestamp.String(), importRecord{F: f, Raw: rawJSON(runtimeRedactIn(x, nil))})
	}
	return agg.records(), nil
}
