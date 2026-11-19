package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// KubeLinter JSON (`kube-linter lint --format json`): Checks[] (the checks
// that ran, with description and remediation), Reports[] (Check,
// Diagnostic.Message, Remediation, Object.Metadata.FilePath and the
// Kubernetes object) and Summary. KubeLinter has no severity and no line
// numbers: checks that grant host or root access are high, all others
// medium.

type kubeLinterReport struct {
	Diagnostic struct {
		Message string `json:"Message"`
	} `json:"Diagnostic"`
	Check       string `json:"Check"`
	Remediation string `json:"Remediation"`
	Object      struct {
		Metadata struct {
			FilePath string `json:"FilePath"`
		} `json:"Metadata"`
		K8sObject struct {
			Namespace        string `json:"Namespace"`
			Name             string `json:"Name"`
			GroupVersionKind struct {
				Kind string `json:"Kind"`
			} `json:"GroupVersionKind"`
		} `json:"K8sObject"`
	} `json:"Object"`
}

// kubeLinterHigh are the checks whose failure gives a container host or
// root-level access.
var kubeLinterHigh = map[string]bool{
	"privileged-container": true, "privilege-escalation-container": true, "docker-sock": true, "host-ipc": true,
	"host-network": true, "host-pid": true, "sensitive-host-mounts": true, "unsafe-sysctls": true,
	"access-to-secrets": true, "cluster-admin-role-binding": true, "access-to-create-pods": true, "writable-host-mount": true,
}

func init() {
	registerImportFormat(ImportFormat{ID: "kube-linter", Label: "KubeLinter JSON", Tool: "KubeLinter", Category: "iac", Media: "json", Order: 263,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("Checks", "Reports", "Summary")
		},
		parse: parseKubeLinter})
}

func parseKubeLinter(raw []byte) ([]importRecord, error) {
	var doc struct {
		Checks []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"Checks"`
		Reports []json.RawMessage `json:"Reports"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("kube-linter: invalid JSON: %w", err)
	}
	descs := map[string]string{}
	for _, c := range doc.Checks {
		descs[c.Name] = c.Description
	}
	var out []importRecord
	for i, it := range doc.Reports {
		var r kubeLinterReport
		if err := json.Unmarshal(it, &r); err != nil || r.Check == "" {
			return out, fmt.Errorf("kube-linter: report %d: expected an object with Check", i+1)
		}
		obj := r.Object.K8sObject
		ref := strings.Trim(obj.Namespace+"/"+obj.GroupVersionKind.Kind+"/"+obj.Name, "/")
		f := Finding{Category: "iac", RuleID: r.Check, Title: fmt.Sprintf("%s (%s)", firstNonEmpty(descs[r.Check], r.Check), ref),
			Severity: "medium", FilePath: NormalizePath(r.Object.Metadata.FilePath),
			Description: joinText(r.Diagnostic.Message, "Object: "+ref, "Remediation: "+r.Remediation)}
		if kubeLinterHigh[r.Check] {
			f.Severity = "high"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(ref + "|" + r.Diagnostic.Message), Raw: it})
	}
	return out, nil
}
