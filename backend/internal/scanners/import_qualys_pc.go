package scanners

import (
	"fmt"
	"strings"
)

// Qualys Policy Compliance posture information XML (API
// /api/2.0/fo/compliance/posture/info/?action=list):
// POSTURE_INFO_LIST_OUTPUT/RESPONSE with INFO_LIST/INFO (ID, HOST_ID,
// CONTROL_ID, TECHNOLOGY_ID, INSTANCE, STATUS Passed/Failed/Error,
// optional REMEDIATION) and a GLOSSARY of controls (ID, STATEMENT,
// CRITICALITY LABEL/VALUE), hosts (ID, IP, DNS, NETBIOS) and technologies.
// Failed postures are findings; Error postures (the control could not be
// evaluated) are kept with low confidence; Passed postures are not
// findings. Criticality 5 (URGENT) is critical, 4 high, 3 medium, 2 low,
// 1 info. A finding is located on its host.

type qualysPCDoc struct {
	Response struct {
		Info []struct {
			ID           string `xml:"ID"`
			HostID       string `xml:"HOST_ID"`
			ControlID    string `xml:"CONTROL_ID"`
			TechnologyID string `xml:"TECHNOLOGY_ID"`
			Instance     string `xml:"INSTANCE"`
			Status       string `xml:"STATUS"`
			Remediation  string `xml:"REMEDIATION"`
			Evaluated    string `xml:"EVALUATION_DATE"`
			FirstFail    string `xml:"FIRST_FAIL_DATE"`
		} `xml:"INFO_LIST>INFO"`
		Controls []struct {
			ID          string `xml:"ID"`
			Statement   string `xml:"STATEMENT"`
			Criticality struct {
				Label string `xml:"LABEL"`
				Value int    `xml:"VALUE"`
			} `xml:"CRITICALITY"`
			Rationales  []string `xml:"RATIONALE_LIST>RATIONALE>TEXT"`
			Remediation string   `xml:"REMEDIATION"`
		} `xml:"GLOSSARY>CONTROL_LIST>CONTROL"`
		Hosts []struct {
			ID  string `xml:"ID"`
			IP  string `xml:"IP"`
			DNS string `xml:"DNS"`
			OS  string `xml:"OPERATING_SYSTEM"`
		} `xml:"GLOSSARY>HOST_LIST>HOST"`
		Technologies []struct {
			ID   string `xml:"ID"`
			Name string `xml:"NAME"`
		} `xml:"GLOSSARY>TECHNOLOGY_LIST>TECHNOLOGY"`
	} `xml:"RESPONSE"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "qualys-pc", Label: "Qualys Policy Compliance posture XML", Tool: "Qualys PC", Category: "compliance", Media: "xml", Order: 566,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "POSTURE_INFO_LIST_OUTPUT" },
		parse: parseQualysPC})
}

func parseQualysPC(raw []byte) ([]importRecord, error) {
	var doc qualysPCDoc
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("qualys pc: %w", err)
	}
	r := doc.Response
	controls := map[string]int{}
	for i, c := range r.Controls {
		controls[c.ID] = i
	}
	hosts := map[string]string{}
	for _, h := range r.Hosts {
		hosts[h.ID] = firstNonEmpty(h.DNS, h.IP)
	}
	techs := map[string]string{}
	for _, t := range r.Technologies {
		techs[t.ID] = t.Name
	}
	var out []importRecord
	for i, in := range r.Info {
		if in.ControlID == "" {
			return out, fmt.Errorf("qualys pc: INFO %d: expected CONTROL_ID", i+1)
		}
		st := strings.ToLower(strings.TrimSpace(in.Status))
		if st != "failed" && st != "error" {
			continue
		}
		f := Finding{Category: "compliance", RuleID: "QPC-" + in.ControlID, Title: "Qualys control " + in.ControlID + " failed", Severity: "medium",
			FilePath: firstNonEmpty(hosts[in.HostID], "host "+in.HostID)}
		var crit, rationale, remediation string
		if ci, ok := controls[in.ControlID]; ok {
			c := r.Controls[ci]
			f.Title = firstNonEmpty(strings.TrimSpace(c.Statement), f.Title)
			if sev := map[int]string{5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}[c.Criticality.Value]; sev != "" {
				f.Severity = sev
			}
			crit = strings.TrimSpace(fmt.Sprintf("%s (%d)", c.Criticality.Label, c.Criticality.Value))
			rationale, remediation = strings.Join(c.Rationales, "\n"), c.Remediation
		}
		f.Description = joinText(fmt.Sprintf("Control %s on %s (%s, instance %s): %s.", in.ControlID, f.FilePath, techs[in.TechnologyID], in.Instance, in.Status),
			labeled("Criticality", crit), labeled("Rationale", rationale), labeled("Remediation", firstNonEmpty(in.Remediation, remediation)),
			labeled("Evaluated", in.Evaluated), labeled("First failed", in.FirstFail))
		if st == "error" {
			f.Severity, f.Confidence = "low", "low"
			f.Description = joinText(f.Description, "The control could not be evaluated (Error); it needs a manual review.")
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(in.TechnologyID + "|" + in.Instance), Raw: rawJSON(in)})
	}
	return out, nil
}
