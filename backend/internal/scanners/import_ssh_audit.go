package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ssh-audit JSON (`ssh-audit -j <host>`): target, banner (software),
// kex[], key[], enc[] and mac[] algorithms (algorithm, keysize, notes:
// fail[], warn[], info[]), cves[] (name, cvssv2, description) and
// recommendations. An algorithm with fail notes is a medium finding, one
// with only warn notes low; CVEs of the server software take the severity
// of their CVSS score. Findings are located at the target and use the
// crypto category.

type sshAuditAlg struct {
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"keysize"`
	Notes     struct {
		Fail []string `json:"fail"`
		Warn []string `json:"warn"`
	} `json:"notes"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "ssh-audit", Label: "ssh-audit JSON (-j)", Tool: "ssh-audit", Category: "crypto", Media: "json", Order: 711,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("banner", "kex", "target") && p.hasAny("enc", "mac", "key")
		},
		parse: parseSSHAudit})
}

func parseSSHAudit(raw []byte) ([]importRecord, error) {
	var doc struct {
		Target string `json:"target"`
		Banner struct {
			Software string `json:"software"`
			Raw      string `json:"raw"`
		} `json:"banner"`
		Kex  []sshAuditAlg `json:"kex"`
		Key  []sshAuditAlg `json:"key"`
		Enc  []sshAuditAlg `json:"enc"`
		Mac  []sshAuditAlg `json:"mac"`
		CVEs []struct {
			Name        string  `json:"name"`
			CVSS        float64 `json:"cvssv2"`
			Description string  `json:"description"`
		} `json:"cves"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("ssh-audit: invalid JSON: %w", err)
	}
	var out []importRecord
	kinds := []struct {
		name, label string
		algs        []sshAuditAlg
	}{{"kex", "key exchange", doc.Kex}, {"key", "host key", doc.Key}, {"enc", "cipher", doc.Enc}, {"mac", "MAC", doc.Mac}}
	for _, k := range kinds {
		for _, a := range k.algs {
			if len(a.Notes.Fail) == 0 && len(a.Notes.Warn) == 0 {
				continue
			}
			sev := "low"
			if len(a.Notes.Fail) > 0 {
				sev = "medium"
			}
			f := Finding{Category: "crypto", RuleID: "ssh-" + k.name + ": " + a.Algorithm, Title: fmt.Sprintf("Weak SSH %s algorithm %s", k.label, a.Algorithm),
				Severity: sev, FilePath: doc.Target,
				Description: joinText(fmt.Sprintf("The SSH server %s (%s) offers the %s algorithm %s.", doc.Target, doc.Banner.Software, k.label, a.Algorithm),
					labeled("Fail", strings.Join(a.Notes.Fail, "; ")), labeled("Warn", strings.Join(a.Notes.Warn, "; ")))}
			out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"target": doc.Target, k.name: a})})
		}
	}
	for _, c := range doc.CVEs {
		f := Finding{Category: "crypto", RuleID: c.Name, CVE: c.Name, Title: c.Name + " in " + doc.Banner.Software, CVSS: floatPtr(c.CVSS), FilePath: doc.Target,
			PackageName: doc.Banner.Software, Description: c.Description}
		if f.CVSS != nil {
			f.Severity = FromScore(*f.CVSS)
		}
		out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"target": doc.Target, "cve": c})})
	}
	return out, nil
}
