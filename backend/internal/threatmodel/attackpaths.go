package threatmodel

import (
	"fmt"
	"slices"
	"strings"

	"pathos/internal/posture"
	"pathos/internal/threatmodel/frameworks"
)

// AttackPathRule turns an attack path of the application (internal/posture:
// internet → entry → … → finding) into a threat.
var AttackPathRule = Rule{ID: "TM-AP-001", Version: "1", Element: KindProcess, Severity: "from the finding", Confidence: 0.8,
	Title:      "Attack path from the internet to an open finding",
	Logic:      "Each attack path of the application (posture: a tested web application or API, an internet-facing repository or an observed internet-exposed workload leading to an open finding with risk ≥ 50) becomes one threat. Category from the finding (secrets: information disclosure; dependencies, images and infrastructure: elevation of privilege; code by CWE), severity from the finding, confidence 0.95 when actively exploited (KEV), 0.9 with a public exploit or when observed (dynamic testing or runtime), else 0.8.",
	Mitigation: "Fix or mitigate the finding at the end of the path (its remediation guidance is on the finding), or break the path: remove the exposure or add a compensating control in front of it.",
	Mappings:   rm("attack", "T1190")}

// cweCategory maps CWE ids to a STRIDE category for code findings.
var cweCategory = map[string]string{
	"CWE-79": Tampering, "CWE-89": Tampering, "CWE-77": Tampering, "CWE-78": Tampering, "CWE-94": ElevationOfPrivilege,
	"CWE-611": InformationDisclosure, "CWE-918": InformationDisclosure, "CWE-22": InformationDisclosure, "CWE-200": InformationDisclosure,
	"CWE-209": InformationDisclosure, "CWE-312": InformationDisclosure, "CWE-319": InformationDisclosure, "CWE-532": InformationDisclosure,
	"CWE-798": InformationDisclosure, "CWE-287": Spoofing, "CWE-306": Spoofing, "CWE-384": Spoofing, "CWE-352": Spoofing,
	"CWE-862": ElevationOfPrivilege, "CWE-863": ElevationOfPrivilege, "CWE-639": ElevationOfPrivilege, "CWE-269": ElevationOfPrivilege,
	"CWE-502": ElevationOfPrivilege, "CWE-400": DenialOfService, "CWE-770": DenialOfService, "CWE-1333": DenialOfService,
	"CWE-117": Repudiation, "CWE-778": Repudiation,
}

// NormalizeCWE turns "89", "cwe-89" or "CWE-89: SQL…" into "CWE-89".
func NormalizeCWE(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimPrefix(s, "CWE-")
	s = strings.TrimPrefix(s, "CWE")
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n == 0 {
		return ""
	}
	return "CWE-" + s[:n]
}

func attackPathCategory(a posture.AttackPath) string {
	switch a.Category {
	case "secrets":
		return InformationDisclosure
	case "sca", "image", "container", "iac":
		return ElevationOfPrivilege
	}
	for _, c := range a.CWE {
		if cat, ok := cweCategory[NormalizeCWE(c)]; ok {
			return cat
		}
	}
	if a.Category == "sca" {
		return ElevationOfPrivilege
	}
	return Tampering
}

// FromAttackPath converts one attack path into a threat. The element is
// the CodeGraph node the finding is located in when known (elementKey),
// else the repository.
func FromAttackPath(a posture.AttackPath, elementKey, elementLabel, elementType string) Threat {
	r := AttackPathRule
	sev := a.Severity
	if !slices.Contains(Severities, sev) {
		sev = "medium"
	}
	conf, creason := 0.8, "0.80 path through an internet-facing asset (inventory)"
	observed := a.Entry == "dast_target" || a.Entry == "runtime_exposure"
	switch {
	case a.KEV:
		conf, creason = 0.95, "0.95 actively exploited (CISA KEV)"
	case a.Exploit:
		conf, creason = 0.9, "0.90 a public exploit exists"
	case observed:
		conf, creason = 0.9, "0.90 the entry was observed (dynamic testing or runtime)"
	}
	ev := Evidence{Rule: &RuleRef{ID: r.ID, Version: r.Version, Logic: r.Logic}, RepositoryID: a.RepositoryID.String(),
		AttackPath: map[string]any{"entry": a.Entry, "steps": a.Steps, "reasons": a.Reasons, "risk": a.Risk, "kev": a.KEV,
			"exploit_available": a.Exploit, "finding_id": a.FindingID},
		Findings: []EvFinding{{ID: a.FindingID.String(), Title: a.Title, Severity: a.Severity, CWE: firstCWE(a.CWE)}},
		Links:    []Link{{Label: "Finding and its remediation", Href: "/findings?finding=" + a.FindingID.String()}, {Label: "Attack paths", Href: "/posture/attack-paths"}}}
	if a.CVE != "" {
		ev.Links = append(ev.Links, Link{Label: "Blast radius of " + a.CVE, Href: "/posture/blast-radius?cve=" + a.CVE})
	}
	if a.Entry == "runtime_exposure" {
		ev.Runtime = append(ev.Runtime, a.Reasons...)
	}
	if elementKey == "" {
		elementKey, elementLabel, elementType = "repository", "repository", "repository"
	}
	ev.Nodes = []EvNode{{Key: elementKey, Label: elementLabel, Type: elementType, File: a.FilePath, Line: a.Line}}
	loc := ""
	if a.FilePath != "" {
		loc = " in " + a.FilePath
	}
	t := Threat{RuleID: r.ID, RuleVersion: r.Version, Method: MethodAttackPath, Category: attackPathCategory(a),
		Subject:     "finding:" + a.FindingID.String(),
		Title:       "Attack path to " + clipTitle(a.Title),
		Description: fmt.Sprintf("An attacker on the internet can reach the open %s finding %q%s through %s. %s.", a.Severity, a.Title, loc, entryText(a.Entry), strings.Join(a.Reasons, "; ")),
		Severity:    sev, SeverityReason: "the finding's severity (" + a.Severity + ")",
		Confidence: conf, ConfidenceReason: creason, Evidence: ev, Mitigation: r.Mitigation,
		Elements:   []ElementRef{{Kind: KindProcess, Key: elementKey, Name: elementLabel, NodeType: elementType}},
		FindingIDs: []string{a.FindingID.String()}}
	if observed {
		t.EvidenceType = EvidenceObserved
	} else {
		t.EvidenceType = EvidenceVerified
	}
	t.Fingerprint = Fingerprint(r.ID, a.RepositoryID.String(), t.Subject)
	t.Mappings = append(t.Mappings, r.Mappings...)
	for _, c := range a.CWE {
		if id := NormalizeCWE(c); id != "" {
			t.Mappings = append(t.Mappings, Mapping{Framework: frameworks.CWE, ID: id, Source: "finding"})
			// CAPEC attack patterns that exploit the weakness (CAPEC data).
			for _, p := range firstN(frameworks.Related(frameworks.CAPEC, id, "CAPEC-"), 2) {
				t.Mappings = append(t.Mappings, Mapping{Framework: frameworks.CAPEC, ID: p, Source: "rule"})
			}
		}
	}
	return t
}

func firstCWE(c []string) string {
	for _, x := range c {
		if id := NormalizeCWE(x); id != "" {
			return id
		}
	}
	return ""
}

func entryText(e string) string {
	switch e {
	case "dast_target":
		return "the tested web application or API"
	case "runtime_exposure":
		return "an internet-exposed workload observed at run time"
	}
	return "the internet-facing application"
}

func clipTitle(s string) string {
	if len(s) <= 200 {
		return s
	}
	cut := s[:200]
	for len(cut) > 0 && cut[len(cut)-1]&0xC0 == 0x80 {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}
