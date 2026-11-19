package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Wiz GraphQL API results: issues (issuesV2 or issues query) and
// vulnerability findings (vulnerabilityFindings query), as the full
// response ({"data": {"issuesV2": {"nodes": [...]}}}) or the nodes array.
// Issue nodes: id, status (OPEN, IN_PROGRESS, RESOLVED, REJECTED),
// severity, sourceRule (id, name, description, resolutionRecommendation)
// and entitySnapshot (the cloud resource: id, name, type, providerId,
// externalId, cloudPlatform, subscriptionExternalId). Vulnerability
// nodes: id, name (the CVE), vulnerabilityExternalId, detailedName (the
// package), version, fixedVersion, vendorSeverity or severity, score,
// description, remediation, status (OPEN, RESOLVED, IGNORED), locationPath
// and vulnerableAsset. Resolved nodes are not findings; rejected issues
// and ignored vulnerabilities are kept with low confidence. Issues are
// misconfiguration findings, vulnerabilities sca findings.

type wizNode struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Severity   string `json:"severity"`
	Type       string `json:"type"`
	CreatedAt  string `json:"createdAt"`
	SourceRule *struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		Description    string `json:"description"`
		ControlDesc    string `json:"controlDescription"`
		Recommendation string `json:"resolutionRecommendation"`
	} `json:"sourceRule"`
	Entity *struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		Type          string `json:"type"`
		NativeType    string `json:"nativeType"`
		ProviderID    string `json:"providerId"`
		ExternalID    string `json:"externalId"`
		CloudPlatform string `json:"cloudPlatform"`
		Subscription  string `json:"subscriptionExternalId"`
		Region        string `json:"region"`
	} `json:"entitySnapshot"`
	// Vulnerability findings.
	Name           string  `json:"name"`
	ExternalID     string  `json:"vulnerabilityExternalId"`
	DetailedName   string  `json:"detailedName"`
	Version        string  `json:"version"`
	FixedVersion   string  `json:"fixedVersion"`
	VendorSeverity string  `json:"vendorSeverity"`
	Score          float64 `json:"score"`
	Description    string  `json:"description"`
	CVEDescription string  `json:"CVEDescription"`
	Remediation    string  `json:"remediation"`
	LocationPath   string  `json:"locationPath"`
	PortalURL      string  `json:"portalUrl"`
	Asset          *struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Type       string `json:"type"`
		ProviderID string `json:"providerUniqueId"`
	} `json:"vulnerableAsset"`
}

func isWizNode(m map[string]json.RawMessage) bool {
	return hasKeys(m, "id", "sourceRule", "entitySnapshot") || hasKeys(m, "id", "vulnerableAsset", "detailedName")
}

func init() {
	registerImportFormat(ImportFormat{ID: "wiz", Label: "Wiz issues and vulnerability findings (GraphQL API JSON)", Tool: "Wiz", Media: "json", Order: 602,
		match: func(p *importProbe) bool {
			if p.kind == "array" {
				return isWizNode(p.keys)
			}
			return p.kind == "object" && p.has("data") && p.headHas(`"nodes"`) &&
				(p.headHas(`"issuesV2"`) || p.headHas(`"vulnerabilityFindings"`) || (p.headHas(`"issues"`) && p.headHas(`"entitySnapshot"`)))
		},
		parse: parseWiz})
}

func parseWiz(raw []byte) ([]importRecord, error) {
	nodes, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("wiz: invalid JSON: %w", err)
	}
	if nodes == nil {
		var doc struct {
			Data map[string]struct {
				Nodes []json.RawMessage `json:"nodes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("wiz: invalid JSON: %w", err)
		}
		for _, q := range []string{"issuesV2", "issues", "vulnerabilityFindings"} {
			nodes = append(nodes, doc.Data[q].Nodes...)
		}
	}
	var out []importRecord
	for i, nr := range nodes {
		var n wizNode
		if err := json.Unmarshal(nr, &n); err != nil || n.ID == "" {
			return out, fmt.Errorf("wiz: node %d: expected an object with id", i+1)
		}
		st := strings.ToUpper(n.Status)
		if st == "RESOLVED" {
			continue
		}
		var f Finding
		switch {
		case n.SourceRule != nil || n.Entity != nil:
			f = Finding{Category: "misconfiguration", Severity: n.Severity}
			if r := n.SourceRule; r != nil {
				f.RuleID, f.Title = firstNonEmpty(r.ID, n.Type), r.Name
				f.Description = joinText(firstNonEmpty(r.Description, r.ControlDesc), labeled("Recommendation", r.Recommendation))
			}
			if e := n.Entity; e != nil {
				f.FilePath = firstNonEmpty(e.ProviderID, e.ExternalID, e.ID)
				f.Description = joinText(f.Description, fmt.Sprintf("Resource: %s (%s %s, %s, subscription %s, %s)", e.Name, e.CloudPlatform,
					firstNonEmpty(e.NativeType, e.Type), e.Region, e.Subscription, f.FilePath))
			}
			f.RuleID = firstNonEmpty(f.RuleID, n.Type, "wiz-issue")
			f.Title = firstNonEmpty(f.Title, "Wiz issue "+n.ID)
		default:
			cve := firstNonEmpty(n.ExternalID, n.Name)
			f = Finding{Category: "sca", RuleID: cve, CVE: cve, Severity: firstNonEmpty(n.VendorSeverity, n.Severity), CVSS: floatPtr(n.Score),
				PackageName: n.DetailedName, PackageVersion: n.Version, FixedVersion: n.FixedVersion,
				Title:       strings.TrimSpace(fmt.Sprintf("%s in %s %s", cve, n.DetailedName, n.Version)),
				Description: joinText(firstNonEmpty(n.Description, n.CVEDescription), labeled("Remediation", n.Remediation), labeled("Location", n.LocationPath))}
			if a := n.Asset; a != nil {
				f.FilePath = firstNonEmpty(a.ProviderID, a.Name, a.ID)
				f.Description = joinText(f.Description, fmt.Sprintf("Asset: %s (%s)", a.Name, a.Type))
			}
		}
		f.Description = joinText(f.Description, labeled("Wiz", n.PortalURL), "Wiz status: "+firstNonEmpty(st, "OPEN"))
		if st == "REJECTED" || st == "IGNORED" {
			f.Confidence = "low"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(n.ID), Raw: nr})
	}
	return out, nil
}
