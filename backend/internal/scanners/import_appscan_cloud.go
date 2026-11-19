package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// HCL AppScan on Cloud (ASoC) issues JSON (API v4 GET
// /api/v4/Issues/{scope}/{id}): {"Items": [...], "Count"} with Id,
// IssueType, Severity (Critical, High, Medium, Low, Informational),
// Status (New, Open, InProgress, Reopened, Noise, Passed, Fixed),
// DiscoveryMethod or Scanner (SAST, DAST, IAST, SCA), Cwe, Cve, Cvss,
// CvssVector, the code location (SourceFile, Line, Api, Location), the URL
// (Scheme, Host, Port, Path, Element) and the library (LibraryName,
// LibraryVersion, Package). Fixed and Passed issues are not findings;
// Noise issues are kept with low confidence. The list has no description
// (it is in the issue details).

type asocIssue struct {
	ID         string      `json:"Id"`
	IssueType  string      `json:"IssueType"`
	Severity   string      `json:"Severity"`
	Status     string      `json:"Status"`
	Discovery  string      `json:"DiscoveryMethod"`
	Scanner    string      `json:"Scanner"`
	CWE        looseString `json:"Cwe"`
	CVE        string      `json:"Cve"`
	CVSS       looseString `json:"Cvss"`
	CVSSVector string      `json:"CvssVector"`
	SourceFile string      `json:"SourceFile"`
	Line       looseString `json:"Line"`
	API        string      `json:"Api"`
	Location   string      `json:"Location"`
	Scheme     string      `json:"Scheme"`
	Host       string      `json:"Host"`
	Port       looseString `json:"Port"`
	Path       string      `json:"Path"`
	Element    string      `json:"Element"`
	Library    string      `json:"LibraryName"`
	LibVersion string      `json:"LibraryVersion"`
	Package    string      `json:"Package"`
	Latest     string      `json:"LatestReleaseVersion"`
	ScanName   string      `json:"ScanName"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "appscan-cloud", Label: "HCL AppScan on Cloud issues JSON (API v4)", Tool: "AppScan on Cloud", Media: "json", Order: 618,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("Items"), "Id", "IssueType", "Severity", "Status")
		},
		parse: parseAppScanCloud})
}

func parseAppScanCloud(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "Items")
	if err != nil {
		return nil, fmt.Errorf("appscan on cloud: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var s asocIssue
		if err := json.Unmarshal(it, &s); err != nil || s.ID == "" {
			return out, fmt.Errorf("appscan on cloud: item %d: expected Id", i+1)
		}
		st := strings.ToLower(s.Status)
		if st == "fixed" || st == "passed" {
			continue
		}
		f := Finding{RuleID: s.IssueType, Title: s.IssueType, Severity: s.Severity, CWE: []string{string(s.CWE)}, CVE: s.CVE, CVSS: cvssOf(string(s.CVSS)),
			CVSSVector: s.CVSSVector}
		switch strings.ToUpper(firstNonEmpty(s.Discovery, s.Scanner)) {
		case "DAST", "IAST":
			f.Category = "dast"
			if strings.EqualFold(firstNonEmpty(s.Discovery, s.Scanner), "IAST") {
				f.Category = "iast"
			}
			u := s.Location
			if s.Host != "" {
				u = strings.ToLower(firstNonEmpty(s.Scheme, "https")) + "://" + s.Host
				if p := string(s.Port); p != "" && p != "0" && p != "80" && p != "443" {
					u += ":" + p
				}
				u += s.Path
			}
			f.FilePath = u
		case "SCA":
			f.Category = "sca"
			f.PackageName, f.PackageVersion, f.FixedVersion = firstNonEmpty(s.Library, s.Package), s.LibVersion, s.Latest
			f.FilePath = firstNonEmpty(s.Location, s.Package, s.Library)
			if f.CVE != "" {
				f.RuleID, f.Title = f.CVE, fmt.Sprintf("%s in %s %s", f.CVE, f.PackageName, f.PackageVersion)
			}
		default:
			f.Category = "sast"
			f.FilePath, f.StartLine = NormalizePath(firstNonEmpty(s.SourceFile, s.Location)), intPtr(atoiLoose(string(s.Line)))
		}
		f.Description = joinText(fmt.Sprintf("AppScan on Cloud %s issue %s: %s.", firstNonEmpty(s.Discovery, s.Scanner), s.ID, s.IssueType), labeled("API", s.API),
			labeled("Element", s.Element), labeled("Status", s.Status), labeled("Scan", s.ScanName), "The issue list has no description: see the issue details in AppScan on Cloud.")
		if st == "noise" {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "AppScan verdict: noise.")
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(s.API + "|" + s.Element), Raw: it})
	}
	return out, nil
}
