package releases

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"pathos/internal/platform/buildinfo"
)

// VEX (Vulnerability Exploitability eXchange) documents: OpenVEX v0.2.0
// and CycloneDX 1.6. Export turns PATHOS decisions into statements; import
// parses statements, which become reviewable suggestions (never automatic
// status changes).

// VEX statuses (OpenVEX vocabulary, used internally for both formats).
const (
	VEXNotAffected        = "not_affected"
	VEXAffected           = "affected"
	VEXFixed              = "fixed"
	VEXUnderInvestigation = "under_investigation"
)

// VEXFinding is the input for one exported statement.
type VEXFinding struct {
	Vulnerability  string // CVE or advisory ID
	PackageName    string
	PackageVersion string
	PURL           string // component purl when known
	FixedVersion   string
	Status         string // PATHOS finding status
	Reachability   string // reachable | not_reachable | unknown
	Reason         string // decision note (false positive reason, risk justification)
	AcceptedUntil  *time.Time
}

// Statement is one normalized VEX statement.
type Statement struct {
	Vulnerability   string   `json:"vulnerability"`
	Aliases         []string `json:"aliases,omitempty"`
	Products        []string `json:"products"` // purls or other identifiers
	Status          string   `json:"status"`
	Justification   string   `json:"justification,omitempty"`
	ImpactStatement string   `json:"impact_statement,omitempty"`
	ActionStatement string   `json:"action_statement,omitempty"`
}

// genericPURL builds pkg:generic/<name>@<version> for packages without a
// known purl.
func genericPURL(name, version string) string {
	p := "pkg:generic/" + url.PathEscape(name)
	if version != "" {
		p += "@" + url.PathEscape(version)
	}
	return p
}

// statusRank orders statuses from most to least conservative, so that a
// component reported in several places keeps the most cautious statement.
var statusRank = map[string]int{VEXAffected: 0, VEXUnderInvestigation: 1, VEXFixed: 2, VEXNotAffected: 3}

// StatementFor maps one PATHOS finding to a VEX statement.
func StatementFor(f VEXFinding) Statement {
	prod := f.PURL
	if prod == "" {
		prod = genericPURL(f.PackageName, f.PackageVersion)
	}
	st := Statement{Vulnerability: f.Vulnerability, Products: []string{prod}}
	reason := strings.TrimSpace(f.Reason)
	switch f.Status {
	case "false_positive":
		st.Status = VEXNotAffected
		if f.Reachability == "not_reachable" {
			st.Justification = "vulnerable_code_not_in_execute_path"
		}
		st.ImpactStatement = reason
		if st.ImpactStatement == "" {
			st.ImpactStatement = "Assessed as not affected (false positive) in PATHOS."
		}
	case "fixed":
		st.Status = VEXFixed
	case "accepted_risk":
		st.Status = VEXAffected
		st.ActionStatement = "Risk accepted; no fix planned"
		if f.AcceptedUntil != nil {
			st.ActionStatement += " until " + f.AcceptedUntil.UTC().Format("2006-01-02")
		}
		if reason != "" {
			st.ActionStatement += ": " + reason
		}
	case "needs_review":
		st.Status = VEXUnderInvestigation
	default: // open, in_progress
		st.Status = VEXAffected
		if f.FixedVersion != "" {
			st.ActionStatement = "Update " + f.PackageName + " to " + f.FixedVersion + " or later"
		} else {
			st.ActionStatement = "No fixed version is known yet; remediation is being tracked"
		}
	}
	return st
}

// Statements maps findings to statements, one per (vulnerability,
// product), keeping the most conservative status, sorted for stable output.
func Statements(fs []VEXFinding) []Statement {
	type key struct{ vuln, prod string }
	byKey := map[key]Statement{}
	var order []key
	for _, f := range fs {
		if f.Vulnerability == "" {
			continue
		}
		st := StatementFor(f)
		k := key{strings.ToUpper(st.Vulnerability), st.Products[0]}
		cur, ok := byKey[k]
		if !ok {
			order = append(order, k)
			byKey[k] = st
			continue
		}
		if statusRank[st.Status] < statusRank[cur.Status] {
			byKey[k] = st
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].vuln != order[j].vuln {
			return order[i].vuln < order[j].vuln
		}
		return order[i].prod < order[j].prod
	})
	out := make([]Statement, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}

func newURN() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// OpenVEXDocument renders statements as an OpenVEX v0.2.0 document.
func OpenVEXDocument(author, docID string, stmts []Statement, now time.Time) ([]byte, error) {
	type product struct {
		ID string `json:"@id"`
	}
	type vuln struct {
		Name string `json:"name"`
	}
	type stmt struct {
		Vulnerability   vuln      `json:"vulnerability"`
		Products        []product `json:"products"`
		Status          string    `json:"status"`
		Justification   string    `json:"justification,omitempty"`
		ImpactStatement string    `json:"impact_statement,omitempty"`
		ActionStatement string    `json:"action_statement,omitempty"`
	}
	ts := now.UTC().Format(time.RFC3339)
	out := struct {
		Context   string `json:"@context"`
		ID        string `json:"@id"`
		Author    string `json:"author"`
		Timestamp string `json:"timestamp"`
		Version   int    `json:"version"`
		Tooling   string `json:"tooling"`
		Stmts     []stmt `json:"statements"`
	}{Context: "https://openvex.dev/ns/v0.2.0", ID: docID, Author: author, Timestamp: ts, Version: 1, Tooling: buildinfo.Stamp(now), Stmts: []stmt{}}
	for _, s := range stmts {
		x := stmt{Vulnerability: vuln{Name: s.Vulnerability}, Status: s.Status, Justification: s.Justification,
			ImpactStatement: s.ImpactStatement, ActionStatement: s.ActionStatement}
		for _, p := range s.Products {
			x.Products = append(x.Products, product{ID: p})
		}
		if s.Status == VEXNotAffected && x.Justification == "" && x.ImpactStatement == "" {
			return nil, errors.New("not_affected statements need a justification or an impact statement")
		}
		if s.Status == VEXAffected && x.ActionStatement == "" {
			return nil, errors.New("affected statements need an action statement")
		}
		out.Stmts = append(out.Stmts, x)
	}
	return json.MarshalIndent(out, "", "  ")
}

// openVEXToCDXJustification maps OpenVEX justifications onto CycloneDX.
var openVEXToCDXJustification = map[string]string{
	"component_not_present":                             "code_not_present",
	"vulnerable_code_not_present":                       "code_not_present",
	"vulnerable_code_not_in_execute_path":               "code_not_reachable",
	"vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
	"inline_mitigations_already_exist":                  "protected_by_mitigating_control",
}

var cdxToOpenVEXJustification = map[string]string{
	"code_not_present":                "vulnerable_code_not_present",
	"code_not_reachable":              "vulnerable_code_not_in_execute_path",
	"requires_configuration":          "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_dependency":             "component_not_present",
	"requires_environment":            "vulnerable_code_cannot_be_controlled_by_adversary",
	"protected_by_compiler":           "inline_mitigations_already_exist",
	"protected_at_runtime":            "inline_mitigations_already_exist",
	"protected_at_perimeter":          "inline_mitigations_already_exist",
	"protected_by_mitigating_control": "inline_mitigations_already_exist",
}

// CycloneDXVEXDocument renders statements as a CycloneDX 1.6 VEX BOM.
// subject names the product (application version or repository).
func CycloneDXVEXDocument(subject, subjectVersion string, stmts []Statement, now time.Time) ([]byte, error) {
	type comp struct {
		Ref     string `json:"bom-ref"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl,omitempty"`
	}
	type analysis struct {
		State         string   `json:"state"`
		Justification string   `json:"justification,omitempty"`
		Response      []string `json:"response,omitempty"`
		Detail        string   `json:"detail,omitempty"`
	}
	type affect struct {
		Ref string `json:"ref"`
	}
	type vuln struct {
		ID       string   `json:"id"`
		Analysis analysis `json:"analysis"`
		Affects  []affect `json:"affects"`
	}
	refs := map[string]bool{}
	var comps []comp
	vulns := []vuln{}
	for _, s := range stmts {
		v := vuln{ID: s.Vulnerability}
		for _, p := range s.Products {
			if !refs[p] {
				refs[p] = true
				name, version := purlNameVersion(p)
				comps = append(comps, comp{Ref: p, Type: "library", Name: name, Version: version, PURL: p})
			}
			v.Affects = append(v.Affects, affect{Ref: p})
		}
		switch s.Status {
		case VEXNotAffected:
			v.Analysis = analysis{State: "not_affected", Justification: openVEXToCDXJustification[s.Justification], Detail: s.ImpactStatement}
		case VEXFixed:
			v.Analysis = analysis{State: "resolved"}
		case VEXUnderInvestigation:
			v.Analysis = analysis{State: "in_triage"}
		default:
			v.Analysis = analysis{State: "exploitable", Detail: s.ActionStatement}
			if strings.HasPrefix(s.ActionStatement, "Risk accepted") {
				v.Analysis.Response = []string{"will_not_fix"}
			} else if strings.HasPrefix(s.ActionStatement, "Update ") {
				v.Analysis.Response = []string{"update"}
			}
		}
		vulns = append(vulns, v)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].Ref < comps[j].Ref })
	if comps == nil {
		comps = []comp{}
	}
	subj := map[string]any{"type": "application", "name": subject, "bom-ref": "subject"}
	if subjectVersion != "" {
		subj["version"] = subjectVersion
	}
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": newURN(),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": now.UTC().Format(time.RFC3339),
			"tools": map[string]any{"components": []map[string]string{{"type": "application", "publisher": buildinfo.Vendor,
				"name": buildinfo.Product, "version": buildinfo.Version}}},
			"component":  subj,
			"properties": []map[string]string{{"name": "pathos:generated-by", "value": buildinfo.Stamp(now)}, {"name": "pathos:build", "value": buildinfo.Commit}},
		},
		"components":      comps,
		"vulnerabilities": vulns,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// purlNameVersion extracts the name (with namespace) and version of a purl.
func purlNameVersion(p string) (string, string) {
	rest, ok := strings.CutPrefix(p, "pkg:")
	if !ok {
		return p, ""
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	_, rest, _ = strings.Cut(rest, "/")
	version := ""
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest, version = rest[:i], rest[i+1:]
	}
	if n, err := url.PathUnescape(rest); err == nil {
		rest = n
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	return rest, version
}

// purlBase strips the version and qualifiers of a purl.
func purlBase(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i > 0 && !strings.Contains(p[i:], "/") {
		p = p[:i]
	}
	return strings.ToLower(p)
}

// ParseVEX detects and parses an OpenVEX or CycloneDX VEX document.
// It returns the format ("openvex" | "cyclonedx"), the author and the
// statements.
func ParseVEX(raw []byte) (string, string, []Statement, error) {
	var probe struct {
		Context   string          `json:"@context"`
		BOMFormat string          `json:"bomFormat"`
		Stmts     json.RawMessage `json:"statements"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", "", nil, errors.New("the document is not valid JSON")
	}
	switch {
	case strings.Contains(probe.Context, "openvex.dev") || (probe.BOMFormat == "" && len(probe.Stmts) > 0):
		author, st, err := parseOpenVEX(raw)
		return "openvex", author, st, err
	case probe.BOMFormat == "CycloneDX":
		author, st, err := parseCycloneDXVEX(raw)
		return "cyclonedx", author, st, err
	}
	return "", "", nil, errors.New("not an OpenVEX or CycloneDX VEX document")
}

const maxStatements = 20000

func parseOpenVEX(raw []byte) (string, []Statement, error) {
	type product struct {
		ID          string            `json:"@id"`
		Identifiers map[string]string `json:"identifiers"`
		Subs        []struct {
			ID          string            `json:"@id"`
			Identifiers map[string]string `json:"identifiers"`
		} `json:"subcomponents"`
	}
	var doc struct {
		Author string `json:"author"`
		Stmts  []struct {
			Vulnerability   json.RawMessage `json:"vulnerability"`
			Products        []product       `json:"products"`
			Status          string          `json:"status"`
			Justification   string          `json:"justification"`
			ImpactStatement string          `json:"impact_statement"`
			ActionStatement string          `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", nil, errors.New("invalid OpenVEX document")
	}
	if len(doc.Stmts) > maxStatements {
		return "", nil, fmt.Errorf("too many statements (maximum %d)", maxStatements)
	}
	var out []Statement
	for i, s := range doc.Stmts {
		st := Statement{Status: s.Status, Justification: s.Justification, ImpactStatement: s.ImpactStatement, ActionStatement: s.ActionStatement}
		// v0.2.0: an object {name, @id, aliases}; v0.0.x: a string.
		var name string
		if err := json.Unmarshal(s.Vulnerability, &name); err == nil {
			st.Vulnerability = name
		} else {
			var v struct {
				Name    string   `json:"name"`
				ID      string   `json:"@id"`
				Aliases []string `json:"aliases"`
			}
			if err := json.Unmarshal(s.Vulnerability, &v); err != nil {
				return "", nil, fmt.Errorf("statement %d: invalid vulnerability", i+1)
			}
			st.Vulnerability, st.Aliases = v.Name, v.Aliases
			if st.Vulnerability == "" {
				st.Vulnerability = v.ID
			}
		}
		if st.Vulnerability == "" {
			return "", nil, fmt.Errorf("statement %d: vulnerability name is required", i+1)
		}
		switch st.Status {
		case VEXNotAffected, VEXAffected, VEXFixed, VEXUnderInvestigation:
		default:
			return "", nil, fmt.Errorf("statement %d: invalid status %q", i+1, st.Status)
		}
		for _, p := range s.Products {
			// The vulnerable component is the subcomponent when given.
			if len(p.Subs) > 0 {
				for _, sc := range p.Subs {
					st.Products = append(st.Products, firstNonEmpty(sc.Identifiers["purl"], sc.ID))
				}
				continue
			}
			st.Products = append(st.Products, firstNonEmpty(p.Identifiers["purl"], p.ID))
		}
		out = append(out, st)
	}
	return doc.Author, out, nil
}

func parseCycloneDXVEX(raw []byte) (string, []Statement, error) {
	var doc struct {
		Metadata struct {
			Authors []struct {
				Name string `json:"name"`
			} `json:"authors"`
		} `json:"metadata"`
		Components []struct {
			Ref  string `json:"bom-ref"`
			PURL string `json:"purl"`
		} `json:"components"`
		Vulns []struct {
			ID         string `json:"id"`
			References []struct {
				ID string `json:"id"`
			} `json:"references"`
			Analysis struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Response      []string `json:"response"`
				Detail        string   `json:"detail"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", nil, errors.New("invalid CycloneDX document")
	}
	if len(doc.Vulns) > maxStatements {
		return "", nil, fmt.Errorf("too many vulnerabilities (maximum %d)", maxStatements)
	}
	purls := map[string]string{}
	for _, c := range doc.Components {
		if c.Ref != "" {
			purls[c.Ref] = c.PURL
		}
	}
	author := ""
	if len(doc.Metadata.Authors) > 0 {
		author = doc.Metadata.Authors[0].Name
	}
	var out []Statement
	for i, v := range doc.Vulns {
		if v.ID == "" {
			return "", nil, fmt.Errorf("vulnerability %d: id is required", i+1)
		}
		st := Statement{Vulnerability: v.ID}
		for _, r := range v.References {
			if r.ID != "" {
				st.Aliases = append(st.Aliases, r.ID)
			}
		}
		switch v.Analysis.State {
		case "not_affected", "false_positive":
			st.Status = VEXNotAffected
			st.Justification = cdxToOpenVEXJustification[v.Analysis.Justification]
			st.ImpactStatement = v.Analysis.Detail
		case "resolved", "resolved_with_pedigree":
			st.Status = VEXFixed
		case "exploitable":
			st.Status, st.ActionStatement = VEXAffected, v.Analysis.Detail
		case "in_triage", "":
			st.Status = VEXUnderInvestigation
		default:
			return "", nil, fmt.Errorf("vulnerability %d: invalid analysis state %q", i+1, v.Analysis.State)
		}
		for _, a := range v.Affects {
			st.Products = append(st.Products, firstNonEmpty(purls[a.Ref], a.Ref))
		}
		out = append(out, st)
	}
	return author, out, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Candidate is a finding that a statement may apply to.
type Candidate struct {
	Vulnerability  string   // finding CVE
	RuleID         string   // advisory ID (GHSA, OSV) when the CVE is empty
	PackageName    string   // finding package
	PackageVersion string   // finding package version
	PURLs          []string // purls of the finding's component in the inventory
}

// Matches reports whether a statement applies to a candidate finding: the
// vulnerability (or an alias) equals the finding's CVE or advisory ID, and,
// when the statement names products, one of them is the finding's package
// (by purl, else by name) with a matching version when one is given.
func (s Statement) Matches(c Candidate) bool {
	ids := append([]string{s.Vulnerability}, s.Aliases...)
	hit := false
	for _, id := range ids {
		if id != "" && (strings.EqualFold(id, c.Vulnerability) || strings.EqualFold(id, c.RuleID)) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	if len(s.Products) == 0 {
		return true
	}
	for _, p := range s.Products {
		if productMatches(p, c) {
			return true
		}
	}
	return false
}

func productMatches(p string, c Candidate) bool {
	if !strings.HasPrefix(p, "pkg:") {
		return false
	}
	_, ver := purlNameVersion(p)
	if ver != "" && c.PackageVersion != "" && ver != c.PackageVersion {
		return false
	}
	base := purlBase(p)
	for _, cp := range c.PURLs {
		if purlBase(cp) == base {
			return true
		}
	}
	// No inventory purl: compare names (last path element, case-insensitive).
	name, _ := purlNameVersion(p)
	last := func(s string) string {
		s = strings.ToLower(s)
		if i := strings.LastIndexAny(s, "/:"); i >= 0 {
			return s[i+1:]
		}
		return s
	}
	return c.PackageName != "" && last(name) == last(c.PackageName)
}
