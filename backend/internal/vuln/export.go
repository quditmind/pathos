package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
)

// SBOM export from a repository's component inventory and dependency graph
// (whatever produced it: a scan or an imported SBOM).

type invComponent struct {
	Ref, Name, Version, PURL, Type string
	Licenses                       []string
	Depth                          *int
}

func loadInventory(ctx context.Context, q db.Querier, repoID uuid.UUID) ([]invComponent, map[string][]string, error) {
	rows, err := q.Query(ctx, `SELECT bom_ref, name, version, purl, type, licenses, depth FROM sbom_components WHERE repository_id = $1
		ORDER BY depth NULLS LAST, lower(name), version`, repoID)
	if err != nil {
		return nil, nil, err
	}
	comps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (invComponent, error) {
		var c invComponent
		return c, r.Scan(&c.Ref, &c.Name, &c.Version, &c.PURL, &c.Type, &c.Licenses, &c.Depth)
	})
	if err != nil {
		return nil, nil, err
	}
	erows, err := q.Query(ctx, `SELECT parent_ref, child_ref FROM sbom_dependencies WHERE repository_id = $1`, repoID)
	if err != nil {
		return nil, nil, err
	}
	edges := map[string][]string{}
	for erows.Next() {
		var p, c string
		if err := erows.Scan(&p, &c); err != nil {
			erows.Close()
			return nil, nil, err
		}
		edges[p] = append(edges[p], c)
	}
	erows.Close()
	return comps, edges, erows.Err()
}

var (
	spdxIDChars = regexp.MustCompile(`[^A-Za-z0-9.-]`)
	spdxLicExpr = regexp.MustCompile(`^[A-Za-z0-9.+-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+-]+)*$`)
)

// spdxLicense returns a valid SPDX license expression or NOASSERTION.
func spdxLicense(lics []string) string {
	var ok []string
	for _, l := range lics {
		l = strings.Trim(strings.TrimSpace(l), "()")
		if !spdxLicExpr.MatchString(l) {
			return "NOASSERTION"
		}
		ok = append(ok, l)
	}
	if len(ok) == 0 {
		return "NOASSERTION"
	}
	if len(ok) == 1 {
		return ok[0]
	}
	return "(" + strings.Join(ok, ") AND (") + ")"
}

// SPDXDocument renders the inventory as SPDX 2.3 JSON.
func SPDXDocument(name string, comps []invComponent, edges map[string][]string, now time.Time) ([]byte, error) {
	type ref struct {
		Category string `json:"referenceCategory"`
		Type     string `json:"referenceType"`
		Locator  string `json:"referenceLocator"`
	}
	type pkg struct {
		ID               string `json:"SPDXID"`
		Name             string `json:"name"`
		Version          string `json:"versionInfo,omitempty"`
		Download         string `json:"downloadLocation"`
		FilesAnalyzed    bool   `json:"filesAnalyzed"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
		Copyright        string `json:"copyrightText"`
		Refs             []ref  `json:"externalRefs,omitempty"`
	}
	type rel struct {
		Element string `json:"spdxElementId"`
		Type    string `json:"relationshipType"`
		Related string `json:"relatedSpdxElement"`
	}
	ids := map[string]string{}
	var pkgs []pkg
	for i, c := range comps {
		id := fmt.Sprintf("SPDXRef-Package-%d-%s", i+1, spdxIDChars.ReplaceAllString(c.Name, "-"))
		if len(id) > 120 {
			id = id[:120]
		}
		if c.Ref != "" {
			ids[c.Ref] = id
		}
		p := pkg{ID: id, Name: c.Name, Version: c.Version, Download: "NOASSERTION", LicenseConcluded: "NOASSERTION",
			LicenseDeclared: spdxLicense(c.Licenses), Copyright: "NOASSERTION"}
		if c.PURL != "" {
			p.Refs = []ref{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: c.PURL}}
		}
		pkgs = append(pkgs, p)
	}
	var rels []rel
	described := false
	for _, c := range comps {
		if c.Depth != nil && *c.Depth == 0 && ids[c.Ref] != "" {
			rels = append(rels, rel{"SPDXRef-DOCUMENT", "DESCRIBES", ids[c.Ref]})
			described = true
		}
	}
	if !described {
		for _, p := range pkgs {
			rels = append(rels, rel{"SPDXRef-DOCUMENT", "DESCRIBES", p.ID})
		}
	}
	for parent, children := range edges {
		for _, ch := range children {
			if ids[parent] != "" && ids[ch] != "" {
				rels = append(rels, rel{ids[parent], "DEPENDS_ON", ids[ch]})
			}
		}
	}
	if pkgs == nil {
		pkgs = []pkg{}
	}
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
		"documentNamespace": "urn:uuid:" + uuid.NewString(),
		"creationInfo":      map[string]any{"created": now.UTC().Format(time.RFC3339), "creators": []string{"Tool: PATHOS"}},
		"packages":          pkgs, "relationships": rels,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// CycloneDXDocument renders the inventory as CycloneDX 1.5 JSON.
func CycloneDXDocument(name string, comps []invComponent, edges map[string][]string, now time.Time) ([]byte, error) {
	type lic struct {
		License map[string]string `json:"license,omitempty"`
		Expr    string            `json:"expression,omitempty"`
	}
	type comp struct {
		Ref      string `json:"bom-ref,omitempty"`
		Type     string `json:"type"`
		Name     string `json:"name"`
		Version  string `json:"version,omitempty"`
		PURL     string `json:"purl,omitempty"`
		Licenses []lic  `json:"licenses,omitempty"`
	}
	type dep struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	}
	cs := []comp{}
	for i, c := range comps {
		ref := c.Ref
		if ref == "" {
			ref = fmt.Sprintf("pathos-%d", i+1)
		}
		typ := c.Type
		if typ == "" {
			typ = "library"
		}
		x := comp{Ref: ref, Type: typ, Name: c.Name, Version: c.Version, PURL: c.PURL}
		for _, l := range c.Licenses {
			if spdxLicExpr.MatchString(l) && !strings.Contains(l, " ") {
				x.Licenses = append(x.Licenses, lic{License: map[string]string{"id": l}})
			} else {
				x.Licenses = append(x.Licenses, lic{License: map[string]string{"name": l}})
			}
		}
		cs = append(cs, x)
	}
	deps := []dep{}
	for p, ch := range edges {
		deps = append(deps, dep{Ref: p, DependsOn: ch})
	}
	doc := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:" + uuid.NewString(), "version": 1,
		"metadata":   map[string]any{"timestamp": now.UTC().Format(time.RFC3339), "tools": []map[string]string{{"name": "PATHOS"}}, "component": map[string]string{"type": "application", "name": name}},
		"components": cs, "dependencies": deps,
	}
	return json.MarshalIndent(doc, "", "  ")
}
