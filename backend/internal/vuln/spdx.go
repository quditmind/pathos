package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ParseSPDX extracts packages from an SPDX 2.x JSON document.
func ParseSPDX(raw []byte) ([]Component, error) {
	c, _, err := parseSPDX(raw)
	return c, err
}

func parseSPDX(raw []byte) ([]Component, map[string]string, error) {
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			ID               string `json:"SPDXID"`
			Name             string `json:"name"`
			VersionInfo      string `json:"versionInfo"`
			Supplier         string `json:"supplier"`
			LicenseConcluded string `json:"licenseConcluded"`
			LicenseDeclared  string `json:"licenseDeclared"`
			PrimaryPurpose   string `json:"primaryPackagePurpose"`
			ExternalRefs     []struct {
				Category string `json:"referenceCategory"`
				Type     string `json:"referenceType"`
				Locator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-2.") {
		return nil, nil, errors.New("not an SPDX 2.x JSON document")
	}
	out := make([]Component, 0, len(doc.Packages))
	seen := map[string]string{}
	aliases := map[string]string{}
	for _, p := range doc.Packages {
		if p.Name == "" {
			continue
		}
		purl := ""
		for _, r := range p.ExternalRefs {
			if r.Type == "purl" {
				purl = r.Locator
				break
			}
		}
		typ := strings.ToLower(p.PrimaryPurpose)
		if typ == "" {
			typ = "library"
		}
		if typ == "file" || pathLikeComponent(p.Name, p.VersionInfo) {
			continue
		}
		typ = componentType(typ, purl)
		key := p.Name + "@" + p.VersionInfo + "|" + purl
		if kept, ok := seen[key]; ok {
			if p.ID != "" && kept != "" {
				aliases[p.ID] = kept
			}
			continue
		}
		seen[key] = clip(p.ID, 1000)
		var lic []string
		for _, l := range []string{p.LicenseConcluded, p.LicenseDeclared} {
			l = strings.TrimSpace(l)
			if l != "" && l != "NOASSERTION" && l != "NONE" && !slices.Contains(lic, l) && len(l) <= 200 {
				lic = append(lic, l)
			}
		}
		if lic == nil {
			lic = []string{}
		}
		out = append(out, Component{Name: clip(p.Name, 300), Version: clip(p.VersionInfo, 100), PURL: clip(purl, 500), Type: clip(typ, 50), Licenses: lic,
			Ref: clip(p.ID, 1000)})
		if len(out) >= 50000 {
			break
		}
	}
	return out, aliases, nil
}

// DetectSBOM returns the format of an SBOM document: cyclonedx, spdx or "".
func DetectSBOM(raw []byte) string {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return ""
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return "cyclonedx"
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-2."):
		return "spdx"
	}
	return ""
}

// ParseSBOM parses a CycloneDX or SPDX JSON SBOM.
func ParseSBOM(raw []byte) (string, []Component, error) {
	switch f := DetectSBOM(raw); f {
	case "cyclonedx":
		c, err := ParseCycloneDX(raw)
		return f, c, err
	case "spdx":
		c, err := ParseSPDX(raw)
		return f, c, err
	}
	return "", nil, errors.New("unrecognised SBOM: expected CycloneDX JSON or SPDX 2.x JSON")
}

// StoreImportedSBOM replaces a repository's component inventory and
// dependency graph with an imported SBOM.
func StoreImportedSBOM(ctx context.Context, tx pgx.Tx, orgID, repoID uuid.UUID, raw []byte) (int, error) {
	var comps []Component
	var aliases map[string]string
	var err error
	switch DetectSBOM(raw) {
	case "cyclonedx":
		comps, aliases, err = parseCycloneDX(raw)
	case "spdx":
		comps, aliases, err = parseSPDX(raw)
	default:
		err = errors.New("unrecognised SBOM: expected CycloneDX JSON or SPDX 2.x JSON")
	}
	if err != nil {
		return 0, err
	}
	if err := replaceComponents(ctx, tx, orgID, repoID, nil, "import", comps); err != nil {
		return 0, err
	}
	if err := storeGraph(ctx, tx, orgID, repoID, ParseGraph(raw), aliases); err != nil {
		return 0, err
	}
	// Licence policy violations of the imported components.
	_, _, err = SyncLicenseFindings(ctx, tx, orgID, &repoID, nil)
	return len(comps), err
}
