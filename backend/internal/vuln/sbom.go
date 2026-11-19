package vuln

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"pathos/internal/platform/objstore"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Component is one SBOM entry.
type Component struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl"`
	Type     string   `json:"type"`
	Licenses []string `json:"licenses"`
	// Ref is the component's identifier in the SBOM (CycloneDX bom-ref,
	// SPDX SPDXID), used by dependency edges.
	Ref string `json:"bom_ref,omitempty"`
}

// ParseCycloneDX extracts components from a CycloneDX JSON document.
func ParseCycloneDX(raw []byte) ([]Component, error) {
	c, _, err := parseCycloneDX(raw)
	return c, err
}

// parseCycloneDX also returns aliases: refs of duplicate components mapped
// to the ref of the component kept.
func parseCycloneDX(raw []byte) ([]Component, map[string]string, error) {
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Ref      string `json:"bom-ref"`
			Name     string `json:"name"`
			Group    string `json:"group"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Type     string `json:"type"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
				Expression string `json:"expression"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	if doc.BOMFormat != "CycloneDX" {
		return nil, nil, errors.New("not a CycloneDX document")
	}
	out := make([]Component, 0, len(doc.Components))
	seen := map[string]string{}
	aliases := map[string]string{}
	for _, c := range doc.Components {
		name := c.Name
		if c.Group != "" {
			name = c.Group + "/" + c.Name
		}
		if name == "" || c.Type == "file" {
			continue
		}
		key := name + "@" + c.Version + "|" + c.PURL
		if kept, ok := seen[key]; ok {
			if c.Ref != "" && kept != "" {
				aliases[c.Ref] = kept
			}
			continue
		}
		seen[key] = clip(c.Ref, 1000)
		var lic []string
		for _, l := range c.Licenses {
			v := firstNonEmpty(l.License.ID, l.Expression, l.License.Name)
			if v != "" && !slices.Contains(lic, v) && len(v) <= 200 {
				lic = append(lic, v)
			}
		}
		if lic == nil {
			lic = []string{}
		}
		out = append(out, Component{Name: clip(name, 300), Version: clip(c.Version, 100), PURL: clip(c.PURL, 500), Type: clip(c.Type, 50), Licenses: lic,
			Ref: clip(c.Ref, 1000)})
		if len(out) >= 50000 {
			break
		}
	}
	return out, aliases, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// StoreSBOM replaces a repository's component inventory with the latest
// SBOM (called from scan ingestion for Syft output).
func StoreSBOM(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID, raw []byte) (int, error) {
	comps, aliases, err := parseCycloneDX(raw)
	if err != nil {
		return 0, err
	}
	if err := replaceComponents(ctx, tx, orgID, repoID, &jobID, "scan", comps); err != nil {
		return 0, err
	}
	return len(comps), storeGraph(ctx, tx, orgID, repoID, ParseGraph(raw), aliases)
}

// replaceComponents replaces a repository's component inventory of one
// kind: the SBOM (Syft scans and imports, which replace each other) or the
// AI-BOM (source "aibom", replaced by the next AI-BOM only).
func replaceComponents(ctx context.Context, tx pgx.Tx, orgID, repoID uuid.UUID, jobID *uuid.UUID, source string, comps []Component) error {
	if _, err := tx.Exec(ctx, `DELETE FROM sbom_components WHERE repository_id = $1 AND (source = 'aibom') = ($2 = 'aibom')`,
		repoID, source); err != nil {
		return err
	}
	rows := make([][]any, len(comps))
	for i, c := range comps {
		rows[i] = []any{orgID, repoID, jobID, c.Name, c.Version, c.PURL, c.Type, c.Licenses, source, c.Ref}
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"sbom_components"},
		[]string{"organization_id", "repository_id", "scan_job_id", "name", "version", "purl", "type", "licenses", "source", "bom_ref"}, pgx.CopyFromRows(rows))
	return err
}

// StoreAIBOM replaces a repository's AI-BOM components (scanner ai-bom):
// CycloneDX components keep their type (framework, library,
// machine-learning-model); services (LLM APIs the code calls) are stored
// as components of type "service".
func StoreAIBOM(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID, raw []byte) (int, error) {
	comps, err := ParseAIBOM(raw)
	if err != nil {
		return 0, err
	}
	return len(comps), replaceComponents(ctx, tx, orgID, repoID, &jobID, "aibom", comps)
}

// ParseAIBOM reads the components and services of an AI-BOM.
func ParseAIBOM(raw []byte) ([]Component, error) {
	comps, _, err := parseCycloneDX(raw)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Services []struct {
			Ref      string `json:"bom-ref"`
			Name     string `json:"name"`
			Provider struct {
				Name string `json:"name"`
			} `json:"provider"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	for _, sv := range doc.Services {
		if sv.Name == "" || len(comps) >= 50000 {
			continue
		}
		name := sv.Name
		if sv.Provider.Name != "" && !strings.HasPrefix(name, sv.Provider.Name) {
			name = sv.Provider.Name + "/" + name
		}
		comps = append(comps, Component{Name: clip(name, 300), Type: "service", Licenses: []string{}, Ref: clip(sv.Ref, 1000)})
	}
	return comps, nil
}

// ComponentGroup aggregates a component across repositories.
type ComponentGroup struct {
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	PURL          string   `json:"purl"`
	Type          string   `json:"type"`
	Licenses      []string `json:"licenses"`
	LicensePolicy string   `json:"license_policy"` // "", review, deny (deny wins: min() sorts deny first)
	Repositories  []string `json:"repositories"`
	OpenVulns     int      `json:"open_vulnerabilities"`
}

// components searches the inventory (scoped to sbom.read).
func (s *Service) components(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermSBOMRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 5)
	like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(strings.TrimSpace(q.Get("q")))) + "%"
	var repo *uuid.UUID
	if v := q.Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid repository_id"))
			return
		}
		repo = &id
	}
	policy := q.Get("license")
	if policy != "" && policy != "deny" && policy != "review" && policy != "violations" {
		s.fail(w, r, httpx.BadRequest("license must be deny, review or violations"))
		return
	}
	args = append([]any{p.OrganizationID, like, repo, policy}, args...)
	rows, err := s.DB.Query(ctx, `
		WITH c AS (
		  SELECT sc.name, sc.version, sc.purl, sc.type, sc.licenses, r.full_name, r.id AS repo_id,
		         (SELECT min(lp.decision) FROM license_policies lp WHERE lp.organization_id = $1 AND lp.spdx_id = ANY(sc.licenses)) AS policy
		  FROM sbom_components sc JOIN repositories r ON r.id = sc.repository_id LEFT JOIN countries co ON co.id = r.country_id
		  WHERE sc.organization_id = $1 AND r.archived_at IS NULL AND (lower(sc.name) LIKE $2 OR lower(sc.purl) LIKE $2)
		    AND ($3::uuid IS NULL OR r.id = $3) AND `+scope+`)
		SELECT c.name, c.version, max(c.purl), max(c.type),
		       (SELECT COALESCE(array_agg(DISTINCT l), '{}') FROM c c2, unnest(c2.licenses) l WHERE c2.name = c.name AND c2.version = c.version),
		       COALESCE(min(c.policy), ''), array_agg(DISTINCT c.full_name ORDER BY c.full_name),
		       (SELECT count(*) FROM findings f WHERE f.repository_id = ANY(array_agg(c.repo_id)) AND f.category = 'sca'
		          AND f.status IN ('open', 'in_progress', 'needs_review') AND f.package_name = c.name AND f.package_version = c.version)
		FROM c
		WHERE $4 = '' OR ($4 = 'violations' AND c.policy IS NOT NULL) OR c.policy = $4
		GROUP BY c.name, c.version ORDER BY lower(c.name), c.version LIMIT 500`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ComponentGroup])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []ComponentGroup{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// repoSBOM downloads the latest CycloneDX SBOM of a repository.
func (s *Service) repoSBOM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Authz.Require(ctx, p, authz.PermSBOMRead, authz.Scope{Type: authz.ScopeRepository, ID: id}); err != nil {
		if errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(authz.PermSBOMRead) {
			err = errNotFound
		}
		s.fail(w, r, err)
		return
	}
	// format: cyclonedx (default: the latest scan's SBOM file, else generated
	// from the inventory) or spdx (generated from the inventory).
	format := r.URL.Query().Get("format")
	if format == "spdx" || format == "cyclonedx-inventory" {
		s.exportInventory(w, r, id, format)
		return
	}
	if format != "" && format != "cyclonedx" {
		s.fail(w, r, httpx.BadRequest("format must be cyclonedx or spdx"))
		return
	}
	var data []byte
	var key *string
	var name string
	err = s.DB.QueryRow(ctx, `SELECT a.data_gzip, a.object_key, r.name FROM scan_artifacts a JOIN scan_results sr ON sr.id = a.scan_result_id
		JOIN scan_jobs j ON j.id = sr.scan_job_id JOIN repositories r ON r.id = j.repository_id
		WHERE j.repository_id = $1 AND j.organization_id = $2 AND a.kind = 'sbom' ORDER BY a.created_at DESC LIMIT 1`, id, p.OrganizationID).Scan(&data, &key, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		// No scan SBOM (e.g. an imported one): generate from the inventory.
		s.exportInventory(w, r, id, "cyclonedx-inventory")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if data, err = objstore.Load(ctx, s.Artifacts, key, data); err != nil {
		s.fail(w, r, err)
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer zr.Close()
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 {
			return '_'
		}
		return r
	}, name)+`.cdx.json"`)
	_, _ = io.Copy(w, io.LimitReader(zr, 512<<20))
}

func (s *Service) exportInventory(w http.ResponseWriter, r *http.Request, repoID uuid.UUID, format string) {
	ctx := r.Context()
	var name string
	if err := s.DB.QueryRow(ctx, `SELECT COALESCE(NULLIF(display_name, ''), full_name) FROM repositories WHERE id = $1`, repoID).Scan(&name); err != nil {
		s.fail(w, r, err)
		return
	}
	comps, edges, err := loadInventory(ctx, s.DB, repoID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(comps) == 0 {
		s.fail(w, r, httpx.E(http.StatusNotFound, "no_sbom", "the repository has no component inventory yet"))
		return
	}
	var out []byte
	ct, ext := "application/vnd.cyclonedx+json", ".cdx.json"
	if format == "spdx" {
		out, err = SPDXDocument(name, comps, edges, time.Now())
		ct, ext = "application/spdx+json", ".spdx.json"
	} else {
		out, err = CycloneDXDocument(name, comps, edges, time.Now())
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == '/' {
			return '_'
		}
		return r
	}, name)+ext+`"`)
	_, _ = w.Write(out)
}
