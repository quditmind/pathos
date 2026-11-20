package scans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

// Scan profile tiers (PATHOS 3.0 M6, decision C9): Quick, Standard and
// Comprehensive are seeded per organization beside the existing Default
// profile, which stays. Custom is the existing profile editor. The tiers
// are behind the scan_profile_tiers feature flag: they are seeded either
// way, but listed and readable only while the flag is on.

// TiersFlag is the feature flag of the seeded tier profiles.
const TiersFlag = "scan_profile_tiers"

// Tier is one seeded profile template.
type Tier struct {
	ID          string
	Name        string
	Description string
	// PerKind caps the tools per kind of check (0: no cap).
	PerKind int
	// CoreOnly limits the tier to the tools of the core worker image.
	CoreOnly bool
}

// Tiers are the seeded templates, in display order.
var Tiers = []Tier{
	{ID: "quick", Name: "Quick", PerKind: 2, CoreOnly: true,
		Description: "Fast checks with the tools bundled in the core worker: up to 2 per kind of check"},
	{ID: "standard", Name: "Standard", PerKind: 6,
		Description: "Up to 6 tools per kind of check, from the tools a PATHOS worker image runs"},
	{ID: "comprehensive", Name: "Comprehensive",
		Description: "Every tool a PATHOS worker image runs in repository scans"},
}

// optInTools need an opt-in service and are seeded only in Comprehensive
// (ClamAV streams every file to the clamd service; without it the check is
// recorded as skipped).
var optInTools = []string{scanners.ClamAV}

// profileEligible reports whether a repository profile can select sc; it
// mirrors profileRequest.validate, so seeded settings always validate.
// Tools with decision "optional" (licence-limited, for example Semgrep CE
// registry rules or Bearer's Elastic licence) are left to the
// administrator's own choice and never seeded. The CodeGraph discovery tool
// (pathos-graph) runs only in CodeGraph builds and is refused in profiles.
func profileEligible(sc scanners.Scanner) bool {
	return sc.AdapterAvailable && !sc.Intrusive && sc.Network != "target" && !sc.TargetOnly && sc.Decision == "use" && !scanners.IsGraphTool(sc.Key)
}

// TierSettings returns the settings of a tier: for every kind of check, the
// eligible catalogued tools in the §7 table's order (then the kind's extra
// tools), capped per kind.
func TierSettings(t Tier) ProfileSettings {
	st := ProfileSettings{SeverityThreshold: "info", TimeoutSeconds: 1800, SBOM: true, RetentionDays: 90,
		Exclusions: []string{"node_modules/**", "vendor/**", "**/testdata/**"}}
	if t.ID == "comprehensive" {
		st.TimeoutSeconds = 7200
	}
	seen := map[string]bool{}
	add := func(key string) {
		if !seen[key] {
			seen[key] = true
			st.Scanners = append(st.Scanners, ProfileScanner{Key: key, Config: json.RawMessage("{}")})
		}
	}
	for _, k := range append(append([]scanners.CheckKind{}, scanners.CheckKinds...), scanners.OutsideKinds...) {
		// Kinds scheduled after PATHOS 2.0 (fuzz testing) run long; only
		// Comprehensive seeds them.
		if k.AfterV2 && t.PerKind > 0 {
			continue
		}
		n := 0
		for _, key := range k.CatalogKeys() {
			sc, ok := scanners.Lookup(key)
			if !ok || !profileEligible(sc) || (t.CoreOnly && sc.Family != "core") || (t.PerKind > 0 && slices.Contains(optInTools, key)) {
				continue
			}
			if t.PerKind > 0 && n >= t.PerKind {
				break
			}
			n++
			add(key)
		}
	}
	// Mandatory scanners are always on; Grype scans the Syft SBOM.
	for _, sc := range scanners.Catalog {
		if sc.Mandatory {
			add(sc.Key)
		}
	}
	if seen[scanners.Grype] {
		add(scanners.Syft)
	}
	return st
}

// EnsureTierProfiles seeds the Quick, Standard and Comprehensive profiles
// of an organization. It is idempotent: a template is seeded once (the
// template column records it), and an administrator's rename, edit or
// archive is never undone. A custom profile that already uses a tier's
// name keeps it; the tier is then named "<name> (PATHOS)".
func EnsureTierProfiles(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		for _, t := range Tiers {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_profiles WHERE organization_id = $1 AND template = $2)`,
				orgID, t.ID).Scan(&exists); err != nil {
				return err
			}
			if exists {
				continue
			}
			name := t.Name
			var taken bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_profiles WHERE organization_id = $1 AND lower(name) = lower($2)
				AND archived_at IS NULL)`, orgID, name).Scan(&taken); err != nil {
				return err
			}
			if taken {
				name += " (PATHOS)"
			}
			pid := uuid.Must(uuid.NewV7())
			// A concurrent seed of the same template inserts nothing.
			err := tx.QueryRow(ctx, `INSERT INTO scan_profiles (id, organization_id, name, description, template) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (organization_id, template) WHERE template IS NOT NULL DO NOTHING RETURNING id`,
				pid, orgID, name, t.Description, t.ID).Scan(&pid)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if _, err := insertVersion(ctx, tx, orgID, pid, 1, TierSettings(t), "Seeded "+t.Name+" profile", nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// tiersVisible reports whether the organization sees the tier profiles.
func (s *Service) tiersVisible(ctx context.Context, orgID uuid.UUID) (bool, error) {
	return featureflags.Enabled(ctx, s.DB, orgID, TiersFlag)
}

// --- kinds of check of a profile ----------------------------------------------

// ProfileKindTool is a selected tool of a profile kind.
type ProfileKindTool struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Listed   bool   `json:"listed"` // one of the kind's §7 tools
	Runnable bool   `json:"runnable"`
}

// ProfileKind is one kind of check as a profile covers it.
type ProfileKind struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Phase   int    `json:"phase"`
	AfterV2 bool   `json:"after_v2"`
	Outside bool   `json:"outside_kinds"`
	// ToolsTarget is the prompt's 10 tools per kind; Listed counts the
	// profile's tools among them ("N of 10 tools").
	ToolsTarget int `json:"tools_target"`
	Listed      int `json:"listed"`
	// Selected are the profile's tools of the kind (§7 and extra tools).
	Selected []ProfileKindTool `json:"selected"`
	Runnable int               `json:"runnable"`
	// Available counts the kind's tools a repository profile can select.
	Available int `json:"available"`
	// RepositoryScope: a repository profile can cover the kind at all
	// (false for kinds run on scan targets or not built yet).
	RepositoryScope bool `json:"repository_scope"`
	// LacksRunnable: the kind applies to repository scans, but no selected
	// tool of it is advertised by an online worker.
	LacksRunnable bool `json:"lacks_runnable"`
}

func (s *Service) profileKinds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansRead) && !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pr, err := s.loadVisibleProfile(ctx, p.OrganizationID, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	online, workers, err := onlineTools(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	selected := map[string]bool{}
	for _, ps := range pr.Current.Scanners {
		selected[ps.Key] = true
	}
	out := []ProfileKind{}
	for i, k := range append(append([]scanners.CheckKind{}, scanners.CheckKinds...), scanners.OutsideKinds...) {
		pk := ProfileKind{ID: k.ID, Name: k.Name, Phase: k.Phase, AfterV2: k.AfterV2, Outside: i >= len(scanners.CheckKinds),
			ToolsTarget: scanners.ToolsPerKind, Selected: []ProfileKindTool{}}
		listed := k.ListedKeys()
		for _, key := range k.CatalogKeys() {
			sc, ok := scanners.Lookup(key)
			if !ok {
				continue
			}
			if profileEligible(sc) || (sc.AdapterAvailable && !sc.TargetOnly && !sc.Intrusive && sc.Network != "target" && !scanners.IsGraphTool(sc.Key)) {
				pk.Available++
			}
			if !selected[key] {
				continue
			}
			t := ProfileKindTool{Key: key, Name: sc.Name, Listed: slices.Contains(listed, key), Runnable: online[key] != nil}
			if t.Listed {
				pk.Listed++
			}
			if t.Runnable {
				pk.Runnable++
			}
			pk.Selected = append(pk.Selected, t)
		}
		pk.RepositoryScope = pk.Available > 0
		pk.LacksRunnable = pk.RepositoryScope && pk.Runnable == 0
		out = append(out, pk)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"profile_id": pr.ID, "kinds": out, "workers_online": workers})
}
