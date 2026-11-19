// Package featureflags is the per-organization feature flag framework.
// Every module added after PATHOS 2.2 is behind a flag that is off by
// default until its milestone is approved (prompt §1 rule 9). Flags are
// server-side: GET /api/v1/meta lists them for the signed-in organization
// and handlers of a flagged module call Require. Administrators with
// settings.manage change them at /api/v1/admin/feature-flags; every change
// is audited.
package featureflags

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Flag is one known feature flag.
type Flag struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Milestone is the PATHOS 3.0 milestone that delivers the module.
	Milestone string `json:"milestone"`
}

// Known lists every flag, in display order. A flag must be listed here
// before code can check it; all are off by default.
var Known = []Flag{
	{"connectors", "Connectors hub (/connectors): every integration with health and AI troubleshooting", "M2"},
	{"onboarding", "Combined connect, register, classify and inventory onboarding flow", "M3"},
	{"codegraph", "CodeGraph: discovery worker, graph store and views", "M4"},
	{"threat_models", "Threat modelling on CodeGraph (STRIDE, attack paths)", "M5"},
	{"reverse_engineering", "Reverse engineering workspace (static tier)", "M10"},
	{"remediation_workspace", "Remediation workspace and gates", "M8"},
	{"continuous_monitoring", "Continuous monitoring feed and architecture drift", "M9"},
	{"lifecycle_overview", "Application security lifecycle overview", "M3"},
}

// IsKnown reports whether name is a known flag.
func IsKnown(name string) bool {
	return slices.ContainsFunc(Known, func(f Flag) bool { return f.Name == name })
}

// Load returns every known flag of the organization (false unless set).
func Load(ctx context.Context, q db.Querier, orgID uuid.UUID) (map[string]bool, error) {
	out := make(map[string]bool, len(Known))
	for _, f := range Known {
		out[f.Name] = false
	}
	rows, err := q.Query(ctx, `SELECT name, enabled FROM feature_flags WHERE organization_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var on bool
		if err := rows.Scan(&name, &on); err != nil {
			return nil, err
		}
		if _, known := out[name]; known {
			out[name] = on
		}
	}
	return out, rows.Err()
}

// Enabled reports whether the organization has the flag on.
func Enabled(ctx context.Context, q db.Querier, orgID uuid.UUID, name string) (bool, error) {
	var on bool
	err := q.QueryRow(ctx, `SELECT enabled FROM feature_flags WHERE organization_id = $1 AND name = $2`, orgID, name).Scan(&on)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return on, err
}

// Disabled is the API error of a module whose flag is off
// (PTH-PLAT-1007, 404 so a disabled module looks absent).
func Disabled(name string) *httpx.Error {
	return httpx.E(http.StatusNotFound, "feature_disabled", "the "+name+" feature is not enabled for this organization").WithDiag("PTH-PLAT-1007")
}

// Require returns Disabled(name) unless the flag is on.
func Require(ctx context.Context, q db.Querier, orgID uuid.UUID, name string) error {
	on, err := Enabled(ctx, q, orgID, name)
	if err != nil {
		return err
	}
	if !on {
		return Disabled(name)
	}
	return nil
}

// Service serves the administration API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the endpoints.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/admin/feature-flags", s.list)
	mux.HandleFunc("PUT /api/v1/admin/feature-flags", s.update)
}

// View is one flag as the administration API returns it.
type View struct {
	Flag
	Enabled   bool       `json:"enabled"`
	UpdatedAt *time.Time `json:"updated_at"`
	UpdatedBy *string    `json:"updated_by"`
}

func (s *Service) admin(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := s.Authz.Require(r.Context(), p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, authz.ErrForbidden) {
		err = httpx.ErrForbidden
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) views(ctx context.Context, q db.Querier, orgID uuid.UUID) ([]View, error) {
	rows, err := q.Query(ctx, `SELECT f.name, f.enabled, f.updated_at, u.email FROM feature_flags f
		LEFT JOIN users u ON u.id = f.updated_by AND u.organization_id = f.organization_id
		WHERE f.organization_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	type row struct {
		on bool
		at time.Time
		by *string
	}
	set := map[string]row{}
	for rows.Next() {
		var name string
		var x row
		if err := rows.Scan(&name, &x.on, &x.at, &x.by); err != nil {
			rows.Close()
			return nil, err
		}
		set[name] = x
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]View, 0, len(Known))
	for _, f := range Known {
		v := View{Flag: f}
		if x, ok := set[f.Name]; ok {
			at := x.at
			v.Enabled, v.UpdatedAt, v.UpdatedBy = x.on, &at, x.by
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.views(r.Context(), s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// update sets flags: {"flags": {"connectors": true, ...}}. Flags not named
// keep their value.
func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Flags map[string]bool `json:"flags"`
	}
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(in.Flags) == 0 {
		s.fail(w, r, httpx.BadRequest("flags is required: an object of flag name to true or false"))
		return
	}
	bad := map[string]string{}
	for name := range in.Flags {
		if !IsKnown(name) {
			bad[name] = "unknown feature flag"
		}
	}
	if len(bad) > 0 {
		s.fail(w, r, &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: "unknown feature flag", Fields: bad})
		return
	}
	names := make([]string, 0, len(in.Flags))
	for _, f := range Known { // stable order for the audit log
		if _, ok := in.Flags[f.Name]; ok {
			names = append(names, f.Name)
		}
	}
	var out []View
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		for _, name := range names {
			on := in.Flags[name]
			var was bool
			err := tx.QueryRow(ctx, `SELECT enabled FROM feature_flags WHERE organization_id = $1 AND name = $2 FOR UPDATE`, p.OrganizationID, name).Scan(&was)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if was == on {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO feature_flags (id, organization_id, name, enabled, updated_by, updated_at)
				VALUES ($1, $2, $3, $4, $5, now())
				ON CONFLICT (organization_id, name) DO UPDATE SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = now()`,
				uuid.Must(uuid.NewV7()), p.OrganizationID, name, on, p.UserID); err != nil {
				return err
			}
			if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "feature_flag.update", TargetType: "feature_flag", TargetID: name,
				Metadata: map[string]any{"enabled": on, "was_enabled": was}}); err != nil {
				return err
			}
		}
		var err error
		out, err = s.views(ctx, tx, p.OrganizationID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
