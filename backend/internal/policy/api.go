package policy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Service serves the security policies API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/security-policies", s.list)
	mux.HandleFunc("POST /api/v1/security-policies", s.create)
	mux.HandleFunc("POST /api/v1/security-policies/preview", s.preview)
	mux.HandleFunc("POST /api/v1/security-policies/evaluate", s.evaluateNow)
	mux.HandleFunc("GET /api/v1/security-policies/{id}", s.get)
	mux.HandleFunc("PUT /api/v1/security-policies/{id}", s.update)
	mux.HandleFunc("DELETE /api/v1/security-policies/{id}", s.remove)
	mux.HandleFunc("GET /api/v1/security-policies/{id}/violations", s.violations)
	mux.HandleFunc("GET /api/v1/findings/{id}/policies", s.findingPolicies)
}

// View is a policy as returned by the API.
type View struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Enabled        bool       `json:"enabled"`
	Conditions     Conditions `json:"conditions"`
	Actions        Actions    `json:"actions"`
	Version        int        `json:"version"`
	AppliesToPRs   bool       `json:"applies_to_pull_requests"`
	OpenViolations int        `json:"open_violations"`
	CreatedBy      string     `json:"created_by"`
	UpdatedBy      string     `json:"updated_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	EvaluatedAt    *time.Time `json:"evaluated_at"`
}

const viewSelect = `SELECT p.id, p.name, p.description, p.enabled, p.conditions, p.actions, p.version,
	(SELECT count(*) FROM policy_violations v WHERE v.policy_id = p.id AND v.resolved_at IS NULL),
	COALESCE(cu.email, ''), COALESCE(uu.email, ''), p.created_at, p.updated_at, p.evaluated_at
	FROM security_policies p LEFT JOIN users cu ON cu.id = p.created_by LEFT JOIN users uu ON uu.id = p.updated_by`

func scanView(row pgx.Row) (View, error) {
	var v View
	var c, a []byte
	err := row.Scan(&v.ID, &v.Name, &v.Description, &v.Enabled, &c, &a, &v.Version, &v.OpenViolations, &v.CreatedBy, &v.UpdatedBy,
		&v.CreatedAt, &v.UpdatedAt, &v.EvaluatedAt)
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(c, &v.Conditions); err != nil {
		return v, err
	}
	if err := json.Unmarshal(a, &v.Actions); err != nil {
		return v, err
	}
	v.AppliesToPRs = !v.Conditions.BranchOnly()
	return v, nil
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("a policy with this name already exists")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) requireRead(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil || !p.HasAnywhere(authz.PermFindingsRead) {
		return nil, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) requireManage(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, authz.ErrForbidden
	}
	return p, s.Authz.Require(r.Context(), p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID})
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireRead(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), viewSelect+` WHERE p.organization_id = $1 ORDER BY p.enabled DESC, lower(p.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (View, error) { return scanView(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []View{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireRead(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	v, err := scanView(s.DB.QueryRow(r.Context(), viewSelect+` WHERE p.organization_id = $1 AND p.id = $2`, p.OrganizationID, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

type input struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Enabled     *bool      `json:"enabled"`
	Conditions  Conditions `json:"conditions"`
	Actions     Actions    `json:"actions"`
}

func (in *input) validate() error {
	in.Name, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Description)
	if in.Name == "" || len(in.Name) > 200 {
		return httpx.BadRequest("name is required (at most 200 characters)")
	}
	if len(in.Description) > 2000 {
		return httpx.BadRequest("description: at most 2000 characters")
	}
	if err := Normalize(&in.Conditions, &in.Actions); err != nil {
		return httpx.BadRequest(err.Error())
	}
	return nil
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in input
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	enabled := in.Enabled == nil || *in.Enabled
	id := uuid.Must(uuid.NewV7())
	c, _ := json.Marshal(in.Conditions)
	a, _ := json.Marshal(in.Actions)
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `INSERT INTO security_policies (id, organization_id, name, description, enabled, conditions, actions, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`, id, p.OrganizationID, in.Name, in.Description, enabled, c, a, p.UserID); err != nil {
			return err
		}
		if _, err := Evaluate(r.Context(), tx, p.OrganizationID, nil); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "security_policy.create", TargetType: "security_policy", TargetID: id.String(),
			Metadata: map[string]any{"name": in.Name, "enabled": enabled, "conditions": in.Conditions, "actions": in.Actions}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := scanView(s.DB.QueryRow(r.Context(), viewSelect+` WHERE p.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, v)
}

func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	var in input
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	c, _ := json.Marshal(in.Conditions)
	a, _ := json.Marshal(in.Actions)
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		before, err := scanView(tx.QueryRow(r.Context(), viewSelect+` WHERE p.organization_id = $1 AND p.id = $2 FOR UPDATE OF p`, p.OrganizationID, id))
		if err != nil {
			return err
		}
		enabled := before.Enabled
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		if before.Actions.SLADays != nil {
			// Deadlines it tightened are recomputed; Evaluate below applies
			// the new definition and the other policies again.
			if err := RestoreSLA(r.Context(), tx, id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(r.Context(), `UPDATE security_policies SET name = $2, description = $3, enabled = $4, conditions = $5, actions = $6,
			version = version + 1, updated_by = $7, updated_at = now() WHERE id = $1`, id, in.Name, in.Description, enabled, c, a, p.UserID); err != nil {
			return err
		}
		if !enabled {
			// A disabled policy has no open violations.
			if _, err := tx.Exec(r.Context(), `UPDATE policy_violations SET resolved_at = now() WHERE policy_id = $1 AND resolved_at IS NULL`, id); err != nil {
				return err
			}
		}
		if _, err := Evaluate(r.Context(), tx, p.OrganizationID, nil); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "security_policy.update", TargetType: "security_policy", TargetID: id.String(),
			Metadata: map[string]any{"before": map[string]any{"name": before.Name, "enabled": before.Enabled, "conditions": before.Conditions, "actions": before.Actions},
				"after": map[string]any{"name": in.Name, "enabled": enabled, "conditions": in.Conditions, "actions": in.Actions}}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := scanView(s.DB.QueryRow(r.Context(), viewSelect+` WHERE p.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Service) remove(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(r.Context(), `SELECT true FROM security_policies WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
			p.OrganizationID, id).Scan(&exists); err != nil {
			return err
		}
		if err := RestoreSLA(r.Context(), tx, id); err != nil {
			return err
		}
		var name string
		if err := tx.QueryRow(r.Context(), `DELETE FROM security_policies WHERE organization_id = $1 AND id = $2 RETURNING name`,
			p.OrganizationID, id).Scan(&name); err != nil {
			return err
		}
		if _, err := Evaluate(r.Context(), tx, p.OrganizationID, nil); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "security_policy.delete", TargetType: "security_policy", TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Match is a finding matched by a policy.
type Match struct {
	FindingID      uuid.UUID  `json:"finding_id"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	Category       string     `json:"category"`
	RepositoryID   uuid.UUID  `json:"repository_id"`
	RepositoryName string     `json:"repository_name"`
	Status         string     `json:"status"`
	FirstMatchedAt *time.Time `json:"first_matched_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}

// preview counts the open findings a draft policy would match (in the
// caller's scope) without saving anything.
func (s *Service) preview(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireRead(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Conditions Conditions `json:"conditions"`
	}
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	act := Actions{Notify: true}
	if err := Normalize(&in.Conditions, &act); err != nil {
		s.fail(w, r, httpx.BadRequest(err.Error()))
		return
	}
	f := authz.FilterFor(p, authz.PermFindingsRead)
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args = append([]any{p.OrganizationID}, args...)
	where, err := Where(in.Conditions, FindingColumns, &args)
	if err != nil {
		s.fail(w, r, httpx.BadRequest(err.Error()))
		return
	}
	base := ` FROM findings f JOIN repositories r ON r.id = f.repository_id
		WHERE f.organization_id = $1 AND f.status IN ` + openStatuses + ` AND r.archived_at IS NULL AND ` + scope + ` AND ` + where
	var total int
	if err := s.DB.QueryRow(r.Context(), `SELECT count(*)`+base, args...).Scan(&total); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT f.id, f.title, f.severity, f.category, r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), f.status`+base+`
		ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity), f.risk_score DESC NULLS LAST LIMIT 20`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sample, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Match, error) {
		var m Match
		return m, r.Scan(&m.FindingID, &m.Title, &m.Severity, &m.Category, &m.RepositoryID, &m.RepositoryName, &m.Status)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if sample == nil {
		sample = []Match{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"matching": total, "sample": sample, "applies_to_pull_requests": !in.Conditions.BranchOnly()})
}

func (s *Service) violations(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireRead(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	var exists bool
	if err := s.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM security_policies WHERE organization_id = $1 AND id = $2)`,
		p.OrganizationID, id).Scan(&exists); err != nil || !exists {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	f := authz.FilterFor(p, authz.PermFindingsRead)
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 3)
	args = append([]any{id, r.URL.Query().Get("status") == "resolved"}, args...)
	rows, err := s.DB.Query(r.Context(), `SELECT f.id, f.title, f.severity, f.category, r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), f.status,
		  v.first_matched_at, v.resolved_at
		FROM policy_violations v JOIN findings f ON f.id = v.finding_id JOIN repositories r ON r.id = v.repository_id
		WHERE v.policy_id = $1 AND (v.resolved_at IS NOT NULL) = $2 AND `+scope+`
		ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity), v.first_matched_at DESC LIMIT 500`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Match, error) {
		var m Match
		return m, r.Scan(&m.FindingID, &m.Title, &m.Severity, &m.Category, &m.RepositoryID, &m.RepositoryName, &m.Status, &m.FirstMatchedAt, &m.ResolvedAt)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Match{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// findingPolicies lists the policies an open finding violates.
func (s *Service) findingPolicies(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireRead(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	f := authz.FilterFor(p, authz.PermFindingsRead)
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 3)
	args = append([]any{p.OrganizationID, id}, args...)
	var visible bool
	if err := s.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM findings fi JOIN repositories r ON r.id = fi.repository_id
		WHERE fi.organization_id = $1 AND fi.id = $2 AND `+scope+`)`, args...).Scan(&visible); err != nil || !visible {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	type pol struct {
		ID      uuid.UUID `json:"id"`
		Name    string    `json:"name"`
		Actions Actions   `json:"actions"`
		Since   time.Time `json:"since"`
	}
	rows, err := s.DB.Query(r.Context(), `SELECT p.id, p.name, p.actions, v.first_matched_at FROM policy_violations v
		JOIN security_policies p ON p.id = v.policy_id WHERE v.finding_id = $1 AND v.resolved_at IS NULL ORDER BY p.name`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pol, error) {
		var x pol
		var a []byte
		if err := r.Scan(&x.ID, &x.Name, &a, &x.Since); err != nil {
			return x, err
		}
		return x, json.Unmarshal(a, &x.Actions)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []pol{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Service) evaluateNow(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var n int
	err = pgx.BeginFunc(r.Context(), s.DB, func(tx pgx.Tx) error {
		var err error
		n, err = Evaluate(r.Context(), tx, p.OrganizationID, nil)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"open_violations": n})
}
