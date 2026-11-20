package compliance

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/lifecycle"
	"pathos/internal/org"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/httpx"
)

// Service serves compliance views over the caller's findings.
type Service struct {
	DB        *pgxpool.Pool
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/compliance/frameworks", s.list)
	mux.HandleFunc("GET /api/v1/compliance/frameworks/{key}", s.get)
	mux.HandleFunc("GET /api/v1/compliance/frameworks/{key}/export", s.export)
}

// ControlStatus is a control with the open findings mapped to it.
type ControlStatus struct {
	Control
	// Status: failing (open critical or high findings), attention (other
	// open findings), passing (none) or not_applicable (no repository in
	// scope).
	Status       string         `json:"status"`
	Open         int            `json:"open_findings"`
	BySeverity   map[string]int `json:"by_severity"`
	Repositories int            `json:"repositories"`
}

// Summary is a framework with its control results.
type Summary struct {
	Key            string          `json:"key"`
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	ScopeKey       string          `json:"scope_key"`
	Description    string          `json:"description"`
	RepositoriesIn int             `json:"repositories_in_scope"`
	Failing        int             `json:"failing"`
	Attention      int             `json:"attention"`
	Passing        int             `json:"passing"`
	Controls       []ControlStatus `json:"controls,omitempty"`
	// LifecycleEvidence (PATHOS 3.0 M9): CodeGraph, threat models,
	// remediation and gates for the framework's repositories, each section
	// stating its evidence (framework detail and export only).
	LifecycleEvidence []lifecycle.Section `json:"lifecycle_evidence,omitempty"`
}

func (s *Service) evaluate(ctx context.Context, p *authz.Principal, f Framework, withControls bool) (Summary, error) {
	out := Summary{Key: f.Key, Name: f.Name, Version: f.Version, ScopeKey: f.ScopeKey, Description: f.Description}
	filter := authz.FilterFor(p, authz.PermFindingsRead)
	scope, sargs := org.ScopeSQL(filter, "r.id", "r.business_unit_id", "r.country_id", 2)
	base := append([]any{p.OrganizationID}, sargs...)
	// Repositories in the framework's scope that the caller can see.
	args := append([]any{}, base...)
	ph := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }
	inScope := "true"
	if f.ScopeKey != "" {
		inScope = "EXISTS (SELECT 1 FROM repository_compliance_scopes cs WHERE cs.repository_id = r.id AND cs.scope_key = " + ph(f.ScopeKey) + ")"
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND `+scope+` AND `+inScope,
		args...).Scan(&out.RepositoriesIn); err != nil {
		return out, err
	}
	for _, c := range f.Controls {
		args = append([]any{}, base...)
		cs := ControlStatus{Control: c, BySeverity: map[string]int{}}
		rows, err := s.DB.Query(ctx, `SELECT f.severity, count(*), count(DISTINCT f.repository_id) FROM findings f JOIN repositories r ON r.id = f.repository_id
			WHERE f.organization_id = $1 AND r.archived_at IS NULL AND `+scope+` AND f.status IN ('open', 'in_progress', 'needs_review')
			  AND `+ScopeSQL(f, ph)+` AND `+MatchSQL(c, ph)+` GROUP BY f.severity`, args...)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var sev string
			var n, repos int
			if err := rows.Scan(&sev, &n, &repos); err != nil {
				rows.Close()
				return out, err
			}
			cs.BySeverity[sev] = n
			cs.Open += n
			cs.Repositories = max(cs.Repositories, repos)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
		switch {
		case out.RepositoriesIn == 0:
			cs.Status = "not_applicable"
		case cs.BySeverity["critical"]+cs.BySeverity["high"] > 0:
			cs.Status = "failing"
			out.Failing++
		case cs.Open > 0:
			cs.Status = "attention"
			out.Attention++
		default:
			cs.Status = "passing"
			out.Passing++
		}
		if withControls {
			out.Controls = append(out.Controls, cs)
		}
	}
	return out, nil
}

func (s *Service) principal(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil || authz.FilterFor(p, authz.PermFindingsRead).None() {
		return nil, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, authz.ErrForbidden) {
		err = httpx.ErrForbidden
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]Summary, 0, len(Frameworks))
	for _, f := range Frameworks {
		sum, err := s.evaluate(r.Context(), p, f, false)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, sum)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items,
		"note": complianceNote})
}

func (s *Service) detail(r *http.Request) (*authz.Principal, Summary, error) {
	p, err := s.principal(r)
	if err != nil {
		return nil, Summary{}, err
	}
	f, ok := Lookup(r.PathValue("key"))
	if !ok {
		return nil, Summary{}, httpx.ErrNotFound
	}
	sum, err := s.evaluate(r.Context(), p, f, true)
	if err != nil {
		return nil, sum, err
	}
	// The framework's repositories in the caller's scope.
	scope, sargs := org.ScopeSQL(authz.FilterFor(p, authz.PermFindingsRead), "r.id", "r.business_unit_id", "r.country_id", 2)
	if f.ScopeKey != "" {
		sargs = append(sargs, f.ScopeKey)
		scope += " AND EXISTS (SELECT 1 FROM repository_compliance_scopes cs WHERE cs.repository_id = r.id AND cs.scope_key = $" + strconv.Itoa(len(sargs)+1) + ")"
	}
	sum.LifecycleEvidence, err = lifecycle.Sections(r.Context(), s.DB, p, lifecycle.Scope{OrgID: p.OrganizationID, RepoCond: scope, Args: sargs})
	return p, sum, err
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	_, sum, err := s.detail(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sum)
}

// export: GET /api/v1/compliance/frameworks/{key}/export?format=json|csv,
// a version-stamped compliance report (findings.export).
func (s *Service) export(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		s.fail(w, r, httpx.E(http.StatusBadRequest, "unsupported_format", "format must be json or csv").WithDiag("PTH-REP-1101"))
		return
	}
	p, sum, err := s.detail(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermFindingsExport) {
		s.fail(w, r, httpx.ErrForbidden.WithDiag("PTH-REP-1001"))
		return
	}
	now := time.Now().UTC()
	_ = audit.Write(r.Context(), s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "compliance.export", TargetType: "compliance_framework", TargetID: sum.Key, Metadata: map[string]any{"format": format}})
	name := "pathos-compliance-" + sum.Key + "-" + now.Format("20060102")
	if format == "json" {
		httpx.Download(w, "application/json", name+".json")
		_ = json.NewEncoder(w).Encode(map[string]any{"generated_by": buildinfo.Stamp(now), "pathos_version": buildinfo.Version,
			"pathos_build": buildinfo.Commit, "generated_at": now, "note": complianceNote, "framework": sum})
		return
	}
	httpx.Download(w, "text/csv; charset=utf-8", name+".csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"control", "title", "status", "open_findings", "critical", "high", "medium", "low", "repositories"})
	for _, c := range sum.Controls {
		_ = cw.Write([]string{c.ID, c.Title, c.Status, strconv.Itoa(c.Open), strconv.Itoa(c.BySeverity["critical"]), strconv.Itoa(c.BySeverity["high"]),
			strconv.Itoa(c.BySeverity["medium"]), strconv.Itoa(c.BySeverity["low"]), strconv.Itoa(c.Repositories)})
	}
	cw.Flush()
}

const complianceNote = "Indicative mapping of open findings to controls; it is evidence for an assessment, not a compliance verdict."
