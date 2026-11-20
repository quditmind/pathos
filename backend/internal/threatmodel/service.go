package threatmodel

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/tenant"
	"pathos/internal/threatmodel/frameworks"
)

// Error codes (catalogue: internal/platform/diag/catalogue_tm.go).
const (
	CodeState            = "PTH-TM-1001"
	CodeNoSnapshot       = "PTH-TM-1002"
	CodeEvidence         = "PTH-TM-1003"
	CodeNoMitigation     = "PTH-TM-1004"
	CodeSelfApproval     = "PTH-TM-1005"
	CodeUnverified       = "PTH-TM-1006"
	CodeReason           = "PTH-TM-1007"
	CodeExists           = "PTH-TM-1008"
	CodeGenerated        = "PTH-TM-1009"
	CodeGenerateFailed   = "PTH-TM-1010"
	CodeImportParse      = "PTH-TM-1101"
	CodeImportFormat     = "PTH-TM-1102"
	CodeImportTooLarge   = "PTH-TM-1103"
	flagName             = "threat_models"
	maxImportBodyBytes   = 10 << 20
	defaultAttackMinRisk = 50
)

// Service serves the threat-model API (behind the threat_models flag).
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/threat-frameworks", s.frameworksIndex)
	mux.HandleFunc("GET /api/v1/threat-frameworks/{framework}/entries", s.frameworkEntries)
	mux.HandleFunc("GET /api/v1/threat-models/settings", s.getSettings)
	mux.HandleFunc("PUT /api/v1/threat-models/settings", s.putSettings)
	mux.HandleFunc("POST /api/v1/threat-models/import", s.importModel)
	mux.HandleFunc("GET /api/v1/threat-models", s.list)
	mux.HandleFunc("POST /api/v1/threat-models", s.create)
	mux.HandleFunc("GET /api/v1/threat-models/{id}", s.get)
	mux.HandleFunc("PATCH /api/v1/threat-models/{id}", s.patch)
	mux.HandleFunc("POST /api/v1/threat-models/{id}/generate", s.generate)
	mux.HandleFunc("GET /api/v1/threat-models/{id}/versions", s.versions)
	mux.HandleFunc("POST /api/v1/threat-models/{id}/versions", s.newVersion)
	mux.HandleFunc("GET /api/v1/threat-models/{id}/threats", s.threats)
	mux.HandleFunc("POST /api/v1/threat-models/{id}/threats", s.addThreat)
	mux.HandleFunc("POST /api/v1/threat-models/{id}/submit", s.submit)
	mux.HandleFunc("POST /api/v1/threat-models/{id}/approve", s.approve)
	mux.HandleFunc("POST /api/v1/threat-models/{id}/reject", s.reject)
	mux.HandleFunc("GET /api/v1/threat-models/{id}/diagram", s.diagram)
	mux.HandleFunc("GET /api/v1/threat-models/{id}/export", s.export)
	mux.HandleFunc("GET /api/v1/threats/{id}", s.getThreat)
	mux.HandleFunc("PATCH /api/v1/threats/{id}", s.patchThreat)
	mux.HandleFunc("DELETE /api/v1/threats/{id}", s.deleteThreat)
}

var errNotFound = errors.New("not found")

func stateErr(msg string) error {
	return httpx.E(http.StatusConflict, "threat_model_state", msg).WithDiag(CodeState)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ge *ErrGenerate
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case errors.Is(err, errNoSnapshot):
		err = httpx.E(http.StatusConflict, "no_codegraph_snapshot",
			"the application has no ready CodeGraph snapshot; build CodeGraph for it first").WithDiag(CodeNoSnapshot)
	case errors.As(err, &ge):
		s.Log.Error("threat generation failed", "err", ge.Err, "error_code", CodeGenerateFailed, "request_id", httpx.RequestID(r))
		err = httpx.E(http.StatusInternalServerError, "threat_generation_failed", "the generated threats could not be stored").WithDiag(CodeGenerateFailed)
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" && strings.Contains(pe.ConstraintName, "threat_models_open_uq") {
		err = stateErr("another draft or in-review version of this model exists")
	}
	httpx.WriteError(w, r, s.Log, err)
}

// caller returns the principal after the flag check.
func (s *Service) caller(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, flagName); err != nil {
		return nil, err
	}
	return p, nil
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

// requireScope checks perm on the model's scope: the repository, or every
// active repository of the application (organization-wide grants cover
// all). Callers without access get 404, unless they hold perm nowhere.
func (s *Service) requireScope(ctx context.Context, p *authz.Principal, perm authz.Permission, appID uuid.UUID, repoID *uuid.UUID) error {
	if p.HasOrgWide(perm) {
		return nil
	}
	hide := func(err error) error {
		if errors.Is(err, org.ErrScopeNotFound) || (errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm)) {
			return errNotFound
		}
		return err
	}
	if repoID != nil {
		return hide(s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: *repoID}))
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND application_id = $2 AND archived_at IS NULL`,
		p.OrganizationID, appID)
	if err != nil {
		return err
	}
	repos, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return hide(authz.ErrForbidden)
	}
	for _, id := range repos {
		if err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: id}); err != nil {
			return hide(err)
		}
	}
	return nil
}

// model loads a model version and checks perm on its scope.
func (s *Service) model(ctx context.Context, p *authz.Principal, id uuid.UUID, perm authz.Permission) (Model, error) {
	m, err := getModel(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		return m, err
	}
	if err := s.requireScope(ctx, p, perm, m.ApplicationID, m.RepositoryID); err != nil {
		return m, err
	}
	s.decorate(ctx, p, &m)
	return m, nil
}

// decorate sets what the caller may do with the version.
func (s *Service) decorate(ctx context.Context, p *authz.Principal, m *Model) {
	m.CanEdit = m.Status == "draft" && s.requireScope(ctx, p, authz.PermThreatsManage, m.ApplicationID, m.RepositoryID) == nil
	m.CanApprove = m.Status == "in_review" && !isAuthor(*m, p.UserID) &&
		s.requireScope(ctx, p, authz.PermThreatsApprove, m.ApplicationID, m.RepositoryID) == nil
}

func isAuthor(m Model, user uuid.UUID) bool {
	return (m.CreatedBy != nil && m.CreatedBy.ID == user) || (m.SubmittedBy != nil && m.SubmittedBy.ID == user)
}

func (s *Service) audit(ctx context.Context, q db.Querier, r *http.Request, p *authz.Principal, action string, m Model, meta map[string]any) error {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["application_id"], meta["version"], meta["lineage_id"] = m.ApplicationID, m.Version, m.LineageID
	return audit.Write(ctx, q, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email, Action: action,
		TargetType: "threat_model", TargetID: m.ID.String(), RequestID: httpx.RequestID(r), Metadata: meta})
}

// --- models ----------------------------------------------------------------------

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermThreatsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	var appID *uuid.UUID
	if v := q.Get("application_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("application_id must be a UUID"))
			return
		}
		appID = &id
	}
	status := q.Get("status")
	if status != "" && !slices.Contains([]string{"draft", "in_review", "approved", "superseded", "archived"}, status) {
		s.fail(w, r, httpx.BadRequest("unknown status"))
		return
	}
	// The latest version of each model.
	rows, err := s.DB.Query(ctx, `SELECT * FROM (`+modelSelect+` WHERE m.organization_id = $1 AND ($2::uuid IS NULL OR m.application_id = $2)
		AND m.version = (SELECT max(x.version) FROM threat_models x WHERE x.lineage_id = m.lineage_id)) y
		WHERE ($3 = '' OR y.status = $3) ORDER BY y.updated_at DESC, y.id LIMIT 500`, p.OrganizationID, appID, status)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Model, error) { return scanModel(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := []*Model{}
	for i := range all {
		if err := s.requireScope(ctx, p, authz.PermThreatsRead, all[i].ApplicationID, all[i].RepositoryID); err != nil {
			if errors.Is(err, errNotFound) || errors.Is(err, authz.ErrForbidden) {
				continue
			}
			s.fail(w, r, err)
			return
		}
		s.decorate(ctx, p, &all[i])
		out = append(out, &all[i])
	}
	if err := fillCounts(ctx, s.DB, out); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type createRequest struct {
	ApplicationID uuid.UUID  `json:"application_id"`
	RepositoryID  *uuid.UUID `json:"repository_id"`
	Title         string     `json:"title"`
	Summary       string     `json:"summary"`
	Generate      bool       `json:"generate"`
}

// newModel inserts version 1 of a model (application and repository checked).
func (s *Service) newModel(ctx context.Context, tx pgx.Tx, p *authz.Principal, appID uuid.UUID, repoID *uuid.UUID, title, summary, method, format string) (uuid.UUID, error) {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, appID).Scan(&ok); err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, errNotFound
	}
	if repoID != nil {
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repositories WHERE organization_id = $1 AND id = $2 AND application_id = $3)`,
			p.OrganizationID, *repoID, appID).Scan(&ok); err != nil {
			return uuid.Nil, err
		}
		if !ok {
			return uuid.Nil, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "repository_id is not a repository of the application")
		}
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM threat_models WHERE organization_id = $1 AND application_id = $2
		AND repository_id IS NOT DISTINCT FROM $3)`, p.OrganizationID, appID, repoID).Scan(&exists); err != nil {
		return uuid.Nil, err
	}
	if exists {
		return uuid.Nil, httpx.E(http.StatusConflict, "threat_model_exists", "a threat model already exists for this application and repository scope").WithDiag(CodeExists)
	}
	id := uuid.Must(uuid.NewV7())
	_, err := tx.Exec(ctx, `INSERT INTO threat_models (id, organization_id, lineage_id, version, application_id, repository_id, status, method,
		imported_format, title, summary, created_by) VALUES ($1, $2, $1, 1, $3, $4, 'draft', $5, $6, $7, $8, $9)`,
		id, p.OrganizationID, appID, repoID, method, format, title, summary, p.UserID)
	return id, err
}

func validTitle(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t == "" || len(t) > 200 {
		return "", httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "title must be 1 to 200 characters")
	}
	return t, nil
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in createRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	title, err := validTitle(in.Title)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(in.Summary) > 8000 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "summary is at most 8000 characters"))
		return
	}
	if err := s.requireScope(ctx, p, authz.PermThreatsManage, in.ApplicationID, in.RepositoryID); err != nil {
		s.fail(w, r, err)
		return
	}
	var gen *generated
	engines := slices.Clone(Engines)
	if in.Generate {
		gen, err = compute(ctx, s.DB, Model{orgID: p.OrganizationID, ApplicationID: in.ApplicationID, RepositoryID: in.RepositoryID}, p, engines)
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var id uuid.UUID
	var res GenResult
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if id, err = s.newModel(ctx, tx, p, in.ApplicationID, in.RepositoryID, title, in.Summary, map[bool]string{true: "stride", false: MethodManual}[in.Generate], ""); err != nil {
			return err
		}
		m, err := getModel(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if gen != nil {
			if res, err = apply(ctx, tx, m, gen, engines, &p.UserID); err != nil {
				return &ErrGenerate{err}
			}
		}
		return s.audit(ctx, tx, r, p, "threat_model.create", m, map[string]any{"title": title, "generated": in.Generate, "result": res})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"model": m, "result": res})
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	els, err := listElements(ctx, s.DB, m.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	vs, err := s.lineage(ctx, p, m)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"model": m, "elements": els, "versions": vs})
}

func (s *Service) lineage(ctx context.Context, p *authz.Principal, m Model) ([]*Model, error) {
	rows, err := s.DB.Query(ctx, modelSelect+` WHERE m.organization_id = $1 AND m.lineage_id = $2 ORDER BY m.version DESC`, p.OrganizationID, m.LineageID)
	if err != nil {
		return nil, err
	}
	vs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Model, error) { return scanModel(r) })
	if err != nil {
		return nil, err
	}
	out := make([]*Model, len(vs))
	for i := range vs {
		s.decorate(ctx, p, &vs[i])
		out[i] = &vs[i]
	}
	return out, fillCounts(ctx, s.DB, out)
}

type patchRequest struct {
	Title   *string `json:"title"`
	Summary *string `json:"summary"`
}

// draftFor loads a model for an edit: threats.manage and draft status.
func (s *Service) draftFor(ctx context.Context, p *authz.Principal, id uuid.UUID) (Model, error) {
	m, err := s.model(ctx, p, id, authz.PermThreatsManage)
	if err != nil {
		return m, err
	}
	if m.Status != "draft" {
		return m, stateErr("version " + strconv.Itoa(m.Version) + " is " + strings.ReplaceAll(m.Status, "_", " ") + "; only a draft can be changed")
	}
	return m, nil
}

func (s *Service) patch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in patchRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.draftFor(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	title, summary := m.Title, m.Summary
	if in.Title != nil {
		if title, err = validTitle(*in.Title); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if in.Summary != nil {
		if len(*in.Summary) > 8000 {
			s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "summary is at most 8000 characters"))
			return
		}
		summary = *in.Summary
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE threat_models SET title = $2, summary = $3, updated_at = now() WHERE id = $1 AND status = 'draft'`, m.ID, title, summary); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model.update", m, map[string]any{"title": title})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondModel(w, r, p, m.ID, http.StatusOK, nil)
}

func (s *Service) respondModel(w http.ResponseWriter, r *http.Request, p *authz.Principal, id uuid.UUID, status int, result any) {
	m, err := s.model(r.Context(), p, id, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if result != nil {
		httpx.WriteJSON(w, status, map[string]any{"model": m, "result": result})
		return
	}
	httpx.WriteJSON(w, status, m)
}

type generateRequest struct {
	Engines []string `json:"engines"`
}

// openVersion returns the draft to work in: the model itself when it is a
// draft, else a new draft version after it (created in tx). A version that
// is not the latest, or an in-review version, is refused.
func openVersion(ctx context.Context, tx pgx.Tx, m Model, actor *uuid.UUID) (uuid.UUID, bool, error) {
	var latest int
	if err := tx.QueryRow(ctx, `SELECT max(version) FROM threat_models WHERE lineage_id = $1`, m.LineageID).Scan(&latest); err != nil {
		return uuid.Nil, false, err
	}
	switch {
	case m.Version != latest:
		return uuid.Nil, false, stateErr("a newer version of this model exists; open the latest version")
	case m.Status == "draft":
		return m.ID, false, nil
	case m.Status == "approved":
		id, err := copyVersion(ctx, tx, m, actor)
		return id, true, err
	}
	return uuid.Nil, false, stateErr("version " + strconv.Itoa(m.Version) + " is " + strings.ReplaceAll(m.Status, "_", " "))
}

func (s *Service) generate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in generateRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &in); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	engines := in.Engines
	if len(engines) == 0 {
		engines = slices.Clone(Engines)
	}
	for _, e := range engines {
		if !slices.Contains(Engines, e) {
			s.fail(w, r, httpx.BadRequest("unknown engine "+strconv.Quote(e)+"; engines are stride and attack_paths (LINDDUN threats are added manually)"))
			return
		}
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	gen, err := compute(ctx, s.DB, m, p, engines)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var res GenResult
	var target uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var created bool
		var err error
		if target, created, err = openVersion(ctx, tx, m, &p.UserID); err != nil {
			return err
		}
		tm, err := getModel(ctx, tx, p.OrganizationID, target)
		if err != nil {
			return err
		}
		if res, err = apply(ctx, tx, tm, gen, engines, &p.UserID); err != nil {
			return &ErrGenerate{err}
		}
		res.CreatedVersion = created
		return s.audit(ctx, tx, r, p, "threat_model.generate", tm, map[string]any{"engines": engines, "result": res})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondModel(w, r, p, target, http.StatusOK, res)
}

func (s *Service) newVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var nid uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM threat_models WHERE lineage_id = $1 AND status IN ('draft', 'in_review')`, m.LineageID).Scan(&open); err != nil {
			return err
		}
		if open > 0 {
			return stateErr("a draft or in-review version of this model exists")
		}
		var err error
		if nid, err = copyVersion(ctx, tx, m, &p.UserID); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model.new_version", m, map[string]any{"new_version_id": nid})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondModel(w, r, p, nid, http.StatusCreated, nil)
}

func (s *Service) versions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	vs, err := s.lineage(ctx, p, m)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	as, err := listApprovals(ctx, s.DB, m.LineageID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if as == nil {
		as = []Approval{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": vs, "approvals": as})
}

// --- review ------------------------------------------------------------------------

type noteRequest struct {
	Note     string `json:"note"`
	Decision string `json:"decision"`
}

func (s *Service) decodeNote(w http.ResponseWriter, r *http.Request) (noteRequest, error) {
	var in noteRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &in); err != nil {
			return in, err
		}
	}
	if len(in.Note) > 4000 {
		return in, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "note is at most 4000 characters")
	}
	return in, nil
}

func (s *Service) submit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := s.decodeNote(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.draftFor(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if m.Counts.Total == 0 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_model_empty", "the model has no threats; generate or add threats first").WithDiag(CodeNoMitigation))
		return
	}
	if n := m.Counts.WithoutMitigation; n > 0 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_without_mitigation",
			strconv.Itoa(n)+" open or accepted threat(s) have no mitigation").WithDiag(CodeNoMitigation))
		return
	}
	if n := m.Counts.Unverified; n > 0 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_unverified",
			strconv.Itoa(n)+" manual or imported threat(s) are not linked to evidence; link them or set them not applicable").WithDiag(CodeUnverified))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE threat_models SET status = 'in_review', submitted_by = $2, submitted_at = now(), updated_at = now()
			WHERE id = $1 AND status = 'draft'`, m.ID, p.UserID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return stateErr("the version is no longer a draft")
		}
		if err := addApproval(ctx, tx, m, "submitted", p.UserID, in.Note); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model.submit", m, nil)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondModel(w, r, p, m.ID, http.StatusOK, nil)
}

// reviewFor loads a model for a decision: threats.approve, in review, and
// the caller is neither its author nor its submitter.
func (s *Service) reviewFor(ctx context.Context, p *authz.Principal, id uuid.UUID) (Model, error) {
	m, err := s.model(ctx, p, id, authz.PermThreatsApprove)
	if err != nil {
		if errors.Is(err, errNotFound) && !p.HasAnywhere(authz.PermThreatsApprove) {
			return m, authz.ErrForbidden
		}
		return m, err
	}
	if m.Status != "in_review" {
		return m, stateErr("version " + strconv.Itoa(m.Version) + " is " + strings.ReplaceAll(m.Status, "_", " ") + ", not in review")
	}
	if isAuthor(m, p.UserID) {
		return m, httpx.E(http.StatusConflict, "threat_model_self_approval",
			"you created or submitted this version; another person must review it").WithDiag(CodeSelfApproval)
	}
	return m, nil
}

func (s *Service) approve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := s.decodeNote(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.reviewFor(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE threat_models SET status = 'superseded', updated_at = now() WHERE lineage_id = $1 AND status = 'approved'`, m.LineageID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE threat_models SET status = 'approved', approved_by = $2, approved_at = now(), updated_at = now()
			WHERE id = $1 AND status = 'in_review'`, m.ID, p.UserID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return stateErr("the version is no longer in review")
		}
		if err := addApproval(ctx, tx, m, "approved", p.UserID, in.Note); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model.approve", m, map[string]any{"note": in.Note})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondModel(w, r, p, m.ID, http.StatusOK, nil)
}

func (s *Service) reject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := s.decodeNote(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Decision == "" {
		in.Decision = "changes_requested"
	}
	if in.Decision != "rejected" && in.Decision != "changes_requested" {
		s.fail(w, r, httpx.BadRequest("decision must be rejected or changes_requested"))
		return
	}
	if strings.TrimSpace(in.Note) == "" {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "say what must change (note)"))
		return
	}
	m, err := s.reviewFor(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE threat_models SET status = 'draft', submitted_by = NULL, submitted_at = NULL, updated_at = now()
			WHERE id = $1 AND status = 'in_review'`, m.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return stateErr("the version is no longer in review")
		}
		if err := addApproval(ctx, tx, m, in.Decision, p.UserID, in.Note); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model."+in.Decision, m, map[string]any{"note": in.Note})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondModel(w, r, p, m.ID, http.StatusOK, nil)
}

// --- settings and frameworks --------------------------------------------------------

// Settings are the organization's threat-model settings.
type Settings struct {
	AutoUpdate bool `json:"auto_update"`
}

func loadSettings(ctx context.Context, q db.Querier, orgID uuid.UUID) (Settings, error) {
	st := Settings{AutoUpdate: true}
	err := q.QueryRow(ctx, `SELECT auto_update FROM threat_model_settings WHERE organization_id = $1`, orgID).Scan(&st.AutoUpdate)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return st, err
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermThreatsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	st, err := loadSettings(r.Context(), s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) putSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasOrgWide(authz.PermThreatsManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var in Settings
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO threat_model_settings (organization_id, auto_update, updated_by, updated_at) VALUES ($1, $2, $3, now())
			ON CONFLICT (organization_id) DO UPDATE SET auto_update = EXCLUDED.auto_update, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			p.OrganizationID, in.AutoUpdate, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "threat_model.settings.update", TargetType: "threat_model_settings", TargetID: p.OrganizationID.String(),
			RequestID: httpx.RequestID(r), Metadata: map[string]any{"auto_update": in.AutoUpdate}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, in)
}

func (s *Service) frameworksIndex(w http.ResponseWriter, r *http.Request) {
	if _, err := s.caller(r); err != nil {
		s.fail(w, r, err)
		return
	}
	rel, err := frameworks.Releases()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	stride := []map[string]string{}
	for _, c := range StrideCategories {
		stride = append(stride, map[string]string{"id": c, "name": CategoryLabels[c]})
	}
	rules := append(slices.Clone(Rules), AttackPathRule)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"frameworks": rel, "rules": rules, "stride": stride,
		"linddun": frameworks.Linddun(), "notices": frameworks.Notices()})
}

func (s *Service) frameworkEntries(w http.ResponseWriter, r *http.Request) {
	if _, err := s.caller(r); err != nil {
		s.fail(w, r, err)
		return
	}
	f := r.PathValue("framework")
	if !slices.Contains(frameworks.Bundled, f) && f != frameworks.LINDDUN {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			s.fail(w, r, httpx.BadRequest("limit must be 1 to 100"))
			return
		}
		limit = n
	}
	q := r.URL.Query().Get("q")
	if len(q) > 200 {
		s.fail(w, r, httpx.BadRequest("q is at most 200 characters"))
		return
	}
	items, err := frameworks.Search(f, q, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []frameworks.Entry{}
	}
	release, notice := "categories only", "LINDDUN is developed by DistriNet, KU Leuven ("+frameworks.LinddunCitation+")."
	if d, err := frameworks.Get(f); err == nil {
		release, notice = d.Release, d.Notice
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"framework": f, "release": release, "notice": notice, "items": items})
}

// --- feedback loop ------------------------------------------------------------------

// AutoUpdateOutcome is what the architecture feedback loop did to one
// threat model lineage after a new CodeGraph snapshot.
type AutoUpdateOutcome struct {
	// LineageID and Title identify the model.
	LineageID uuid.UUID
	Title     string
	// ModelID and Version: the version that holds the regenerated draft
	// (Updated), or the latest version left alone (review needed).
	ModelID uuid.UUID
	Version int
	// Updated: the draft was regenerated (in place, or as a new draft
	// version after the approved one: CreatedVersion). Otherwise the model
	// needs a review: automatic updates are off, the latest version is in
	// review, or it is a manual model that was never generated.
	Updated        bool
	CreatedVersion bool
	Reason         string
	Result         GenResult
	// ApprovedVersion is the approved version left unchanged, if any.
	ApprovedVersion int
}

// OnSnapshotReady regenerates the application's threat models in a draft
// after a new CodeGraph snapshot is stored (when the flag and auto_update
// are on): an existing draft in place, else a new draft version after the
// approved one; an in-review version is left alone. Errors are logged.
func (s *Service) OnSnapshotReady(ctx context.Context, orgID, appID, snapshotID uuid.UUID) {
	_, _ = s.AutoUpdate(ctx, orgID, appID, snapshotID)
}

// AutoUpdate is OnSnapshotReady returning what it did per model lineage
// (the monitoring feed records it, PATHOS 3.0 M9). Approved versions are
// never changed: a regenerated draft is a new version that needs review
// and approval. Without the threat_models flag it returns nothing.
func (s *Service) AutoUpdate(ctx context.Context, orgID, appID, snapshotID uuid.UUID) ([]AutoUpdateOutcome, error) {
	ctx = tenant.WithOrg(ctx, orgID)
	log := s.Log.With("application_id", appID, "snapshot_id", snapshotID)
	if on, err := featureflags.Enabled(ctx, s.DB, orgID, flagName); err != nil || !on {
		return nil, err
	}
	st, err := loadSettings(ctx, s.DB, orgID)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, `SELECT m.id FROM threat_models m WHERE m.organization_id = $1 AND m.application_id = $2
		AND m.version = (SELECT max(x.version) FROM threat_models x WHERE x.lineage_id = m.lineage_id)
		AND m.status IN ('draft', 'approved', 'in_review') AND m.method <> 'imported'`, orgID, appID)
	if err != nil {
		log.Warn("threat model auto-update: lookup failed", "err", err)
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	var out []AutoUpdateOutcome
	for _, id := range ids {
		m, err := getModel(ctx, s.DB, orgID, id)
		if err != nil {
			continue
		}
		oc := AutoUpdateOutcome{LineageID: m.LineageID, Title: m.Title, ModelID: m.ID, Version: m.Version}
		if m.Status == "approved" {
			oc.ApprovedVersion = m.Version
		}
		switch {
		case m.Status == "in_review":
			oc.Reason = "the latest version is in review; it was left unchanged"
			out = append(out, oc)
			continue
		case !st.AutoUpdate:
			oc.Reason = "automatic updates are off"
			out = append(out, oc)
			continue
		case m.Method == MethodManual && m.GeneratedAt == nil:
			continue // never generated: the author chose a manual model
		}
		gen, err := compute(ctx, s.DB, m, nil, Engines)
		if err != nil {
			log.Warn("threat model auto-update: generation failed", "err", err, "threat_model_id", id, "error_code", CodeGenerateFailed)
			continue
		}
		err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
			target, created, err := openVersion(ctx, tx, m, nil)
			if err != nil {
				return err
			}
			tm, err := getModel(ctx, tx, orgID, target)
			if err != nil {
				return err
			}
			res, err := apply(ctx, tx, tm, gen, Engines, nil)
			if err != nil {
				return err
			}
			res.CreatedVersion = created
			oc.ModelID, oc.Version, oc.Updated, oc.CreatedVersion, oc.Result = target, tm.Version, true, created, res
			return audit.Write(ctx, tx, audit.Entry{OrganizationID: orgID, Action: "threat_model.auto_update", TargetType: "threat_model",
				TargetID: target.String(), Metadata: map[string]any{"application_id": appID, "snapshot_id": snapshotID, "result": res,
					"version": tm.Version, "lineage_id": tm.LineageID}})
		})
		if err != nil {
			log.Warn("threat model auto-update failed", "err", err, "threat_model_id", id, "error_code", CodeGenerateFailed)
			continue
		}
		out = append(out, oc)
	}
	return out, nil
}
