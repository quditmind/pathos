package codegraph

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/objstore"
)

// Service serves the CodeGraph API (behind the codegraph feature flag).
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// Artifacts holds archived snapshots (nil: archived snapshots keep
	// only their summary).
	Artifacts objstore.Store
	// Now is the clock (tests).
	Now   func() time.Time
	cache *skeletonCache
}

// NewService returns a service with its skeleton cache.
func NewService(pool *pgxpool.Pool, az *authz.Authorizer, log *slog.Logger, principal func(context.Context) *authz.Principal, artifacts objstore.Store) *Service {
	return &Service{DB: pool, Authz: az, Log: log, Principal: principal, Artifacts: artifacts, cache: &skeletonCache{}}
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/codegraph/views", s.views)
	mux.HandleFunc("GET /api/v1/codegraph/settings", s.getSettings)
	mux.HandleFunc("PUT /api/v1/codegraph/settings", s.putSettings)
	mux.HandleFunc("POST /api/v1/codegraph/applications/{id}/build", s.build)
	mux.HandleFunc("GET /api/v1/codegraph/applications/{id}/snapshots", s.listSnapshots)
	mux.HandleFunc("GET /api/v1/codegraph/applications/{id}/snapshots/{sid}", s.getSnapshot)
	mux.HandleFunc("GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/graph", s.graph)
	mux.HandleFunc("GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/nodes/{nid}", s.node)
	mux.HandleFunc("GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/paths", s.paths)
	mux.HandleFunc("GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/export", s.export)
	mux.HandleFunc("GET /api/v1/codegraph/applications/{id}/diff", s.diff)
}

var errNotFound = errors.New("not found")

func errBadQuery(msg string) error {
	return httpx.E(http.StatusBadRequest, "invalid_request", msg).WithDiag(CodeBadQuery)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

// caller returns the principal after the flag check.
func (s *Service) caller(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, "codegraph"); err != nil {
		return nil, err
	}
	return p, nil
}

// requireRepo checks perm on a repository, hiding existence from callers
// without access.
func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repoID uuid.UUID) error {
	err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repoID})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, org.ErrScopeNotFound):
		return errNotFound
	case errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm):
		return errNotFound
	}
	return err
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

// application checks the application exists in the caller's organization.
func (s *Service) application(ctx context.Context, p *authz.Principal, r *http.Request) (uuid.UUID, string, error) {
	id, err := pathUUID(r, "id")
	if err != nil {
		return id, "", err
	}
	var name string
	err = s.DB.QueryRow(ctx, `SELECT name FROM applications WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id).Scan(&name)
	return id, name, err
}

// Snapshot is the API form of a snapshot.
type Snapshot struct {
	ID             uuid.UUID      `json:"id"`
	ApplicationID  uuid.UUID      `json:"application_id"`
	RepositoryID   uuid.UUID      `json:"repository_id"`
	RepositoryName string         `json:"repository_name"`
	ScanJobID      *uuid.UUID     `json:"scan_job_id"`
	Ref            string         `json:"ref"`
	CommitSHA      string         `json:"commit_sha"`
	Trigger        string         `json:"trigger"`
	Status         string         `json:"status"`
	Storage        string         `json:"storage"`
	NodeCount      int            `json:"node_count"`
	EdgeCount      int            `json:"edge_count"`
	Engines        map[string]any `json:"engines"`
	Stats          map[string]any `json:"stats"`
	ErrorCode      string         `json:"error_code,omitempty"`
	Error          string         `json:"error,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	StartedAt      *time.Time     `json:"started_at"`
	FinishedAt     *time.Time     `json:"finished_at"`
	ArchivedAt     *time.Time     `json:"archived_at"`
	objectKey      *string
	orgID          uuid.UUID
}

const snapshotSelect = `SELECT s.id, s.application_id, s.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name), s.scan_job_id,
	s.ref, s.commit_sha, s.trigger, s.status, s.storage, s.node_count, s.edge_count, s.engines, s.stats, s.error_code, s.error,
	s.created_at, s.started_at, s.finished_at, s.archived_at, s.object_key, s.organization_id
	FROM codegraph_snapshots s JOIN repositories r ON r.id = s.repository_id`

func scanSnapshot(row pgx.Row) (Snapshot, error) {
	var sn Snapshot
	var engines, stats []byte
	err := row.Scan(&sn.ID, &sn.ApplicationID, &sn.RepositoryID, &sn.RepositoryName, &sn.ScanJobID, &sn.Ref, &sn.CommitSHA, &sn.Trigger,
		&sn.Status, &sn.Storage, &sn.NodeCount, &sn.EdgeCount, &engines, &stats, &sn.ErrorCode, &sn.Error, &sn.CreatedAt,
		&sn.StartedAt, &sn.FinishedAt, &sn.ArchivedAt, &sn.objectKey, &sn.orgID)
	if err != nil {
		return sn, err
	}
	_ = json.Unmarshal(engines, &sn.Engines)
	_ = json.Unmarshal(stats, &sn.Stats)
	return sn, nil
}

// snapshot loads one snapshot of the application and checks findings.read
// on its repository.
func (s *Service) snapshot(ctx context.Context, p *authz.Principal, appID uuid.UUID, sid uuid.UUID) (Snapshot, error) {
	if err := Reconcile(ctx, s.DB, &p.OrganizationID); err != nil {
		return Snapshot{}, err
	}
	sn, err := scanSnapshot(s.DB.QueryRow(ctx, snapshotSelect+` WHERE s.organization_id = $1 AND s.application_id = $2 AND s.id = $3`,
		p.OrganizationID, appID, sid))
	if err != nil {
		return sn, err
	}
	return sn, s.requireRepo(ctx, p, authz.PermFindingsRead, sn.RepositoryID)
}

// ready checks the snapshot's graph can be read.
func ready(sn Snapshot) error {
	switch {
	case sn.Status == "archived" || sn.Storage != "rows":
		return httpx.E(http.StatusConflict, "snapshot_archived", "the snapshot is archived; only its export remains").WithDiag(CodeArchived)
	case sn.Status != "ready" && sn.Status != "partial":
		return httpx.E(http.StatusConflict, "snapshot_not_ready", "the snapshot is "+sn.Status).WithDiag(CodeNotReady)
	}
	return nil
}

func (s *Service) skeleton(ctx context.Context, id uuid.UUID) (*skeleton, error) {
	if sk := s.cache.get(id); sk != nil {
		return sk, nil
	}
	sk, err := loadSkeleton(ctx, s.DB, id)
	if err != nil {
		return nil, err
	}
	s.cache.put(sk)
	return sk, nil
}

// --- views and settings ------------------------------------------------------

func (s *Service) views(w http.ResponseWriter, r *http.Request) {
	if _, err := s.caller(r); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"views": Views, "node_types": NodeTypes, "edge_types": EdgeTypes,
		"layers": Layers, "evidence_types": EvidenceTypes, "evidence_ref_kinds": RefKinds})
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermFindingsRead) && !p.HasAnywhere(authz.PermSettingsManage) {
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
	if err := s.Authz.Require(ctx, p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		s.fail(w, r, err)
		return
	}
	var in Settings
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.MinIntervalMinutes < 0 || in.MinIntervalMinutes > 10080 || in.KeepSnapshots < 1 || in.KeepSnapshots > 1000 {
		s.fail(w, r, httpx.BadRequest("min_interval_minutes must be 0 to 10080 and keep_snapshots 1 to 1000"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO codegraph_settings (organization_id, auto_rebuild, min_interval_minutes, keep_snapshots, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, now()) ON CONFLICT (organization_id) DO UPDATE SET auto_rebuild = EXCLUDED.auto_rebuild,
			min_interval_minutes = EXCLUDED.min_interval_minutes, keep_snapshots = EXCLUDED.keep_snapshots,
			updated_by = EXCLUDED.updated_by, updated_at = now()`, p.OrganizationID, in.AutoRebuild, in.MinIntervalMinutes, in.KeepSnapshots, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "codegraph.settings.update", TargetType: "codegraph_settings", TargetID: p.OrganizationID.String(),
			RequestID: httpx.RequestID(r), Metadata: map[string]any{"auto_rebuild": in.AutoRebuild,
				"min_interval_minutes": in.MinIntervalMinutes, "keep_snapshots": in.KeepSnapshots}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// --- build -------------------------------------------------------------------

type buildRequest struct {
	RepositoryID *uuid.UUID `json:"repository_id"`
	Ref          string     `json:"ref"`
}

func (s *Service) build(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	appID, appName, err := s.application(ctx, p, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req buildRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if len(req.Ref) > 255 || strings.ContainsAny(req.Ref, " \t\n") {
		s.fail(w, r, httpx.BadRequest("ref must be a branch or tag name"))
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND application_id = $2 AND archived_at IS NULL
		AND ($3::uuid IS NULL OR id = $3) ORDER BY full_name LIMIT 50`, p.OrganizationID, appID, req.RepositoryID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repoIDs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var allowed []uuid.UUID
	for _, id := range repoIDs {
		if err := s.requireRepo(ctx, p, authz.PermScansRun, id); err == nil {
			allowed = append(allowed, id)
		} else if !errors.Is(err, errNotFound) && !errors.Is(err, authz.ErrForbidden) {
			s.fail(w, r, err)
			return
		}
	}
	if len(allowed) == 0 {
		if len(repoIDs) > 0 {
			s.fail(w, r, authz.ErrForbidden)
			return
		}
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "no_repositories",
			"the application has no active repository to build (or repository_id is not one of its repositories)").WithDiag(CodeNoRepositories))
		return
	}
	online, err := graphWorkerOnline(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !online {
		s.fail(w, r, httpx.E(http.StatusConflict, "no_graph_worker",
			"no CodeGraph worker (worker-graph) is online; start it with COMPOSE_PROFILES=graph").WithDiag(CodeNoWorker))
		return
	}
	type failed struct {
		RepositoryID uuid.UUID `json:"repository_id"`
		Code         string    `json:"code"`
		Message      string    `json:"message"`
	}
	var out []BuildResult
	var errs []failed
	for _, repoID := range allowed {
		var res BuildResult
		err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
			var err error
			if res, err = queueBuild(ctx, tx, p.OrganizationID, appID, repoID, "manual", req.Ref, &p.UserID); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "codegraph.build", TargetType: "codegraph_snapshot", TargetID: res.SnapshotID.String(), RequestID: httpx.RequestID(r),
				Metadata: map[string]any{"application": appName, "repository_id": repoID, "scan_job_id": res.ScanJobID, "coalesced": res.Coalesced}})
		})
		if err != nil {
			mapped := buildError(err)
			var he *httpx.Error
			if errors.As(mapped, &he) && len(allowed) > 1 {
				errs = append(errs, failed{RepositoryID: repoID, Code: CodeNotBuildable, Message: he.Message})
				continue
			}
			s.fail(w, r, mapped)
			return
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		s.fail(w, r, httpx.E(http.StatusConflict, "not_buildable", "no repository of the application can be built").WithDiag(CodeNotBuildable))
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"snapshots": out, "errors": errs})
}

// --- snapshots ---------------------------------------------------------------

func (s *Service) listSnapshots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	appID, _, err := s.application(ctx, p, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	if err := Reconcile(ctx, s.DB, &p.OrganizationID); err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	var repoID *uuid.UUID
	if v := q.Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("repository_id must be a UUID"))
			return
		}
		repoID = &id
	}
	status := q.Get("status")
	if status != "" && !slices.Contains([]string{"queued", "building", "ready", "partial", "failed", "archived"}, status) {
		s.fail(w, r, httpx.BadRequest("unknown status"))
		return
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > 200 {
			s.fail(w, r, httpx.BadRequest("limit must be between 1 and 200"))
			return
		}
	}
	expr, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 6)
	rows, err := s.DB.Query(ctx, snapshotSelect+` WHERE s.organization_id = $1 AND s.application_id = $2
		AND ($3::uuid IS NULL OR s.repository_id = $3) AND ($4 = '' OR s.status = $4) AND `+expr+`
		ORDER BY s.created_at DESC LIMIT $5`, append([]any{p.OrganizationID, appID, repoID, status, limit}, args...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := []Snapshot{}
	for rows.Next() {
		sn, err := scanSnapshot(rows)
		if err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		out = append(out, sn)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"snapshots": out})
}

func (s *Service) getSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, sn, err := s.loadFor(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = p
	out := map[string]any{"snapshot": sn, "views": Views}
	if sn.Storage == "rows" && (sn.Status == "ready" || sn.Status == "partial") {
		counts := func(query string) (map[string]int, error) {
			rows, err := s.DB.Query(ctx, query, sn.ID)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			m := map[string]int{}
			for rows.Next() {
				var k string
				var n int
				if err := rows.Scan(&k, &n); err != nil {
					return nil, err
				}
				m[k] = n
			}
			return m, rows.Err()
		}
		for name, q := range map[string]string{
			"node_types":     `SELECT type, count(*) FROM codegraph_nodes WHERE snapshot_id = $1 GROUP BY type`,
			"layers":         `SELECT layer, count(*) FROM codegraph_nodes WHERE snapshot_id = $1 GROUP BY layer`,
			"edge_types":     `SELECT type, count(*) FROM codegraph_edges WHERE snapshot_id = $1 GROUP BY type`,
			"evidence_types": `SELECT evidence, count(*) FROM codegraph_edges WHERE snapshot_id = $1 GROUP BY evidence`,
			"open_findings":  `SELECT key, sum(value::int)::int FROM codegraph_nodes, jsonb_each_text(finding_counts) WHERE snapshot_id = $1 GROUP BY key`,
		} {
			m, err := counts(q)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			out[name] = m
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// loadFor resolves caller, application and snapshot of a snapshot route.
func (s *Service) loadFor(r *http.Request) (*authz.Principal, Snapshot, error) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		return nil, Snapshot{}, err
	}
	appID, _, err := s.application(ctx, p, r)
	if err != nil {
		return nil, Snapshot{}, err
	}
	sid, err := pathUUID(r, "sid")
	if err != nil {
		return nil, Snapshot{}, err
	}
	sn, err := s.snapshot(ctx, p, appID, sid)
	return p, sn, err
}

// --- graph views -------------------------------------------------------------

// NodeOut is a node of the API (contract).
type NodeOut struct {
	ID            string         `json:"id"`
	Key           string         `json:"key"`
	Type          string         `json:"type"`
	Label         string         `json:"label"`
	Layer         string         `json:"layer"`
	Parent        *string        `json:"parent"`
	Group         string         `json:"group"`
	Attrs         map[string]any `json:"attrs"`
	FindingCounts map[string]int `json:"finding_counts"`
}

// EdgeOut is an edge of the API (contract). Count > 1 for lifted or
// aggregated edges; their evidence_refs are samples of the originals.
type EdgeOut struct {
	ID           string        `json:"id"`
	Source       string        `json:"source"`
	Target       string        `json:"target"`
	Type         string        `json:"type"`
	Evidence     string        `json:"evidence"`
	Count        int           `json:"count"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// AggOut is an aggregate (a group of nodes shown as one).
type AggOut struct {
	ID            string         `json:"id"`
	Label         string         `json:"label"`
	Count         int            `json:"count"`
	ChildTypes    map[string]int `json:"child_types"`
	FindingCounts map[string]int `json:"finding_counts"`
}

func parseList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// parseViewParams reads view, focus, depth, layers, filters and limit.
func parseViewParams(q url.Values) (viewDef, viewParams, error) {
	name := q.Get("view")
	if name == "" {
		name = "architecture"
	}
	def, ok := ViewByName(name)
	if !ok {
		return def, viewParams{}, errBadQuery("unknown view " + strconv.Quote(name))
	}
	p := viewParams{focus: q.Get("focus"), depth: 1, limit: defaultLimit}
	var err error
	if v := q.Get("depth"); v != "" {
		if p.depth, err = strconv.Atoi(v); err != nil || p.depth < 1 || p.depth > maxDepth {
			return def, p, errBadQuery("depth must be between 1 and 3")
		}
	}
	if v := q.Get("limit"); v != "" {
		if p.limit, err = strconv.Atoi(v); err != nil || p.limit < 1 || p.limit > maxLimit {
			return def, p, errBadQuery("limit must be between 1 and 2000")
		}
	}
	p.layers = parseList(q.Get("layers"))
	for _, l := range p.layers {
		if !slices.Contains(Layers, l) {
			return def, p, errBadQuery("unknown layer " + strconv.Quote(l))
		}
	}
	// filters=type:function,language:Go,technology:postgres,severity:high,evidence:verified,q:auth
	for _, f := range parseList(q.Get("filters")) {
		k, v, ok := strings.Cut(f, ":")
		v = strings.TrimSpace(v)
		if !ok || v == "" {
			return def, p, errBadQuery("filters are key:value pairs separated by commas")
		}
		switch k {
		case "type", "kind":
			if !slices.Contains(NodeTypes, v) {
				return def, p, errBadQuery("unknown node type " + strconv.Quote(v))
			}
			p.types = append(p.types, v)
		case "language":
			p.langs = append(p.langs, v)
		case "technology", "framework":
			p.techs = append(p.techs, v)
		case "severity":
			if !slices.Contains([]string{"critical", "high", "medium", "low", "info"}, v) {
				return def, p, errBadQuery("unknown severity " + strconv.Quote(v))
			}
			p.sevs = append(p.sevs, v)
		case "evidence":
			if !slices.Contains(EvidenceTypes, v) {
				return def, p, errBadQuery("unknown evidence type " + strconv.Quote(v))
			}
			p.evidence = append(p.evidence, v)
		case "q":
			if len(v) > 200 {
				return def, p, errBadQuery("q is too long")
			}
			p.q = v
		default:
			return def, p, errBadQuery("unknown filter " + strconv.Quote(k))
		}
	}
	return def, p, nil
}

func (s *Service) graph(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, sn, err := s.loadFor(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := ready(sn); err != nil {
		s.fail(w, r, err)
		return
	}
	def, vp, err := parseViewParams(r.URL.Query())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sk, err := s.skeleton(ctx, sn.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var base *skeleton
	var baseID *uuid.UUID
	if def.change {
		base, baseID, err = s.changeBase(ctx, p, sn, r.URL.Query().Get("compare"))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if base != nil {
			vp.diff = diff(base, sk)
		} else {
			vp.diff = &diffResult{}
		}
	}
	res, err := sk.compute(def, vp)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.render(ctx, sn.ID, sk, res)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if def.change {
		for _, j := range res.removed {
			if len(out.Nodes) >= vp.limit+200 {
				out.Truncated = true
				break
			}
			n := base.nodes[j]
			out.Nodes = append(out.Nodes, NodeOut{ID: n.id.String(), Key: n.key, Type: n.typ, Label: n.label, Layer: n.layer,
				Group: n.group, Attrs: map[string]any{"file": n.file, "change": "removed"}, FindingCounts: map[string]int{}})
		}
		for i := range out.Nodes {
			if idx, ok := sk.byID[uuid.MustParse(out.Nodes[i].ID)]; ok {
				if c, ok := res.changed[idx]; ok {
					out.Nodes[i].Attrs["change"] = c
				}
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"snapshot_id": sn.ID, "view": def.Name, "focus": vp.focus, "depth": vp.depth,
		"limit": vp.limit, "nodes": out.Nodes, "edges": out.Edges, "aggregated": out.Aggregated, "truncated": out.Truncated,
		"base_snapshot_id": baseID})
}

// changeBase picks the base snapshot of change_impact: compare=<id>, else
// the newest earlier ready snapshot of the same repository.
func (s *Service) changeBase(ctx context.Context, p *authz.Principal, sn Snapshot, compare string) (*skeleton, *uuid.UUID, error) {
	var bid uuid.UUID
	if compare != "" {
		id, err := uuid.Parse(compare)
		if err != nil {
			return nil, nil, errBadQuery("compare must be a snapshot id")
		}
		b, err := s.snapshot(ctx, p, sn.ApplicationID, id)
		if err != nil {
			return nil, nil, err
		}
		if b.RepositoryID != sn.RepositoryID {
			return nil, nil, httpx.E(http.StatusUnprocessableEntity, "different_repositories",
				"the snapshots belong to different repositories").WithDiag(CodeDiffMismatch)
		}
		if err := ready(b); err != nil {
			return nil, nil, err
		}
		bid = id
	} else {
		err := s.DB.QueryRow(ctx, `SELECT id FROM codegraph_snapshots WHERE organization_id = $1 AND repository_id = $2
			AND created_at < $3 AND status IN ('ready', 'partial') AND storage = 'rows' ORDER BY created_at DESC LIMIT 1`,
			p.OrganizationID, sn.RepositoryID, sn.CreatedAt).Scan(&bid)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
	}
	sk, err := s.skeleton(ctx, bid)
	return sk, &bid, err
}

type rendered struct {
	Nodes      []NodeOut
	Edges      []EdgeOut
	Aggregated []AggOut
	Truncated  bool
}

// render reads attributes and evidence for a view result.
func (s *Service) render(ctx context.Context, snapshotID uuid.UUID, sk *skeleton, res *viewResult) (rendered, error) {
	out := rendered{Nodes: []NodeOut{}, Edges: []EdgeOut{}, Aggregated: []AggOut{}, Truncated: res.truncated}
	var idx []int32
	for _, u := range res.units {
		if u.node >= 0 {
			idx = append(idx, u.node)
			continue
		}
		label := strings.TrimPrefix(strings.TrimPrefix(u.group, "dir:"), "type:")
		if strings.HasPrefix(u.group, "type:") {
			label += " (all)"
		}
		out.Aggregated = append(out.Aggregated, AggOut{ID: "agg:" + u.group, Label: label, Count: len(u.members),
			ChildTypes: sk.childTypes(u.members), FindingCounts: sk.sumCounts(u.members)})
	}
	nodes, err := s.fetchNodes(ctx, snapshotID, sk, idx)
	if err != nil {
		return out, err
	}
	out.Nodes = nodes
	var samples []int32
	for _, e := range res.edges {
		samples = append(samples, e.samples...)
	}
	refs, err := s.fetchRefs(ctx, snapshotID, sk, samples, 3)
	if err != nil {
		return out, err
	}
	for _, e := range res.edges {
		a, b := res.units[e.a].id(sk), res.units[e.b].id(sk)
		id := syntheticEdgeID(a, e.typ, b)
		if e.original {
			id = sk.edges[e.samples[0]].id.String()
		}
		var er []EvidenceRef
		for _, si := range e.samples {
			for _, rf := range refs[si] {
				if len(er) < 3 {
					er = append(er, rf)
				}
			}
		}
		out.Edges = append(out.Edges, EdgeOut{ID: id, Source: a, Target: b, Type: e.typ, Evidence: e.evidence, Count: e.count, EvidenceRefs: er})
	}
	return out, nil
}

// fetchNodes reads full node rows for skeleton indexes (in that order).
func (s *Service) fetchNodes(ctx context.Context, snapshotID uuid.UUID, sk *skeleton, idx []int32) ([]NodeOut, error) {
	out := make([]NodeOut, 0, len(idx))
	if len(idx) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, len(idx))
	for i, x := range idx {
		ids[i] = sk.nodes[x].id
	}
	rows, err := s.DB.Query(ctx, `SELECT id, attrs, finding_counts, file_path, start_line, end_line, language, technology
		FROM codegraph_nodes WHERE snapshot_id = $1 AND id = ANY($2)`, snapshotID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type full struct {
		attrs  map[string]any
		counts map[string]int
	}
	got := make(map[uuid.UUID]full, len(ids))
	for rows.Next() {
		var id uuid.UUID
		var attrs, counts []byte
		var file, lang, tech string
		var start, end *int
		if err := rows.Scan(&id, &attrs, &counts, &file, &start, &end, &lang, &tech); err != nil {
			return nil, err
		}
		f := full{attrs: map[string]any{}, counts: map[string]int{}}
		_ = json.Unmarshal(attrs, &f.attrs)
		_ = json.Unmarshal(counts, &f.counts)
		if file != "" {
			f.attrs["file"] = file
		}
		if start != nil {
			f.attrs["line"] = *start
		}
		if end != nil {
			f.attrs["end_line"] = *end
		}
		if lang != "" {
			f.attrs["language"] = lang
		}
		if tech != "" {
			f.attrs["technology"] = tech
		}
		got[id] = f
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, x := range idx {
		n := sk.nodes[x]
		f := got[n.id]
		if f.attrs == nil {
			f.attrs, f.counts = map[string]any{}, map[string]int{}
		}
		var parent *string
		if n.parent >= 0 {
			ps := sk.nodes[n.parent].id.String()
			parent = &ps
		}
		out = append(out, NodeOut{ID: n.id.String(), Key: n.key, Type: n.typ, Label: n.label, Layer: n.layer, Parent: parent,
			Group: "agg:" + n.group, Attrs: f.attrs, FindingCounts: f.counts})
	}
	return out, nil
}

// fetchRefs reads up to per evidence references of each edge.
func (s *Service) fetchRefs(ctx context.Context, snapshotID uuid.UUID, sk *skeleton, edges []int32, per int) (map[int32][]EvidenceRef, error) {
	out := map[int32][]EvidenceRef{}
	if len(edges) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, 0, len(edges))
	back := make(map[uuid.UUID]int32, len(edges))
	for _, e := range edges {
		id := sk.edges[e].id
		if _, dup := back[id]; !dup {
			back[id] = e
			ids = append(ids, id)
		}
	}
	rows, err := s.DB.Query(ctx, `SELECT edge_id, kind, ref, detail FROM (
		SELECT edge_id, kind, ref, detail, row_number() OVER (PARTITION BY edge_id ORDER BY id) AS rn
		FROM codegraph_evidence WHERE snapshot_id = $1 AND edge_id = ANY($2)) x WHERE rn <= $3`, snapshotID, ids, per)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var r EvidenceRef
		if err := rows.Scan(&id, &r.Kind, &r.Ref, &r.Detail); err != nil {
			return nil, err
		}
		out[back[id]] = append(out[back[id]], r)
	}
	return out, rows.Err()
}

// --- inspector -----------------------------------------------------------------

func (s *Service) node(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, sn, err := s.loadFor(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := ready(sn); err != nil {
		s.fail(w, r, err)
		return
	}
	nid, err := pathUUID(r, "nid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sk, err := s.skeleton(ctx, sn.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	i, ok := sk.byID[nid]
	if !ok {
		s.fail(w, r, errNotFound)
		return
	}
	nodes, err := s.fetchNodes(ctx, sn.ID, sk, []int32{i})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n := sk.nodes[i]
	type brief struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Label string `json:"label"`
	}
	b := func(j int32) brief { return brief{sk.nodes[j].id.String(), sk.nodes[j].typ, sk.nodes[j].label} }
	var ancestors []brief
	for j := n.parent; j >= 0 && len(ancestors) < 64; j = sk.nodes[j].parent {
		ancestors = append([]brief{b(j)}, ancestors...)
	}
	childTypes := sk.childTypes(sk.childs[i])
	// Roll-up of open findings over the containment subtree.
	rollup := map[string]int{}
	stack := []int32{i}
	for len(stack) > 0 && len(stack) < 1_000_000 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for k, v := range sk.nodes[x].sev {
			rollup[k] += int(v)
		}
		stack = append(stack, sk.childs[x]...)
	}
	type rel struct {
		EdgeOut
		Other brief `json:"other"`
	}
	const maxRel = 200
	var sample []int32
	for _, list := range [][]int32{sk.out[i], sk.in[i]} {
		sample = append(sample, list[:min(len(list), maxRel)]...)
	}
	refs, err := s.fetchRefs(ctx, sn.ID, sk, sample, maxRefsPerEdge)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	mk := func(list []int32, outgoing bool) []rel {
		res := []rel{}
		for _, ei := range list[:min(len(list), maxRel)] {
			e := sk.edges[ei]
			other := e.dst
			if !outgoing {
				other = e.src
			}
			res = append(res, rel{EdgeOut: EdgeOut{ID: e.id.String(), Source: sk.nodes[e.src].id.String(), Target: sk.nodes[e.dst].id.String(),
				Type: e.typ, Evidence: e.evidence, Count: 1, EvidenceRefs: refs[ei]}, Other: b(other)})
		}
		return res
	}
	findings, err := s.nodeFindings(ctx, sn, nodes[0])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	links, err := s.sourceLinks(ctx, sn, nodes[0], refs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"node": nodes[0], "ancestors": ancestors,
		"children":  map[string]any{"count": len(sk.childs[i]), "types": childTypes},
		"edges_out": mk(sk.out[i], true), "edges_in": mk(sk.in[i], false),
		"edges_out_total": len(sk.out[i]), "edges_in_total": len(sk.in[i]),
		"finding_counts": nodes[0].FindingCounts, "rollup_finding_counts": rollup, "findings": findings, "source_links": links})
}

type findingBrief struct {
	ID        uuid.UUID `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	RuleID    string    `json:"rule_id"`
	FilePath  string    `json:"file_path"`
	StartLine *int      `json:"start_line"`
}

// nodeFindings lists the open findings located in a node (its file and
// line range, its directory for a module, its package for a component).
func (s *Service) nodeFindings(ctx context.Context, sn Snapshot, n NodeOut) ([]findingBrief, error) {
	file, _ := n.Attrs["file"].(string)
	start, end := -1, -1
	if v, ok := n.Attrs["line"].(int); ok {
		start = v
	}
	if v, ok := n.Attrs["end_line"].(int); ok {
		end = v
	}
	var cond string
	var arg any
	switch {
	case n.Type == "component":
		name, _ := n.Attrs["name"].(string)
		if name == "" {
			name = n.Label
		}
		cond, arg = `lower(f.package_name) = lower($3)`, name
	case n.Type == "module" && strings.HasPrefix(n.Group, "agg:dir:"):
		dir := strings.TrimPrefix(n.Group, "agg:dir:")
		if dir == "." {
			cond, arg = `f.file_path <> '' AND $3 = $3`, ""
		} else {
			cond, arg = `f.file_path LIKE $3`, strings.NewReplacer("%", `\%`, "_", `\_`).Replace(dir)+"/%"
		}
	case file != "" && (n.Type == "function" || n.Type == "class") && start >= 0 && end >= start:
		cond, arg = `f.file_path = $3 AND f.start_line BETWEEN `+strconv.Itoa(start)+` AND `+strconv.Itoa(end), file
	case file != "":
		cond, arg = `f.file_path = $3`, file
	default:
		return []findingBrief{}, nil
	}
	rows, err := s.DB.Query(ctx, `SELECT f.id, f.title, f.severity, f.status, f.rule_id, f.file_path, f.start_line FROM findings f
		WHERE f.organization_id = $1 AND f.repository_id = $2 AND f.status IN ('open', 'in_progress', 'needs_review')
		AND f.scan_target_id IS NULL AND `+cond+`
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id LIMIT 100`,
		sn.orgID, sn.RepositoryID, arg)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (findingBrief, error) {
		var f findingBrief
		err := r.Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.RuleID, &f.FilePath, &f.StartLine)
		return f, err
	})
	if out == nil {
		out = []findingBrief{}
	}
	return out, err
}

type sourceLink struct {
	File string `json:"file"`
	Line int    `json:"line"`
	URL  string `json:"url"`
}

// sourceLinks links the node's location and its edges' file evidence to
// the repository's web view at the snapshot's commit (GitHub and Azure
// DevOps; other sources get the file and line without a URL).
func (s *Service) sourceLinks(ctx context.Context, sn Snapshot, n NodeOut, refs map[int32][]EvidenceRef) ([]sourceLink, error) {
	var webURL, provider string
	_ = s.DB.QueryRow(ctx, `SELECT r.url, COALESCE(c.provider, '') FROM repositories r LEFT JOIN scm_connections c ON c.id = r.scm_connection_id
		WHERE r.id = $1`, sn.RepositoryID).Scan(&webURL, &provider)
	version := firstNonEmpty(sn.CommitSHA, sn.Ref)
	link := func(file string, line int) sourceLink {
		l := sourceLink{File: file, Line: line}
		if webURL == "" || version == "" || !strings.HasPrefix(webURL, "https://") {
			return l
		}
		base := strings.TrimSuffix(webURL, "/")
		esc := (&url.URL{Path: file}).EscapedPath()
		switch provider {
		case "github", "github_enterprise":
			l.URL = base + "/blob/" + url.PathEscape(version) + "/" + esc
			if line > 0 {
				l.URL += "#L" + strconv.Itoa(line)
			}
		case "azure_devops", "azure_devops_server":
			v := "GB" + version
			if sn.CommitSHA != "" {
				v = "GC" + sn.CommitSHA
			}
			l.URL = base + "?path=/" + url.QueryEscape(file) + "&version=" + url.QueryEscape(v)
			if line > 0 {
				l.URL += "&line=" + strconv.Itoa(line)
			}
		}
		return l
	}
	out := []sourceLink{}
	seen := map[string]bool{}
	if file, _ := n.Attrs["file"].(string); file != "" {
		line, _ := n.Attrs["line"].(int)
		out = append(out, link(file, line))
		seen[file+":"+strconv.Itoa(line)] = true
	}
	for _, rs := range refs {
		for _, rf := range rs {
			if rf.Kind != "file_line" || seen[rf.Ref] || len(out) >= 50 {
				continue
			}
			seen[rf.Ref] = true
			f, l := splitFileLine(rf.Ref)
			out = append(out, link(f, l))
		}
	}
	return out, nil
}

// --- paths ---------------------------------------------------------------------

func (s *Service) paths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, sn, err := s.loadFor(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := ready(sn); err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	sk, err := s.skeleton(ctx, sn.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	node := func(name string, required bool) (int32, error) {
		v := q.Get(name)
		if v == "" {
			if required {
				return -1, errBadQuery(name + " is required")
			}
			return -1, nil
		}
		id, err := uuid.Parse(v)
		if err != nil {
			return -1, errBadQuery(name + " must be a node id")
		}
		i, ok := sk.byID[id]
		if !ok {
			return -1, errNotFound
		}
		return i, nil
	}
	from, err := node("from", true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	to, err := node("to", false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	dir := q.Get("direction")
	if dir == "" {
		dir = "out"
	}
	if dir != "out" && dir != "in" {
		s.fail(w, r, errBadQuery("direction must be in or out"))
		return
	}
	hops, limit := defaultHops, defaultPaths
	if v := q.Get("max"); v != "" {
		if hops, err = strconv.Atoi(v); err != nil || hops < 1 || hops > maxHops {
			s.fail(w, r, errBadQuery("max must be between 1 and 8 hops"))
			return
		}
	}
	if v := q.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > maxPaths {
			s.fail(w, r, errBadQuery("limit must be between 1 and 50"))
			return
		}
	}
	types := parseList(q.Get("types"))
	for _, t := range types {
		if !slices.Contains(EdgeTypes, t) {
			s.fail(w, r, errBadQuery("unknown edge type "+strconv.Quote(t)))
			return
		}
	}
	res := sk.paths(from, to, dir, hops, limit, types)
	nodes, err := s.fetchNodes(ctx, sn.ID, sk, res.nodes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	refs, err := s.fetchRefs(ctx, sn.ID, sk, res.edges, 3)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	edges := make([]EdgeOut, 0, len(res.edges))
	for _, ei := range res.edges {
		e := sk.edges[ei]
		edges = append(edges, EdgeOut{ID: e.id.String(), Source: sk.nodes[e.src].id.String(), Target: sk.nodes[e.dst].id.String(),
			Type: e.typ, Evidence: e.evidence, Count: 1, EvidenceRefs: refs[ei]})
	}
	paths := make([][]string, 0, len(res.paths))
	for _, pth := range res.paths {
		ids := make([]string, len(pth))
		for i, ei := range pth {
			ids[i] = sk.edges[ei].id.String()
		}
		paths = append(paths, ids)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"from": sk.nodes[from].id, "direction": dir, "max": hops, "paths": paths,
		"nodes": nodes, "edges": edges, "truncated": res.truncated, "budget_exceeded": res.budget})
}

// --- diff ------------------------------------------------------------------------

func (s *Service) diff(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	appID, _, err := s.application(ctx, p, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	fromID, err1 := uuid.Parse(q.Get("from"))
	toID, err2 := uuid.Parse(q.Get("to"))
	if err1 != nil || err2 != nil {
		s.fail(w, r, errBadQuery("from and to must be snapshot ids"))
		return
	}
	from, err := s.snapshot(ctx, p, appID, fromID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	to, err := s.snapshot(ctx, p, appID, toID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if from.RepositoryID != to.RepositoryID {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "different_repositories", "the snapshots belong to different repositories").WithDiag(CodeDiffMismatch))
		return
	}
	for _, sn := range []Snapshot{from, to} {
		if err := ready(sn); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	base, err := s.skeleton(ctx, from.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	head, err := s.skeleton(ctx, to.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := diff(base, head)
	const maxItems = 2000
	truncated := false
	type dnode struct {
		ID    string `json:"id"`
		Key   string `json:"key"`
		Type  string `json:"type"`
		Label string `json:"label"`
		Layer string `json:"layer"`
		File  string `json:"file,omitempty"`
	}
	type dedge struct {
		ID        string `json:"id"`
		Key       string `json:"key"`
		SourceKey string `json:"source_key"`
		TargetKey string `json:"target_key"`
		Type      string `json:"type"`
		Evidence  string `json:"evidence"`
		Previous  string `json:"previous_evidence,omitempty"`
	}
	nodesOf := func(sk *skeleton, keys []string) []dnode {
		out := []dnode{}
		for _, k := range keys {
			if len(out) >= maxItems {
				truncated = true
				break
			}
			n := sk.nodes[sk.byKey[k]]
			out = append(out, dnode{n.id.String(), n.key, n.typ, n.label, n.layer, n.file})
		}
		return out
	}
	edgesOf := func(sk, other *skeleton, keys []string) []dedge {
		out := []dedge{}
		for _, k := range keys {
			if len(out) >= maxItems {
				truncated = true
				break
			}
			ei, ok := sk.edgeByKey(k)
			if !ok {
				continue
			}
			e := sk.edges[ei]
			de := dedge{ID: e.id.String(), Key: k, SourceKey: sk.nodes[e.src].key, TargetKey: sk.nodes[e.dst].key, Type: e.typ, Evidence: e.evidence}
			if other != nil {
				if oi, ok := other.edgeByKey(k); ok {
					de.Previous = other.edges[oi].evidence
				}
			}
			out = append(out, de)
		}
		return out
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"from": from.ID, "to": to.ID, "repository_id": to.RepositoryID,
		"summary": map[string]int{"added_nodes": len(d.addedNodes), "removed_nodes": len(d.removedNodes), "changed_nodes": len(d.changedNodes),
			"added_edges": len(d.addedEdges), "removed_edges": len(d.removedEdges), "changed_edges": len(d.changedEdges)},
		"added":     map[string]any{"nodes": nodesOf(head, d.addedNodes), "edges": edgesOf(head, nil, d.addedEdges)},
		"removed":   map[string]any{"nodes": nodesOf(base, d.removedNodes), "edges": edgesOf(base, nil, d.removedEdges)},
		"changed":   map[string]any{"nodes": nodesOf(head, d.changedNodes), "edges": edgesOf(head, base, d.changedEdges)},
		"truncated": truncated,
	})
}
