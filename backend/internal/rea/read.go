package rea

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Analysis is the API form of an analysis.
type Analysis struct {
	ID               uuid.UUID          `json:"id"`
	TargetID         uuid.UUID          `json:"target_id"`
	ArtifactName     string             `json:"artifact_name"`
	ArtifactSHA256   string             `json:"artifact_sha256"`
	RepositoryID     uuid.UUID          `json:"repository_id"`
	RepositoryName   string             `json:"repository_name"`
	ApplicationID    *uuid.UUID         `json:"application_id"`
	ScanJobID        *uuid.UUID         `json:"scan_job_id"`
	Status           string             `json:"status"`
	TrustBasis       string             `json:"trust_basis"`
	CommitSHA        string             `json:"commit_sha"`
	CommitSource     string             `json:"commit_source"`
	SnapshotID       *uuid.UUID         `json:"snapshot_id"`
	SourceSnapshotID *uuid.UUID         `json:"source_snapshot_id"`
	DiffStatus       string             `json:"diff_status"`
	Format           string             `json:"format"`
	Arch             string             `json:"arch"`
	Language         string             `json:"language"`
	Tools            map[string]ToolRun `json:"tools"`
	Stats            map[string]any     `json:"stats"`
	ErrorCode        string             `json:"error_code,omitempty"`
	Error            string             `json:"error,omitempty"`
	RequestedBy      *string            `json:"requested_by"`
	CreatedAt        time.Time          `json:"created_at"`
	StartedAt        *time.Time         `json:"started_at"`
	FinishedAt       *time.Time         `json:"finished_at"`
	orgID            uuid.UUID
}

const analysisSelect = `SELECT a.id, a.target_id, a.artifact_name, a.artifact_sha256, a.repository_id,
	COALESCE(NULLIF(r.display_name, ''), r.full_name), a.application_id, a.scan_job_id, a.status, a.trust_basis, a.commit_sha,
	a.commit_source, a.snapshot_id, a.source_snapshot_id, a.diff_status, a.format, a.arch, a.language, a.tools, a.stats, a.error_code,
	a.error, COALESCE(NULLIF(u.display_name, ''), u.email), a.created_at, a.started_at, a.finished_at, a.organization_id
	FROM rea_analyses a JOIN repositories r ON r.id = a.repository_id LEFT JOIN users u ON u.id = a.requested_by`

func scanAnalysis(row pgx.Row) (Analysis, error) {
	var a Analysis
	var tools, stats []byte
	err := row.Scan(&a.ID, &a.TargetID, &a.ArtifactName, &a.ArtifactSHA256, &a.RepositoryID, &a.RepositoryName, &a.ApplicationID,
		&a.ScanJobID, &a.Status, &a.TrustBasis, &a.CommitSHA, &a.CommitSource, &a.SnapshotID, &a.SourceSnapshotID, &a.DiffStatus,
		&a.Format, &a.Arch, &a.Language, &tools, &stats, &a.ErrorCode, &a.Error, &a.RequestedBy, &a.CreatedAt, &a.StartedAt,
		&a.FinishedAt, &a.orgID)
	if err != nil {
		return a, err
	}
	a.Tools, a.Stats = map[string]ToolRun{}, map[string]any{}
	_ = json.Unmarshal(tools, &a.Tools)
	_ = json.Unmarshal(stats, &a.Stats)
	return a, nil
}

// analysis loads an analysis and checks findings.read on its repository.
func (s *Service) analysis(ctx context.Context, p *authz.Principal, id uuid.UUID) (Analysis, error) {
	if err := reconcile(ctx, s.DB, p.OrganizationID); err != nil {
		s.Log.Warn("reverse-engineering status reconcile failed", "err", err)
	}
	a, err := scanAnalysis(s.DB.QueryRow(ctx, analysisSelect+` WHERE a.organization_id = $1 AND a.id = $2`, p.OrganizationID, id))
	if err != nil {
		return a, err
	}
	return a, s.requireRepo(ctx, p, authz.PermFindingsRead, a.RepositoryID)
}

// loadReady resolves the caller and a ready analysis of the route.
func (s *Service) loadReady(r *http.Request) (*authz.Principal, Analysis, error) {
	p, err := s.caller(r)
	if err != nil {
		return nil, Analysis{}, err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return nil, Analysis{}, err
	}
	a, err := s.analysis(r.Context(), p, id)
	if err != nil {
		return nil, a, err
	}
	if (a.Status != "ready" && a.Status != "partial") || a.SnapshotID == nil {
		return nil, a, httpx.E(http.StatusConflict, "rea_not_ready", "the analysis is "+a.Status).WithDiag(CodeNotReady)
	}
	return p, a, nil
}

func (s *Service) listAnalyses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	uid := func(k string) (*uuid.UUID, error) {
		v := q.Get(k)
		if v == "" {
			return nil, nil
		}
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, httpx.BadRequest(k + " must be a UUID")
		}
		return &id, nil
	}
	targetID, err := uid("target_id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repoID, err := uid("repository_id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := q.Get("status")
	if status != "" && !slices.Contains([]string{"queued", "running", "ready", "partial", "failed"}, status) {
		s.fail(w, r, httpx.BadRequest("unknown status"))
		return
	}
	limit, err := intParam(q.Get("limit"), 50, 1, 200)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := reconcile(ctx, s.DB, p.OrganizationID); err != nil {
		s.Log.Warn("reverse-engineering status reconcile failed", "err", err)
	}
	expr, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 6)
	rows, err := s.DB.Query(ctx, analysisSelect+` WHERE a.organization_id = $1 AND ($2::uuid IS NULL OR a.target_id = $2)
		AND ($3::uuid IS NULL OR a.repository_id = $3) AND ($4 = '' OR a.status = $4) AND `+expr+`
		ORDER BY a.created_at DESC LIMIT $5`, append([]any{p.OrganizationID, targetID, repoID, status, limit}, args...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Analysis, error) { return scanAnalysis(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Analysis{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"analyses": out})
}

func (s *Service) getAnalysis(w http.ResponseWriter, r *http.Request) {
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
	a, err := s.analysis(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	counts := map[string]int{"functions": 0, "imports": 0, "strings": 0, "sections": 0, "calls": 0}
	if a.SnapshotID != nil {
		rows, err := s.DB.Query(ctx, `SELECT type, count(*) FROM codegraph_nodes WHERE snapshot_id = $1 GROUP BY type
			UNION ALL SELECT 'edge:' || type, count(*) FROM codegraph_edges WHERE snapshot_id = $1 AND type = 'calls' GROUP BY type`, *a.SnapshotID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				s.fail(w, r, err)
				return
			}
			switch k {
			case "binary_function":
				counts["functions"] = n
			case "import":
				counts["imports"] = n
			case "string_ref":
				counts["strings"] = n
			case "section":
				counts["sections"] = n
			case "edge:calls":
				counts["calls"] = n
			}
		}
		rows.Close()
	}
	var trust json.RawMessage
	_ = s.DB.QueryRow(ctx, `SELECT trust_detail FROM rea_analyses WHERE id = $1`, a.ID).Scan(&trust)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"analysis": a, "counts": counts, "trust": trust})
}

// --- facts ---------------------------------------------------------------------

// FunctionItem is a function of the Functions tab.
type FunctionItem struct {
	NodeID    uuid.UUID     `json:"node_id"`
	Key       string        `json:"key"`
	Name      string        `json:"name"`
	Addr      string        `json:"addr"`
	Offset    int64         `json:"offset"`
	Size      int64         `json:"size"`
	Section   string        `json:"section"`
	Tool      string        `json:"tool"`
	Library   bool          `json:"library"`
	Match     string        `json:"match"`
	Sensitive bool          `json:"sensitive"`
	Source    *SourceRefOut `json:"source"`
	HasCode   bool          `json:"has_code"`
}

// SourceRefOut is a source location of a matched item.
type SourceRefOut struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	NodeKey string `json:"node_key"`
}

const functionSelect = `SELECT n.id, n.node_key, n.label, COALESCE(n.attrs->>'addr', ''), COALESCE((n.attrs->>'offset')::bigint, 0),
	COALESCE((n.attrs->>'size')::bigint, 0), COALESCE(n.attrs->>'section', ''), COALESCE(n.attrs->>'tool', ''),
	COALESCE((n.attrs->>'library')::boolean, false), COALESCE(n.attrs->>'package', ''),
	d.side, COALESCE(d.sensitive, false), COALESCE(d.source_file, ''), COALESCE(d.source_line, 0), COALESCE(d.source_node_key, ''),
	EXISTS (SELECT 1 FROM rea_code c WHERE c.analysis_id = $2 AND c.node_key = n.node_key)
	FROM codegraph_nodes n
	LEFT JOIN LATERAL (SELECT side, sensitive, source_file, source_line, source_node_key FROM rea_diff_items x
	                   WHERE x.analysis_id = $2 AND x.binary_node_key = n.node_key AND x.kind = 'function' LIMIT 1) d ON true`

func scanFunction(row pgx.Row) (FunctionItem, error) {
	var f FunctionItem
	var pkg string
	var side *string
	var src SourceRefOut
	err := row.Scan(&f.NodeID, &f.Key, &f.Name, &f.Addr, &f.Offset, &f.Size, &f.Section, &f.Tool, &f.Library, &pkg, &side, &f.Sensitive,
		&src.File, &src.Line, &src.NodeKey, &f.HasCode)
	if err != nil {
		return f, err
	}
	switch {
	case side != nil:
		f.Match = *side
	case f.Library:
		f.Match = "library"
	default:
		f.Match = "unmatched"
	}
	if _, ok := sensitiveGoPackages[pkg]; ok {
		f.Sensitive = true
	}
	if src.File != "" || src.NodeKey != "" {
		f.Source = &src
	}
	return f, nil
}

func (s *Service) functions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	search := strings.TrimSpace(q.Get("q"))
	match := q.Get("match")
	if match != "" && !slices.Contains([]string{"matched", "binary_only", "library", "unmatched", "sensitive"}, match) {
		s.fail(w, r, httpx.BadRequest("match must be matched, binary_only, library, unmatched or sensitive"))
		return
	}
	limit, err := intParam(q.Get("limit"), 50, 1, 500)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	offset, err := intParam(q.Get("offset"), 0, 0, 1_000_000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	where := ` WHERE n.snapshot_id = $1 AND n.type = 'binary_function' AND ($3 = '' OR n.label ILIKE '%' || $3 || '%' OR n.attrs->>'addr' = $3)
		AND CASE $4
		  WHEN 'matched' THEN d.side = 'matched'
		  WHEN 'binary_only' THEN d.side = 'binary_only'
		  WHEN 'library' THEN d.side IS NULL AND COALESCE((n.attrs->>'library')::boolean, false)
		  WHEN 'unmatched' THEN d.side IS NULL AND NOT COALESCE((n.attrs->>'library')::boolean, false)
		  WHEN 'sensitive' THEN COALESCE(d.sensitive, false) OR n.attrs->>'package' = ANY($5)
		  ELSE true END`
	sens := make([]string, 0, len(sensitiveGoPackages))
	for k := range sensitiveGoPackages {
		sens = append(sens, k)
	}
	args := []any{*a.SnapshotID, a.ID, search, match, sens}
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM codegraph_nodes n
		LEFT JOIN LATERAL (SELECT side, sensitive FROM rea_diff_items x WHERE x.analysis_id = $2 AND x.binary_node_key = n.node_key
		AND x.kind = 'function' LIMIT 1) d ON true`+where, args...).Scan(&total); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, functionSelect+where+` ORDER BY COALESCE((n.attrs->>'library')::boolean, false), n.label, n.id
		LIMIT $6 OFFSET $7`, append(args, limit, offset)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FunctionItem, error) { return scanFunction(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []FunctionItem{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// StringItem is a string of the Strings tab.
type StringItem struct {
	NodeID   uuid.UUID `json:"node_id"`
	Value    string    `json:"value"`
	Offset   int64     `json:"offset"`
	VAddr    int64     `json:"vaddr"`
	Section  string    `json:"section"`
	Kind     string    `json:"kind"`
	Redacted bool      `json:"redacted"`
	Tool     string    `json:"tool"`
}

const stringSelect = `SELECT n.id, n.label, COALESCE((n.attrs->>'offset')::bigint, 0), COALESCE((n.attrs->>'vaddr')::bigint, 0),
	COALESCE(n.attrs->>'section', ''), COALESCE(n.attrs->>'kind', ''), COALESCE((n.attrs->>'redacted')::boolean, false),
	COALESCE(n.attrs->>'tool', '') FROM codegraph_nodes n`

func scanString(row pgx.Row) (StringItem, error) {
	var it StringItem
	err := row.Scan(&it.NodeID, &it.Value, &it.Offset, &it.VAddr, &it.Section, &it.Kind, &it.Redacted, &it.Tool)
	if it.Redacted {
		it.Value = "[REDACTED]"
	}
	return it, err
}

func (s *Service) function(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	nid, err := pathUUID(r, "nid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := scanFunction(s.DB.QueryRow(ctx, functionSelect+` WHERE n.snapshot_id = $1 AND n.id = $3 AND n.type = 'binary_function'`,
		*a.SnapshotID, a.ID, nid))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var code map[string]any
	var tool, kind, body string
	switch err := s.DB.QueryRow(ctx, `SELECT tool, kind, body FROM rea_code WHERE analysis_id = $1 AND node_key = $2`, a.ID, f.Key).
		Scan(&tool, &kind, &body); {
	case err == nil:
		code = map[string]any{"tool": tool, "kind": kind, "text": body}
	case !errors.Is(err, pgx.ErrNoRows):
		s.fail(w, r, err)
		return
	}
	related := func(query string) ([]FunctionItem, error) {
		rows, err := s.DB.Query(ctx, functionSelect+query, *a.SnapshotID, a.ID, nid)
		if err != nil {
			return nil, err
		}
		out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FunctionItem, error) { return scanFunction(row) })
		if out == nil {
			out = []FunctionItem{}
		}
		return out, err
	}
	// The joins start from the edges of the node (edge indexes on source
	// and target): a fresh graph has no planner statistics yet.
	callees, err := related(` JOIN codegraph_edges e ON e.target_id = n.id WHERE e.snapshot_id = $1 AND e.source_id = $3 AND e.type = 'calls'
		AND n.type = 'binary_function' ORDER BY n.label LIMIT 100`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	callers, err := related(` JOIN codegraph_edges e ON e.source_id = n.id WHERE e.snapshot_id = $1 AND e.target_id = $3 AND e.type = 'calls'
		ORDER BY n.label LIMIT 100`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var imports []map[string]any
	rows, err := s.DB.Query(ctx, `SELECT n.id, n.label, COALESCE(n.attrs->>'library', '') FROM codegraph_edges e
		JOIN codegraph_nodes n ON n.id = e.target_id WHERE e.snapshot_id = $1 AND e.source_id = $2 AND e.type = 'calls' AND n.type = 'import'
		ORDER BY n.label LIMIT 100`, *a.SnapshotID, nid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var id uuid.UUID
		var name, lib string
		if err := rows.Scan(&id, &name, &lib); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		imports = append(imports, map[string]any{"node_id": id, "name": name, "library": lib})
	}
	rows.Close()
	srows, err := s.DB.Query(ctx, stringSelect+` JOIN codegraph_edges e ON e.target_id = n.id WHERE e.snapshot_id = $1 AND e.source_id = $2
		AND e.type = 'references' AND n.type = 'string_ref' ORDER BY n.label LIMIT 100`, *a.SnapshotID, nid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	strs, err := pgx.CollectRows(srows, func(row pgx.CollectableRow) (StringItem, error) { return scanString(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if strs == nil {
		strs = []StringItem{}
	}
	if imports == nil {
		imports = []map[string]any{}
	}
	ev := []EvidenceItem{binEv(f.Offset, f.Tool, "function "+f.Name+" at "+f.Addr)}
	if f.Source != nil {
		ev = append(ev, srcEv(f.Source.File, f.Source.Line, "matched source function"))
	}
	out := map[string]any{"function": f, "code": code, "callers": callers, "callees": callees, "imports": imports, "strings": strs, "evidence": ev}
	if code == nil {
		out["code_withheld"] = "no code view was produced for this function (the analysis keeps code for the artifact's own and sensitive functions, up to its limit)"
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) strings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	search := strings.TrimSpace(q.Get("q"))
	kind := q.Get("kind")
	if kind != "" && !slices.Contains([]string{"text", "url", "path", "route", "secret", "format"}, kind) {
		s.fail(w, r, httpx.BadRequest("unknown string kind"))
		return
	}
	limit, err := intParam(q.Get("limit"), 50, 1, 500)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	offset, err := intParam(q.Get("offset"), 0, 0, 1_000_000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	where := ` WHERE n.snapshot_id = $1 AND n.type = 'string_ref' AND ($2 = '' OR (n.label ILIKE '%' || $2 || '%' AND NOT COALESCE((n.attrs->>'redacted')::boolean, false)))
		AND ($3 = '' OR n.attrs->>'kind' = $3)`
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM codegraph_nodes n`+where, *a.SnapshotID, search, kind).Scan(&total); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, stringSelect+where+` ORDER BY COALESCE((n.attrs->>'offset')::bigint, 0), n.id LIMIT $4 OFFSET $5`,
		*a.SnapshotID, search, kind, limit, offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (StringItem, error) { return scanString(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []StringItem{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Service) imports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	search := strings.TrimSpace(q.Get("q"))
	limit, err := intParam(q.Get("limit"), 50, 1, 500)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	offset, err := intParam(q.Get("offset"), 0, 0, 1_000_000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	where := ` WHERE n.snapshot_id = $1 AND n.type = 'import' AND ($2 = '' OR n.label ILIKE '%' || $2 || '%' OR n.attrs->>'library' ILIKE '%' || $2 || '%')`
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM codegraph_nodes n`+where, *a.SnapshotID, search).Scan(&total); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT n.id, n.node_key, n.label, COALESCE(n.attrs->>'library', ''), COALESCE(n.attrs->>'kind', ''),
		COALESCE(n.attrs->>'tool', '') FROM codegraph_nodes n`+where+` ORDER BY n.attrs->>'library', n.label, n.id LIMIT $3 OFFSET $4`,
		*a.SnapshotID, search, limit, offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type item struct {
		NodeID    uuid.UUID `json:"node_id"`
		Name      string    `json:"name"`
		Library   string    `json:"library"`
		Kind      string    `json:"kind"`
		Tool      string    `json:"tool"`
		Sensitive bool      `json:"sensitive"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		var key string
		if err := rows.Scan(&it.NodeID, &key, &it.Name, &it.Library, &it.Kind, &it.Tool); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		_, goSens := sensitiveGoPackages[strings.TrimPrefix(key, "imp:go:")]
		_, nativeSens := sensitiveImports[it.Name]
		it.Sensitive = (strings.HasPrefix(key, "imp:go:") && goSens) || (!strings.HasPrefix(key, "imp:go:") && nativeSens)
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Service) sections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT n.id, n.label, COALESCE((n.attrs->>'offset')::bigint, 0), COALESCE((n.attrs->>'vaddr')::bigint, 0),
		COALESCE((n.attrs->>'size')::bigint, 0), COALESCE(n.attrs->>'perm', ''), COALESCE((n.attrs->>'entropy')::float8, 0),
		COALESCE(n.attrs->>'tool', '') FROM codegraph_nodes n WHERE n.snapshot_id = $1 AND n.type = 'section'
		ORDER BY COALESCE((n.attrs->>'offset')::bigint, 0), n.id LIMIT 2000`, *a.SnapshotID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type item struct {
		NodeID  uuid.UUID `json:"node_id"`
		Name    string    `json:"name"`
		Offset  int64     `json:"offset"`
		VAddr   int64     `json:"vaddr"`
		Size    int64     `json:"size"`
		Perm    string    `json:"perm"`
		Entropy float64   `json:"entropy"`
		Tool    string    `json:"tool"`
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (item, error) {
		var it item
		err := row.Scan(&it.NodeID, &it.Name, &it.Offset, &it.VAddr, &it.Size, &it.Perm, &it.Entropy, &it.Tool)
		return it, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []item{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Service) graph(w http.ResponseWriter, r *http.Request) {
	p, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Graph.BinaryGraph(r.Context(), p, *a.SnapshotID, r.URL.Query())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out["analysis_id"] = a.ID
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) graphNode(w http.ResponseWriter, r *http.Request) {
	p, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	nid, err := pathUUID(r, "nid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Graph.BinaryNode(r.Context(), p, *a.SnapshotID, nid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
