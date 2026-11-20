package rea

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/codegraph"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/platform/tenant"
	"pathos/internal/scanners"
	"pathos/internal/scans"
)

// OnREAResult stores the document of a reverse-engineering execution
// (scans.Service hook). Errors are recorded on the analysis, never returned.
func (s *Service) OnREAResult(ctx context.Context, orgID, jobID uuid.UUID, res scans.REAResult) {
	ctx = tenant.WithOrg(ctx, orgID)
	log := s.Log.With("scan_job_id", jobID)
	var id uuid.UUID
	var sha string
	err := s.DB.QueryRow(ctx, `SELECT id, artifact_sha256 FROM rea_analyses WHERE scan_job_id = $1 AND organization_id = $2`, jobID, orgID).
		Scan(&id, &sha)
	if errors.Is(err, pgx.ErrNoRows) {
		log.Warn("reverse-engineering result without an analysis ignored")
		return
	}
	if err != nil {
		log.Error("reverse-engineering analysis lookup failed", "err", err, "error_code", CodeStoreFailed)
		return
	}
	if res.Status != "succeeded" {
		code := CodeSandboxFailed
		if res.Status == "timed_out" {
			code = CodeTimedOut
		}
		msg := "the analysis " + strings.ReplaceAll(res.Status, "_", " ")
		if res.Error != "" {
			msg += ": " + res.Error
		}
		s.failAnalysis(ctx, id, code, msg)
		log.Warn("reverse-engineering analysis did not succeed", "status", res.Status, "error_code", code)
		return
	}
	start := time.Now()
	d, err := ParseDoc(res.Raw, sha)
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			s.failAnalysis(ctx, id, CodeInvalidDoc, ve.Error())
			log.Warn("reverse-engineering document refused", "err", err, "error_code", CodeInvalidDoc)
			return
		}
		s.failAnalysis(ctx, id, CodeStoreFailed, "the analysis could not be read")
		return
	}
	if err := s.store(ctx, orgID, id, d); err != nil {
		var ve *codegraph.ValidationError
		if errors.As(err, &ve) {
			s.failAnalysis(ctx, id, CodeInvalidDoc, ve.Error())
			log.Warn("reverse-engineering graph refused", "err", err, "error_code", CodeInvalidDoc)
			return
		}
		s.failAnalysis(ctx, id, CodeStoreFailed, "the analysis could not be stored")
		log.Error("reverse-engineering store failed", "err", err, "error_code", CodeStoreFailed)
		return
	}
	if err := s.computeDiff(ctx, orgID, id, nil); err != nil {
		log.Error("source ↔ binary diff failed", "err", err, "error_code", CodeStoreFailed)
	}
	log.Info("reverse-engineering analysis stored", "analysis_id", id, "functions", len(d.Functions), "strings", len(d.Strings),
		"duration_ms", time.Since(start).Milliseconds())
}

func (s *Service) failAnalysis(ctx context.Context, id uuid.UUID, code, msg string) {
	if _, err := s.DB.Exec(ctx, `UPDATE rea_analyses SET status = 'failed', error_code = $2, error = left($3, 2000),
		started_at = COALESCE(started_at, now()), finished_at = now() WHERE id = $1 AND status IN ('queued', 'running')`,
		id, code, logging.RedactString(msg)); err != nil {
		s.Log.Error("reverse-engineering status update failed", "analysis_id", id, "err", err)
	}
}

var vcsRevisionRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// store writes the binary graph, the code views and the analysis summary
// in one transaction.
func (s *Service) store(ctx context.Context, orgID, id uuid.UUID, d *Doc) error {
	return db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var status, commit, commitSource string
		var repoID uuid.UUID
		var appID *uuid.UUID
		var enabled []string
		if err := tx.QueryRow(ctx, `SELECT status, commit_sha, commit_source, repository_id, application_id, tools FROM rea_analyses
			WHERE id = $1 FOR UPDATE`, id).Scan(&status, &commit, &commitSource, &repoID, &appID, new([]byte)); err != nil {
			return err
		}
		if status != "queued" && status != "running" {
			return fmt.Errorf("analysis is %s", status)
		}
		// The commit: verified provenance (set at start) wins; otherwise the
		// build information embedded in a Go binary.
		if commitSource == "" && d.Go != nil {
			if rev := strings.ToLower(d.Go.Settings["vcs.revision"]); vcsRevisionRe.MatchString(rev) {
				commit, commitSource = rev, "binary"
			}
		}
		partial := false
		if t, _ := d.Stats["truncated"].(bool); t {
			partial = true
		}
		_ = tx.QueryRow(ctx, `SELECT COALESCE(array_agg(t), '{}') FROM jsonb_array_elements_text(
			(SELECT config_snapshot->'scanners'->0->'config'->'tools' FROM scan_jobs WHERE id = (SELECT scan_job_id FROM rea_analyses WHERE id = $1))) t`,
			id).Scan(&enabled)
		for k, t := range d.Tools {
			if slices.Contains(enabled, k) && (t.Status == "failed" || t.Status == "timed_out") {
				partial = true
			}
		}
		engines := map[string]string{}
		for k, t := range d.Tools {
			if t.Status == "succeeded" {
				engines[k] = t.Version
			}
		}
		g := d.Graph()
		sid, _, err := codegraph.StoreBinary(ctx, tx, codegraph.BinaryRef{OrgID: orgID, RepoID: repoID, AppID: appID, CommitSHA: commit,
			Partial: partial, Engines: engines, Stats: map[string]any{"analysis_id": id.String()}}, g)
		if err != nil {
			return err
		}
		for i := 0; i < len(d.Code); i += 200 {
			b := &pgx.Batch{}
			for _, c := range d.Code[i:min(i+200, len(d.Code))] {
				tool := c.Tool
				if tool == "pathos-rea" || tool == "go" {
					tool = "radare2"
				}
				b.Queue(`INSERT INTO rea_code (id, organization_id, analysis_id, node_key, tool, kind, body) VALUES ($1, $2, $3, $4, $5, $6, $7)
					ON CONFLICT (analysis_id, node_key) DO NOTHING`, uuid.Must(uuid.NewV7()), orgID, id, c.Function, tool, c.Kind, c.Text)
			}
			if err := tx.SendBatch(ctx, b).Close(); err != nil {
				return err
			}
		}
		tools, _ := json.Marshal(d.Tools)
		stats := summaryStats(d)
		statsJSON, _ := json.Marshal(stats)
		st := "ready"
		if partial {
			st = "partial"
		}
		_, err = tx.Exec(ctx, `UPDATE rea_analyses SET status = $2, snapshot_id = $3, format = $4, arch = $5, language = $6, tools = $7,
			stats = $8, commit_sha = $9, commit_source = $10, started_at = COALESCE(started_at, now()), finished_at = now(),
			error_code = '', error = '' WHERE id = $1`,
			id, st, sid, text(d.Artifact.Format, 32), text(d.Artifact.Arch, 32), text(d.Artifact.Language, 32), tools, statsJSON, commit, commitSource)
		return err
	})
}

// summaryStats keeps the document's statistics, the Go build information
// and the firmware contents (bounded) on the analysis.
func summaryStats(d *Doc) map[string]any {
	out := map[string]any{}
	for k, v := range d.Stats {
		switch v.(type) {
		case string, bool, float64, json.Number:
			out[text(k, 64)] = v
		}
	}
	out["sections"], out["functions"], out["imports"], out["strings"], out["calls"] = len(d.Sections), len(d.Functions), len(d.Imports),
		len(d.Strings), len(d.Calls)
	out["bits"], out["os"], out["stripped"], out["entry"], out["size"] = d.Artifact.Bits, d.Artifact.OS, d.Artifact.Stripped, d.Artifact.Entry, d.Artifact.Size
	if g := d.Go; g != nil {
		gi := map[string]any{"go_version": g.GoVersion, "path": g.Path, "main_module": g.MainModule.Path, "deps": len(g.Deps)}
		for _, k := range []string{"vcs", "vcs.revision", "vcs.time", "vcs.modified", "GOOS", "GOARCH", "CGO_ENABLED"} {
			if v := g.Settings[k]; v != "" {
				gi[k] = v
			}
		}
		out["go"] = gi
	}
	if f := d.Firmware; f != nil {
		var entries []map[string]any
		for _, e := range f.Entries {
			if len(entries) >= 100 {
				break
			}
			entries = append(entries, map[string]any{"offset": e.Offset, "type": text(e.Type, 64), "description": text(e.Description, 300),
				"size": e.Size, "extracted": e.Extracted})
		}
		var files []map[string]any
		for _, x := range f.Files {
			if len(files) >= 200 {
				break
			}
			files = append(files, map[string]any{"path": text(x.Path, 300), "size": x.Size, "type": text(x.Type, 64), "sha256": text(x.SHA256, 64)})
		}
		out["firmware"] = map[string]any{"entries": entries, "files": files, "entries_total": len(f.Entries), "files_total": len(f.Files)}
	}
	if b, _ := json.Marshal(out); len(b) > 60000 {
		delete(out, "firmware")
	}
	return out
}

// reconcile settles analyses whose execution ended without a stored
// result (worker failure, lease expiry, cancellation) and marks running
// ones.
func reconcile(ctx context.Context, q db.Querier, orgID uuid.UUID) error {
	if _, err := q.Exec(ctx, `UPDATE rea_analyses a SET status = 'running', started_at = COALESCE(a.started_at, j.started_at)
		FROM scan_jobs j WHERE j.id = a.scan_job_id AND a.organization_id = $1 AND a.status = 'queued' AND j.status = 'running'`, orgID); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE rea_analyses a SET status = 'failed', error_code = $2, finished_at = COALESCE(j.finished_at, now()),
		error = left(CASE WHEN j.error <> '' THEN j.error WHEN j.status = 'cancelled' THEN 'the analysis was cancelled'
		                  ELSE 'the analysis ended without a result' END, 2000)
		FROM scan_jobs j WHERE j.id = a.scan_job_id AND a.organization_id = $1 AND a.status IN ('queued', 'running')
		  AND j.status IN ('succeeded', 'partial', 'failed', 'cancelled') AND j.finished_at < now() - interval '30 seconds'`, orgID, CodeSandboxFailed)
	return err
}

// --- source ↔ binary diff ----------------------------------------------------

// computeDiff compares the analysis with a source snapshot: the given one
// (chosen by a person) or the newest ready snapshot of the artifact's
// repository at the analysis commit.
func (s *Service) computeDiff(ctx context.Context, orgID, id uuid.UUID, chosen *uuid.UUID) error {
	var repoID uuid.UUID
	var commit, artifact string
	var snapshotID *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, commit_sha, snapshot_id, artifact_name FROM rea_analyses WHERE id = $1 AND organization_id = $2`,
		id, orgID).Scan(&repoID, &commit, &snapshotID, &artifact); err != nil {
		return err
	}
	if snapshotID == nil {
		return nil
	}
	var src uuid.UUID
	switch {
	case chosen != nil:
		src = *chosen
	case commit == "":
		_, err := s.DB.Exec(ctx, `UPDATE rea_analyses SET diff_status = 'no_commit' WHERE id = $1`, id)
		return err
	default:
		err := s.DB.QueryRow(ctx, `SELECT id FROM codegraph_snapshots WHERE organization_id = $1 AND repository_id = $2 AND kind = 'source'
			AND status IN ('ready', 'partial') AND storage = 'rows' AND (commit_sha = $3 OR (length($3) < 40 AND commit_sha LIKE $3 || '%'))
			ORDER BY created_at DESC LIMIT 1`, orgID, repoID, commit).Scan(&src)
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = s.DB.Exec(ctx, `UPDATE rea_analyses SET diff_status = 'no_source_snapshot' WHERE id = $1`, id)
			return err
		}
		if err != nil {
			return err
		}
	}
	d, err := s.docFromGraph(ctx, *snapshotID)
	if err != nil {
		return err
	}
	rows, err := s.DB.Query(ctx, `SELECT node_key, type, label, file_path, COALESCE(start_line, 0), attrs FROM codegraph_nodes
		WHERE snapshot_id = $1 AND type IN ('function', 'route', 'module', 'component', 'file', 'external_service')`, src)
	if err != nil {
		return err
	}
	source, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SourceNode, error) {
		var n SourceNode
		var attrs []byte
		err := row.Scan(&n.Key, &n.Type, &n.Label, &n.File, &n.Line, &attrs)
		_ = json.Unmarshal(attrs, &n.Attrs)
		return n, err
	})
	if err != nil {
		return err
	}
	items := Compare(d, source)
	drafts := Drafts(items, artifact)
	return db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM rea_diff_items WHERE analysis_id = $1`, id); err != nil {
			return err
		}
		ids := make([]uuid.UUID, len(items))
		for i := 0; i < len(items); i += 500 {
			b := &pgx.Batch{}
			for j := i; j < min(i+500, len(items)); j++ {
				it := items[j]
				ids[j] = uuid.Must(uuid.NewV7())
				ev, _ := json.Marshal(it.Evidence)
				var off *int64
				if it.HasOffset {
					off = &it.BinaryOffset
				}
				var line *int
				if it.SourceLine > 0 {
					line = &it.SourceLine
				}
				b.Queue(`INSERT INTO rea_diff_items (id, organization_id, analysis_id, side, kind, name, binary_node_key, source_node_key,
					source_file, source_line, binary_offset, tool, sensitive, sensitive_reason, evidence)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
					ids[j], orgID, id, it.Side, it.Kind, it.Name, text(it.BinaryKey, 300), text(it.SourceKey, 300), text(it.SourceFile, 1000), line,
					off, text(it.Tool, 32), it.Sensitive, text(it.SensitiveReason, 500), ev)
			}
			if err := tx.SendBatch(ctx, b).Close(); err != nil {
				return err
			}
		}
		for _, dr := range drafts {
			ev, _ := json.Marshal(dr.Evidence)
			if _, err := tx.Exec(ctx, `INSERT INTO rea_finding_drafts (id, organization_id, analysis_id, diff_item_id, title, description,
				severity, rule_id, cwe, evidence) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
				uuid.Must(uuid.NewV7()), orgID, id, ids[dr.ItemIndex], dr.Title, dr.Description, dr.Severity, dr.RuleID, dr.CWE, ev); err != nil {
				return err
			}
		}
		commitSource := ""
		if chosen != nil {
			commitSource = "user"
		}
		_, err := tx.Exec(ctx, `UPDATE rea_analyses SET diff_status = 'ready', source_snapshot_id = $2,
			commit_source = CASE WHEN $3 <> '' THEN $3 ELSE commit_source END,
			commit_sha = CASE WHEN $3 <> '' THEN (SELECT commit_sha FROM codegraph_snapshots WHERE id = $2) ELSE commit_sha END
			WHERE id = $1`, id, src, commitSource)
		return err
	})
}

// docFromGraph rebuilds the facts the diff needs from a stored binary
// graph (functions, imports, strings and string references).
func (s *Service) docFromGraph(ctx context.Context, sid uuid.UUID) (*Doc, error) {
	d := &Doc{}
	rows, err := s.DB.Query(ctx, `SELECT node_key, type, label, attrs FROM codegraph_nodes WHERE snapshot_id = $1
		AND type IN ('binary', 'binary_function', 'import', 'string_ref')`, sid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, typ, label string
		var raw []byte
		if err := rows.Scan(&key, &typ, &label, &raw); err != nil {
			return nil, err
		}
		var a map[string]any
		_ = json.Unmarshal(raw, &a)
		str := func(k string) string { v, _ := a[k].(string); return v }
		num := func(k string) int64 { v, _ := a[k].(float64); return int64(v) }
		boolean := func(k string) bool { v, _ := a[k].(bool); return v }
		switch typ {
		case "binary":
			d.Artifact.Language, d.Artifact.Format = str("language"), str("format")
			d.Artifact.FileName = label
		case "binary_function":
			d.Functions = append(d.Functions, Function{ID: key, Name: label, Addr: str("addr"), Offset: num("offset"), Size: num("size"),
				Section: str("section"), Tool: str("tool"), Library: boolean("library"), Package: str("package")})
		case "import":
			d.Imports = append(d.Imports, Import{ID: key, Name: label, Library: str("library"), Kind: str("kind"), Offset: num("offset"), Tool: str("tool")})
		case "string_ref":
			d.Strings = append(d.Strings, String{ID: key, Value: label, Offset: num("offset"), Section: str("section"), Kind: str("kind"),
				Redacted: boolean("redacted"), Tool: str("tool")})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	erows, err := s.DB.Query(ctx, `SELECT s.node_key, t.node_key FROM codegraph_edges e JOIN codegraph_nodes s ON s.id = e.source_id
		JOIN codegraph_nodes t ON t.id = e.target_id WHERE e.snapshot_id = $1 AND e.type = 'references'`, sid)
	if err != nil {
		return nil, err
	}
	defer erows.Close()
	for erows.Next() {
		var from, to string
		if err := erows.Scan(&from, &to); err != nil {
			return nil, err
		}
		d.StringRefs = append(d.StringRefs, Ref{From: from, To: to})
	}
	if err := erows.Err(); err != nil {
		return nil, err
	}
	// Go build information (main module and package) from the analysis.
	var goInfo map[string]any
	_ = s.DB.QueryRow(ctx, `SELECT stats->'go' FROM rea_analyses WHERE snapshot_id = $1`, sid).Scan(&goInfo)
	if goInfo != nil {
		g := &GoInfo{}
		g.Path, _ = goInfo["path"].(string)
		g.MainModule.Path, _ = goInfo["main_module"].(string)
		g.GoVersion, _ = goInfo["go_version"].(string)
		d.Go = g
		d.Artifact.Language = "go"
	}
	return d, nil
}

// --- diff and drafts API ----------------------------------------------------

func (s *Service) diff(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	side, kind := q.Get("side"), q.Get("kind")
	if side != "" && !slices.Contains([]string{"binary_only", "source_only", "matched"}, side) {
		s.fail(w, r, httpx.BadRequest("side must be binary_only, source_only or matched"))
		return
	}
	if kind != "" && !slices.Contains([]string{"function", "package", "route", "string"}, kind) {
		s.fail(w, r, httpx.BadRequest("kind must be function, package, route or string"))
		return
	}
	sensitiveOnly := q.Get("sensitive") == "true"
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
	counts := map[string]int{"binary_only": 0, "source_only": 0, "matched": 0}
	rows, err := s.DB.Query(ctx, `SELECT side, count(*) FROM rea_diff_items WHERE analysis_id = $1 GROUP BY side`, a.ID)
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
		counts[k] = n
	}
	rows.Close()
	where := ` WHERE d.analysis_id = $1 AND ($2 = '' OR d.side = $2) AND ($3 = '' OR d.kind = $3) AND (NOT $4 OR d.sensitive)`
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM rea_diff_items d`+where, a.ID, side, kind, sensitiveOnly).Scan(&total); err != nil {
		s.fail(w, r, err)
		return
	}
	irows, err := s.DB.Query(ctx, `SELECT d.id, d.side, d.kind, d.name, d.sensitive, d.sensitive_reason, d.binary_node_key, d.binary_offset,
		d.tool, d.source_node_key, d.source_file, COALESCE(d.source_line, 0), d.evidence, bn.id, sn.id
		FROM rea_diff_items d
		LEFT JOIN codegraph_nodes bn ON bn.snapshot_id = $5 AND bn.node_key = d.binary_node_key AND d.binary_node_key <> ''
		LEFT JOIN codegraph_nodes sn ON sn.snapshot_id = $6 AND sn.node_key = d.source_node_key AND d.source_node_key <> ''`+where+`
		ORDER BY d.sensitive DESC, d.side, d.kind, d.name, d.id LIMIT $7 OFFSET $8`,
		a.ID, side, kind, sensitiveOnly, a.SnapshotID, a.SourceSnapshotID, limit, offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type binRef struct {
		NodeID *uuid.UUID `json:"node_id"`
		Key    string     `json:"key"`
		Offset *int64     `json:"offset"`
		Tool   string     `json:"tool"`
	}
	type srcRef struct {
		NodeID *uuid.UUID `json:"node_id"`
		Key    string     `json:"key"`
		File   string     `json:"file"`
		Line   int        `json:"line"`
	}
	type item struct {
		ID              uuid.UUID       `json:"id"`
		Side            string          `json:"side"`
		Kind            string          `json:"kind"`
		Name            string          `json:"name"`
		Sensitive       bool            `json:"sensitive"`
		SensitiveReason string          `json:"sensitive_reason"`
		Binary          *binRef         `json:"binary"`
		Source          *srcRef         `json:"source"`
		Evidence        json.RawMessage `json:"evidence"`
	}
	items := []item{}
	for irows.Next() {
		var it item
		var bk, tool, sk, file string
		var off *int64
		var line int
		var bid, sid *uuid.UUID
		if err := irows.Scan(&it.ID, &it.Side, &it.Kind, &it.Name, &it.Sensitive, &it.SensitiveReason, &bk, &off, &tool, &sk, &file, &line,
			&it.Evidence, &bid, &sid); err != nil {
			irows.Close()
			s.fail(w, r, err)
			return
		}
		if bk != "" {
			it.Binary = &binRef{NodeID: bid, Key: bk, Offset: off, Tool: tool}
		}
		if sk != "" || file != "" {
			it.Source = &srcRef{NodeID: sid, Key: sk, File: file, Line: line}
		}
		items = append(items, it)
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": a.DiffStatus, "commit_sha": a.CommitSHA, "commit_source": a.CommitSource,
		"source_snapshot_id": a.SourceSnapshotID, "counts": counts, "items": items, "total": total})
}

type diffRequest struct {
	SourceSnapshotID uuid.UUID `json:"source_snapshot_id"`
}

// recomputeDiff compares the analysis with a CodeGraph source snapshot a
// person chose (the diff is then labelled commit_source "user").
func (s *Service) recomputeDiff(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, a, err := s.loadReady(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Authz.Require(ctx, p, authz.PermREARun, authz.Scope{Type: authz.ScopeRepository, ID: a.RepositoryID}); err != nil {
		s.fail(w, r, err)
		return
	}
	var in diffRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var repoID uuid.UUID
	err = s.DB.QueryRow(ctx, `SELECT repository_id FROM codegraph_snapshots WHERE organization_id = $1 AND id = $2 AND kind = 'source'
		AND status IN ('ready', 'partial') AND storage = 'rows'`, p.OrganizationID, in.SourceSnapshotID).Scan(&repoID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && repoID != a.RepositoryID) {
		s.fail(w, r, httpx.E(http.StatusConflict, "rea_no_source_snapshot",
			"choose a ready CodeGraph snapshot of the artifact's repository").WithDiag(CodeNoSourceSnapshot))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var decided int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM rea_finding_drafts WHERE analysis_id = $1 AND status <> 'proposed'`, a.ID).Scan(&decided); err != nil {
		s.fail(w, r, err)
		return
	}
	if decided > 0 {
		s.fail(w, r, httpx.Conflict("finding drafts of this analysis were already decided; run a new analysis to compare with another snapshot"))
		return
	}
	if err := s.computeDiff(ctx, p.OrganizationID, a.ID, &in.SourceSnapshotID); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "rea.diff.recompute", TargetType: "rea_analysis", TargetID: a.ID.String(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"source_snapshot_id": in.SourceSnapshotID}})
	r2 := r.Clone(ctx)
	r2.URL.RawQuery = ""
	s.diff(w, r2)
}

// DraftOut is a finding draft (always a proposal until a person decides).
type DraftOut struct {
	ID            uuid.UUID       `json:"id"`
	Title         string          `json:"title"`
	Description   string          `json:"description"`
	Severity      string          `json:"severity"`
	RuleID        string          `json:"rule_id"`
	CWE           []string        `json:"cwe"`
	Status        string          `json:"status"`
	Label         string          `json:"label"`
	Evidence      json.RawMessage `json:"evidence"`
	DiffItemID    uuid.UUID       `json:"diff_item_id"`
	FindingID     *uuid.UUID      `json:"finding_id"`
	ApplicationID *uuid.UUID      `json:"application_id"`
	AnalysisID    uuid.UUID       `json:"analysis_id"`
	Reason        string          `json:"decision_reason,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

const draftSelect = `SELECT d.id, d.title, d.description, d.severity, d.rule_id, d.cwe, d.status, d.evidence, d.diff_item_id, d.finding_id,
	a.application_id, d.analysis_id, d.decision_reason, d.created_at, a.repository_id
	FROM rea_finding_drafts d JOIN rea_analyses a ON a.id = d.analysis_id`

func scanDraft(row pgx.Row) (DraftOut, uuid.UUID, error) {
	var d DraftOut
	var repoID uuid.UUID
	err := row.Scan(&d.ID, &d.Title, &d.Description, &d.Severity, &d.RuleID, &d.CWE, &d.Status, &d.Evidence, &d.DiffItemID, &d.FindingID,
		&d.ApplicationID, &d.AnalysisID, &d.Reason, &d.CreatedAt, &repoID)
	d.Label = "proposal"
	return d, repoID, err
}

func (s *Service) drafts(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.DB.Query(ctx, draftSelect+` WHERE d.analysis_id = $1 ORDER BY CASE d.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
		WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, d.created_at`, a.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (DraftOut, error) { d, _, err := scanDraft(row); return d, err })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []DraftOut{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"drafts": out})
}

// draft loads a draft and checks perm on its repository.
func (s *Service) draft(ctx context.Context, p *authz.Principal, perm authz.Permission, id uuid.UUID) (DraftOut, uuid.UUID, error) {
	d, repoID, err := scanDraft(s.DB.QueryRow(ctx, draftSelect+` WHERE d.organization_id = $1 AND d.id = $2`, p.OrganizationID, id))
	if err != nil {
		return d, repoID, err
	}
	if err := s.requireRepo(ctx, p, perm, repoID); err != nil {
		return d, repoID, err
	}
	if d.Status != "proposed" {
		return d, repoID, httpx.Conflict("the draft was already " + d.Status)
	}
	return d, repoID, nil
}

// createFinding turns a proposal into a finding by a person's decision.
// The finding starts as needs_review (never confirmed by itself) and keeps
// the draft's evidence.
func (s *Service) createFinding(w http.ResponseWriter, r *http.Request) {
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
	d, repoID, err := s.draft(ctx, p, authz.PermFindingsTriage, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var jobID, targetID uuid.UUID
	var artifact, sha string
	if err := s.DB.QueryRow(ctx, `SELECT scan_job_id, target_id, artifact_name, artifact_sha256 FROM rea_analyses WHERE id = $1`, d.AnalysisID).
		Scan(&jobID, &targetID, &artifact, &sha); err != nil {
		s.fail(w, r, err)
		return
	}
	var findingID uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		desc := d.Description + "\n\nEvidence (verified):\n" + evidenceText(d.Evidence)
		f := scanners.Finding{ScannerKey: scanners.PathosREA, Category: "binary", RuleID: d.RuleID, Title: d.Title, Severity: d.Severity,
			Description: text(desc, 8000), FilePath: firstNonEmpty(artifact, sha), Confidence: "medium", CWE: d.CWE}
		var err error
		findingID, err = scans.InsertReviewFinding(ctx, tx, p.OrganizationID, repoID, jobID, targetID, f, "rea:"+sha+":"+d.RuleID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE rea_finding_drafts SET status = 'created', finding_id = $2, decided_by = $3, decided_at = now()
			WHERE id = $1 AND status = 'proposed'`, d.ID, findingID, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "rea.draft.create_finding", TargetType: "finding", TargetID: findingID.String(), RequestID: httpx.RequestID(r),
			Metadata: map[string]any{"draft_id": d.ID, "analysis_id": d.AnalysisID, "rule_id": d.RuleID, "severity": d.Severity}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"finding_id": findingID, "status": "needs_review"})
}

func evidenceText(raw json.RawMessage) string {
	var ev []EvidenceItem
	_ = json.Unmarshal(raw, &ev)
	var b strings.Builder
	for _, e := range ev {
		fmt.Fprintf(&b, "- %s %s — %s\n", e.Kind, e.Ref, e.Detail)
	}
	return b.String()
}

type dismissRequest struct {
	Reason string `json:"reason"`
}

func (s *Service) dismissDraft(w http.ResponseWriter, r *http.Request) {
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
	d, _, err := s.draft(ctx, p, authz.PermFindingsTriage, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in dismissRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || len(in.Reason) > 1000 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "invalid_request", "give a reason of at most 1000 characters"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE rea_finding_drafts SET status = 'dismissed', decided_by = $2, decided_at = now(), decision_reason = $3
			WHERE id = $1 AND status = 'proposed'`, d.ID, p.UserID, in.Reason); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "rea.draft.dismiss", TargetType: "rea_finding_draft", TargetID: d.ID.String(), RequestID: httpx.RequestID(r),
			Metadata: map[string]any{"analysis_id": d.AnalysisID, "rule_id": d.RuleID, "reason": in.Reason}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Status, d.Reason = "dismissed", in.Reason
	httpx.WriteJSON(w, http.StatusOK, d)
}
