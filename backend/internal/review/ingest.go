package review

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/objstore"
	"pathos/internal/scanners"
)

// Reasons recorded on automatically created reviews.
const (
	reasonNeedsReview = "Automated triage marked the finding as needing human review"
	reasonAINeeds     = "AI review could not decide (verdict: needs review)"
	reasonAIFalsePos  = "AI review suggested a false positive; a human must confirm"
	reasonRules       = "New finding matching the automatic review rules"
	reasonPolicy      = "Required by security policy: "
)

// coverSQL lists active users holding a permission that covers repository
// $2 (organization, region, business unit or repository grant).
const coverSQL = `
	WITH target AS (SELECT r.id, r.business_unit_id, c.region_id FROM repositories r
	                LEFT JOIN countries c ON c.id = r.country_id WHERE r.id = $2),
	     bus AS (WITH RECURSIVE up AS (SELECT id, parent_id FROM business_units WHERE id = (SELECT business_unit_id FROM target)
	              UNION ALL SELECT b.id, b.parent_id FROM business_units b JOIN up ON b.id = up.parent_id) SELECT id FROM up)
	SELECT DISTINCT u.id
	FROM role_assignments ra
	JOIN role_permissions rp ON rp.role_id = ra.role_id AND rp.permission_key = $3
	JOIN users u ON u.id = ra.user_id AND u.status = 'active'
	WHERE ra.organization_id = $1
	  AND (ra.scope_type = 'organization'
	       OR (ra.scope_type = 'repository' AND ra.scope_id = $2)
	       OR (ra.scope_type = 'business_unit' AND ra.scope_id IN (SELECT id FROM bus))
	       OR (ra.scope_type = 'region' AND ra.scope_id = (SELECT region_id FROM target)))`

// usersWith returns active users holding perm on repository repo.
func usersWith(ctx context.Context, q db.Querier, orgID, repo uuid.UUID, perm authz.Permission) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, coverSQL, orgID, repo, string(perm))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func userHas(ctx context.Context, q db.Querier, orgID, repo, user uuid.UUID, perm authz.Permission) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (`+coverSQL+` AND u.id = $4)`, orgID, repo, string(perm), user).Scan(&ok)
	return ok, err
}

// insertReviews creates reviews for findings (deduplicated by finding) and
// returns the ids of the reviews created. Findings that already have a
// review are skipped.
func insertReviews(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, findings []uuid.UUID, reasons []string, source string,
	by *uuid.UUID, priority *string, due *time.Time) ([]uuid.UUID, error) {
	if len(findings) == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO human_review_settings (organization_id) VALUES ($1) ON CONFLICT DO NOTHING`, orgID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		WITH input AS (SELECT DISTINCT ON (fid) fid, reason FROM unnest($2::uuid[], $3::text[]) AS t(fid, reason)),
		st AS (SELECT priority_by_severity, sla_days FROM human_review_settings WHERE organization_id = $1),
		ins AS (
		  INSERT INTO human_reviews (id, organization_id, finding_id, repository_id, scan_job_id, commit_sha, branch, snapshot_id, scanner_key,
		      file_path, start_line, original_severity, original_cvss, priority, due_at, source, source_reason, created_by, status)
		  SELECT gen_random_uuid(), f.organization_id, f.id, f.repository_id, occ.job_id,
		         COALESCE(NULLIF(occ.commit_sha, ''), occ.job_commit, ''), COALESCE(occ.ref, ''), occ.snapshot_id,
		         COALESCE(occ.scanner_key, f.scanner_keys[1], ''), f.file_path, f.start_line, f.severity, f.cvss,
		         COALESCE($6, st.priority_by_severity->>f.severity, 'p3'),
		         COALESCE($7, CASE WHEN COALESCE((st.sla_days->>f.severity)::int, 0) > 0
		                           THEN now() + make_interval(days => (st.sla_days->>f.severity)::int) END),
		         $4, left(input.reason, 2000), $5, 'pending'
		  FROM input
		  JOIN findings f ON f.id = input.fid AND f.organization_id = $1
		  CROSS JOIN st
		  LEFT JOIN LATERAL (
		      SELECT j.id AS job_id, o.commit_sha, j.commit_sha AS job_commit, j.ref, j.snapshot_id, sr.scanner_key
		      FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id JOIN scan_jobs j ON j.id = sr.scan_job_id
		      WHERE o.finding_id = f.id ORDER BY o.created_at DESC, o.id DESC LIMIT 1) occ ON true
		  ON CONFLICT (finding_id) DO NOTHING
		  RETURNING id, organization_id, finding_id, round, source_reason)
		INSERT INTO human_review_history (organization_id, review_id, finding_id, round, actor_id, action, field, new_value, note)
		SELECT organization_id, id, finding_id, round, $5, 'review.created', 'status', to_jsonb('pending'::text), source_reason FROM ins
		RETURNING review_id`, orgID, findings, reasons, source, by, priority, due)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// Ingest queues eligible findings of an organization according to the
// configuration. It is idempotent: a finding is never queued twice.
func (s *Service) Ingest(ctx context.Context, orgID uuid.UUID) (int, error) {
	st, err := loadSettings(ctx, s.DB, orgID)
	if err != nil {
		return 0, err
	}
	// Security policies that require a review apply whether or not
	// automatic queuing is on.
	byPolicy, err := s.ingestPolicyRequired(ctx, orgID, st)
	if err != nil {
		return 0, err
	}
	n, err := s.ingestAuto(ctx, orgID, st)
	return byPolicy + n, err
}

func (s *Service) ingestPolicyRequired(ctx context.Context, orgID uuid.UUID, st Settings) (int, error) {
	rows, err := s.DB.Query(ctx, `
		SELECT DISTINCT ON (v.finding_id) v.finding_id, p.name FROM policy_violations v
		JOIN security_policies p ON p.id = v.policy_id AND p.enabled AND (p.actions->>'require_review')::boolean
		JOIN findings f ON f.id = v.finding_id
		WHERE v.organization_id = $1 AND v.resolved_at IS NULL AND f.status IN ('open', 'in_progress', 'needs_review')
		  AND NOT EXISTS (SELECT 1 FROM human_reviews h WHERE h.finding_id = v.finding_id)
		ORDER BY v.finding_id, p.name LIMIT 2000`, orgID)
	if err != nil {
		return 0, err
	}
	var ids []uuid.UUID
	var reasons []string
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return 0, err
		}
		ids, reasons = append(ids, id), append(reasons, reasonPolicy+name)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ids) == 0 {
		return 0, err
	}
	var created []uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if created, err = insertReviews(ctx, tx, orgID, ids, reasons, "automatic", nil, nil, nil); err != nil {
			return err
		}
		return s.autoAssign(ctx, tx, orgID, st, created)
	})
	if err == nil && len(created) > 0 {
		s.Log.Info("findings queued for human review by policy", "count", len(created))
	}
	return len(created), err
}

func (s *Service) ingestAuto(ctx context.Context, orgID uuid.UUID, st Settings) (int, error) {
	if !st.AutoQueue || len(st.AutoTriggers) == 0 {
		return 0, nil
	}
	minRank := SeverityRank(st.AutoMinSeverity)
	var sevs []string
	for _, sv := range Severities {
		if SeverityRank(sv) >= minRank {
			sevs = append(sevs, sv)
		}
	}
	rows, err := s.DB.Query(ctx, `
		WITH cand AS (
		  SELECT f.id, f.status,
		         (SELECT ar.verdict FROM ai_reviews ar WHERE ar.finding_id = f.id AND ar.status IN ('applied', 'pending_approval')
		          ORDER BY ar.created_at DESC LIMIT 1) AS ai_verdict,
		         (SELECT h.source FROM finding_status_history h WHERE h.finding_id = f.id ORDER BY h.created_at DESC, h.id DESC LIMIT 1) AS last_source
		  FROM findings f JOIN repositories r ON r.id = f.repository_id
		  WHERE f.organization_id = $1 AND r.archived_at IS NULL
		    AND f.status IN ('open', 'in_progress', 'needs_review', 'false_positive')
		    AND f.category = ANY($2) AND f.severity = ANY($3)
		    AND (cardinality($4::text[]) = 0 OR f.scanner_keys && $4::text[])
		    AND NOT EXISTS (SELECT 1 FROM human_reviews h WHERE h.finding_id = f.id))
		SELECT id, CASE
		    WHEN 'needs_review' = ANY($5) AND status = 'needs_review' THEN $6
		    WHEN 'ai_needs_review' = ANY($5) AND ai_verdict = 'needs_review' AND status <> 'false_positive' THEN $7
		    WHEN 'ai_false_positive' = ANY($5) AND ai_verdict = 'false_positive' AND (status <> 'false_positive' OR last_source = 'ai') THEN $8
		    WHEN 'new_findings' = ANY($5) AND status <> 'false_positive' THEN $9 END AS reason
		FROM cand
		WHERE CASE
		    WHEN 'needs_review' = ANY($5) AND status = 'needs_review' THEN true
		    WHEN 'ai_needs_review' = ANY($5) AND ai_verdict = 'needs_review' AND status <> 'false_positive' THEN true
		    WHEN 'ai_false_positive' = ANY($5) AND ai_verdict = 'false_positive' AND (status <> 'false_positive' OR last_source = 'ai') THEN true
		    WHEN 'new_findings' = ANY($5) AND status <> 'false_positive' THEN true
		    ELSE false END
		LIMIT 2000`,
		orgID, st.AutoCategories, sevs, st.AutoScanners, st.AutoTriggers, reasonNeedsReview, reasonAINeeds, reasonAIFalsePos, reasonRules)
	if err != nil {
		return 0, err
	}
	var ids []uuid.UUID
	var reasons []string
	for rows.Next() {
		var id uuid.UUID
		var reason string
		if err := rows.Scan(&id, &reason); err != nil {
			rows.Close()
			return 0, err
		}
		ids, reasons = append(ids, id), append(reasons, reason)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var created []uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if created, err = insertReviews(ctx, tx, orgID, ids, reasons, "automatic", nil, nil, nil); err != nil {
			return err
		}
		return s.autoAssign(ctx, tx, orgID, st, created)
	})
	if err != nil {
		return 0, err
	}
	if len(created) > 0 {
		s.Log.Info("findings queued for human review", "count", len(created))
	}
	return len(created), nil
}

// autoAssign applies the assignment strategy to new reviews.
func (s *Service) autoAssign(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, st Settings, ids []uuid.UUID) error {
	if st.AssignmentStrategy == "manual" || len(st.AssignmentPool) == 0 || len(ids) == 0 {
		return nil
	}
	// Current open workload of each pool member.
	load := map[uuid.UUID]int{}
	rows, err := tx.Query(ctx, `SELECT u, (SELECT count(*) FROM human_reviews h WHERE h.reviewer_id = u AND h.status <> 'completed')
		FROM unnest($1::uuid[]) u`, st.AssignmentPool)
	if err != nil {
		return err
	}
	for rows.Next() {
		var u uuid.UUID
		var n int
		if err := rows.Scan(&u, &n); err != nil {
			rows.Close()
			return err
		}
		load[u] = n
	}
	rows.Close()
	// Round robin continues after the most recent automatic assignee.
	next := 0
	if st.AssignmentStrategy == "round_robin" {
		var last *uuid.UUID
		_ = tx.QueryRow(ctx, `SELECT (new_value #>> '{}')::uuid FROM human_review_history WHERE organization_id = $1
			AND action = 'review.assigned' AND actor_id IS NULL AND field = 'reviewer_id' ORDER BY created_at DESC, id DESC LIMIT 1`, orgID).Scan(&last)
		if last != nil {
			for i, u := range st.AssignmentPool {
				if u == *last {
					next = i + 1
				}
			}
		}
	}
	for _, id := range ids {
		v, err := scanRec(tx.QueryRow(ctx, recSelect+` WHERE h.id = $1 FOR UPDATE OF h`, id))
		if err != nil {
			return err
		}
		eligible, err := usersWith(ctx, tx, orgID, v.RepoID, authz.PermReviewsAssess)
		if err != nil {
			return err
		}
		var pick *uuid.UUID
		switch st.AssignmentStrategy {
		case "round_robin":
			for k := range st.AssignmentPool {
				u := st.AssignmentPool[(next+k)%len(st.AssignmentPool)]
				if containsUUID(eligible, u) {
					pick, next = &u, (next+k+1)%len(st.AssignmentPool)
					break
				}
			}
		case "least_loaded":
			best := -1
			for _, u := range st.AssignmentPool {
				if containsUUID(eligible, u) && (best < 0 || load[u] < best) {
					u := u
					pick, best = &u, load[u]
				}
			}
		}
		if pick == nil {
			continue // nobody in the pool may assess this repository
		}
		load[*pick]++
		if err := assignTx(ctx, tx, v, nil, *pick, nil, "automatic assignment ("+st.AssignmentStrategy+")", st.NotifyAssignment); err != nil {
			return err
		}
	}
	return nil
}

func containsUUID(list []uuid.UUID, u uuid.UUID) bool {
	for _, x := range list {
		if x == u {
			return true
		}
	}
	return false
}

// assignTx sets the reviewer of v (actor nil = PATHOS).
func assignTx(ctx context.Context, tx pgx.Tx, v rec, actor *uuid.UUID, reviewer uuid.UUID, due *time.Time, note string, notify bool) error {
	status := v.Status
	if status == StatusPending || status == StatusReopened && v.ReviewerID == nil {
		status = StatusAssigned
	}
	if _, err := tx.Exec(ctx, `UPDATE human_reviews SET reviewer_id = $2, status = $3, due_at = COALESCE($4, due_at), updated_at = now() WHERE id = $1`,
		v.ID, reviewer, status, due); err != nil {
		return err
	}
	action := "review.assigned"
	if v.ReviewerID != nil {
		action = "review.reassigned"
	}
	if err := hist(ctx, tx, v, actor, action, "reviewer_id", v.ReviewerID, reviewer, note); err != nil {
		return err
	}
	if status != v.Status {
		if err := hist(ctx, tx, v, actor, "review.status", "status", v.Status, status, ""); err != nil {
			return err
		}
	}
	if due != nil {
		if err := hist(ctx, tx, v, actor, "review.due_date", "due_at", v.DueAt, due, ""); err != nil {
			return err
		}
	}
	if notify && (actor == nil || *actor != reviewer) {
		return emit(ctx, tx, v, "review.assigned", map[string]any{"assignee_id": reviewer, "actor": actor})
	}
	return nil
}

// emit queues a notification event.
func emit(ctx context.Context, q db.Querier, v rec, key string, payload map[string]any) error {
	b, _ := json.Marshal(payload)
	_, err := q.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
		VALUES ($1, $2, $3, $4, $5, $6)`, v.OrgID, key, v.RepoID, v.EffectiveSeverity(), v.ID, b)
	return err
}

// --- original scanner output ------------------------------------------------

// captureOriginal stores the scanner's own record of the finding (and its
// code flows) on the review, once. Reports are pruned by retention, so the
// capture runs soon after the review is created.
func (s *Service) captureOriginal(ctx context.Context, v rec) error {
	var done bool
	if err := s.DB.QueryRow(ctx, `SELECT original_captured_at IS NOT NULL FROM human_reviews WHERE id = $1`, v.ID).Scan(&done); err != nil || done {
		return err
	}
	var raw []byte
	var key *string
	var scanner, contentType string
	err := s.DB.QueryRow(ctx, `SELECT a.data_gzip, a.object_key, sr.scanner_key, a.content_type FROM finding_occurrences o
		JOIN scan_results sr ON sr.id = o.scan_result_id
		JOIN scan_artifacts a ON a.scan_result_id = sr.id AND a.kind = 'raw'
		WHERE o.finding_id = $1 ORDER BY (sr.scan_job_id = $2) DESC, o.created_at DESC LIMIT 1`, v.FindingID, v.ScanJobID).Scan(&raw, &key, &scanner, &contentType)
	var capErr string
	var loc *scanners.Located
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		capErr = "the raw scanner report is no longer available (retention)"
	case err != nil:
		return err
	default:
		data, lerr := objstore.Load(ctx, s.Artifacts, key, raw)
		if lerr != nil {
			return lerr // transient: retry later
		}
		zr, zerr := gzip.NewReader(bytes.NewReader(data))
		if zerr != nil {
			capErr = "the raw scanner report could not be read"
			break
		}
		plain, rerr := io.ReadAll(io.LimitReader(zr, 256<<20))
		_ = zr.Close()
		if rerr != nil {
			capErr = "the raw scanner report could not be read"
			break
		}
		loc, err = scanners.LocateArtifact(scanner, contentType, plain, v.Fingerprint)
		if err != nil {
			loc, capErr = nil, "the finding was not found in the scanner report"
		}
	}
	var out, rule, flows, related any
	if loc != nil {
		out, rule = []byte(loc.Raw), nil
		if len(loc.Rule) > 0 {
			rule = []byte(loc.Rule)
		}
		if loc.Flows != nil {
			flows, _ = json.Marshal(loc.Flows)
		}
		if loc.Related != nil {
			related, _ = json.Marshal(loc.Related)
		}
	}
	_, err = s.DB.Exec(ctx, `UPDATE human_reviews SET original_output = $2, original_rule = $3, original_flows = $4, original_related = $5,
		original_capture_error = $6, original_captured_at = now() WHERE id = $1 AND original_captured_at IS NULL`, v.ID, out, rule, flows, related, capErr)
	return err
}

// captureBacklog captures originals for recent reviews.
func (s *Service) captureBacklog(ctx context.Context, limit int) {
	rows, err := s.DB.Query(ctx, recSelect+` WHERE h.original_captured_at IS NULL ORDER BY h.created_at LIMIT $1`, limit)
	if err != nil {
		s.Log.Warn("human review capture", "err", err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (rec, error) { return scanRec(r) })
	if err != nil {
		s.Log.Warn("human review capture", "err", err)
		return
	}
	for _, v := range list {
		if err := s.captureOriginal(ctx, v); err != nil {
			s.Log.Warn("human review capture", "review", v.Key, "err", err)
		}
	}
}

// notifyOverdue emits one review.overdue event per overdue review.
func (s *Service) notifyOverdue(ctx context.Context) {
	rows, err := s.DB.Query(ctx, recSelect+` JOIN human_review_settings st ON st.organization_id = h.organization_id
		WHERE st.notify_overdue AND h.status <> 'completed' AND h.due_at < now() AND h.reviewer_id IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM notification_events e WHERE e.event_key = 'review.overdue' AND e.subject_id = h.id
		                  AND e.created_at > h.due_at)
		LIMIT 500`)
	if err != nil {
		s.Log.Warn("human review overdue", "err", err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (rec, error) { return scanRec(r) })
	if err != nil {
		return
	}
	for _, v := range list {
		if err := emit(ctx, s.DB, v, "review.overdue", map[string]any{"assignee_id": v.ReviewerID}); err != nil {
			s.Log.Warn("human review overdue", "err", err)
		}
	}
}

// OnScanFinished queues eligible findings after a scan.
func (s *Service) OnScanFinished(ctx context.Context, orgID, _ uuid.UUID) {
	if _, err := s.Ingest(ctx, orgID); err != nil {
		s.Log.Warn("human review ingest after scan", "err", err)
	}
}

// RunBackground ingests, captures scanner output and detects overdue
// reviews until ctx ends (jobs role).
func (s *Service) RunBackground(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		rows, err := s.DB.Query(ctx, `SELECT id FROM organizations`)
		if err == nil {
			orgs, _ := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			for _, o := range orgs {
				if _, err := s.Ingest(ctx, o); err != nil && ctx.Err() == nil {
					s.Log.Warn("human review ingest", "err", err)
				}
			}
		}
		s.captureBacklog(ctx, 100)
		s.notifyOverdue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sync runs ingestion now (review managers).
func (s *Service) sync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReviewsAssign) && !p.HasOrgWide(authz.PermReviewsConfigure) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	n, err := s.Ingest(ctx, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "human_review.sync", TargetType: "organization", TargetID: p.OrganizationID.String(), Metadata: map[string]any{"created": n}})
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"created": n})
}
