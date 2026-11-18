// Package insights stores and serves developer context: security-material
// changes between scanned commits (package material provides the rules)
// and opt-in developer attribution of findings.
//
// Privacy: attribution is off by default. While it is off the worker is
// not asked for commit authors and nothing about people is stored. Only git
// author names are ever stored, never e-mail addresses; a name maps to a
// PATHOS user only when an administrator links them. Turning attribution
// off erases every stored author name.
package insights

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/material"
	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
)

// ChangeReport is what the worker uploads (mirrors worker.ChangeReport).
type ChangeReport struct {
	Version         int               `json:"version"`
	Status          string            `json:"status"`
	Reason          string            `json:"reason"`
	BaseSHA         string            `json:"base_sha"`
	HeadSHA         string            `json:"head_sha"`
	FilesChanged    int               `json:"files_changed"`
	Truncated       bool              `json:"truncated"`
	Changes         []material.Change `json:"changes"`
	Commits         []Commit          `json:"commits"`
	CommitsComplete bool              `json:"commits_complete"`
}

// Commit is one commit between two scans.
type Commit struct {
	SHA        string    `json:"sha"`
	AuthorName string    `json:"author_name"`
	AuthoredAt time.Time `json:"authored_at"`
	Files      []string  `json:"files"`
}

// AttributionEnabled reports the organization's attribution switch.
func AttributionEnabled(ctx context.Context, q db.Querier, orgID uuid.UUID) bool {
	var on bool
	_ = q.QueryRow(ctx, `SELECT attribution_enabled FROM developer_insight_settings WHERE organization_id = $1`, orgID).Scan(&on)
	return on
}

// LeaseInfo returns what the worker needs for change detection: the commit
// of the repository's previous successful branch scan and whether to
// collect commit authors. Pull request and scan target jobs get nothing.
func LeaseInfo(ctx context.Context, q db.Querier, orgID, jobID uuid.UUID) (prev string, authors bool) {
	var repoID uuid.UUID
	var pr *int
	var target, snapshot *uuid.UUID
	var ref string
	if err := q.QueryRow(ctx, `SELECT repository_id, pull_request, target_id, snapshot_id, ref FROM scan_jobs WHERE id = $1 AND organization_id = $2`,
		jobID, orgID).Scan(&repoID, &pr, &target, &snapshot, &ref); err != nil || pr != nil || target != nil || snapshot != nil {
		return "", false
	}
	// The previous scan of the same ref, so a scan of another branch does
	// not show the whole branch difference as material changes.
	_ = q.QueryRow(ctx, `SELECT commit_sha FROM scan_jobs
		WHERE repository_id = $1 AND id <> $2 AND ref = $3 AND status IN ('succeeded', 'partial') AND pull_request IS NULL
		  AND target_id IS NULL AND snapshot_id IS NULL AND commit_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'
		ORDER BY finished_at DESC NULLS LAST LIMIT 1`, repoID, jobID, ref).Scan(&prev)
	return prev, AttributionEnabled(ctx, q, orgID)
}

var statuses = []string{"computed", "baseline", "unchanged", "unavailable"}

const (
	maxDependencyChanges = 200
	maxStoredCommits     = 500
)

// StoreChanges records a worker's change report for a job and emits the
// "change.material" notification event when material changes were found.
// Reports for pull request and scan target jobs are ignored. It returns
// the number of stored changes.
func StoreChanges(ctx context.Context, pool *pgxpool.Pool, orgID, jobID uuid.UUID, rep ChangeReport) (int, error) {
	if rep.Version != 1 || !slices.Contains(statuses, rep.Status) {
		return 0, errors.New("invalid change report")
	}
	var repoID uuid.UUID
	var pr *int
	var target *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT repository_id, pull_request, target_id FROM scan_jobs WHERE id = $1 AND organization_id = $2`,
		jobID, orgID).Scan(&repoID, &pr, &target); err != nil {
		return 0, err
	}
	if pr != nil || target != nil {
		return 0, nil
	}
	enabled := AttributionEnabled(ctx, pool, orgID)
	if !enabled {
		rep.Commits = nil // never store people data while attribution is off
	}
	if len(rep.Commits) > maxStoredCommits {
		rep.Commits, rep.CommitsComplete = rep.Commits[:maxStoredCommits], false
	}
	stored := 0
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		// A retried job replaces what an earlier attempt stored.
		if _, err := tx.Exec(ctx, `DELETE FROM material_change_runs WHERE scan_job_id = $1`, jobID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scan_commits WHERE scan_job_id = $1`, jobID); err != nil {
			return err
		}
		changes := make([]material.Change, 0, len(rep.Changes))
		for _, c := range rep.Changes {
			if r, ok := material.RuleByID(c.RuleID); ok && r.Category == c.Category && r.Category != material.CatDependency {
				changes = append(changes, c)
			}
		}
		if len(changes) > material.MaxChanges {
			changes, rep.Truncated = changes[:material.MaxChanges], true
		}
		depStatus, deps, err := dependencyChanges(ctx, tx, orgID, repoID, jobID)
		if err != nil {
			return err
		}
		changes = append(changes, deps...)
		if _, err := tx.Exec(ctx, `INSERT INTO material_change_runs (scan_job_id, organization_id, repository_id, status, reason, base_sha, head_sha,
			files_changed, truncated, change_count, dependency_status, commits_complete) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			jobID, orgID, repoID, rep.Status, clip(logging.RedactString(rep.Reason), 1000), clip(rep.BaseSHA, 64), clip(rep.HeadSHA, 64),
			max(rep.FilesChanged, 0), rep.Truncated, len(changes), depStatus, rep.CommitsComplete && len(rep.Commits) > 0); err != nil {
			return err
		}
		authorOf := lastAuthors(rep.Commits)
		rows := make([][]any, 0, len(changes))
		for _, c := range changes {
			level := "medium"
			if r, ok := material.RuleByID(c.RuleID); ok {
				level = r.Level
			}
			var start, end *int
			if c.StartLine > 0 {
				s, e := c.StartLine, max(c.EndLine, c.StartLine)
				start, end = &s, &e
			}
			side := c.Side
			if side != "added" && side != "removed" {
				side = "file"
			}
			ct := c.ChangeType
			if !slices.Contains([]string{"added", "modified", "deleted", "renamed"}, ct) {
				ct = ""
			}
			rows = append(rows, []any{orgID, repoID, jobID, c.Category, clip(c.RuleID, 100), level, clip(c.FilePath, 1000), ct, side, start, end,
				max(c.MatchCount, 1), clip(logging.RedactString(c.Snippet), 1000), clip(c.Explanation, 2000), clip(c.Detail, 500),
				clip(authorOf[c.FilePath], 200)})
		}
		if len(rows) > 0 {
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"material_changes"}, []string{"organization_id", "repository_id", "scan_job_id", "category",
				"rule_id", "level", "file_path", "change_type", "side", "start_line", "end_line", "match_count", "snippet", "explanation", "detail",
				"author_name"}, pgx.CopyFromRows(rows)); err != nil {
				return err
			}
		}
		if len(rep.Commits) > 0 {
			crow := make([][]any, 0, len(rep.Commits))
			seen := map[string]bool{}
			for i, c := range rep.Commits {
				if seen[c.SHA] || c.SHA == "" || len(c.SHA) > 64 {
					continue
				}
				seen[c.SHA] = true
				var at *time.Time
				if !c.AuthoredAt.IsZero() {
					at = &c.AuthoredAt
				}
				files := c.Files
				if len(files) > 500 {
					files = files[:500]
				}
				crow = append(crow, []any{jobID, orgID, repoID, i, c.SHA, clip(cleanName(c.AuthorName), 200), at, nonNil(files)})
			}
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_commits"}, []string{"scan_job_id", "organization_id", "repository_id", "position",
				"sha", "author_name", "authored_at", "files"}, pgx.CopyFromRows(crow)); err != nil {
				return err
			}
		}
		stored = len(changes)
		if stored == 0 {
			return nil
		}
		return emitEvent(ctx, tx, orgID, repoID, jobID, changes)
	})
	return stored, err
}

// emitEvent queues the "change.material" notification. Its severity is
// "high" when a high-level rule matched, otherwise "medium".
func emitEvent(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID, changes []material.Change) error {
	sev := "medium"
	cats := map[string]int{}
	for _, c := range changes {
		cats[c.Category]++
		if r, ok := material.RuleByID(c.RuleID); ok && r.Level == "high" {
			sev = "high"
		}
	}
	payload, _ := json.Marshal(map[string]any{"count": len(changes), "categories": cats})
	_, err := tx.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
		VALUES ($1, 'change.material', $2, $3, $4, $5::jsonb)`, orgID, repoID, sev, jobID, string(payload))
	return err
}

// lastAuthors maps each file to the author of the newest commit that
// touched it (commits are newest first).
func lastAuthors(commits []Commit) map[string]string {
	out := map[string]string{}
	for _, c := range commits {
		for _, f := range c.Files {
			if _, ok := out[f]; !ok {
				out[f] = cleanName(c.AuthorName)
			}
		}
	}
	return out
}

// dependencyChanges compares this scan's SBOM with the repository's
// dependency baseline and moves the baseline forward.
func dependencyChanges(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID) (string, []material.Change, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT name, version, type FROM sbom_components WHERE repository_id = $1 AND scan_job_id = $2 AND name <> ''
		ORDER BY name, version`, repoID, jobID)
	if err != nil {
		return "", nil, err
	}
	type comp struct{ name, version, typ string }
	var comps []comp
	for rows.Next() {
		var c comp
		if err := rows.Scan(&c.name, &c.version, &c.typ); err != nil {
			rows.Close()
			return "", nil, err
		}
		comps = append(comps, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	if len(comps) == 0 {
		return "none", nil, nil
	}
	depRule, _ := material.RuleByID(material.DependencyRuleID)
	key := func(c comp) string { return strings.ToLower(c.typ + ":" + c.name) }
	var baseline []string
	err = tx.QueryRow(ctx, `SELECT components FROM material_dependency_baselines WHERE repository_id = $1`, repoID).Scan(&baseline)
	status := "computed"
	if errors.Is(err, pgx.ErrNoRows) {
		status = "baseline"
	} else if err != nil {
		return "", nil, err
	}
	known := map[string]bool{}
	for _, b := range baseline {
		known[b] = true
	}
	keys := make([]string, 0, len(comps))
	seen := map[string]bool{}
	var out []material.Change
	for _, c := range comps {
		k := key(c)
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
		if status == "computed" && !known[k] && len(out) < maxDependencyChanges {
			detail := c.name
			if c.version != "" {
				detail += " " + c.version
			}
			if c.typ != "" {
				detail += " (" + c.typ + ")"
			}
			out = append(out, material.Change{Category: material.CatDependency, RuleID: depRule.ID, Side: "added", MatchCount: 1,
				Explanation: depRule.Explanation, Detail: detail, Snippet: detail})
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO material_dependency_baselines (repository_id, organization_id, scan_job_id, components, updated_at)
		VALUES ($1, $2, $3, $4, now()) ON CONFLICT (repository_id) DO UPDATE SET scan_job_id = EXCLUDED.scan_job_id,
		components = EXCLUDED.components, updated_at = now()`, repoID, orgID, jobID, keys); err != nil {
		return "", nil, err
	}
	return status, out, nil
}

// Attribute infers who introduced the findings first reported by a scan
// and who fixed the findings it no longer reported, from the commits
// between the previous and this scan: the newest commit in the range that
// touched the finding's file. Nothing happens while attribution is off or
// when the job has no commits.
func Attribute(ctx context.Context, pool *pgxpool.Pool, orgID, jobID uuid.UUID) (introduced, fixed int, err error) {
	if !AttributionEnabled(ctx, pool, orgID) {
		return 0, 0, nil
	}
	rows, err := pool.Query(ctx, `SELECT sha, author_name, files FROM scan_commits WHERE scan_job_id = $1 ORDER BY position`, jobID)
	if err != nil {
		return 0, 0, err
	}
	type touch struct{ sha, author string }
	byFile := map[string]touch{}
	for rows.Next() {
		var sha, author string
		var files []string
		if err := rows.Scan(&sha, &author, &files); err != nil {
			rows.Close()
			return 0, 0, err
		}
		for _, f := range files {
			if _, ok := byFile[f]; !ok {
				byFile[f] = touch{sha, author}
			}
		}
	}
	rows.Close()
	if len(byFile) == 0 {
		return 0, 0, nil
	}
	var repoID uuid.UUID
	var started *time.Time
	if err := pool.QueryRow(ctx, `SELECT repository_id, COALESCE(started_at, queued_at) FROM scan_jobs WHERE id = $1`, jobID).Scan(&repoID, &started); err != nil {
		return 0, 0, err
	}
	type hit struct {
		id   uuid.UUID
		path string
		at   time.Time
	}
	collect := func(sql string, args ...any) ([]hit, error) {
		rows, err := pool.Query(ctx, sql, args...)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, func(r pgx.CollectableRow) (hit, error) {
			var h hit
			err := r.Scan(&h.id, &h.path, &h.at)
			return h, err
		})
	}
	newF, err := collect(`SELECT id, file_path, first_seen_at FROM findings WHERE first_scan_job_id = $1 AND file_path <> ''`, jobID)
	if err != nil {
		return 0, 0, err
	}
	// Findings this scan auto-resolved (status history written by the
	// scanner source during this job).
	fixedF, err := collect(`SELECT f.id, f.file_path, COALESCE(f.resolved_at, now()) FROM findings f
		WHERE f.repository_id = $1 AND f.status = 'fixed' AND f.file_path <> '' AND f.scan_target_id IS NULL
		  AND EXISTS (SELECT 1 FROM finding_status_history h WHERE h.finding_id = f.id AND h.to_status = 'fixed'
		              AND h.source = 'scanner' AND h.created_at >= $2)`, repoID, started)
	if err != nil {
		return 0, 0, err
	}
	err = db.InTx(ctx, pool, func(tx pgx.Tx) error {
		for _, h := range newF {
			t, ok := byFile[normPath(h.path)]
			if !ok {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO finding_attribution (finding_id, organization_id, repository_id, introduced_by, introduced_commit,
				introduced_scan_job_id, introduced_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (finding_id) DO UPDATE SET introduced_by = EXCLUDED.introduced_by, introduced_commit = EXCLUDED.introduced_commit,
				introduced_scan_job_id = EXCLUDED.introduced_scan_job_id, introduced_at = EXCLUDED.introduced_at, updated_at = now()`,
				h.id, orgID, repoID, t.author, t.sha, jobID, h.at); err != nil {
				return err
			}
			introduced++
		}
		for _, h := range fixedF {
			t, ok := byFile[normPath(h.path)]
			if !ok {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO finding_attribution (finding_id, organization_id, repository_id, fixed_by, fixed_commit,
				fixed_scan_job_id, fixed_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (finding_id) DO UPDATE SET fixed_by = EXCLUDED.fixed_by, fixed_commit = EXCLUDED.fixed_commit,
				fixed_scan_job_id = EXCLUDED.fixed_scan_job_id, fixed_at = EXCLUDED.fixed_at, updated_at = now()`,
				h.id, orgID, repoID, t.author, t.sha, jobID, h.at); err != nil {
				return err
			}
			fixed++
		}
		return nil
	})
	return introduced, fixed, err
}

func normPath(p string) string {
	p = strings.TrimPrefix(p, "./")
	return strings.TrimPrefix(p, "/")
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "")
	}
	return s
}

func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	return strings.TrimSpace(s)
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
