package posture

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
)

// UnmanagedRepo is a repository in PATHOS with a governance gap.
type UnmanagedRepo struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Key         string     `json:"repository_key"`
	Issues      []string   `json:"issues"`
	LastScanAt  *time.Time `json:"last_scan_at"`
	LastPushAt  *time.Time `json:"last_pushed_at"`
	OpenTotal   int        `json:"open_findings"`
	Criticality string     `json:"criticality"`
}

// ShadowRepo is a repository an SCM connection sees that is not in PATHOS.
type ShadowRepo struct {
	ConnectionID   uuid.UUID  `json:"scm_connection_id"`
	ConnectionName string     `json:"scm_connection_name"`
	Provider       string     `json:"provider"`
	ExternalID     string     `json:"external_id"`
	FullName       string     `json:"full_name"`
	URL            string     `json:"url"`
	Visibility     string     `json:"visibility"`
	PushedAt       *time.Time `json:"pushed_at"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
}

// issueLabels documents the governance gaps the report detects.
var issueLabels = map[string]string{
	"no_application":    "Not mapped to an application",
	"no_owner":          "No owner or responsible team",
	"never_scanned":     "Never scanned successfully",
	"stale_scan":        "Not scanned successfully recently",
	"scanning_disabled": "Scanning disabled",
	"sync_failing":      "SCM synchronization failing (missing, no permission or error)",
	"archived_in_scm":   "Archived in the SCM but active in PATHOS",
}

func (s *Service) unmanaged(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	staleDays, err := intParam(r, "stale_days", 30, 1, 365)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	activeDays, err := intParam(r, "active_days", 90, 1, 3650)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cond, args, err := scope(p, authz.PermReposRead, 3)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	args = append([]any{p.OrganizationID, staleDays}, args...)
	// #nosec G202 -- cond is built from placeholders
	rows, err := s.DB.Query(ctx, `
	SELECT r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), r.repository_key, r.criticality, r.last_pushed_at, x.last_scan,
	       (SELECT count(*) FROM findings f WHERE f.repository_id = r.id AND f.status IN `+openStatuses+`),
	       array_remove(ARRAY[
	         CASE WHEN r.application_id IS NULL THEN 'no_application' END,
	         CASE WHEN r.application_owner_id IS NULL AND r.technical_owner_id IS NULL AND r.business_owner_id IS NULL
	                   AND r.responsible_team_id IS NULL THEN 'no_owner' END,
	         CASE WHEN x.last_scan IS NULL AND r.scan_enabled THEN 'never_scanned' END,
	         CASE WHEN x.last_scan < now() - make_interval(days => $2) AND r.scan_enabled THEN 'stale_scan' END,
	         CASE WHEN NOT r.scan_enabled THEN 'scanning_disabled' END,
	         CASE WHEN r.sync_status IN ('failed', 'missing', 'permission_denied') THEN 'sync_failing' END,
	         CASE WHEN r.remote_archived OR r.sync_status = 'archived_upstream' THEN 'archived_in_scm' END], NULL)
	FROM repositories r
	LEFT JOIN LATERAL (SELECT max(j.finished_at) AS last_scan FROM scan_jobs j
	                   WHERE j.repository_id = r.id AND j.status IN ('succeeded', 'partial')) x ON true
	WHERE r.organization_id = $1 AND r.archived_at IS NULL AND `+cond+`
	ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low'], r.criticality), lower(r.full_name)`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	gaps := []UnmanagedRepo{}
	counts := map[string]int{}
	for rows.Next() {
		var u UnmanagedRepo
		if err := rows.Scan(&u.ID, &u.Name, &u.Key, &u.Criticality, &u.LastPushAt, &u.LastScanAt, &u.OpenTotal, &u.Issues); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		if len(u.Issues) == 0 {
			continue
		}
		for _, i := range u.Issues {
			counts[i]++
		}
		gaps = append(gaps, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}

	// Shadow repositories: only for callers who see every repository (an
	// unimported repository has no scope yet).
	resp := map[string]any{"stale_days": staleDays, "active_days": activeDays, "issue_labels": issueLabels, "counts": counts,
		"repositories": gaps}
	if !p.HasOrgWide(authz.PermReposRead) {
		resp["shadow_visible"] = false
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	}
	srows, err := s.DB.Query(ctx, `
	SELECT x.scm_connection_id, c.name, c.provider, x.external_id, x.full_name, x.url, x.visibility, x.pushed_at, x.first_seen_at
	FROM scm_remote_repositories x JOIN scm_connections c ON c.id = x.scm_connection_id AND c.archived_at IS NULL
	WHERE x.organization_id = $1 AND NOT x.archived
	  AND (x.pushed_at IS NULL OR x.pushed_at >= now() - make_interval(days => $2))
	  AND NOT EXISTS (SELECT 1 FROM repositories r WHERE r.organization_id = x.organization_id
	                    AND r.scm_connection_id = x.scm_connection_id AND r.external_id = x.external_id)
	ORDER BY x.pushed_at DESC NULLS LAST, lower(x.full_name) LIMIT 2000`, p.OrganizationID, activeDays)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	shadow := []ShadowRepo{}
	for srows.Next() {
		var sh ShadowRepo
		if err := srows.Scan(&sh.ConnectionID, &sh.ConnectionName, &sh.Provider, &sh.ExternalID, &sh.FullName, &sh.URL, &sh.Visibility,
			&sh.PushedAt, &sh.FirstSeenAt); err != nil {
			srows.Close()
			s.fail(w, r, err)
			return
		}
		shadow = append(shadow, sh)
	}
	srows.Close()
	type invRun struct {
		ConnectionID   uuid.UUID  `json:"scm_connection_id"`
		ConnectionName string     `json:"scm_connection_name"`
		Status         *string    `json:"status"`
		FinishedAt     *time.Time `json:"finished_at"`
		Repositories   *int       `json:"repositories"`
		Truncated      *bool      `json:"truncated"`
		Error          *string    `json:"error"`
	}
	irows, err := s.DB.Query(ctx, `
	SELECT c.id, c.name, ir.status, ir.finished_at, ir.repositories, ir.truncated, ir.error
	FROM scm_connections c LEFT JOIN LATERAL (SELECT * FROM scm_inventory_runs r WHERE r.scm_connection_id = c.id
	                                         ORDER BY r.started_at DESC LIMIT 1) ir ON true
	WHERE c.organization_id = $1 AND c.archived_at IS NULL ORDER BY lower(c.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	runs := []invRun{}
	for irows.Next() {
		var ir invRun
		if err := irows.Scan(&ir.ConnectionID, &ir.ConnectionName, &ir.Status, &ir.FinishedAt, &ir.Repositories, &ir.Truncated, &ir.Error); err != nil {
			irows.Close()
			s.fail(w, r, err)
			return
		}
		runs = append(runs, ir)
	}
	irows.Close()
	resp["shadow_visible"] = true
	resp["shadow"] = shadow
	resp["inventory"] = runs
	resp["counts"].(map[string]int)["shadow"] = len(shadow)
	if len(shadow) >= 2000 {
		resp["shadow_truncated"] = true
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
