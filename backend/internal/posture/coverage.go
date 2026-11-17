package posture

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
)

// Coverage categories, in display order. Source scans count for sast,
// secrets, sca, iac and cicd (zizmor); scan targets for container (image
// targets) and dast (web application and API targets), as long as the
// target still exists and is enabled. Imported results count for their
// category.
var coverageCategories = []string{"sast", "secrets", "sca", "iac", "cicd", "container", "dast"}

// Cell is one repository × category.
type Cell struct {
	// covered: successful within the window; stale: only older; never: no
	// successful run; not_configured: container or DAST with no target.
	Status   string     `json:"status"`
	LastAt   *time.Time `json:"last_at"`
	Scanners []string   `json:"scanners"`
}

// CoverageRow is one repository's coverage.
type CoverageRow struct {
	RepositoryID    uuid.UUID       `json:"repository_id"`
	RepositoryName  string          `json:"repository_name"`
	RepositoryKey   string          `json:"repository_key"`
	ApplicationID   *uuid.UUID      `json:"application_id"`
	ApplicationName *string         `json:"application_name"`
	ScanEnabled     bool            `json:"scan_enabled"`
	Cells           map[string]Cell `json:"cells"`
}

func (s *Service) coverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	days, err := intParam(r, "days", 30, 1, 365)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cond, args, err := scope(p, authz.PermReposRead, 2)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	args = append([]any{p.OrganizationID}, args...)
	q := r.URL.Query()
	if v := q.Get("application_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid application_id"))
			return
		}
		args = append(args, id)
		cond += fmt.Sprintf(" AND r.application_id = $%d", len(args))
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		args = append(args, "%"+strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(v))+"%")
		cond += fmt.Sprintf(" AND (lower(r.full_name) LIKE $%[1]d OR lower(r.repository_key) LIKE $%[1]d)", len(args))
	}
	// #nosec G202 -- cond is built from placeholders
	rows, err := s.DB.Query(ctx, `
	WITH rs AS (
	  SELECT r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name) AS name, r.repository_key, r.application_id, r.scan_enabled
	  FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND `+cond+`
	  ORDER BY lower(r.full_name) LIMIT 1000),
	runs AS (
	  SELECT j.repository_id AS repo,
	         CASE WHEN sr.scanner_key IN ('zizmor', 'actionlint') THEN 'cicd'
	              WHEN j.target_kind = 'image' THEN 'container'
	              WHEN j.target_kind IN ('url', 'api') THEN 'dast'
	              WHEN j.target_kind = 'sbom' THEN 'sca'
	              ELSE c.category END AS cat,
	         sr.scanner_key, j.finished_at
	  FROM scan_jobs j JOIN rs ON rs.id = j.repository_id
	  JOIN scan_results sr ON sr.scan_job_id = j.id
	  LEFT JOIN scanner_catalog c ON c.key = sr.scanner_key
	  WHERE sr.status = 'succeeded' AND j.finished_at IS NOT NULL
	    -- target scans count while their target still exists and is enabled
	    AND (j.target_kind = 'repository' OR EXISTS (SELECT 1 FROM scan_targets t WHERE t.id = j.target_id AND t.enabled)))
	SELECT rs.id, rs.name, rs.repository_key, rs.application_id, a.name, rs.scan_enabled,
	       COALESCE((SELECT jsonb_object_agg(x.cat, jsonb_build_object('last_at', x.last_at, 'scanners', x.scanners)) FROM (
	         SELECT cat, max(finished_at) AS last_at, array_agg(DISTINCT scanner_key ORDER BY scanner_key) AS scanners
	         FROM runs WHERE runs.repo = rs.id AND cat IS NOT NULL GROUP BY cat) x), '{}'::jsonb),
	       EXISTS (SELECT 1 FROM scan_targets t WHERE t.repository_id = rs.id AND t.kind = 'image' AND t.enabled),
	       EXISTS (SELECT 1 FROM scan_targets t WHERE t.repository_id = rs.id AND t.kind IN ('url', 'api') AND t.enabled)
	FROM rs LEFT JOIN applications a ON a.id = rs.application_id
	ORDER BY lower(rs.name)`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	out := []CoverageRow{}
	totals := map[string]int{}
	for rows.Next() {
		var row CoverageRow
		var cats map[string]struct {
			LastAt   *time.Time `json:"last_at"`
			Scanners []string   `json:"scanners"`
		}
		var hasImage, hasDAST bool
		if err := rows.Scan(&row.RepositoryID, &row.RepositoryName, &row.RepositoryKey, &row.ApplicationID, &row.ApplicationName,
			&row.ScanEnabled, &cats, &hasImage, &hasDAST); err != nil {
			s.fail(w, r, err)
			return
		}
		row.Cells = map[string]Cell{}
		for _, cat := range coverageCategories {
			c := Cell{Status: "never", Scanners: []string{}}
			if v, ok := cats[cat]; ok && v.LastAt != nil {
				c.LastAt, c.Scanners = v.LastAt, v.Scanners
				c.Status = "stale"
				if v.LastAt.After(cutoff) {
					c.Status = "covered"
					totals[cat]++
				}
			} else if (cat == "container" && !hasImage) || (cat == "dast" && !hasDAST) {
				c.Status = "not_configured"
			}
			row.Cells[cat] = c
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	summary := make([]map[string]any, 0, len(coverageCategories))
	for _, cat := range coverageCategories {
		pct := 0.0
		if len(out) > 0 {
			pct = float64(int(float64(totals[cat])/float64(len(out))*1000+0.5)) / 10
		}
		summary = append(summary, map[string]any{"category": cat, "covered": totals[cat], "percent": pct})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "categories": coverageCategories, "summary": summary,
		"items": out, "truncated": len(out) >= 1000})
}
