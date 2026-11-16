package repos

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
)

func (s *Service) registerInsights(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/repositories/insights", s.repositoryInsights)
	mux.HandleFunc("GET /api/v1/repositories/{id}/security", s.repositorySecurity)
}

// InsightBucket is one group in a breakdown.
type InsightBucket struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
	Color string `json:"color,omitempty"`
}

// repositoryInsights computes the repository and business dashboards from
// persisted records, within the caller's scope and the list filters.
func (s *Service) repositoryInsights(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	args := []any{p.OrganizationID, p.UserID}
	where := []string{"r.organization_id = $1"}
	scope, ok := readScope(p, &args)
	if !ok {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	where = append(where, scope)
	// Totals cover active and archived assets; breakdowns use the filters
	// (default: active).
	q := r.URL.Query()
	if q.Get("status") == "" {
		q.Set("status", "all")
		r.URL.RawQuery = q.Encode()
	}
	if err := repoListFilter(r, &where, &args); err != nil {
		s.fail(w, r, err)
		return
	}
	from := ` FROM repositories r LEFT JOIN scm_connections c ON c.id = r.scm_connection_id
		LEFT JOIN countries co ON co.id = r.country_id WHERE ` + strings.Join(where, " AND ")
	ap, err := s.loadPolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	type totals struct {
		Total                 int        `json:"total"`
		Active                int        `json:"active"`
		Archived              int        `json:"archived"`
		Critical              int        `json:"critical"`
		WithoutBusinessOwner  int        `json:"without_business_owner"`
		WithoutTechnicalOwner int        `json:"without_technical_owner"`
		Production            int        `json:"production"`
		ConfidentialRestrict  int        `json:"confidential_or_restricted"`
		PendingImports        int        `json:"pending_imports"`
		FailedImports         int        `json:"failed_imports"`
		SyncFailures          int        `json:"sync_failures"`
		LastSuccessfulSyncAt  *time.Time `json:"last_successful_sync_at"`
		PubliclyExposed       int        `json:"publicly_exposed"`
		NotPublic             int        `json:"not_public"`
		ExposureUnknown       int        `json:"exposure_unknown"`
		MissingProductionURL  int        `json:"missing_production_url"`
		MissingOwnership      int        `json:"missing_ownership"`
	}
	var t totals
	if err := s.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE r.archived_at IS NULL), count(*) FILTER (WHERE r.archived_at IS NOT NULL),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.criticality = 'critical'),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.business_owner_id IS NULL),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.technical_owner_id IS NULL),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.environment = 'production'),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.data_classification IN ('confidential', 'restricted')),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.sync_status IN ('failed', 'missing', 'permission_denied')),
		max(r.last_sync_ok_at),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.public_exposure = 'yes'),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.public_exposure = 'no'),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.public_exposure = 'unknown'),
		count(*) FILTER (WHERE r.archived_at IS NULL AND r.production_url = ''),
		count(*) FILTER (WHERE r.archived_at IS NULL AND (r.business_owner_id IS NULL OR r.technical_owner_id IS NULL))`+from, args...).
		Scan(&t.Total, &t.Active, &t.Archived, &t.Critical, &t.WithoutBusinessOwner,
			&t.WithoutTechnicalOwner, &t.Production, &t.ConfidentialRestrict, &t.SyncFailures, &t.LastSuccessfulSyncAt,
			&t.PubliclyExposed, &t.NotPublic, &t.ExposureUnknown, &t.MissingProductionURL, &t.MissingOwnership); err != nil {
		s.fail(w, r, err)
		return
	}
	// Imports are not repositories yet: visible ones are the caller's, or
	// all for organization-wide managers.
	impWhere := "i.organization_id = $1"
	impArgs := []any{p.OrganizationID}
	if !p.HasOrgWide(authz.PermReposManage) && !p.HasOrgWide(authz.PermReposRead) {
		impWhere += " AND j.requested_by = $2"
		impArgs = append(impArgs, p.UserID)
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE i.status IN ('draft', 'pending', 'queued', 'validating', 'importing', 'registering')),
		count(*) FILTER (WHERE i.status IN ('failed', 'needs_attention') AND i.completed_at > now() - interval '30 days')
		FROM repository_import_items i JOIN repository_import_jobs j ON j.id = i.job_id WHERE `+impWhere, impArgs...).
		Scan(&t.PendingImports, &t.FailedImports); err != nil {
		s.fail(w, r, err)
		return
	}

	active := " AND r.archived_at IS NULL"
	group := func(keyExpr, labelExpr, extraFrom string, limit int) ([]InsightBucket, error) {
		sql := fmt.Sprintf(`SELECT COALESCE(%s, ''), COALESCE(%s, ''), count(*) %s %s%s GROUP BY 1, 2 ORDER BY 3 DESC, 2 LIMIT %d`,
			keyExpr, labelExpr, strings.Replace(from, " WHERE ", " "+extraFrom+" WHERE ", 1), "", active, limit)
		rows, err := s.DB.Query(ctx, sql, args...)
		if err != nil {
			return nil, err
		}
		out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (InsightBucket, error) {
			var b InsightBucket
			return b, row.Scan(&b.Key, &b.Label, &b.Count)
		})
		if out == nil {
			out = []InsightBucket{}
		}
		return out, err
	}
	catalog := func(kind string, b []InsightBucket) []InsightBucket {
		for i := range b {
			if b[i].Key == "" {
				b[i].Label = "Not set"
				continue
			}
			b[i].Label, b[i].Color = ap.label(kind, b[i].Key)
		}
		return b
	}
	out := map[string]any{"totals": t}
	type breakdown struct {
		name, key, label, from, kind string
		limit                        int
	}
	for _, bd := range []breakdown{
		{"by_provider", "COALESCE(c.provider, 'upload')", "COALESCE(c.provider, 'upload')", "", "", 20},
		{"by_business_region", "brg.id::text", "brg.name", "LEFT JOIN regions brg ON brg.id = r.business_region_id", "", 50},
		{"by_business_unit", "bu.id::text", "bu.name", "LEFT JOIN business_units bu ON bu.id = r.business_unit_id", "", 50},
		{"by_business_owner", "bo.id::text", "COALESCE(NULLIF(bo.display_name, ''), bo.email)", "LEFT JOIN users bo ON bo.id = r.business_owner_id", "", 10},
		{"by_criticality", "r.criticality", "r.criticality", "", KindCriticality, 10},
		{"by_data_classification", "r.data_classification", "r.data_classification", "", KindDataClassification, 20},
		{"by_environment", "r.environment", "r.environment", "", KindEnvironment, 20},
		{"by_lifecycle", "r.lifecycle_status", "r.lifecycle_status", "", KindLifecycleStatus, 20},
		{"by_public_exposure", "r.public_exposure", "r.public_exposure", "", "", 3},
		{"by_compliance", "cs.scope_key", "cs.scope_key", "JOIN repository_compliance_scopes cs ON cs.repository_id = r.id", KindCompliance, 30},
	} {
		b, err := group(bd.key, bd.label, bd.from, bd.limit)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		switch {
		case bd.kind != "":
			b = catalog(bd.kind, b)
		case bd.name == "by_public_exposure":
			for i := range b {
				b[i].Label, b[i].Color = map[string]string{"yes": "Publicly exposed", "no": "Not public", "unknown": "Unknown"}[b[i].Key],
					map[string]string{"yes": "#cf222e", "no": "#2da44e", "unknown": "#6e7781"}[b[i].Key]
			}
		case bd.name == "by_provider":
			for i := range b {
				if info, ok := providerInfo(b[i].Key); ok {
					b[i].Label = info.Label
				} else if b[i].Key == "upload" {
					b[i].Label = "Local upload"
				}
			}
		default:
			for i := range b {
				if b[i].Key == "" {
					b[i].Label = "Not set"
				}
			}
		}
		out[bd.name] = b
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// repositorySecurity summarizes the latest scan and open findings.
func (s *Service) repositorySecurity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, repo, err := s.loadRepoFor(r, authz.PermReposRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type scanner struct {
		Key      string `json:"key"`
		Version  string `json:"version"`
		Status   string `json:"status"`
		Findings int    `json:"findings"`
	}
	type latest struct {
		ID          string     `json:"id"`
		Status      string     `json:"status"`
		Trigger     string     `json:"trigger"`
		CommitSHA   string     `json:"commit_sha"`
		SnapshotID  *string    `json:"snapshot_id"`
		ProfileName string     `json:"profile_name"`
		QueuedAt    time.Time  `json:"queued_at"`
		FinishedAt  *time.Time `json:"finished_at"`
		Scanners    []scanner  `json:"scanners"`
	}
	var l *latest
	var cand latest
	err = s.DB.QueryRow(ctx, `SELECT j.id::text, j.status, j.trigger, j.commit_sha, j.snapshot_id::text, COALESCE(sp.name, ''), j.queued_at, j.finished_at
		FROM scan_jobs j
		LEFT JOIN scan_profile_versions v ON v.id = j.profile_version_id
		LEFT JOIN scan_profiles sp ON sp.id = v.profile_id
		WHERE j.organization_id = $1 AND j.repository_id = $2 ORDER BY j.queued_at DESC LIMIT 1`, p.OrganizationID, repo.ID).
		Scan(&cand.ID, &cand.Status, &cand.Trigger, &cand.CommitSHA, &cand.SnapshotID, &cand.ProfileName, &cand.QueuedAt, &cand.FinishedAt)
	if err == nil {
		l = &cand
		rows, err := s.DB.Query(ctx, `SELECT scanner_key, scanner_version, status, findings_count FROM scan_results
			WHERE scan_job_id = $1::uuid ORDER BY scanner_key`, cand.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		l.Scanners, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (scanner, error) {
			var sc scanner
			return sc, row.Scan(&sc.Key, &sc.Version, &sc.Status, &sc.Findings)
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if l.Scanners == nil {
			l.Scanners = []scanner{}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, r, err)
		return
	}
	open := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	if p.HasAnywhere(authz.PermFindingsRead) && s.requireRepo(ctx, p, authz.PermFindingsRead, repo.ID) == nil {
		rows, err := s.DB.Query(ctx, `SELECT severity, count(*) FROM findings WHERE repository_id = $1 AND status IN ('open', 'in_progress', 'needs_review')
			GROUP BY severity`, repo.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for rows.Next() {
			var sev string
			var n int
			if err := rows.Scan(&sev, &n); err != nil {
				rows.Close()
				s.fail(w, r, err)
				return
			}
			open[sev] = n
		}
		rows.Close()
	}
	ap, err := s.loadPolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"latest_scan": l, "open_findings": open, "scan_on_import": ap.ScanOnImport})
}
