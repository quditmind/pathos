package posture

import (
	"net/http"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
)

// Related findings (cross-tool correlation, never merged):
//
//	same_location      another tool reports the same file within three
//	                   lines with a common CWE (or, without CWEs, the same
//	                   kind of finding): likely the same weakness
//	same_vulnerability the same CVE elsewhere in the repository, e.g. in a
//	                   manifest and in the container image built from it
//
// Dependency findings of the same package and CVE are already merged across
// tools at ingestion (one finding, several scanners).

// Related is a finding related to another.
type Related struct {
	ID          uuid.UUID `json:"id"`
	Relation    string    `json:"relation"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	ScannerKeys []string  `json:"scanner_keys"`
	FilePath    string    `json:"file_path"`
	StartLine   *int      `json:"start_line"`
	TargetName  *string   `json:"scan_target_name"`
	Risk        *float64  `json:"risk_score"`
}

func (s *Service) related(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var repoID uuid.UUID
	var cve string
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, cve FROM findings WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id).
		Scan(&repoID, &cve); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsRead, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `
	WITH me AS (SELECT * FROM findings WHERE id = $1)
	SELECT o.id,
	       CASE WHEN me.cve <> '' AND o.cve = me.cve THEN 'same_vulnerability' ELSE 'same_location' END,
	       o.title, o.severity, o.status, o.scanner_keys, o.file_path, o.start_line, st.name, o.risk_score::float8
	FROM me JOIN findings o ON o.repository_id = me.repository_id AND o.id <> me.id
	LEFT JOIN scan_targets st ON st.id = o.scan_target_id
	WHERE (me.cve <> '' AND o.cve = me.cve)
	   OR (me.category NOT IN ('sca', 'container') AND o.category NOT IN ('sca', 'container')
	       AND o.file_path = me.file_path AND me.file_path <> ''
	       AND me.start_line IS NOT NULL AND o.start_line IS NOT NULL AND abs(o.start_line - me.start_line) <= 3
	       AND NOT (o.scanner_keys && me.scanner_keys)
	       AND (o.cwe && me.cwe OR (cardinality(o.cwe) = 0 AND cardinality(me.cwe) = 0 AND o.category = me.category)))
	ORDER BY 2, o.risk_score DESC NULLS LAST LIMIT 50`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []Related{}
	for rows.Next() {
		var x Related
		if err := rows.Scan(&x.ID, &x.Relation, &x.Title, &x.Severity, &x.Status, &x.ScannerKeys, &x.FilePath, &x.StartLine, &x.TargetName, &x.Risk); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	// How many other repositories (in scope) have this CVE open.
	elsewhere := 0
	if cve != "" {
		cond, args, err := scope(p, authz.PermFindingsRead, 4)
		if err == nil {
			args = append([]any{p.OrganizationID, cve, repoID}, args...)
			// #nosec G202 -- cond is built from placeholders
			_ = s.DB.QueryRow(ctx, `SELECT count(DISTINCT f.repository_id) FROM findings f JOIN repositories r ON r.id = f.repository_id
				WHERE f.organization_id = $1 AND f.cve = $2 AND f.repository_id <> $3 AND f.status IN `+openStatuses+` AND `+cond, args...).Scan(&elsewhere)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "cve": cve, "other_repositories": elsewhere})
}
