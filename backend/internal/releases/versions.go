package releases

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Version is an application version (release).
type Version struct {
	ID            uuid.UUID  `json:"id"`
	ApplicationID uuid.UUID  `json:"application_id"`
	Version       string     `json:"version"`
	Description   string     `json:"description"`
	ReleasedAt    *time.Time `json:"released_at"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	Repositories  int        `json:"repository_count"`
	Components    int        `json:"component_count"`
	OpenFindings  int        `json:"open_findings"`
}

const versionSelect = `
	SELECT v.id, v.application_id, v.version, v.description, v.released_at,
	       COALESCE(NULLIF(u.display_name, ''), u.email, ''), v.created_at,
	       (SELECT count(*) FROM application_version_repositories x WHERE x.version_id = v.id),
	       (SELECT count(*) FROM application_version_components x WHERE x.version_id = v.id),
	       (SELECT count(*) FROM application_version_findings x LEFT JOIN findings f ON f.id = x.finding_id
	         WHERE x.version_id = v.id AND COALESCE(f.status, x.status) IN ('open', 'in_progress', 'needs_review'))
	FROM application_versions v LEFT JOIN users u ON u.id = v.created_by`

func scanVersion(row pgx.Row) (Version, error) {
	var v Version
	err := row.Scan(&v.ID, &v.ApplicationID, &v.Version, &v.Description, &v.ReleasedAt, &v.CreatedBy, &v.CreatedAt,
		&v.Repositories, &v.Components, &v.OpenFindings)
	return v, err
}

func (s *Service) listVersions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, a, err := s.appForRead(r, authz.PermReposRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, versionSelect+` WHERE v.organization_id = $1 AND v.application_id = $2 ORDER BY v.created_at DESC`, p.OrganizationID, a.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Version, error) { return scanVersion(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Version{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "application": map[string]any{"id": a.ID, "name": a.Name},
		"can_manage": s.Authz.Require(ctx, p, authz.PermReposManage, s.appScope(p, a)) == nil})
}

type versionRequest struct {
	Version      string     `json:"version"`
	Description  string     `json:"description"`
	ReleasedAt   *time.Time `json:"released_at"`
	Repositories []struct {
		RepositoryID uuid.UUID  `json:"repository_id"`
		ScanJobID    *uuid.UUID `json:"scan_job_id"`
	} `json:"repositories"`
}

// createVersion freezes what the application consists of now: for each
// repository (all of the application's, or those listed), the scan used
// (latest successful scan of the scan branch unless one is given), its
// commit, the component inventory and the findings that scan saw.
func (s *Service) createVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, a, err := s.appForManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req versionRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Version = strings.TrimSpace(req.Version)
	if req.Version == "" || len(req.Version) > 100 || strings.ContainsAny(req.Version, "\x00\r\n") {
		s.fail(w, r, httpx.BadRequest("version must be 1-100 characters"))
		return
	}
	if len(req.Description) > 2000 {
		s.fail(w, r, httpx.BadRequest("description must be at most 2000 characters"))
		return
	}
	type pick struct {
		repo uuid.UUID
		job  *uuid.UUID
	}
	var picks []pick
	if len(req.Repositories) == 0 {
		for _, id := range a.Repos {
			picks = append(picks, pick{repo: id})
		}
	} else {
		seen := map[uuid.UUID]bool{}
		for _, x := range req.Repositories {
			if seen[x.RepositoryID] {
				continue
			}
			seen[x.RepositoryID] = true
			found := false
			for _, id := range a.Repos {
				found = found || id == x.RepositoryID
			}
			if !found {
				s.fail(w, r, httpx.BadRequest("repository "+x.RepositoryID.String()+" is not part of this application"))
				return
			}
			picks = append(picks, pick{repo: x.RepositoryID, job: x.ScanJobID})
		}
	}
	if len(picks) == 0 {
		s.fail(w, r, httpx.BadRequest("the application has no repositories"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	var warnings []string
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO application_versions (id, organization_id, application_id, version, description, released_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, p.OrganizationID, a.ID, req.Version, req.Description, req.ReleasedAt, p.UserID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("this application already has a version " + req.Version)
			}
			return err
		}
		for _, pk := range picks {
			var job *uuid.UUID
			var ref, commit, name string
			q := `SELECT j.id, j.ref, j.commit_sha, r.full_name FROM repositories r
				LEFT JOIN LATERAL (SELECT id, ref, commit_sha FROM scan_jobs j WHERE j.repository_id = r.id
				  AND j.status IN ('succeeded', 'partial') AND j.target_id IS NULL AND j.pull_request IS NULL
				  AND ($3::uuid IS NULL OR j.id = $3) ORDER BY j.finished_at DESC NULLS LAST LIMIT 1) j ON true
				WHERE r.organization_id = $1 AND r.id = $2`
			if err := tx.QueryRow(ctx, q, p.OrganizationID, pk.repo, pk.job).Scan(&job, &ref, &commit, &name); err != nil {
				return err
			}
			if pk.job != nil && job == nil {
				return httpx.BadRequest("scan " + pk.job.String() + " is not a successful scan of " + name)
			}
			if job == nil {
				warnings = append(warnings, name+": no successful scan yet; included without components or findings")
				if _, err := tx.Exec(ctx, `INSERT INTO application_version_repositories (version_id, repository_id) VALUES ($1, $2)`, id, pk.repo); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO application_version_repositories (version_id, repository_id, ref, commit_sha, scan_job_id)
				VALUES ($1, $2, $3, $4, $5)`, id, pk.repo, ref, commit, job); err != nil {
				return err
			}
			// The inventory holds the latest scan's components; an older scan
			// is only snapshotted if its components are still the current ones.
			tag, err := tx.Exec(ctx, `INSERT INTO application_version_components (organization_id, version_id, repository_id, name, version, purl, type, licenses)
				SELECT organization_id, $2, repository_id, name, version, purl, type, licenses FROM sbom_components
				WHERE repository_id = $1 AND ($3::uuid IS NULL OR scan_job_id = $3)`, pk.repo, id, pk.job)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				warnings = append(warnings, name+": no component inventory for the selected scan")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO application_version_findings (organization_id, version_id, repository_id, finding_id, fingerprint,
				  category, title, severity, cve, package_name, package_version, fixed_version, status)
				SELECT f.organization_id, $2, f.repository_id, f.id, f.fingerprint, f.category, f.title, f.severity, f.cve,
				       f.package_name, f.package_version, f.fixed_version, f.status
				FROM findings f WHERE f.repository_id = $1 AND f.scan_target_id IS NULL
				  AND EXISTS (SELECT 1 FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id
				              WHERE o.finding_id = f.id AND sr.scan_job_id = $3)
				ON CONFLICT DO NOTHING`, pk.repo, id, job); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application_version.create", TargetType: "application", TargetID: a.ID.String(),
			Metadata: map[string]any{"version_id": id, "version": req.Version, "repositories": len(picks)}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := scanVersion(s.DB.QueryRow(ctx, versionSelect+` WHERE v.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if warnings == nil {
		warnings = []string{}
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"version": v, "warnings": warnings})
}

// version loads a version of the application in the path.
func (s *Service) version(r *http.Request, orgID uuid.UUID, a app) (Version, error) {
	vid, err := pathUUID(r, "vid")
	if err != nil {
		return Version{}, err
	}
	v, err := scanVersion(s.DB.QueryRow(r.Context(), versionSelect+` WHERE v.organization_id = $1 AND v.application_id = $2 AND v.id = $3`, orgID, a.ID, vid))
	if errors.Is(err, pgx.ErrNoRows) {
		return v, errNotFound
	}
	return v, err
}

// VersionRepo is a repository of a version.
type VersionRepo struct {
	RepositoryID uuid.UUID  `json:"repository_id"`
	FullName     string     `json:"full_name"`
	Ref          string     `json:"ref"`
	CommitSHA    string     `json:"commit_sha"`
	ScanJobID    *uuid.UUID `json:"scan_job_id"`
}

// VersionComponent is a frozen component.
type VersionComponent struct {
	RepositoryID uuid.UUID `json:"repository_id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	PURL         string    `json:"purl"`
	Type         string    `json:"type"`
	Licenses     []string  `json:"licenses"`
}

// VersionFinding is a frozen finding with its current decision.
type VersionFinding struct {
	FindingID       *uuid.UUID `json:"finding_id"`
	RepositoryID    uuid.UUID  `json:"repository_id"`
	Category        string     `json:"category"`
	Title           string     `json:"title"`
	Severity        string     `json:"severity"`
	CVE             string     `json:"cve"`
	PackageName     string     `json:"package_name"`
	PackageVersion  string     `json:"package_version"`
	FixedVersion    string     `json:"fixed_version"`
	StatusAtRelease string     `json:"status_at_release"`
	Status          string     `json:"status"`
}

// getVersion returns a version with what the caller may see: repositories
// (repos.read), components (sbom.read) and findings (findings.read).
func (s *Service) getVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, a, err := s.appForRead(r, authz.PermReposRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.version(r, p.OrganizationID, a)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT x.repository_id, r.full_name, x.ref, x.commit_sha, x.scan_job_id
		FROM application_version_repositories x JOIN repositories r ON r.id = x.repository_id WHERE x.version_id = $1 ORDER BY r.full_name`, v.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := pgx.CollectRows(rows, pgx.RowToStructByPos[VersionRepo])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repos := []VersionRepo{}
	var sbomRepos, findingRepos []uuid.UUID
	for _, x := range all {
		if !s.canOnRepo(ctx, p, authz.PermReposRead, x.RepositoryID) {
			continue
		}
		repos = append(repos, x)
		if s.canOnRepo(ctx, p, authz.PermSBOMRead, x.RepositoryID) {
			sbomRepos = append(sbomRepos, x.RepositoryID)
		}
		if s.canOnRepo(ctx, p, authz.PermFindingsRead, x.RepositoryID) {
			findingRepos = append(findingRepos, x.RepositoryID)
		}
	}
	comps := []VersionComponent{}
	if len(sbomRepos) > 0 {
		rows, err := s.DB.Query(ctx, `SELECT repository_id, name, version, purl, type, licenses FROM application_version_components
			WHERE version_id = $1 AND repository_id = ANY($2) ORDER BY lower(name), version LIMIT 20000`, v.ID, sbomRepos)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if comps, err = pgx.CollectRows(rows, pgx.RowToStructByPos[VersionComponent]); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	finds := []VersionFinding{}
	if len(findingRepos) > 0 {
		rows, err := s.DB.Query(ctx, `SELECT x.finding_id, x.repository_id, x.category, x.title, x.severity, x.cve, x.package_name,
			  x.package_version, x.fixed_version, x.status, COALESCE(f.status, x.status)
			FROM application_version_findings x LEFT JOIN findings f ON f.id = x.finding_id
			WHERE x.version_id = $1 AND x.repository_id = ANY($2)
			ORDER BY array_position(ARRAY['critical','high','medium','low','info'], x.severity), x.title LIMIT 20000`, v.ID, findingRepos)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if finds, err = pgx.CollectRows(rows, pgx.RowToStructByPos[VersionFinding]); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if comps == nil {
		comps = []VersionComponent{}
	}
	if finds == nil {
		finds = []VersionFinding{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": v, "application": map[string]any{"id": a.ID, "name": a.Name},
		"repositories": repos, "components": comps, "findings": finds,
		"can_manage": s.Authz.Require(ctx, p, authz.PermReposManage, s.appScope(p, a)) == nil})
}

func (s *Service) deleteVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, a, err := s.appForManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.version(r, p.OrganizationID, a)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM application_versions WHERE id = $1`, v.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application_version.delete", TargetType: "application", TargetID: a.ID.String(),
			Metadata: map[string]any{"version_id": v.ID, "version": v.Version}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PortfolioVersion is an application version containing a component.
type PortfolioVersion struct {
	ApplicationID   uuid.UUID `json:"application_id"`
	ApplicationName string    `json:"application_name"`
	VersionID       uuid.UUID `json:"version_id"`
	Version         string    `json:"version"`
	Repository      string    `json:"repository"`
	Component       string    `json:"component"`
	ComponentVer    string    `json:"component_version"`
	PURL            string    `json:"purl"`
	Matched         string    `json:"matched_by"` // component | vulnerability
}

// PortfolioRepo is a repository whose current inventory contains a component.
type PortfolioRepo struct {
	RepositoryID uuid.UUID `json:"repository_id"`
	Repository   string    `json:"repository"`
	Component    string    `json:"component"`
	ComponentVer string    `json:"component_version"`
	PURL         string    `json:"purl"`
	Matched      string    `json:"matched_by"`
}

// portfolio answers "which application versions, and which repositories
// today, contain this component (or vulnerability)?" within the caller's
// sbom.read scope.
func (s *Service) portfolio(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermSBOMRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	name, version, purl, cve := strings.TrimSpace(q.Get("name")), strings.TrimSpace(q.Get("version")),
		strings.TrimSpace(q.Get("purl")), strings.ToUpper(strings.TrimSpace(q.Get("cve")))
	if name == "" && purl == "" && cve == "" {
		s.fail(w, r, httpx.BadRequest("give a component name, a purl or a CVE"))
		return
	}
	if len(name) > 300 || len(version) > 100 || len(purl) > 600 || len(cve) > 100 {
		s.fail(w, r, httpx.BadRequest("query too long"))
		return
	}
	purlLike := ""
	if purl != "" {
		purlLike = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(purlBase(purl))) + "%"
	}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 6)
	args := append([]any{p.OrganizationID, name, version, purlLike, cve}, sargs...)
	compCond := `(($2 <> '' AND lower(c.name) = lower($2)) OR ($4 <> '' AND lower(c.purl) LIKE $4)) AND ($3 = '' OR c.version = $3)`
	vrows, err := s.DB.Query(ctx, `
		SELECT DISTINCT a.id, a.name, v.id, v.version, r.full_name, c.name, c.version, c.purl, 'component'
		FROM application_version_components c JOIN application_versions v ON v.id = c.version_id
		JOIN applications a ON a.id = v.application_id JOIN repositories r ON r.id = c.repository_id
		WHERE c.organization_id = $1 AND ($2 <> '' OR $4 <> '') AND `+compCond+` AND `+scope+`
		UNION
		SELECT DISTINCT a.id, a.name, v.id, v.version, r.full_name, x.package_name, x.package_version, '', 'vulnerability'
		FROM application_version_findings x JOIN application_versions v ON v.id = x.version_id
		JOIN applications a ON a.id = v.application_id JOIN repositories r ON r.id = x.repository_id
		WHERE x.organization_id = $1 AND $5 <> '' AND upper(x.cve) = $5 AND `+scope+`
		ORDER BY 2, 4 DESC LIMIT 1000`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	versions, err := pgx.CollectRows(vrows, pgx.RowToStructByPos[PortfolioVersion])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rrows, err := s.DB.Query(ctx, `
		SELECT DISTINCT r.id, r.full_name, c.name, c.version, c.purl, 'component'
		FROM sbom_components c JOIN repositories r ON r.id = c.repository_id
		WHERE c.organization_id = $1 AND r.archived_at IS NULL AND ($2 <> '' OR $4 <> '') AND `+compCond+` AND `+scope+`
		UNION
		SELECT DISTINCT r.id, r.full_name, x.package_name, x.package_version, '', 'vulnerability'
		FROM findings x JOIN repositories r ON r.id = x.repository_id
		WHERE x.organization_id = $1 AND r.archived_at IS NULL AND $5 <> '' AND upper(x.cve) = $5
		  AND x.status IN ('open', 'in_progress', 'needs_review', 'accepted_risk') AND `+scope+`
		ORDER BY 2 LIMIT 1000`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repos, err := pgx.CollectRows(rrows, pgx.RowToStructByPos[PortfolioRepo])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if versions == nil {
		versions = []PortfolioVersion{}
	}
	if repos == nil {
		repos = []PortfolioRepo{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"versions": versions, "repositories": repos})
}
