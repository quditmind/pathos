package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// SourceRef identifies a repository to onboard: an existing PATHOS
// repository (repository_id) or a repository discovered through an SCM
// connection.
type SourceRef struct {
	RepositoryID    *uuid.UUID `json:"repository_id,omitempty"`
	ScmConnectionID *uuid.UUID `json:"scm_connection_id,omitempty"`
	ExternalID      string     `json:"external_id"`
	FullName        string     `json:"full_name"`
	URL             string     `json:"url"`
	Organization    string     `json:"organization"`
	Project         string     `json:"project"`
	// Language is the primary language the provider reported (a hint).
	Language string `json:"language"`
}

// resolvedSource is a SourceRef checked against the organization's data.
type resolvedSource struct {
	SourceRef
	Key      string
	Existing *RepoRef
	// ExistingInvisible: the repository is registered but the caller cannot
	// see it.
	ExistingInvisible bool
	Onboarding        *OnboardingRef
}

// RepoRef is an existing repository.
type RepoRef struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	FullName    string    `json:"full_name"`
	URL         string    `json:"url"`
	Application *Ref      `json:"application"`
}

// OnboardingRef is an existing onboarding of the same repository.
type OnboardingRef struct {
	ID              uuid.UUID `json:"id"`
	ApplicationID   uuid.UUID `json:"application_id"`
	ApplicationName string    `json:"application_name"`
	Status          string    `json:"status"`
}

const maxSources = 50

func (sr *SourceRef) normalize() error {
	sr.ExternalID = strings.TrimSpace(sr.ExternalID)
	sr.FullName = strings.Trim(strings.TrimSpace(sr.FullName), "/")
	sr.URL = strings.TrimSpace(sr.URL)
	sr.Language = truncate(strings.TrimSpace(sr.Language), 60)
	if sr.RepositoryID == nil {
		if sr.ScmConnectionID == nil {
			return httpx.BadRequest("each repository needs repository_id or scm_connection_id")
		}
		if sr.FullName == "" || len(sr.FullName) > 500 || len(sr.ExternalID) > 200 || len(sr.URL) > 1000 {
			return httpx.BadRequest("each discovered repository needs full_name (at most 500 characters), external_id and url")
		}
	}
	if len(sr.Organization) > 200 || len(sr.Project) > 200 {
		return httpx.BadRequest("organization and project must be at most 200 characters")
	}
	return nil
}

// resolve checks each source: the connection belongs to the organization,
// whether the repository already exists in PATHOS (same connection and
// external ID, or the same normalised location) and whether it is already
// being onboarded.
func (s *Service) resolve(ctx context.Context, q db.Querier, p *authz.Principal, refs []SourceRef) ([]resolvedSource, error) {
	out := make([]resolvedSource, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		if err := ref.normalize(); err != nil {
			return nil, err
		}
		rs := resolvedSource{SourceRef: ref}
		if ref.RepositoryID != nil {
			var r RepoRef
			var appID *uuid.UUID
			var appName *string
			var connID *uuid.UUID
			var ext, clone string
			err := q.QueryRow(ctx, `SELECT r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), r.full_name, r.url, r.clone_url,
				r.scm_connection_id, r.external_id, a.id, a.name
				FROM repositories r LEFT JOIN applications a ON a.id = r.application_id
				WHERE r.organization_id = $1 AND r.id = $2 AND r.archived_at IS NULL`, p.OrganizationID, *ref.RepositoryID).
				Scan(&r.ID, &r.Name, &r.FullName, &r.URL, &clone, &connID, &ext, &appID, &appName)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, httpx.BadRequest("repository " + ref.RepositoryID.String() + " does not exist")
			}
			if err != nil {
				return nil, err
			}
			if ok, _ := s.Authz.Can(ctx, p, authz.PermReposRead, authz.Scope{Type: authz.ScopeRepository, ID: r.ID}); !ok {
				return nil, httpx.BadRequest("repository " + ref.RepositoryID.String() + " does not exist")
			}
			r.Application = ref2(appID, appName)
			rs.Existing = &r
			rs.FullName, rs.URL, rs.ScmConnectionID, rs.ExternalID = r.FullName, r.URL, connID, ext
			rs.Key = SourceKey(firstNonEmpty(r.URL, clone), "", r.FullName)
			if rs.Key == "" {
				rs.Key = "repository:" + r.ID.String()
			}
		} else {
			var baseURL string
			if err := q.QueryRow(ctx, `SELECT base_url FROM scm_connections WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL`,
				p.OrganizationID, *ref.ScmConnectionID).Scan(&baseURL); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, httpx.BadRequest("SCM connection does not exist")
				}
				return nil, err
			}
			rs.Key = SourceKey(ref.URL, HostOf(baseURL), ref.FullName)
			if err := s.findExisting(ctx, q, p, &rs); err != nil {
				return nil, err
			}
		}
		if seen[rs.Key] {
			return nil, httpx.BadRequest("the same repository is listed twice: " + rs.FullName)
		}
		seen[rs.Key] = true
		var o OnboardingRef
		err := q.QueryRow(ctx, `SELECT o.id, o.application_id, a.name, o.status FROM asset_onboardings o JOIN applications a ON a.id = o.application_id
			WHERE o.organization_id = $1 AND (o.source_key = $2 OR (o.scm_connection_id = $3 AND o.external_id = $4 AND $4 <> '')
			   OR (o.repository_id IS NOT NULL AND o.repository_id = $5)) LIMIT 1`,
			p.OrganizationID, rs.Key, rs.ScmConnectionID, rs.ExternalID, repoIDOf(rs.Existing)).Scan(&o.ID, &o.ApplicationID, &o.ApplicationName, &o.Status)
		if err == nil {
			rs.Onboarding = &o
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, nil
}

func repoIDOf(r *RepoRef) *uuid.UUID {
	if r == nil {
		return nil
	}
	return &r.ID
}

func ref2(id *uuid.UUID, name *string) *Ref { return ref(id, name) }

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// findExisting looks for the discovered repository among the registered
// ones: same connection and external ID, or the same normalised location
// (another connection to the same host, or an older registration).
func (s *Service) findExisting(ctx context.Context, q db.Querier, p *authz.Principal, rs *resolvedSource) error {
	name := rs.FullName
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	rows, err := q.Query(ctx, `SELECT r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), r.full_name, r.url, r.clone_url,
		r.scm_connection_id, r.external_id, a.id, a.name
		FROM repositories r LEFT JOIN applications a ON a.id = r.application_id
		WHERE r.organization_id = $1 AND r.archived_at IS NULL
		  AND ((r.scm_connection_id = $2 AND r.external_id = $3) OR lower(r.full_name) = lower($4) OR lower(r.name) = lower($5))
		LIMIT 50`, p.OrganizationID, rs.ScmConnectionID, rs.ExternalID, rs.FullName, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r RepoRef
		var clone, ext string
		var conn, appID *uuid.UUID
		var appName *string
		if err := rows.Scan(&r.ID, &r.Name, &r.FullName, &r.URL, &clone, &conn, &ext, &appID, &appName); err != nil {
			return err
		}
		same := conn != nil && rs.ScmConnectionID != nil && *conn == *rs.ScmConnectionID && ext == rs.ExternalID && ext != ""
		if !same {
			k1 := SourceKey(r.URL, "", r.FullName)
			k2 := SourceKey(clone, "", r.FullName)
			same = rs.Key != "" && (k1 == rs.Key || k2 == rs.Key)
		}
		if !same {
			continue
		}
		r.Application = ref(appID, appName)
		if ok, _ := s.Authz.Can(ctx, p, authz.PermReposRead, authz.Scope{Type: authz.ScopeRepository, ID: r.ID}); !ok {
			rs.ExistingInvisible = true
			return nil
		}
		rs.Existing = &r
		rid := r.ID
		rs.RepositoryID = &rid
		return nil
	}
	return rows.Err()
}

// Candidate is an existing application the repositories may belong to.
type Candidate struct {
	ID               uuid.UUID `json:"id"`
	Key              string    `json:"application_key"`
	Name             string    `json:"name"`
	OnboardingStatus string    `json:"onboarding_status"`
	RepositoryCount  int       `json:"repository_count"`
	Score            float64   `json:"score"`
	Reasons          []string  `json:"reasons"`
}

// MatchSource is the finding for one repository.
type MatchSource struct {
	SourceRef
	SourceKey         string         `json:"source_key"`
	Existing          *RepoRef       `json:"existing_repository"`
	ExistingInvisible bool           `json:"registered_elsewhere"`
	Onboarding        *OnboardingRef `json:"onboarding"`
}

type matchRequest struct {
	Repositories    []SourceRef `json:"repositories"`
	ApplicationName string      `json:"application_name"`
}

// match: POST /api/v1/onboarding/match finds existing assets before
// anything is created: the repositories themselves (by connection and
// external ID or normalised URL), onboardings in progress, and
// applications by contained repository, shared owner namespace (team) and
// name similarity.
func (s *Service) match(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var req matchRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.Repositories) == 0 || len(req.Repositories) > maxSources {
		s.fail(w, r, httpx.BadRequest(fmt.Sprintf("repositories must list 1-%d repositories", maxSources)))
		return
	}
	if len(req.ApplicationName) > 200 {
		s.fail(w, r, httpx.BadRequest("application_name must be at most 200 characters"))
		return
	}
	srcs, err := s.resolve(ctx, s.DB, p, req.Repositories)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cands, err := s.candidates(ctx, p, srcs, req.ApplicationName)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]MatchSource, 0, len(srcs))
	for _, rs := range srcs {
		ms := MatchSource{SourceRef: rs.SourceRef, SourceKey: rs.Key, Existing: rs.Existing, ExistingInvisible: rs.ExistingInvisible}
		// An onboarding into an application the caller cannot see is
		// reported without its name.
		if rs.Onboarding != nil {
			o := *rs.Onboarding
			if _, err := s.loadVisibleApp(ctx, s.DB, p, o.ApplicationID); err != nil {
				o.ApplicationName, o.ApplicationID = "", uuid.Nil
			}
			ms.Onboarding = &o
		}
		out = append(out, ms)
	}
	suggested := strings.TrimSpace(req.ApplicationName)
	if suggested == "" && len(srcs) > 0 {
		suggested = suggestName(srcs[0].FullName)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"sources": out, "candidates": cands, "suggested_name": suggested})
}

// suggestName turns "acme/payments-api" into "Payments API".
func suggestName(fullName string) string {
	n := fullName
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	parts := strings.FieldsFunc(n, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == ' ' })
	for i, w := range parts {
		switch strings.ToLower(w) {
		case "api", "ui", "sdk", "cli", "iam", "sso":
			parts[i] = strings.ToUpper(w)
		default:
			parts[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return truncate(strings.Join(parts, " "), 200)
}

func (s *Service) candidates(ctx context.Context, p *authz.Principal, srcs []resolvedSource, appName string) ([]Candidate, error) {
	cond, args := visibleAppSQL(p, authz.PermReposRead, 2)
	rows, err := s.DB.Query(ctx, `SELECT a.id, a.application_key, a.name, a.onboarding_status,
		COALESCE((SELECT array_agg(lower(r.full_name)) FROM repositories r WHERE r.application_id = a.id AND r.archived_at IS NULL), '{}'),
		COALESCE((SELECT array_agg(lower(o.full_name)) FROM asset_onboardings o WHERE o.application_id = a.id), '{}')
		FROM applications a WHERE a.organization_id = $1 AND a.archived_at IS NULL AND `+cond+`
		ORDER BY a.id LIMIT 5000`, append([]any{p.OrganizationID}, args...)...)
	if err != nil {
		return nil, err
	}
	type app struct {
		ID         uuid.UUID
		Key        string
		Name       string
		Status     string
		Repos      []string
		Onboarding []string
	}
	apps, err := pgx.CollectRows(rows, pgx.RowToStructByPos[app])
	if err != nil {
		return nil, err
	}
	var out []Candidate
	for _, a := range apps {
		c := Candidate{ID: a.ID, Key: a.Key, Name: a.Name, OnboardingStatus: a.Status, RepositoryCount: len(a.Repos), Reasons: []string{}}
		score := 0.0
		namespaces := map[string]bool{}
		for _, fn := range append(slices.Clone(a.Repos), a.Onboarding...) {
			if ns := Namespace(fn); ns != "" {
				namespaces[ns] = true
			}
		}
		for _, rs := range srcs {
			if rs.Existing != nil && rs.Existing.Application != nil && rs.Existing.Application.ID == a.ID {
				score += 1
				c.Reasons = append(c.Reasons, "Already contains "+rs.FullName)
			}
			if rs.Onboarding != nil && rs.Onboarding.ApplicationID == a.ID {
				score += 1
				c.Reasons = append(c.Reasons, rs.FullName+" is being onboarded into this application")
			}
			if ns := Namespace(rs.FullName); ns != "" && namespaces[ns] {
				score += 0.3
				c.Reasons = append(c.Reasons, "Shares the owner or team "+ns)
			}
		}
		best, bestOf := 0.0, ""
		for _, n := range append([]string{appName}, sourceNames(srcs)...) {
			if strings.TrimSpace(n) == "" {
				continue
			}
			if sim := NameSimilarity(n, a.Name); sim > best {
				best, bestOf = sim, n
			}
		}
		if best >= 0.6 {
			score += best * 0.7
			c.Reasons = append(c.Reasons, fmt.Sprintf("Name similar to %q (%d%%)", bestOf, int(best*100+0.5)))
		}
		c.Reasons = slices.Compact(c.Reasons)
		c.Score = min(1, float64(int(score*100+0.5))/100)
		if c.Score >= 0.4 {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if len(out) > 5 {
		out = out[:5]
	}
	if out == nil {
		out = []Candidate{}
	}
	return out, nil
}

func sourceNames(srcs []resolvedSource) []string {
	out := make([]string, 0, len(srcs))
	for _, rs := range srcs {
		n := rs.FullName
		if i := strings.LastIndex(n, "/"); i >= 0 {
			n = n[i+1:]
		}
		out = append(out, n)
	}
	return out
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

type registerRequest struct {
	// Mode: "link" (to application_id) or "new" (application).
	Mode          string     `json:"mode"`
	ApplicationID *uuid.UUID `json:"application_id"`
	Application   *struct {
		Name           string     `json:"name"`
		Description    string     `json:"description"`
		BusinessUnitID *uuid.UUID `json:"business_unit_id"`
		ExternalRef    string     `json:"external_ref"`
	} `json:"application"`
	Repositories []SourceRef `json:"repositories"`
}

// OnboardingSource is one repository of an onboarding.
type OnboardingSource struct {
	ID              uuid.UUID  `json:"id"`
	FullName        string     `json:"full_name"`
	URL             string     `json:"url"`
	ScmConnectionID *uuid.UUID `json:"scm_connection_id"`
	ExternalID      string     `json:"external_id"`
	Organization    string     `json:"organization"`
	Project         string     `json:"project"`
	Decision        string     `json:"decision"`
	Status          string     `json:"status"`
	RepositoryID    *uuid.UUID `json:"repository_id"`
	RepositoryName  *string    `json:"repository_name"`
	ImportJobID     *uuid.UUID `json:"import_job_id"`
	ImportStatus    *string    `json:"import_status"`
	Language        string     `json:"language"`
	CreatedAt       time.Time  `json:"created_at"`
}

// errAlreadyOnboarding is PTH-ONB-1008.
func errAlreadyOnboarding(rs resolvedSource, visible bool) error {
	e := httpx.E(http.StatusConflict, "already_onboarding",
		rs.FullName+" is already being onboarded; open the existing application instead of registering it again").WithDiag("PTH-ONB-1008")
	if visible && rs.Onboarding != nil {
		e.Details = map[string]any{"application_id": rs.Onboarding.ApplicationID, "application_name": rs.Onboarding.ApplicationName,
			"repository": rs.FullName}
	} else {
		e.Details = map[string]any{"repository": rs.FullName}
	}
	return e
}

// register: POST /api/v1/onboarding links the repositories to an existing
// application or registers a new draft application, records one
// onboarding row per repository and fills detected classification. The
// unique key of asset_onboardings makes a second (or concurrent)
// onboarding of the same repository fail with PTH-ONB-1008 and roll back
// everything, so no duplicate application or repository is created.
func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req registerRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.Repositories) == 0 || len(req.Repositories) > maxSources {
		s.fail(w, r, httpx.BadRequest(fmt.Sprintf("repositories must list 1-%d repositories", maxSources)))
		return
	}
	var bu *uuid.UUID
	switch req.Mode {
	case "link":
		if req.ApplicationID == nil {
			s.fail(w, r, httpx.BadRequest("application_id is required to link"))
			return
		}
	case "new":
		if req.Application == nil || strings.TrimSpace(req.Application.Name) == "" || len(req.Application.Name) > 200 {
			s.fail(w, r, httpx.BadRequest("application.name must be 1-200 characters"))
			return
		}
		if len(req.Application.Description) > 2000 || len(req.Application.ExternalRef) > 100 {
			s.fail(w, r, httpx.BadRequest("description must be at most 2000 and external_ref at most 100 characters"))
			return
		}
		bu = req.Application.BusinessUnitID
		if err := s.Authz.Require(ctx, p, authz.PermReposManage, appScope(p, bu)); err != nil {
			s.fail(w, r, err)
			return
		}
	default:
		s.fail(w, r, httpx.BadRequest("mode must be link or new"))
		return
	}
	var appID uuid.UUID
	created := false
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		srcs, err := s.resolve(ctx, tx, p, req.Repositories)
		if err != nil {
			return err
		}
		for _, rs := range srcs {
			if rs.ExistingInvisible {
				return httpx.E(http.StatusConflict, "already_registered", rs.FullName+
					" is already registered in PATHOS in a scope you cannot see; ask an administrator to link it").WithDiag("PTH-ONB-1004")
			}
			if rs.Onboarding != nil {
				_, verr := s.loadVisibleApp(ctx, tx, p, rs.Onboarding.ApplicationID)
				return errAlreadyOnboarding(rs, verr == nil)
			}
			if rs.Existing != nil {
				// Linking moves the repository into the application at
				// "Save to inventory": the caller must be allowed to.
				if err := s.Authz.Require(ctx, p, authz.PermReposManage, authz.Scope{Type: authz.ScopeRepository, ID: rs.Existing.ID}); err != nil {
					return err
				}
			}
		}
		var name string
		if req.Mode == "link" {
			a, err := s.loadManagedApp(ctx, tx, p, *req.ApplicationID)
			if err != nil {
				return err
			}
			appID, name = a.ID, a.Name
		} else {
			appID, name, created = uuid.Must(uuid.NewV7()), strings.TrimSpace(req.Application.Name), true
			if _, err := tx.Exec(ctx, `INSERT INTO applications (id, organization_id, name, description, business_unit_id, external_ref,
				onboarding_status) VALUES ($1, $2, $3, $4, $5, $6, 'draft')`,
				appID, p.OrganizationID, name, req.Application.Description, bu, strings.TrimSpace(req.Application.ExternalRef)); err != nil {
				if db.IsUniqueViolation(err) {
					var existing uuid.UUID
					_ = s.DB.QueryRow(ctx, `SELECT id FROM applications WHERE organization_id = $1 AND lower(name) = lower($2) AND archived_at IS NULL`,
						p.OrganizationID, name).Scan(&existing)
					e := httpx.E(http.StatusConflict, "application_exists", "an application named "+fmt.Sprintf("%q", name)+
						" already exists; link the repositories to it or choose another name").WithDiag("PTH-ONB-1011")
					if _, verr := s.loadVisibleApp(ctx, s.DB, p, existing); verr == nil {
						e.Details = map[string]any{"application_id": existing}
					}
					return e
				}
				return err
			}
		}
		for _, rs := range srcs {
			decision := "registered_new"
			var repoID *uuid.UUID
			if rs.Existing != nil {
				decision, repoID = "linked_existing", &rs.Existing.ID
			}
			hints, _ := json.Marshal(map[string]string{"language": rs.Language})
			tag, err := tx.Exec(ctx, `INSERT INTO asset_onboardings (id, organization_id, application_id, source_key, scm_connection_id,
				external_id, full_name, url, organization, project, repository_id, decision, hints, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT DO NOTHING`,
				uuid.Must(uuid.NewV7()), p.OrganizationID, appID, rs.Key, rs.ScmConnectionID, rs.ExternalID, rs.FullName,
				truncate(rs.URL, 1000), rs.Organization, rs.Project, repoID, decision, hints, p.UserID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				// A concurrent onboarding of the same repository won.
				var o OnboardingRef
				if err := s.DB.QueryRow(ctx, `SELECT o.id, o.application_id, a.name, o.status FROM asset_onboardings o
					JOIN applications a ON a.id = o.application_id WHERE o.organization_id = $1 AND o.source_key = $2`,
					p.OrganizationID, rs.Key).Scan(&o.ID, &o.ApplicationID, &o.ApplicationName, &o.Status); err == nil {
					rs.Onboarding = &o
				}
				visible := false
				if rs.Onboarding != nil {
					_, verr := s.loadVisibleApp(ctx, s.DB, p, rs.Onboarding.ApplicationID)
					visible = verr == nil
				}
				return errAlreadyOnboarding(rs, visible)
			}
		}
		if err := detectInto(ctx, tx, p.OrganizationID, appID); err != nil {
			return err
		}
		if _, err := applyAppRules(ctx, tx, p, appID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application.onboard", TargetType: "application", TargetID: appID.String(),
			Metadata: map[string]any{"name": name, "mode": req.Mode, "created": created, "repositories": sourceNames(srcs)}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeOnboarding(w, r, p, appID, http.StatusCreated)
}

// detectInto fills empty classification fields of an application from its
// onboarding sources and linked repositories (repository metadata and
// SBOM components) and marks them "detected". Values a person set are
// never overwritten.
func detectInto(ctx context.Context, tx pgx.Tx, orgID, appID uuid.UUID) error {
	var langs, fws, rts []string
	var hosting string
	var residency *uuid.UUID
	var detected []byte
	if err := tx.QueryRow(ctx, `SELECT languages, frameworks, runtimes, hosting_region, data_residency_region_id, detected_fields
		FROM applications WHERE id = $1 FOR UPDATE`, appID).Scan(&langs, &fws, &rts, &hosting, &residency, &detected); err != nil {
		return err
	}
	det := map[string]Detection{}
	_ = json.Unmarshal(detected, &det)

	// Repositories: linked to the application or referenced by its onboarding.
	rows, err := tx.Query(ctx, `SELECT r.id, r.full_name, r.languages, r.technologies, r.hosting_region, r.data_residency_region_id
		FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND (r.application_id = $2
		  OR r.id IN (SELECT repository_id FROM asset_onboardings WHERE application_id = $2 AND repository_id IS NOT NULL))`, orgID, appID)
	if err != nil {
		return err
	}
	type repo struct {
		ID        uuid.UUID
		FullName  string
		Languages map[string]int64
		Tech      []string
		Hosting   string
		Residency *uuid.UUID
	}
	repos, err := pgx.CollectRows(rows, pgx.RowToStructByPos[repo])
	if err != nil {
		return err
	}
	sizes := map[string]int64{}
	var repoIDs []uuid.UUID
	hostings := map[string]bool{}
	residencies := map[uuid.UUID]bool{}
	var names []string
	for _, r := range repos {
		repoIDs = append(repoIDs, r.ID)
		names = append(names, r.FullName)
		for k, v := range r.Languages {
			sizes[k] += v
		}
		if r.Hosting != "" {
			hostings[r.Hosting] = true
		}
		if r.Residency != nil {
			residencies[*r.Residency] = true
		}
	}
	repoLangs := TopLanguages(sizes)
	// Provider hints of repositories not yet in PATHOS.
	hrows, err := tx.Query(ctx, `SELECT hints->>'language' FROM asset_onboardings WHERE application_id = $1 AND repository_id IS NULL
		AND COALESCE(hints->>'language', '') <> ''`, appID)
	if err != nil {
		return err
	}
	hintLangs, err := pgx.CollectRows(hrows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	var purls []string
	if len(repoIDs) > 0 {
		prows, err := tx.Query(ctx, `SELECT DISTINCT purl FROM sbom_components WHERE repository_id = ANY($1) AND purl <> '' LIMIT 20000`, repoIDs)
		if err != nil {
			return err
		}
		if purls, err = pgx.CollectRows(prows, pgx.RowTo[string]); err != nil {
			return err
		}
	}
	sbomFw, sbomRt := DetectFromPackages(purls)
	src := strings.Join(names, ", ")
	if len(langs) == 0 {
		switch {
		case len(repoLangs) > 0:
			langs, det["languages"] = repoLangs, Detection{Source: "repository", Detail: "Language statistics of " + truncate(src, 200)}
		case len(hintLangs) > 0:
			langs, det["languages"] = mergeUnique(nil, hintLangs), Detection{Source: "scm", Detail: "Primary language reported by the provider"}
		}
	}
	if len(fws) == 0 && len(sbomFw) > 0 {
		fws, det["frameworks"] = sbomFw, Detection{Source: "sbom", Detail: "Packages in the SBOM of " + truncate(src, 200)}
	}
	if len(rts) == 0 {
		switch {
		case len(sbomRt) > 0:
			rts, det["runtimes"] = sbomRt, Detection{Source: "sbom", Detail: "Package ecosystems in the SBOM of " + truncate(src, 200)}
		case len(langs) > 0:
			if r := RuntimesFromLanguages(langs); len(r) > 0 {
				rts, det["runtimes"] = r, Detection{Source: "repository", Detail: "Derived from the detected languages"}
			}
		}
	}
	if hosting == "" && len(hostings) == 1 {
		for h := range hostings {
			hosting = h
		}
		det["hosting_region"] = Detection{Source: "repository", Detail: "Hosting region of " + truncate(src, 200)}
	}
	if residency == nil && len(residencies) == 1 {
		for id := range residencies {
			residency = &id
		}
		det["data_residency"] = Detection{Source: "repository", Detail: "Data residency of " + truncate(src, 200)}
	}
	b, _ := json.Marshal(det)
	_, err = tx.Exec(ctx, `UPDATE applications SET languages = $2, frameworks = $3, runtimes = $4, hosting_region = $5,
		data_residency_region_id = $6, detected_fields = $7, updated_at = now() WHERE id = $1`,
		appID, nonNilStrings(langs), nonNilStrings(fws), nonNilStrings(rts), hosting, residency, b)
	return err
}

// resolveSources links onboarding rows to repositories that now exist
// (imported since registration) and refreshes their status.
func resolveSources(ctx context.Context, q db.Querier, appID uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE asset_onboardings o SET repository_id = r.id, updated_at = now()
		FROM repositories r WHERE o.application_id = $1 AND o.repository_id IS NULL AND o.scm_connection_id IS NOT NULL
		  AND r.scm_connection_id = o.scm_connection_id AND r.external_id = o.external_id AND o.external_id <> ''
		  AND NOT EXISTS (SELECT 1 FROM asset_onboardings x WHERE x.repository_id = r.id)`, appID)
	return err
}

func loadSources(ctx context.Context, q db.Querier, appID uuid.UUID) ([]OnboardingSource, error) {
	rows, err := q.Query(ctx, `SELECT o.id, o.full_name, o.url, o.scm_connection_id, o.external_id, o.organization, o.project,
		o.decision, o.status, o.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name), o.import_job_id, j.status,
		COALESCE(o.hints->>'language', ''), o.created_at
		FROM asset_onboardings o LEFT JOIN repositories r ON r.id = o.repository_id
		LEFT JOIN repository_import_jobs j ON j.id = o.import_job_id
		WHERE o.application_id = $1 ORDER BY lower(o.full_name)`, appID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[OnboardingSource])
	if out == nil {
		out = []OnboardingSource{}
	}
	return out, err
}

// Onboarding is an application with its onboarding repositories.
type Onboarding struct {
	Application Application        `json:"application"`
	Sources     []OnboardingSource `json:"sources"`
}

func (s *Service) writeOnboarding(w http.ResponseWriter, r *http.Request, p *authz.Principal, appID uuid.UUID, status int) {
	ctx := r.Context()
	if err := resolveSources(ctx, s.DB, appID); err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.loadApp(ctx, s.DB, p.OrganizationID, appID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	row, err := s.loadVisibleApp(ctx, s.DB, p, appID)
	if err == nil {
		a.CanManage, _ = s.Authz.Can(ctx, p, authz.PermReposManage, appScope(p, row.BU))
	}
	srcs, err := loadSources(ctx, s.DB, appID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, status, Onboarding{Application: a, Sources: srcs})
}

func (s *Service) getOnboarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.loadVisibleApp(ctx, s.DB, p, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeOnboarding(w, r, p, id, http.StatusOK)
}

// DraftItem is one application in onboarding.
type DraftItem struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"application_key"`
	Name        string    `json:"name"`
	Progress    Progress  `json:"progress"`
	SourceCount int       `json:"repository_count"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// listDrafts: GET /api/v1/onboarding lists the visible applications still
// in onboarding with their progress (the inventory shows the status).
func (s *Service) listDrafts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	cond, args := visibleAppSQL(p, authz.PermReposRead, 2)
	rows, err := s.DB.Query(ctx, `SELECT a.id FROM applications a WHERE a.organization_id = $1 AND a.archived_at IS NULL
		AND a.onboarding_status = 'draft' AND `+cond+` ORDER BY a.updated_at DESC LIMIT 200`, append([]any{p.OrganizationID}, args...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]DraftItem, 0, len(ids))
	for _, id := range ids {
		a, err := s.loadApp(ctx, s.DB, p.OrganizationID, id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		var n int
		_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM asset_onboardings WHERE application_id = $1`, id).Scan(&n)
		out = append(out, DraftItem{ID: a.ID, Key: a.Key, Name: a.Name, Progress: a.Progress, SourceCount: n, UpdatedAt: a.UpdatedAt})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// completeOnboarding: POST /api/v1/applications/{id}/onboarding/complete
// ("Save to inventory"). Mandatory fields and tag categories must be set
// (PTH-ONB-1009, PTH-ONB-1010). Existing repositories are linked to the
// application; repositories still to import are returned with the
// registration metadata for the existing import pipeline.
func (s *Service) completeOnboarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	row, err := s.loadManagedApp(ctx, s.DB, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := resolveSources(ctx, tx, id); err != nil {
			return err
		}
		a, err := s.loadApp(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if len(a.Progress.Missing) > 0 {
			fields := map[string]string{}
			names := make([]string, 0, len(a.Progress.Missing))
			for _, f := range a.Progress.Missing {
				fields[f] = "required"
				names = append(names, FieldLabels[f])
			}
			return errFields(http.StatusUnprocessableEntity, "mandatory_fields_missing", "PTH-ONB-1009",
				"fill the mandatory fields before saving to the inventory: "+strings.Join(names, ", "), fields)
		}
		if len(a.Progress.MissingTagCategories) > 0 {
			names := make([]string, 0, len(a.Progress.MissingTagCategories))
			for _, c := range a.Progress.MissingTagCategories {
				names = append(names, c.Name)
			}
			return errFields(http.StatusUnprocessableEntity, "mandatory_tags_missing", "PTH-ONB-1010",
				"a tag is required in: "+strings.Join(names, ", "), map[string]string{"tags": "a tag is required in: " + strings.Join(names, ", ")})
		}
		srcs, err := loadSources(ctx, tx, id)
		if err != nil {
			return err
		}
		var linked []uuid.UUID
		for _, src := range srcs {
			if src.RepositoryID != nil {
				if err := s.Authz.Require(ctx, p, authz.PermReposManage, authz.Scope{Type: authz.ScopeRepository, ID: *src.RepositoryID}); err != nil {
					return err
				}
				linked = append(linked, *src.RepositoryID)
			}
		}
		if len(linked) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE repositories SET application_id = $2, updated_at = now(), updated_by = $3
				WHERE organization_id = $1 AND id = ANY($4) AND application_id IS DISTINCT FROM $2`, p.OrganizationID, id, p.UserID, linked); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE asset_onboardings SET status = 'saved', updated_at = now() WHERE application_id = $1 AND status = 'draft'`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE applications SET onboarding_status = 'complete', updated_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application.onboarding_complete", TargetType: "application", TargetID: id.String(),
			Metadata: map[string]any{"name": row.Name, "repositories_linked": len(linked)}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeOnboarding(w, r, p, id, http.StatusOK)
}

// startDiscovery: POST /api/v1/applications/{id}/onboarding/discovery
// records the import job that registers the remaining repositories (and
// runs their first scan) and marks the onboarding "discovery started".
func (s *Service) startDiscovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		ImportJobID *uuid.UUID `json:"import_job_id"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	row, err := s.loadManagedApp(ctx, s.DB, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if row.Status != "complete" {
		s.fail(w, r, httpx.E(http.StatusConflict, "onboarding_incomplete", "save the application to the inventory before starting discovery").WithDiag("PTH-ONB-1009"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if req.ImportJobID != nil {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repository_import_jobs WHERE organization_id = $1 AND id = $2)`,
				p.OrganizationID, *req.ImportJobID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return httpx.BadRequest("import job does not exist")
			}
			if _, err := tx.Exec(ctx, `UPDATE asset_onboardings SET import_job_id = $2, updated_at = now()
				WHERE application_id = $1 AND repository_id IS NULL`, id, *req.ImportJobID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE asset_onboardings SET status = 'discovery_started', updated_at = now() WHERE application_id = $1`, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application.discovery_start", TargetType: "application", TargetID: id.String(),
			Metadata: map[string]any{"name": row.Name, "import_job_id": req.ImportJobID}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeOnboarding(w, r, p, id, http.StatusOK)
}

// redetect: POST /api/v1/applications/{id}/detect fills empty fields from
// repository metadata and SBOMs again (for example after the first scan).
func (s *Service) redetect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.loadManagedApp(ctx, s.DB, p, id); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := resolveSources(ctx, tx, id); err != nil {
			return err
		}
		if err := detectInto(ctx, tx, p.OrganizationID, id); err != nil {
			return err
		}
		_, err := applyAppRules(ctx, tx, p, id)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeOnboarding(w, r, p, id, http.StatusOK)
}
