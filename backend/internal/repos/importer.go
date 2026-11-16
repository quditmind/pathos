package repos

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// ImportItem describes one repository to import and its placement.
type ImportItem struct {
	ExternalID     string      `json:"external_id"`
	FullName       string      `json:"full_name,omitempty"` // CSV alternative to external_id
	ApplicationID  *uuid.UUID  `json:"application_id,omitempty"`
	BusinessUnitID *uuid.UUID  `json:"business_unit_id,omitempty"`
	CountryID      *uuid.UUID  `json:"country_id,omitempty"`
	Environment    string      `json:"environment,omitempty"`
	Criticality    string      `json:"criticality,omitempty"`
	ScanBranch     string      `json:"scan_branch,omitempty"`
	TagIDs         []uuid.UUID `json:"tag_ids,omitempty"`
}

type importRequest struct {
	ConnectionID uuid.UUID    `json:"scm_connection_id"`
	Repositories []ImportItem `json:"repositories"`
	Defaults     ImportItem   `json:"defaults"`
	DryRun       bool         `json:"dry_run"`
}

// ImportResult reports the outcome per repository.
type ImportResult struct {
	Line         int        `json:"line,omitempty"` // CSV line number
	ExternalID   string     `json:"external_id"`
	FullName     string     `json:"full_name"`
	Status       string     `json:"status"` // imported | would_import | already_imported | error
	Error        string     `json:"error,omitempty"`
	RepositoryID *uuid.UUID `json:"repository_id,omitempty"`
}

const maxImport = 1000

func merge(item, def ImportItem) ImportItem {
	if item.ApplicationID == nil {
		item.ApplicationID = def.ApplicationID
	}
	if item.BusinessUnitID == nil {
		item.BusinessUnitID = def.BusinessUnitID
	}
	if item.CountryID == nil {
		item.CountryID = def.CountryID
	}
	if item.Environment == "" {
		item.Environment = def.Environment
	}
	if item.Criticality == "" {
		item.Criticality = def.Criticality
	}
	if item.TagIDs == nil {
		item.TagIDs = def.TagIDs
	}
	if item.Environment == "" {
		item.Environment = "production"
	}
	if item.Criticality == "" {
		item.Criticality = "medium"
	}
	return item
}

func (s *Service) importRepositories(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	results, imported, err := s.doImport(r.Context(), req, nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": results, "imported": imported, "dry_run": req.DryRun})
}

// doImport validates and imports items. lines carries CSV line numbers.
func (s *Service) doImport(ctx context.Context, req importRequest, lines []int) ([]ImportResult, int, error) {
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposManage) {
		return nil, 0, authz.ErrForbidden
	}
	if len(req.Repositories) == 0 || len(req.Repositories) > maxImport {
		return nil, 0, httpx.BadRequest(fmt.Sprintf("select 1-%d repositories", maxImport))
	}
	c, err := s.getConn(ctx, s.DB, p.OrganizationID, req.ConnectionID)
	if err != nil {
		return nil, 0, err
	}
	remote, err := s.listRemote(ctx, c)
	if err != nil {
		return nil, 0, err
	}
	byID := make(map[string]scm.RemoteRepo, len(remote))
	byName := make(map[string]scm.RemoteRepo, len(remote))
	for _, rr := range remote {
		byID[rr.ExternalID] = rr
		byName[strings.ToLower(rr.FullName)] = rr
	}

	results := make([]ImportResult, 0, len(req.Repositories))
	imported := 0
	for i, raw := range req.Repositories {
		item := merge(raw, req.Defaults)
		res := ImportResult{ExternalID: item.ExternalID, FullName: item.FullName}
		if lines != nil {
			res.Line = lines[i]
		}
		rr, ok := byID[item.ExternalID]
		if !ok && item.FullName != "" {
			rr, ok = byName[strings.ToLower(item.FullName)]
		}
		if !ok {
			res.Status, res.Error = "error", "repository not found in the SCM connection"
			results = append(results, res)
			continue
		}
		res.ExternalID, res.FullName = rr.ExternalID, rr.FullName
		id, status, err := s.importOne(ctx, p, c, rr, item, req.DryRun)
		if err != nil {
			res.Status, res.Error = "error", errMessage(err)
		} else {
			res.Status, res.RepositoryID = status, id
			if status == "imported" {
				imported++
			}
		}
		results = append(results, res)
	}
	if imported > 0 {
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.import", TargetType: "scm_connection", TargetID: c.ID.String(),
			Metadata: map[string]any{"imported": imported, "requested": len(req.Repositories), "name": c.Name}})
	}
	return results, imported, nil
}

func errMessage(err error) string {
	var he *httpx.Error
	switch {
	case errors.As(err, &he):
		return he.Message
	case errors.Is(err, authz.ErrForbidden):
		return "you do not have repos.manage permission for this placement"
	}
	return "could not import (invalid application, business unit or country)"
}

// importOne inserts one repository in its own transaction.
func (s *Service) importOne(ctx context.Context, p *authz.Principal, c Connection, rr scm.RemoteRepo, item ImportItem, dryRun bool) (*uuid.UUID, string, error) {
	ap, err := s.loadPolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		return nil, "", err
	}
	if !ap.active(KindEnvironment, item.Environment) {
		return nil, "", httpx.BadRequest("invalid environment " + item.Environment)
	}
	if !slices.Contains(criticalities, item.Criticality) {
		return nil, "", httpx.BadRequest("invalid criticality " + item.Criticality)
	}
	if item.ScanBranch != "" && !validBranch(item.ScanBranch) {
		return nil, "", httpx.BadRequest("invalid scan branch")
	}
	target, err := s.targetScope(ctx, p, item.BusinessUnitID, item.CountryID)
	if err != nil {
		return nil, "", err
	}
	if err := s.Authz.Require(ctx, p, authz.PermReposManage, target); err != nil {
		return nil, "", err
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var existing uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM repositories WHERE scm_connection_id = $1 AND external_id = $2`, c.ID, rr.ExternalID).Scan(&existing)
	if err == nil {
		return &existing, "already_imported", nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", err
	}
	if err := validateTagSet(ctx, tx, p.OrganizationID, item.TagIDs); err != nil {
		return nil, "", err
	}
	vis := rr.Visibility
	if vis != "public" && vis != "internal" {
		vis = "private"
	}
	var techs []string
	if rr.Language != "" {
		techs = []string{rr.Language}
	}
	id := uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(ctx, `
		INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url,
		  default_branch, scan_branch, visibility, description, technologies, application_id, business_unit_id, country_id,
		  environment, criticality, remote_archived, last_pushed_at, imported_by, scm_organization, scm_project, business_region_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, COALESCE($13::text[], '{}'), $14, $15, $16, $17, $18, $19, $20, $21,
		  $22, $23, (SELECT region_id FROM countries WHERE id = $16))`,
		id, p.OrganizationID, c.ID, rr.ExternalID, rr.FullName, rr.Name, rr.URL, rr.CloneURL, rr.DefaultBranch, item.ScanBranch,
		vis, truncate(rr.Description, 2000), techs, item.ApplicationID, item.BusinessUnitID, item.CountryID,
		item.Environment, item.Criticality, rr.Archived, rr.PushedAt, p.UserID, rr.Organization, rr.Project); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO repository_tags (organization_id, repository_id, tag_id)
		SELECT $1, $2, unnest($3::uuid[])`, p.OrganizationID, id, nonNil(item.TagIDs)); err != nil {
		return nil, "", err
	}
	if dryRun {
		return nil, "would_import", nil // rolled back by the deferred Rollback
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return &id, "imported", nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// CSVColumns are the accepted CSV headers (case-insensitive).
var CSVColumns = []string{"repository", "application", "business_unit", "country", "environment", "criticality", "tags", "scan_branch"}

// importCSV imports repositories described in a CSV upload:
//
//	repository,application,business_unit,country,environment,criticality,tags,scan_branch
//	acme/payments-api,Payments,Finance,DE,production,high,Team:Payments;Data:PCI,main
//
// Names are resolved case-insensitively; country is an ISO alpha-2 code;
// tags are "Category:Tag" pairs separated by semicolons.
func (s *Service) importCSV(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	connID, err := uuid.Parse(r.URL.Query().Get("scm_connection_id"))
	if err != nil {
		s.fail(w, r, httpx.BadRequest("scm_connection_id query parameter is required"))
		return
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/csv") && !strings.HasPrefix(ct, "text/plain") {
		s.fail(w, r, httpx.E(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be text/csv"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		s.fail(w, r, httpx.BadRequest("CSV must be at most 2 MB"))
		return
	}
	cr := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(body), "\ufeff")))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	records, err := cr.ReadAll()
	if err != nil {
		s.fail(w, r, httpx.BadRequest("invalid CSV: "+err.Error()))
		return
	}
	if len(records) < 2 {
		s.fail(w, r, httpx.BadRequest("CSV needs a header row and at least one repository"))
		return
	}
	col := map[string]int{}
	for i, h := range records[0] {
		h = strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains(CSVColumns, h) {
			s.fail(w, r, httpx.BadRequest(fmt.Sprintf("unknown column %q (allowed: %s)", h, strings.Join(CSVColumns, ", "))))
			return
		}
		col[h] = i
	}
	if _, ok := col["repository"]; !ok {
		s.fail(w, r, httpx.BadRequest("a repository column is required"))
		return
	}
	lk, err := s.loadLookups(ctx, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req := importRequest{ConnectionID: connID, DryRun: r.URL.Query().Get("dry_run") == "true"}
	var lines []int
	var rowErrors []ImportResult
	for n, rec := range records[1:] {
		line := n + 2
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		repo := get("repository")
		if repo == "" {
			continue
		}
		item, err := lk.resolve(get)
		if err != nil {
			rowErrors = append(rowErrors, ImportResult{Line: line, FullName: repo, Status: "error", Error: err.Error()})
			continue
		}
		item.FullName = repo
		req.Repositories = append(req.Repositories, item)
		lines = append(lines, line)
	}
	results, imported := rowErrors, 0
	if len(req.Repositories) > 0 {
		res, n, err := s.doImport(ctx, req, lines)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		results, imported = append(results, res...), n
	}
	if results == nil {
		results = []ImportResult{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": results, "imported": imported, "dry_run": req.DryRun})
}

type lookups struct {
	apps, bus, countries map[string]uuid.UUID
	tags                 map[string]uuid.UUID // "category:tag" lower-case
}

func (s *Service) loadLookups(ctx context.Context, orgID uuid.UUID) (*lookups, error) {
	lk := &lookups{apps: map[string]uuid.UUID{}, bus: map[string]uuid.UUID{}, countries: map[string]uuid.UUID{}, tags: map[string]uuid.UUID{}}
	load := func(sql string, into map[string]uuid.UUID) error {
		rows, err := s.DB.Query(ctx, sql, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var id uuid.UUID
			if err := rows.Scan(&k, &id); err != nil {
				return err
			}
			into[strings.ToLower(k)] = id
		}
		return rows.Err()
	}
	for sql, m := range map[string]map[string]uuid.UUID{
		`SELECT name, id FROM applications WHERE organization_id = $1 AND archived_at IS NULL`:                                           lk.apps,
		`SELECT name, id FROM business_units WHERE organization_id = $1 AND archived_at IS NULL`:                                         lk.bus,
		`SELECT code, id FROM countries WHERE organization_id = $1`:                                                                      lk.countries,
		`SELECT tc.name || ':' || t.name, t.id FROM tags t JOIN tag_categories tc ON tc.id = t.category_id WHERE t.organization_id = $1`: lk.tags,
	} {
		if err := load(sql, m); err != nil {
			return nil, err
		}
	}
	return lk, nil
}

func (lk *lookups) resolve(get func(string) string) (ImportItem, error) {
	var item ImportItem
	find := func(m map[string]uuid.UUID, v, what string) (*uuid.UUID, error) {
		if v == "" {
			return nil, nil
		}
		id, ok := m[strings.ToLower(v)]
		if !ok {
			return nil, fmt.Errorf("unknown %s %q", what, v)
		}
		return &id, nil
	}
	var err error
	if item.ApplicationID, err = find(lk.apps, get("application"), "application"); err != nil {
		return item, err
	}
	if item.BusinessUnitID, err = find(lk.bus, get("business_unit"), "business unit"); err != nil {
		return item, err
	}
	if item.CountryID, err = find(lk.countries, get("country"), "country code"); err != nil {
		return item, err
	}
	item.Environment = strings.ToLower(get("environment"))
	item.Criticality = strings.ToLower(get("criticality"))
	item.ScanBranch = get("scan_branch")
	if t := get("tags"); t != "" {
		item.TagIDs = []uuid.UUID{}
		for _, pair := range strings.Split(t, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			cat, tag, ok := strings.Cut(pair, ":")
			if !ok {
				return item, fmt.Errorf("tag %q must be Category:Tag", pair)
			}
			id, ok := lk.tags[strings.ToLower(strings.TrimSpace(cat)+":"+strings.TrimSpace(tag))]
			if !ok {
				return item, fmt.Errorf("unknown tag %q", pair)
			}
			item.TagIDs = append(item.TagIDs, id)
		}
	}
	return item, nil
}
