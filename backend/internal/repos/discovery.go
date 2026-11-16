package repos

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// discoveryClient authorizes a discovery call (importers need repos.manage
// somewhere; placement is authorized at import) and builds the client.
func (s *Service) discoveryClient(w http.ResponseWriter, r *http.Request) (*authz.Principal, Connection, scm.FullClient, bool) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !canDiscover(p) {
		s.fail(w, r, authz.ErrForbidden)
		return nil, Connection{}, nil, false
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return nil, Connection{}, nil, false
	}
	c, err := s.getConn(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return nil, Connection{}, nil, false
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		s.fail(w, r, err)
		return nil, Connection{}, nil, false
	}
	return p, c, cl, true
}

func queryParam(r *http.Request, name string, max int) (string, error) {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if len(v) > max {
		return "", httpx.BadRequest(name + " is too long")
	}
	return v, nil
}

func (s *Service) remoteOrganizations(w http.ResponseWriter, r *http.Request) {
	_, _, cl, ok := s.discoveryClient(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	orgs, err := cl.ListOrganizations(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if orgs == nil {
		orgs = []scm.Organization{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": orgs})
}

func (s *Service) remoteProjects(w http.ResponseWriter, r *http.Request) {
	_, _, cl, ok := s.discoveryClient(w, r)
	if !ok {
		return
	}
	org, err := queryParam(r, "organization", 200)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	projects, err := cl.ListProjects(ctx, org)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if projects == nil {
		projects = []scm.Project{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": projects})
}

func (s *Service) remoteRepositories(w http.ResponseWriter, r *http.Request) {
	p, c, cl, ok := s.discoveryClient(w, r)
	if !ok {
		return
	}
	var q scm.RepoQuery
	var err error
	for _, f := range []struct {
		name string
		dst  *string
		max  int
	}{{"organization", &q.Organization, 200}, {"project", &q.Project, 200}, {"q", &q.Search, 100}, {"page_token", &q.PageToken, 4000}} {
		if *f.dst, err = queryParam(r, f.name, f.max); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	q.PageSize = 50
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	page, err := cl.ListRepositoriesPage(ctx, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	imported, err := s.importedIDs(r.Context(), p.OrganizationID, c.ID, page.Items)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]DiscoveredRepo, 0, len(page.Items))
	for _, rr := range page.Items {
		d := DiscoveredRepo{RemoteRepo: rr}
		if id, ok := imported[rr.ExternalID]; ok {
			d.ImportedID = &id
		}
		items = append(items, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_page_token": page.NextPageToken})
}

// importedIDs maps external IDs of a page to imported repository IDs.
func (s *Service) importedIDs(ctx context.Context, orgID, connID uuid.UUID, page []scm.RemoteRepo) (map[string]uuid.UUID, error) {
	ext := make([]string, 0, len(page))
	for _, rr := range page {
		ext = append(ext, rr.ExternalID)
	}
	rows, err := s.DB.Query(ctx, `SELECT external_id, id FROM repositories
		WHERE organization_id = $1 AND scm_connection_id = $2 AND external_id = ANY($3)`, orgID, connID, ext)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]uuid.UUID{}
	for rows.Next() {
		var e string
		var id uuid.UUID
		if err := rows.Scan(&e, &id); err != nil {
			return nil, err
		}
		out[e] = id
	}
	return out, rows.Err()
}

// repoRefFrom reads a repository reference from query parameters.
func repoRefFrom(r *http.Request) (scm.RepoRef, error) {
	var ref scm.RepoRef
	var err error
	for _, f := range []struct {
		name string
		dst  *string
	}{{"external_id", &ref.ExternalID}, {"full_name", &ref.FullName}, {"organization", &ref.Organization}, {"project", &ref.Project}} {
		if *f.dst, err = queryParam(r, f.name, 300); err != nil {
			return ref, err
		}
	}
	if ref.ExternalID == "" && ref.FullName == "" {
		return ref, httpx.BadRequest("external_id or full_name is required")
	}
	return ref, nil
}

// repoDetails composes the import preview.
func repoDetails(ctx context.Context, cl scm.FullClient, ref scm.RepoRef) (scm.RepoDetails, error) {
	var d scm.RepoDetails
	rr, err := cl.GetRepository(ctx, ref)
	if err != nil {
		return d, err
	}
	d.Repository = rr
	ref = rr.Ref()
	if d.Branches, err = cl.ListBranchHeads(ctx, ref); err != nil {
		return d, err
	}
	for i := range d.Branches {
		d.Branches[i].Default = d.Branches[i].Name == rr.DefaultBranch
	}
	if rr.DefaultBranch != "" {
		if c, err := cl.LatestCommit(ctx, ref, ""); err == nil {
			d.LatestCommit = &c
		}
	}
	if langs, err := cl.Languages(ctx, ref); err == nil {
		d.Languages = langs
	}
	if d.Languages == nil {
		d.Languages = map[string]int64{}
	}
	if d.Branches == nil {
		d.Branches = []scm.Branch{}
	}
	d.Permission = "read" // GetRepository succeeded with this credential
	return d, nil
}

func (s *Service) remoteRepositoryDetails(w http.ResponseWriter, r *http.Request) {
	p, c, cl, ok := s.discoveryClient(w, r)
	if !ok {
		return
	}
	ref, err := repoRefFrom(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	d, err := repoDetails(ctx, cl, ref)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	imported, _ := s.importedIDs(r.Context(), p.OrganizationID, c.ID, []scm.RemoteRepo{d.Repository})
	out := map[string]any{"repository": DiscoveredRepo{RemoteRepo: d.Repository}, "branches": d.Branches,
		"latest_commit": d.LatestCommit, "languages": d.Languages, "permission": d.Permission}
	if id, ok := imported[d.Repository.ExternalID]; ok {
		out["repository"] = DiscoveredRepo{RemoteRepo: d.Repository, ImportedID: &id}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// canDiscover: browsing a connection shows every repository its credential
// can see, so it needs repos.manage at business-unit, region or
// organization scope (not only on individual repositories).
func canDiscover(p *authz.Principal) bool {
	for _, g := range p.Grants {
		if g.Permission == authz.PermReposManage && g.Scope.Type != authz.ScopeRepository {
			return true
		}
	}
	return false
}
