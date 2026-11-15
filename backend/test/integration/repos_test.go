//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/repos"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

type fakeSCM struct{ repos []scm.RemoteRepo }

func (f *fakeSCM) Check(context.Context) (string, error) { return "fake ok", nil }
func (f *fakeSCM) ListRepositories(context.Context) ([]scm.RemoteRepo, error) {
	return f.repos, nil
}
func (f *fakeSCM) ListBranches(context.Context, scm.RemoteRepo) ([]string, error) {
	return []string{"main", "release"}, nil
}

type harness struct {
	t      *testing.T
	mux    *http.ServeMux
	events []scm.WebhookEvent
}

func newHarness(t *testing.T) *harness {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kr, _ := crypto.NewKeyring(map[int][]byte{1: key})
	h := &harness{t: t, mux: http.NewServeMux()}
	fake := &fakeSCM{repos: []scm.RemoteRepo{
		{ExternalID: "101", FullName: "acme/payments-api", Name: "payments-api", URL: "https://github.com/acme/payments-api", DefaultBranch: "main", Visibility: "private", Language: "Go"},
		{ExternalID: "102", FullName: "acme/hr-portal", Name: "hr-portal", URL: "https://github.com/acme/hr-portal", DefaultBranch: "main", Visibility: "internal"},
		{ExternalID: "103", FullName: "acme/website", Name: "website", URL: "https://github.com/acme/website", DefaultBranch: "master", Visibility: "public"},
	}}
	svc := &repos.Service{
		DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}},
		Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom, PublicURL: "https://pathos.test",
		NewClient: func(scm.Config) (scm.Client, error) { return fake, nil },
		OnEvent: func(_ context.Context, _, _ uuid.UUID, ev scm.WebhookEvent) { h.events = append(h.events, ev) },
	}
	svc.Register(h.mux)
	svc.RegisterPublic(h.mux)
	return h
}

// do calls the API as p (nil = unauthenticated) and decodes JSON.
func (h *harness) do(p *authz.Principal, method, path string, body any, headers ...string) (int, map[string]any) {
	h.t.Helper()
	var rd *bytes.Reader
	ct := "application/json"
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd, ct = bytes.NewReader([]byte(b)), "text/csv"
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", ct)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if p != nil {
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func scoped(role string, s authz.Scope) *authz.Principal {
	r, _ := authz.LookupSystemRole(role)
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: orgID, Email: role + "@acme.test"}
	for _, perm := range r.Permissions {
		p.Grants = append(p.Grants, authz.Grant{Permission: perm, Scope: s})
	}
	return p
}

func id(m map[string]any, keys ...string) string {
	var cur any = m
	for _, k := range keys {
		cur = cur.(map[string]any)[k]
	}
	return cur.(string)
}

func TestRepositoryLifecycle(t *testing.T) {
	h := newHarness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	sfx := uuid.NewString()[:6]

	// Taxonomy: mandatory single-value "Team", optional single-value "Data".
	code, team := h.do(admin, "POST", "/api/v1/tag-categories", map[string]any{"name": "Team" + sfx, "is_mandatory": true, "allow_multiple": false})
	if code != 201 {
		t.Fatalf("create category: %d %v", code, team)
	}
	_, payTag := h.do(admin, "POST", "/api/v1/tag-categories/"+id(team, "id")+"/tags", map[string]any{"name": "Payments", "color": "blue"})
	_, platTag := h.do(admin, "POST", "/api/v1/tag-categories/"+id(team, "id")+"/tags", map[string]any{"name": "Platform"})
	_, data := h.do(admin, "POST", "/api/v1/tag-categories", map[string]any{"name": "Data" + sfx, "allow_multiple": false})
	_, pci := h.do(admin, "POST", "/api/v1/tag-categories/"+id(data, "id")+"/tags", map[string]any{"name": "PCI", "color": "red"})
	_, pii := h.do(admin, "POST", "/api/v1/tag-categories/"+id(data, "id")+"/tags", map[string]any{"name": "PII"})
	if code, _ := h.do(admin, "POST", "/api/v1/tag-categories/"+id(team, "id")+"/tags", map[string]any{"name": "x", "color": "neon"}); code != 400 {
		t.Errorf("invalid colour should be rejected, got %d", code)
	}

	// Business units.
	finance, hr := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for bid, name := range map[uuid.UUID]string{finance: "Finance" + sfx, hr: "HR" + sfx} {
		if _, err := appPool.Exec(t.Context(), `INSERT INTO business_units (id, organization_id, name) VALUES ($1, $2, $3)`, bid, orgID, name); err != nil {
			t.Fatal(err)
		}
	}

	// Connection (credentials must never be echoed back).
	code, conn := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{
		"name": "GitHub " + sfx, "provider": "github", "auth_type": "pat", "token": "ghp_supersecret", "owner": "acme"})
	if code != 201 || conn["status"] != "ok" {
		t.Fatalf("create connection: %d %v", code, conn)
	}
	if raw, _ := json.Marshal(conn); bytes.Contains(raw, []byte("ghp_supersecret")) {
		t.Fatal("credential leaked in response")
	}
	connID := id(conn, "id")
	if code, _ := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{"name": "bad", "provider": "github_enterprise",
		"base_url": "https://169.254.169.254/api/v3", "auth_type": "pat", "token": "x"}); code != 400 {
		t.Errorf("metadata address must be rejected, got %d", code)
	}
	if code, _ := h.do(scoped("security_manager", authz.Scope{Type: authz.ScopeOrganization, ID: orgID}), "POST", "/api/v1/scm-connections",
		map[string]any{"name": "x", "provider": "github", "auth_type": "pat", "token": "x"}); code != 403 {
		t.Errorf("security_manager lacks scm.manage, got %d", code)
	}

	code, disc := h.do(admin, "GET", "/api/v1/scm-connections/"+connID+"/discover", nil)
	if code != 200 || len(disc["items"].([]any)) != 3 {
		t.Fatalf("discover: %d %v", code, disc)
	}

	// Import: mandatory tag enforced.
	code, res := h.do(admin, "POST", "/api/v1/repositories/import", map[string]any{
		"scm_connection_id": connID, "repositories": []map[string]any{{"external_id": "101"}}})
	r0 := res["results"].([]any)[0].(map[string]any)
	if code != 200 || r0["status"] != "error" || !strings.Contains(r0["error"].(string), "Team"+sfx) {
		t.Fatalf("missing mandatory tag must fail: %d %v", code, res)
	}
	code, res = h.do(admin, "POST", "/api/v1/repositories/import", map[string]any{
		"scm_connection_id": connID,
		"repositories":      []map[string]any{{"external_id": "101", "business_unit_id": finance, "criticality": "critical"}},
		"defaults":          map[string]any{"tag_ids": []string{id(payTag, "id")}},
	})
	r0 = res["results"].([]any)[0].(map[string]any)
	if r0["status"] != "imported" {
		t.Fatalf("import: %v", res)
	}
	repo1 := r0["repository_id"].(string)
	_, res = h.do(admin, "POST", "/api/v1/repositories/import", map[string]any{"scm_connection_id": connID,
		"repositories": []map[string]any{{"external_id": "101", "tag_ids": []string{id(payTag, "id")}}}})
	if res["results"].([]any)[0].(map[string]any)["status"] != "already_imported" {
		t.Errorf("re-import should be idempotent: %v", res)
	}

	// CSV: dry run first, then for real; unknown names reported per line.
	csv := fmt.Sprintf("repository,business_unit,country,environment,tags\nacme/hr-portal,HR%s,DE,staging,Team%s:Platform\nacme/website,Nope,,production,\n", sfx, sfx)
	code, res = h.do(admin, "POST", "/api/v1/repositories/import-csv?dry_run=true&scm_connection_id="+connID, csv)
	if code != 200 || res["imported"].(float64) != 0 {
		t.Fatalf("dry run: %d %v", code, res)
	}
	statuses := map[string]string{}
	for _, x := range res["results"].([]any) {
		m := x.(map[string]any)
		statuses[m["full_name"].(string)] = m["status"].(string)
	}
	if statuses["acme/hr-portal"] != "would_import" || statuses["acme/website"] != "error" {
		t.Fatalf("dry run statuses: %v", statuses)
	}
	_, res = h.do(admin, "POST", "/api/v1/repositories/import-csv?scm_connection_id="+connID, csv)
	if res["imported"].(float64) != 1 {
		t.Fatalf("csv import: %v", res)
	}

	// Scoped visibility: a Finance analyst sees only Finance repositories.
	analyst := scoped("security_analyst", authz.Scope{Type: authz.ScopeBusinessUnit, ID: finance})
	code, list := h.do(analyst, "GET", "/api/v1/repositories?scm_connection_id="+connID, nil)
	items := list["items"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["full_name"] != "acme/payments-api" {
		t.Fatalf("finance analyst list: %d %v", code, list)
	}
	// Region scope: EMEA (Germany) sees the HR repository.
	var emea uuid.UUID
	_ = appPool.QueryRow(t.Context(), `SELECT id FROM regions WHERE organization_id = $1 AND code = 'EMEA'`, orgID).Scan(&emea)
	_, list = h.do(scoped("viewer", authz.Scope{Type: authz.ScopeRegion, ID: emea}), "GET", "/api/v1/repositories?scm_connection_id="+connID, nil)
	if items := list["items"].([]any); len(items) != 1 || items[0].(map[string]any)["full_name"] != "acme/hr-portal" {
		t.Fatalf("EMEA viewer list: %v", list)
	}
	var repo2 string
	_ = appPool.QueryRow(t.Context(), `SELECT id::text FROM repositories WHERE scm_connection_id = $1 AND external_id = '102'`, connID).Scan(&repo2)

	// Analyst cannot modify; Finance AppSec engineer can, but not move to HR
	// or touch HR repositories.
	if code, _ := h.do(analyst, "PATCH", "/api/v1/repositories/"+repo1, map[string]any{"criticality": "low"}); code != 403 {
		t.Errorf("analyst patch: want 403, got %d", code)
	}
	eng := scoped("appsec_engineer", authz.Scope{Type: authz.ScopeBusinessUnit, ID: finance})
	code, upd := h.do(eng, "PATCH", "/api/v1/repositories/"+repo1, map[string]any{"scan_branch": "release", "technologies": []string{"Go", "Docker"}})
	if code != 200 || upd["scan_branch"] != "release" {
		t.Fatalf("engineer patch: %d %v", code, upd)
	}
	if code, _ := h.do(eng, "PATCH", "/api/v1/repositories/"+repo1, map[string]any{"business_unit_id": hr}); code != 403 {
		t.Errorf("moving to a BU without permission: want 403, got %d", code)
	}
	if code, _ := h.do(eng, "GET", "/api/v1/repositories/"+repo2, nil); code != 404 {
		t.Errorf("out-of-scope repository must look missing: want 404, got %d", code)
	}
	if code, _ := h.do(eng, "PATCH", "/api/v1/repositories/"+repo1, map[string]any{"scan_branch": "--upload-pack=evil"}); code != 400 {
		t.Errorf("option-like branch must be rejected, got %d", code)
	}
	if code, _ := h.do(eng, "PATCH", "/api/v1/repositories/"+repo1, map[string]any{"tag_ids": []string{}}); code != 422 {
		t.Errorf("removing the mandatory tag: want 422, got %d", code)
	}
	if code, br := h.do(eng, "GET", "/api/v1/repositories/"+repo1+"/branches", nil); code != 200 || len(br["items"].([]any)) != 2 {
		t.Errorf("branches: %d %v", code, br)
	}

	// Bulk tagging is atomic and enforces single-value categories.
	code, _ = h.do(admin, "POST", "/api/v1/repositories/bulk-tags", map[string]any{
		"repository_ids": []string{repo1, repo2}, "add": []string{id(pci, "id")}})
	if code != 200 {
		t.Fatalf("bulk tag: %d", code)
	}
	if code, _ := h.do(admin, "POST", "/api/v1/repositories/bulk-tags", map[string]any{
		"repository_ids": []string{repo1}, "add": []string{id(pii, "id")}}); code != 400 {
		t.Errorf("two tags in a single-value category: want 400, got %d", code)
	}
	if code, _ := h.do(eng, "POST", "/api/v1/repositories/bulk-tags", map[string]any{
		"repository_ids": []string{repo1, repo2}, "remove": []string{id(pci, "id")}}); code != 403 {
		t.Errorf("bulk tag across scopes: want 403, got %d", code)
	}
	_ = platTag

	// Applications.
	code, app := h.do(eng, "POST", "/api/v1/applications", map[string]any{"name": "Checkout " + sfx, "business_unit_id": finance, "criticality": "high"})
	if code != 201 {
		t.Fatalf("create app: %d %v", code, app)
	}
	if code, _ := h.do(eng, "POST", "/api/v1/applications", map[string]any{"name": "Org-wide " + sfx}); code != 403 {
		t.Errorf("BU engineer creating an org-level app: want 403, got %d", code)
	}
	h.do(eng, "PATCH", "/api/v1/repositories/"+repo1, map[string]any{"application_id": id(app, "id")})
	_, apps := h.do(analyst, "GET", "/api/v1/applications", nil)
	found := false
	for _, a := range apps["items"].([]any) {
		if a.(map[string]any)["id"] == id(app, "id") {
			found = a.(map[string]any)["repository_count"].(float64) == 1
		}
	}
	if !found {
		t.Errorf("analyst should see the Finance application with 1 repository: %v", apps)
	}

	// Webhooks: signature, replay protection, unknown events.
	_, wh := h.do(admin, "POST", "/api/v1/scm-connections/"+connID+"/webhook-secret", nil)
	secret := []byte(wh["webhook_secret"].(string))
	body := []byte(`{"ref":"refs/heads/main","after":"deadbeef","repository":{"id":102}}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	hook := "/api/webhooks/github/" + connID
	if code, _ := h.do(nil, "POST", hook, body, "X-GitHub-Event", "push", "X-GitHub-Delivery", "d-1", "X-Hub-Signature-256", "sha256=00"); code != 401 {
		t.Errorf("bad signature: want 401, got %d", code)
	}
	if code, r := h.do(nil, "POST", hook, body, "X-GitHub-Event", "push", "X-GitHub-Delivery", "d-1", "X-Hub-Signature-256", sig); code != 202 || r["status"] != "received" {
		t.Errorf("valid push: %d %v", code, r)
	}
	if code, r := h.do(nil, "POST", hook, body, "X-GitHub-Event", "push", "X-GitHub-Delivery", "d-1", "X-Hub-Signature-256", sig); code != 200 || r["status"] != "duplicate" {
		t.Errorf("replay: %d %v", code, r)
	}
	if len(h.events) != 1 || h.events[0].CommitSHA != "deadbeef" {
		t.Errorf("OnEvent should fire once: %+v", h.events)
	}
	if code, _ := h.do(nil, "POST", "/api/webhooks/azure-devops/"+connID, body); code != 404 {
		t.Errorf("provider mismatch must 404, got %d", code)
	}

	// Archive, then delete.
	if code, _ := h.do(admin, "DELETE", "/api/v1/repositories/"+repo1, nil); code != 409 {
		t.Errorf("deleting an active repository: want 409, got %d", code)
	}
	h.do(admin, "POST", "/api/v1/repositories/"+repo1+"/archive", nil)
	_, list = h.do(admin, "GET", "/api/v1/repositories?scm_connection_id="+connID, nil)
	if len(list["items"].([]any)) != 1 {
		t.Errorf("archived repositories are hidden by default: %v", list)
	}
	if code, _ := h.do(admin, "DELETE", "/api/v1/repositories/"+repo1, nil); code != 204 {
		t.Errorf("delete archived: want 204, got %d", code)
	}
	if code, _ := h.do(admin, "DELETE", "/api/v1/scm-connections/"+connID, nil); code != 409 {
		t.Errorf("deleting a connection with repositories: want 409, got %d", code)
	}
	code, cats := h.do(admin, "GET", "/api/v1/tag-categories", nil)
	if code != 200 {
		t.Fatal(code)
	}
	for _, c := range cats["items"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "Team"+sfx && m["noncompliant_repositories"].(float64) != 0 {
			t.Errorf("all active repos have a Team tag: %v", m)
		}
	}
}
