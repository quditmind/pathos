//go:build integration

package integration

import (
	"context"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/audit"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/ingest"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/sourcestore"
	"pathos/internal/repos"
	"pathos/internal/scans"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// onboarding is a harness exposing the service, so tests can run the import
// engine inline (ProcessNextImport) instead of a background worker.
type onboarding struct {
	*harness
	svc  *repos.Service
	fake *fakeSCM
}

func newOnboarding(t *testing.T) *onboarding {
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	fake := &fakeSCM{repos: []scm.RemoteRepo{
		{ExternalID: "201", FullName: "corp/billing", Name: "billing", URL: "https://github.com/corp/billing", CloneURL: "https://github.com/corp/billing.git",
			DefaultBranch: "main", Visibility: "private", Language: "Go", Organization: "corp"},
		{ExternalID: "202", FullName: "corp/portal", Name: "portal", URL: "https://github.com/corp/portal", CloneURL: "https://github.com/corp/portal.git",
			DefaultBranch: "main", Visibility: "internal", Organization: "corp"},
		{ExternalID: "203", FullName: "corp/secret", Name: "secret", CloneURL: "https://github.com/corp/secret.git", DefaultBranch: "main", Organization: "corp"},
	}, commits: map[string]string{}, deny: map[string]bool{"203": true}}
	store, err := sourcestore.NewFS(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	lim := repos.DefaultLimits()
	lim.WorkDir = t.TempDir()
	lim.UploadMaxBytes = 64 << 20
	svc := &repos.Service{
		DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}},
		Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom, PublicURL: "https://pathos.test",
		NewClient: func(scm.Config) (scm.FullClient, error) { return fake, nil },
		Sources:   store, Limits: lim,
	}
	h := &harness{t: t, mux: http.NewServeMux()}
	// Events raised here (sync and import failures) must not be delivered
	// by other tests' dispatcher runs.
	t.Cleanup(func() {
		_, _ = appPool.Exec(context.Background(), `UPDATE notification_events SET processed_at = now()
			WHERE processed_at IS NULL AND event_key IN ('repository.sync_failed', 'import.failed')`)
	})
	svc.Register(h.mux)
	svc.RegisterPublic(h.mux)
	return &onboarding{harness: h, svc: svc, fake: fake}
}

// realUser creates an active user with a system role at organization scope
// and returns the principal loaded the same way the API loads it.
func dbUser(t *testing.T, role string, scope ...authz.Scope) *authz.Principal {
	t.Helper()
	ctx := t.Context()
	uid := uuid.Must(uuid.NewV7())
	email := strings.ToLower(role+"-"+uid.String()[24:]) + "@acme.test"
	if _, err := appPool.Exec(ctx, `INSERT INTO users (id, organization_id, email, display_name, status) VALUES ($1, $2, $3, $4, 'active')`,
		uid, orgID, email, role+" user"); err != nil {
		t.Fatal(err)
	}
	if role != "" {
		sc := authz.Scope{Type: authz.ScopeOrganization, ID: orgID}
		if len(scope) > 0 {
			sc = scope[0]
		}
		if _, err := appPool.Exec(ctx, `INSERT INTO role_assignments (id, organization_id, user_id, role_id, scope_type, scope_id)
			SELECT $1, $2, $3, id, $5, $6 FROM roles WHERE key = $4 AND is_system`, uuid.Must(uuid.NewV7()), orgID, uid, role, string(sc.Type), sc.ID); err != nil {
			t.Fatal(err)
		}
	}
	grants, err := identity.LoadGrants(ctx, appPool, uid)
	if err != nil {
		t.Fatal(err)
	}
	return &authz.Principal{UserID: uid, OrganizationID: orgID, Email: email, Grants: grants}
}

// drain processes queued import items inline.
func (o *onboarding) drain(t *testing.T) {
	t.Helper()
	for range 50 {
		ok, err := o.svc.ProcessNextImport(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return
		}
	}
	t.Fatal("import queue did not drain")
}

func (o *onboarding) job(t *testing.T, p *authz.Principal, id string) map[string]any {
	t.Helper()
	code, job := o.do(p, "GET", "/api/v1/repository-imports/"+id, nil)
	if code != 200 {
		t.Fatalf("get import: %d %v", code, job)
	}
	return job
}

func items(job map[string]any) []map[string]any {
	var out []map[string]any
	for _, it := range job["items"].([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

func firstRegion(t *testing.T) string {
	var id uuid.UUID
	if err := appPool.QueryRow(t.Context(), `SELECT id FROM regions WHERE organization_id = $1 ORDER BY code LIMIT 1`, orgID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestOnboardingSCMImport(t *testing.T) {
	o := newOnboarding(t)
	ctx := t.Context()
	admin := dbUser(t, authz.RoleSuperAdmin)
	bizOwner, techOwner := dbUser(t, "viewer"), dbUser(t, "viewer")
	sfx := uuid.NewString()[:6]
	bu := uuid.Must(uuid.NewV7())
	dept := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, name) VALUES ($1, $2, $3)`, bu, orgID, "Treasury"+sfx); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, name, parent_id) VALUES ($1, $2, $3, $4)`, dept, orgID, "Payments ops"+sfx, bu); err != nil {
		t.Fatal(err)
	}
	region := firstRegion(t)

	code, conn := o.do(admin, "POST", "/api/v1/scm-connections", map[string]any{
		"name": "GH onboarding " + sfx, "provider": "github", "auth_type": "pat", "token": "ghp_x"})
	if code != 201 {
		t.Fatalf("connection: %d %v", code, conn)
	}
	connID := id(conn, "id")

	// Settings and catalogs.
	code, settings := o.do(admin, "GET", "/api/v1/asset-settings", nil)
	if code != 200 || len(settings["classifications"].(map[string]any)["data_classification"].([]any)) < 4 {
		t.Fatalf("asset settings: %d %v", code, settings)
	}
	if code, _ := o.do(scoped("security_analyst", authz.Scope{Type: authz.ScopeOrganization, ID: orgID}), "PATCH", "/api/v1/asset-settings",
		map[string]any{"scan_on_import": true}); code != 403 {
		t.Errorf("analyst must not configure assets: %d", code)
	}
	code, cls := o.do(admin, "POST", "/api/v1/asset-classifications", map[string]any{"kind": "compliance", "key": "dora" + strings.ReplaceAll(sfx, "-", ""), "label": "DORA"})
	if code != 201 {
		t.Fatalf("create classification: %d %v", code, cls)
	}
	if code, _ := o.do(admin, "POST", "/api/v1/asset-classifications", map[string]any{"kind": "criticality", "key": "extreme", "label": "Extreme"}); code != 400 {
		t.Errorf("criticality levels are fixed: %d", code)
	}

	// Tags with description and hex colour (tags.manage).
	_, cat := o.do(admin, "POST", "/api/v1/tag-categories", map[string]any{"name": "Scope" + sfx})
	code, tag := o.do(admin, "POST", "/api/v1/tag-categories/"+id(cat, "id")+"/tags", map[string]any{"name": "Customer-facing", "color": "#1F6FEB", "description": "Used by customers"})
	if code != 201 || tag["color"] != "#1f6feb" {
		t.Fatalf("tag: %d %v", code, tag)
	}
	if code, _ := o.do(scoped("repository_contributor", authz.Scope{Type: authz.ScopeOrganization, ID: orgID}), "POST",
		"/api/v1/tag-categories/"+id(cat, "id")+"/tags", map[string]any{"name": "nope"}); code != 403 {
		t.Errorf("contributors lack tags.manage: %d", code)
	}

	// Validation: required fields are reported per field.
	req := map[string]any{"source": "git", "scm_connection_id": connID, "idempotency_key": "k-" + uuid.NewString(),
		"metadata": map[string]any{"criticality": "high"}, "items": []any{map[string]any{"ref": map[string]any{"external_id": "201", "full_name": "corp/billing"}}}}
	code, val := o.do(admin, "POST", "/api/v1/repository-imports/validate", req)
	fields, _ := val["fields"].(map[string]any)
	if code != 200 || val["valid"] != false || fields["business_owner_id"] != "required" || fields["business_region_id"] != "required" {
		t.Fatalf("validation: %d %v", code, val)
	}
	if code, _ := o.do(admin, "POST", "/api/v1/repository-imports", req); code != 422 {
		t.Errorf("incomplete metadata must be rejected: %d", code)
	}
	if code, res := o.do(admin, "POST", "/api/v1/repository-imports", map[string]any{"source": "devops", "scm_connection_id": connID,
		"idempotency_key": "k-" + uuid.NewString(), "metadata": map[string]any{}, "items": []any{}}); code != 400 {
		t.Errorf("a GitHub connection is not a DevOps source: %d %v", code, res)
	}

	md := map[string]any{
		"description": "Billing platform", "application_type": "backend_service", "business_purpose": "Invoices",
		"business_owner_id": bizOwner.UserID, "technical_owner_id": techOwner.UserID,
		"business_unit_id": bu, "department_id": dept, "business_region_id": region, "hosting_region": "europe",
		"data_residency_region_id": region, "criticality": "critical", "data_classification": "confidential", "environment": "production",
		"internet_exposure": "public", "compliance_scopes": []string{"pci_dss", "gdpr"}, "tag_ids": []string{id(tag, "id")},
		"color": "#CF222E", "lifecycle_status": "active", "go_live_date": "2024-01-15",
		"new_application": map[string]any{"name": "Billing " + sfx, "external_ref": "APP-" + sfx},
	}
	key := "k-" + uuid.NewString()
	req = map[string]any{"source": "git", "scm_connection_id": connID, "idempotency_key": key, "metadata": md, "start_scan": true,
		"items": []any{
			map[string]any{"ref": map[string]any{"external_id": "201", "full_name": "corp/billing"}, "asset_name": "Billing API " + sfx},
			map[string]any{"ref": map[string]any{"external_id": "202", "full_name": "corp/portal"}, "branch": "release", "full_history": true},
			map[string]any{"ref": map[string]any{"external_id": "999", "full_name": "corp/gone"}},
			map[string]any{"ref": map[string]any{"external_id": "203", "full_name": "corp/secret"}},
		}}
	code, val = o.do(admin, "POST", "/api/v1/repository-imports/validate", req)
	if code != 200 || val["valid"] != true {
		t.Fatalf("validate full request: %d %v", code, val)
	}
	if code, _ := o.do(scoped("security_analyst", authz.Scope{Type: authz.ScopeOrganization, ID: orgID}), "POST", "/api/v1/repository-imports", req); code != 403 {
		t.Errorf("analyst must not import: %d", code)
	}
	code, job := o.do(admin, "POST", "/api/v1/repository-imports", req)
	if code != 202 || job["status"] != "queued" || job["total_items"].(float64) != 4 {
		t.Fatalf("create import: %d %v", code, job)
	}
	jobID := id(job, "id")
	// Idempotent resubmission returns the same job.
	if code, again := o.do(admin, "POST", "/api/v1/repository-imports", req); code != 200 || again["id"] != jobID {
		t.Errorf("idempotency: %d %v", code, again)
	}
	// Another user cannot see someone else's job without org-wide rights.
	contrib := dbUser(t, "repository_contributor", authz.Scope{Type: authz.ScopeBusinessUnit, ID: bu})
	if code, _ := o.do(contrib, "GET", "/api/v1/repository-imports/"+jobID, nil); code != 404 {
		t.Errorf("job visible to another user: %d", code)
	}

	o.drain(t)
	job = o.job(t, admin, jobID)
	byName := map[string]map[string]any{}
	for _, it := range items(job) {
		byName[it["display_name"].(string)] = it
	}
	if job["status"] != "failed" || job["completed_items"].(float64) != 2 || job["failed_items"].(float64) != 2 {
		t.Fatalf("job outcome: %v", job)
	}
	if byName["corp/gone"]["error_code"] != "repository_not_found" || byName["corp/secret"]["error_code"] != "permission_denied" {
		t.Errorf("failure codes: %v", byName)
	}
	if byName["corp/billing"]["result"] != "imported" || byName["corp/billing"]["progress"].(float64) != 100 {
		t.Errorf("billing item: %v", byName["corp/billing"])
	}

	// Metadata persisted and resolved.
	repoID := byName["corp/billing"]["repository_id"].(string)
	code, repo := o.do(admin, "GET", "/api/v1/repositories/"+repoID, nil)
	if code != 200 {
		t.Fatalf("get repo: %d %v", code, repo)
	}
	checks := map[string]any{
		"asset_name": "Billing API " + sfx, "display_name": "corp/billing", "criticality": "critical", "data_classification": "confidential",
		"hosting_region": "europe", "internet_exposure": "public", "color": "#cf222e", "lifecycle_status": "active", "go_live_date": "2024-01-15",
		"application_type": "backend_service", "sync_status": "ok", "latest_commit_sha": "1111111111111111111111111111111111111111", "source_type": "scm",
		"scm_organization": "corp", "can_manage": true,
	}
	for k, want := range checks {
		if repo[k] != want {
			t.Errorf("%s = %v, want %v", k, repo[k], want)
		}
	}
	if id(repo, "business_owner", "id") != bizOwner.UserID.String() || id(repo, "department", "id") != dept.String() ||
		id(repo, "business_region", "id") != region || repo["application"] == nil {
		t.Errorf("references not persisted: %v", repo)
	}
	if sc := repo["compliance_scopes"].([]any); len(sc) != 2 {
		t.Errorf("compliance scopes: %v", sc)
	}
	_, portal := o.do(admin, "GET", "/api/v1/repositories/"+byName["corp/portal"]["repository_id"].(string), nil)
	if portal["scan_branch"] != "release" || portal["full_history"] != true {
		t.Errorf("branch / full history: %v", portal)
	}
	if _, runs := o.do(admin, "GET", "/api/v1/repositories/"+repoID+"/sync-runs", nil); len(runs["items"].([]any)) != 1 {
		t.Errorf("import sync run: %v", runs)
	}
	var audited int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'repository.import' AND target_id = $1`, repoID).Scan(&audited)
	if audited != 1 {
		t.Errorf("repository.import audit entries: %d", audited)
	}

	// Retry a failed item after access is granted.
	delete(o.fake.deny, "203")
	code, job = o.do(admin, "POST", "/api/v1/repository-imports/"+jobID+"/retry", map[string]any{"item_ids": []string{byName["corp/secret"]["id"].(string)}})
	if code != 200 || job["status"] != "queued" {
		t.Fatalf("retry: %d %v", code, job)
	}
	o.drain(t)
	job = o.job(t, admin, jobID)
	if job["failed_items"].(float64) != 1 || job["completed_items"].(float64) != 3 {
		t.Errorf("after retry: %v", job)
	}

	// Duplicate import of the same repository is idempotent.
	req["idempotency_key"] = "k-" + uuid.NewString()
	req["items"] = []any{map[string]any{"ref": map[string]any{"external_id": "201", "full_name": "corp/billing"}}}
	req["metadata"].(map[string]any)["new_application"] = nil
	req["metadata"].(map[string]any)["application_id"] = id(repo, "application", "id")
	code, val = o.do(admin, "POST", "/api/v1/repository-imports/validate", req)
	if code != 200 || len(val["items"].([]any)) != 1 || val["items"].([]any)[0].(map[string]any)["code"] != "already_imported" || val["valid"] != true {
		t.Errorf("duplicate validation: %v", val)
	}
	_, job = o.do(admin, "POST", "/api/v1/repository-imports", req)
	o.drain(t)
	if it := items(o.job(t, admin, id(job, "id")))[0]; it["result"] != "already_imported" || it["status"] != "completed" {
		t.Errorf("re-import: %v", it)
	}

	// Cancel before processing.
	req["idempotency_key"] = "k-" + uuid.NewString()
	req["items"] = []any{map[string]any{"ref": map[string]any{"external_id": "999", "full_name": "x/y"}}}
	_, job = o.do(admin, "POST", "/api/v1/repository-imports", req)
	code, job = o.do(admin, "POST", "/api/v1/repository-imports/"+id(job, "id")+"/cancel", nil)
	if code != 200 || job["status"] != "cancelled" || items(job)[0]["status"] != "cancelled" {
		t.Errorf("cancel: %d %v", code, job)
	}

	// Asset owners edit descriptive metadata but not placement.
	if code, res := o.do(techOwner, "PATCH", "/api/v1/repositories/"+repoID, map[string]any{"description": "Edited by owner", "lifecycle_status": "maintenance"}); code != 200 ||
		res["description"] != "Edited by owner" || res["can_manage"] != false || res["can_edit"] != true {
		t.Errorf("owner edit: %d %v", code, res)
	}
	if code, _ := o.do(techOwner, "PATCH", "/api/v1/repositories/"+repoID, map[string]any{"business_unit_id": nil}); code != 403 {
		t.Errorf("owner must not move placement: %d", code)
	}
	if code, res := o.do(admin, "PATCH", "/api/v1/repositories/"+repoID, map[string]any{"business_owner_id": nil}); code != 422 {
		t.Errorf("required business owner cannot be cleared: %d %v", code, res)
	}
	if code, res := o.do(admin, "PATCH", "/api/v1/repositories/"+repoID, map[string]any{"data_classification": "top_secret"}); code != 422 {
		t.Errorf("unknown classification: %d %v", code, res)
	}
	var diff json.RawMessage
	_ = appPool.QueryRow(ctx, `SELECT metadata FROM audit_logs WHERE action = 'repository.update_as_owner' AND target_id = $1`, repoID).Scan(&diff)
	if !bytes.Contains(diff, []byte(`"old": "Billing platform"`)) {
		t.Errorf("owner change not audited with old/new values: %s", diff)
	}

	// List filters and insights.
	_, list := o.do(admin, "GET", "/api/v1/repositories?data_classification=confidential&business_owner_id="+bizOwner.UserID.String()+"&sort=-criticality", nil)
	if n := len(list["items"].([]any)); n != 3 {
		t.Errorf("filtered list: %d %v", n, list)
	}
	if code, res := o.do(admin, "GET", "/api/v1/repositories?sort=bogus", nil); code != 400 {
		t.Errorf("bad sort: %d %v", code, res)
	}
	code, ins := o.do(admin, "GET", "/api/v1/repositories/insights?business_unit_id="+bu.String(), nil)
	tot := ins["totals"].(map[string]any)
	if code != 200 || tot["critical"].(float64) != 3 || tot["confidential_or_restricted"].(float64) != 3 || len(ins["by_compliance"].([]any)) != 2 {
		t.Errorf("insights: %d %v", code, ins)
	}

	// Synchronization: a new head commit, then the repository disappears.
	o.fake.commits["201"] = "2222222222222222222222222222222222222222"
	code, res := o.do(admin, "POST", "/api/v1/repositories/"+repoID+"/sync", nil)
	if code != 200 || res["run"].(map[string]any)["changed"] != true || res["repository"].(map[string]any)["latest_commit_sha"] != "2222222222222222222222222222222222222222" {
		t.Errorf("sync: %d %v", code, res)
	}
	o.fake.repos = o.fake.repos[1:]
	_, res = o.do(admin, "POST", "/api/v1/repositories/"+repoID+"/sync", nil)
	if res["repository"].(map[string]any)["sync_status"] != "missing" {
		t.Errorf("deleted repository not detected: %v", res)
	}
	var notified int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'repository.sync_failed' AND repository_id = $1`, repoID).Scan(&notified)
	if notified != 1 {
		t.Errorf("sync failure notification: %d", notified)
	}
	if notified := countEvents(t, "import.failed", jobID); notified < 1 {
		t.Errorf("import failure notification missing")
	}
	_ = audit.Denied
}

func countEvents(t *testing.T, key, subject string) int {
	var n int
	_ = appPool.QueryRow(t.Context(), `SELECT count(*) FROM notification_events WHERE event_key = $1 AND subject_id = $2::uuid`, key, subject).Scan(&n)
	return n
}

func zipOf(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// upload sends an archive through the chunked upload API.
func (o *onboarding) upload(t *testing.T, p *authz.Principal, name string, data []byte) string {
	t.Helper()
	code, up := o.do(p, "POST", "/api/v1/source-uploads", map[string]any{"filename": name, "size": len(data), "sha256": hexSum(data)})
	if code != 201 {
		t.Fatalf("create upload: %d %v", code, up)
	}
	uid := id(up, "id")
	chunk := int(up["chunk_size"].(float64))
	for n := 0; n*chunk < len(data); n++ {
		part := data[n*chunk : min(len(data), (n+1)*chunk)]
		if code, res := o.do(p, "PUT", fmt.Sprintf("/api/v1/source-uploads/%s/parts/%d", uid, n), part,
			"Content-Type", "application/octet-stream", "X-Content-SHA256", hexSum(part)); code != 200 {
			t.Fatalf("part %d: %d %v", n, code, res)
		}
	}
	if code, res := o.do(p, "POST", "/api/v1/source-uploads/"+uid+"/complete", nil); code != 200 || res["status"] != "complete" {
		t.Fatalf("complete: %d %v", code, res)
	}
	return uid
}

func TestOnboardingUpload(t *testing.T) {
	o := newOnboarding(t)
	ctx := t.Context()
	admin := dbUser(t, authz.RoleSuperAdmin)
	owner := dbUser(t, "viewer")
	bu := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, name) VALUES ($1, $2, $3)`, bu, orgID, "Uploads "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	md := map[string]any{"business_owner_id": owner.UserID, "technical_owner_id": owner.UserID, "business_unit_id": bu,
		"business_region_id": firstRegion(t), "criticality": "medium", "data_classification": "internal", "environment": "development"}

	archive := zipOf(t, map[string]string{"app-main/go.mod": "module x\n", "app-main/main.go": "package main\nfunc main() {}\n",
		"app-main/web/index.ts": "export const a = 1\n"})

	// Part integrity: a corrupted part is refused.
	code, up := o.do(admin, "POST", "/api/v1/source-uploads", map[string]any{"filename": "bad.zip", "size": len(archive), "sha256": hexSum(archive)})
	if code != 201 {
		t.Fatalf("create upload: %d %v", code, up)
	}
	if code, _ := o.do(admin, "PUT", "/api/v1/source-uploads/"+id(up, "id")+"/parts/0", archive, "Content-Type", "application/octet-stream",
		"X-Content-SHA256", strings.Repeat("0", 64)); code != 422 {
		t.Errorf("corrupted part accepted: %d", code)
	}
	if code, _ := o.do(admin, "POST", "/api/v1/source-uploads/"+id(up, "id")+"/complete", nil); code != 409 {
		t.Errorf("incomplete upload completed: %d", code)
	}
	if code, _ := o.do(admin, "POST", "/api/v1/source-uploads", map[string]any{"filename": "x.exe", "size": 10, "sha256": strings.Repeat("a", 64)}); code != 400 {
		t.Errorf("non-archive accepted: %d", code)
	}
	other := dbUser(t, authz.RoleSuperAdmin)
	if code, _ := o.do(other, "GET", "/api/v1/source-uploads/"+id(up, "id"), nil); code != 404 {
		t.Errorf("uploads are private to their uploader: %d", code)
	}

	uid := o.upload(t, admin, "app-main.zip", archive)
	code, job := o.do(admin, "POST", "/api/v1/repository-imports", map[string]any{"source": "upload", "idempotency_key": "u-" + uuid.NewString(),
		"metadata": md, "items": []any{map[string]any{"upload_id": uid}}})
	if code != 202 {
		t.Fatalf("upload import: %d %v", code, job)
	}
	o.drain(t)
	it := items(o.job(t, admin, id(job, "id")))[0]
	if it["status"] != "completed" || it["snapshot_id"] == nil {
		t.Fatalf("upload item: %v", it)
	}
	repoID := it["repository_id"].(string)
	_, repo := o.do(admin, "GET", "/api/v1/repositories/"+repoID, nil)
	snap, _ := repo["current_snapshot"].(map[string]any)
	if repo["source_type"] != "upload" || repo["provider"] != "upload" || repo["scm_connection_id"] != nil || snap == nil ||
		snap["file_count"].(float64) != 3 || snap["malware_scan"] != "not_configured" || repo["display_name"] != "app-main" {
		t.Fatalf("uploaded repository: %v", repo)
	}

	// The worker-facing stream matches the recorded SHA-256 and extracts.
	rc, sum, _, err := o.svc.OpenSnapshot(ctx, orgID, uuid.MustParse(snap["id"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	dst := t.TempDir()
	if err := ingest.ExtractSnapshot(ctx, io.TeeReader(rc, h), dst, ingest.Limits{}); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if hex.EncodeToString(h.Sum(nil)) != sum {
		t.Error("snapshot SHA-256 mismatch")
	}
	if b, err := os.ReadFile(filepath.Join(dst, "main.go")); err != nil || !strings.Contains(string(b), "package main") {
		t.Errorf("top-level directory not stripped or content wrong: %v", err)
	}

	// Scans of uploaded repositories reference the snapshot.
	if _, err := scans.Enqueue(ctx, appPool, orgID, uuid.MustParse(repoID), "manual", "", "", &admin.UserID); err == nil {
		var ref string
		var snapID *uuid.UUID
		_ = appPool.QueryRow(ctx, `SELECT ref, snapshot_id FROM scan_jobs WHERE repository_id = $1 ORDER BY queued_at DESC LIMIT 1`, repoID).Scan(&ref, &snapID)
		if ref != "snapshot" || snapID == nil || snapID.String() != snap["id"] {
			t.Errorf("scan job source: %s %v", ref, snapID)
		}
		_, _ = appPool.Exec(ctx, `DELETE FROM scan_jobs WHERE repository_id = $1`, repoID)
	} else {
		t.Logf("scan enqueue skipped: %v", err)
	}

	// The same archive again is a duplicate unless explicitly allowed.
	uid2 := o.upload(t, admin, "app-main.zip", archive)
	dupReq := map[string]any{"source": "upload", "idempotency_key": "u-" + uuid.NewString(), "metadata": md, "items": []any{map[string]any{"upload_id": uid2}}}
	code, val := o.do(admin, "POST", "/api/v1/repository-imports/validate", dupReq)
	if code != 200 || val["valid"] != false || val["items"].([]any)[0].(map[string]any)["code"] != "duplicate" {
		t.Errorf("duplicate archive: %v", val)
	}
	if code, _ := o.do(admin, "POST", "/api/v1/repository-imports", map[string]any{"source": "upload", "idempotency_key": "u-" + uuid.NewString(),
		"metadata": md, "items": []any{map[string]any{"upload_id": uid2, "target_repository_id": repoID}}}); code != 400 {
		t.Errorf("a new version must not carry asset metadata: %d", code)
	}
	dupReq["metadata"] = map[string]any{}
	dupReq["items"] = []any{map[string]any{"upload_id": uid2, "target_repository_id": repoID, "allow_duplicate": true}}
	code, job = o.do(admin, "POST", "/api/v1/repository-imports", dupReq)
	if code != 202 {
		t.Fatalf("new version: %d %v", code, job)
	}
	o.drain(t)
	if it := items(o.job(t, admin, id(job, "id")))[0]; it["result"] != "snapshot_added" || it["stage"] != "completed" {
		t.Errorf("new snapshot: %v", it)
	}
	if _, snaps := o.do(admin, "GET", "/api/v1/repositories/"+repoID+"/snapshots", nil); len(snaps["items"].([]any)) != 2 {
		t.Errorf("snapshot history: %v", snaps)
	}

	// Malicious archives are rejected without registering anything.
	evil := zipOf(t, map[string]string{"../../etc/cron.d/x": "boom", "ok.txt": "fine"})
	uid3 := o.upload(t, admin, "evil.zip", evil)
	_, job = o.do(admin, "POST", "/api/v1/repository-imports", map[string]any{"source": "upload", "idempotency_key": "u-" + uuid.NewString(),
		"metadata": md, "items": []any{map[string]any{"upload_id": uid3, "display_name": "evil"}}})
	o.drain(t)
	it = items(o.job(t, admin, id(job, "id")))[0]
	if it["status"] != "failed" || it["stage"] != "importing" || it["error_code"] != "archive_rejected" || !strings.Contains(it["error_message"].(string), "path_traversal") || it["repository_id"] != nil {
		t.Errorf("malicious archive: %v", it)
	}
	// Checksum: the browser-declared SHA-256 must match the reassembled file.
	bad := zipOf(t, map[string]string{"a.txt": "a"})
	_, up = o.do(admin, "POST", "/api/v1/source-uploads", map[string]any{"filename": "c.zip", "size": len(bad), "sha256": strings.Repeat("ab", 32)})
	o.do(admin, "PUT", "/api/v1/source-uploads/"+id(up, "id")+"/parts/0", bad, "Content-Type", "application/octet-stream", "X-Content-SHA256", hexSum(bad))
	o.do(admin, "POST", "/api/v1/source-uploads/"+id(up, "id")+"/complete", nil)
	_, job = o.do(admin, "POST", "/api/v1/repository-imports", map[string]any{"source": "upload", "idempotency_key": "u-" + uuid.NewString(),
		"metadata": md, "items": []any{map[string]any{"upload_id": id(up, "id"), "display_name": "checksum"}}})
	o.drain(t)
	if it := items(o.job(t, admin, id(job, "id")))[0]; it["error_code"] != "checksum_mismatch" {
		t.Errorf("checksum: %v", it)
	}
}

// TestOnboardingOrganizationIsolation: principals of another organization
// see none of this organization's assets, imports or uploads.
func TestOnboardingOrganizationIsolation(t *testing.T) {
	o := newOnboarding(t)
	ctx := t.Context()
	admin := dbUser(t, authz.RoleSuperAdmin)
	owner := dbUser(t, "viewer")
	bu := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, name) VALUES ($1, $2, $3)`, bu, orgID, "Iso "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	uid := o.upload(t, admin, "iso.zip", zipOf(t, map[string]string{"x.py": "print(1)\n"}))
	_, job := o.do(admin, "POST", "/api/v1/repository-imports", map[string]any{"source": "upload", "idempotency_key": "i-" + uuid.NewString(),
		"metadata": map[string]any{"business_owner_id": owner.UserID, "technical_owner_id": owner.UserID, "business_unit_id": bu,
			"business_region_id": firstRegion(t), "criticality": "low", "data_classification": "public", "environment": "sandbox"},
		"items": []any{map[string]any{"upload_id": uid}}})
	o.drain(t)
	repoID := items(o.job(t, admin, id(job, "id")))[0]["repository_id"].(string)

	otherOrg := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'Other', $2)`, otherOrg, "other-"+otherOrg.String()[:8]); err != nil {
		t.Fatal(err)
	}
	intruder := &authz.Principal{UserID: uuid.New(), OrganizationID: otherOrg}
	r, _ := authz.LookupSystemRole(authz.RoleSuperAdmin)
	for _, perm := range r.Permissions {
		intruder.Grants = append(intruder.Grants, authz.Grant{Permission: perm, Scope: authz.Scope{Type: authz.ScopeOrganization, ID: otherOrg}})
	}
	for _, path := range []string{"/api/v1/repositories/" + repoID, "/api/v1/repository-imports/" + id(job, "id"),
		"/api/v1/source-uploads/" + uid, "/api/v1/repositories/" + repoID + "/snapshots"} {
		if code, _ := o.do(intruder, "GET", path, nil); code != 404 {
			t.Errorf("%s visible across organizations: %d", path, code)
		}
	}
	if code, _ := o.do(intruder, "PATCH", "/api/v1/repositories/"+repoID, map[string]any{"description": "x"}); code != 404 {
		t.Errorf("cross-organization edit: %d", code)
	}
	_, list := o.do(intruder, "GET", "/api/v1/repositories?status=all", nil)
	for _, it := range list["items"].([]any) {
		if it.(map[string]any)["id"] == repoID {
			t.Error("repository listed across organizations")
		}
	}
	// Referencing another organization's owner fails validation.
	code, val := o.do(intruder, "POST", "/api/v1/repository-imports/validate", map[string]any{"source": "upload", "idempotency_key": "i-" + uuid.NewString(),
		"metadata": map[string]any{"business_owner_id": owner.UserID}, "items": []any{map[string]any{"upload_id": uid}}})
	if code != 200 || val["valid"] != false || val["fields"].(map[string]any)["business_owner_id"] == nil {
		t.Errorf("cross-organization owner accepted: %d %v", code, val)
	}
	_ = httptest.NewRecorder
}
