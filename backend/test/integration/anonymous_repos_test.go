//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/repos"
	"pathos/internal/scans"
)

// TestAnonymousPublicRepositoryImport: a public repository is imported by
// URL without a token, scanned with an anonymous clone, and refused (PTH
// code) when it is private (VALIDATION_REPORT O1).
func TestAnonymousPublicRepositoryImport(t *testing.T) {
	ctx := t.Context()
	name := "anon-" + uuid.NewString()[:6]
	var private atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/repos/{o}/{r}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential sent by the anonymous probe")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.PathValue("r") != name || private.Load() {
			w.WriteHeader(404)
			_, _ = fmt.Fprint(w, `{"message":"Not Found"}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":%d,"full_name":"oss/%s","name":"%s","html_url":"https://github.com/oss/%s","clone_url":"https://github.com/oss/%s.git",
			"default_branch":"main","private":false,"visibility":"public","language":"Go","owner":{"login":"oss"}}`, 9000+len(name), name, name, name, name)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	h := newScanHarness(t)
	rs := &repos.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom,
		Public: &repos.PublicProbe{HTTP: srv.Client(), GitHubAPI: srv.URL + "/gh"},
		EnqueueScan: func(ctx context.Context, orgID, repoID uuid.UUID, trigger string, by *uuid.UUID) error {
			_, err := scans.Enqueue(ctx, appPool, orgID, repoID, trigger, "", "", by)
			return err
		}}
	rh := &harness{t: t, mux: http.NewServeMux()}
	rs.Register(rh.mux)
	admin := reviewUser(t, "platform_admin")
	viewer := reviewUser(t, "viewer")
	url := "https://github.com/oss/" + name

	if code, _ := rh.do(viewer, "POST", "/api/v1/repositories/import-url", map[string]any{"url": url}); code != 403 {
		t.Errorf("viewer cannot import: %d", code)
	}
	code, out := rh.do(admin, "POST", "/api/v1/repositories/import-url", map[string]any{"url": url, "dry_run": true})
	if code != 200 || out["status"] != "would_import" {
		t.Fatalf("dry run: %d %v", code, out)
	}
	code, out = rh.do(admin, "POST", "/api/v1/repositories/import-url", map[string]any{"url": url + ".git", "start_scan": true, "criticality": "high"})
	if code != 201 || out["anonymous"] != true || out["visibility"] != "public" || out["scan_queued"] != true {
		t.Fatalf("anonymous import: %d %v", code, out)
	}
	repoID := out["repository_id"].(string)
	code, out = rh.do(admin, "POST", "/api/v1/repositories/import-url", map[string]any{"url": url})
	if e, _ := out["error"].(map[string]any); code != 409 || e["error_code"] != "PTH-ONB-1105" {
		t.Errorf("duplicate: %d %v", code, out)
	}
	code, out = rh.do(admin, "POST", "/api/v1/repositories/import-url", map[string]any{"url": "https://github.com/oss/secret-" + name})
	if e, _ := out["error"].(map[string]any); code != 422 || e["error_code"] != "PTH-ONB-1102" || e["code"] != "repository_not_public" {
		t.Errorf("private repository: %d %v", code, out)
	}
	code, out = rh.do(admin, "POST", "/api/v1/repositories/import-url", map[string]any{"url": "https://ghp_x:y@github.com/oss/" + name})
	if e, _ := out["error"].(map[string]any); code != 400 || e["error_code"] != "PTH-ONB-1101" {
		t.Errorf("credentials in the URL: %d %v", code, out)
	}
	_, repo := rh.do(admin, "GET", "/api/v1/repositories/"+repoID, nil)
	if repo["source_type"] != "git" || repo["anonymous"] != true || repo["provider"] != "github" || repo["scm_connection_id"] != nil ||
		repo["visibility"] != "public" || repo["default_branch"] != "main" || repo["criticality"] != "high" {
		t.Errorf("repository: %v", repo)
	}
	_, list := rh.do(admin, "GET", "/api/v1/repositories?provider=github&q="+name, nil)
	if items, _ := list["items"].([]any); len(items) != 1 {
		t.Errorf("provider filter includes anonymous repositories: %v", list["items"])
	}

	// The worker gets the public clone URL and no credential.
	var jobID string
	if err := appPool.QueryRow(ctx, `SELECT id FROM scan_jobs WHERE repository_id = $1 AND status = 'queued'`, repoID).Scan(&jobID); err != nil {
		t.Fatalf("onboarding scan: %v", err)
	}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "anon-" + uuid.NewString()[:6], "family": "core"})
	job := h.leaseJob(reg["token"].(string), jobID)
	if job["clone_url"] != "https://github.com/oss/"+name+".git" || job["credential"] != nil || job["public"] != true || job["ref"] != "main" {
		t.Errorf("leased anonymous job: %v", job)
	}
	h.worker(reg["token"].(string), "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded"})

	// The repository turns private: the sync marks it, and no scan runs.
	private.Store(true)
	code, run := rh.do(admin, "POST", "/api/v1/repositories/"+repoID+"/sync", nil)
	if code != 200 || run["run"].(map[string]any)["status"] != "permission_denied" {
		t.Fatalf("sync of a repository that turned private: %d %v", code, run)
	}
	if _, err := scans.Enqueue(ctx, appPool, orgID, uuid.MustParse(repoID), "manual", "", "", nil); !errors.Is(err, scans.ErrScanPrerequisite) {
		t.Errorf("a repository that is no longer public must not be scanned anonymously: %v", err)
	}
	private.Store(false)
	if code, run := rh.do(admin, "POST", "/api/v1/repositories/"+repoID+"/sync", nil); code != 200 || run["run"].(map[string]any)["status"] != "ok" {
		t.Errorf("sync when public again: %d %v", code, run)
	}
	// Source view needs a connection.
	if _, _, err := rs.ReadSourceFile(ctx, orgID, uuid.MustParse(repoID), repos.SourceRef{Commit: "abc"}, "main.go"); err == nil {
		t.Error("anonymous repositories have no source view")
	}
}
