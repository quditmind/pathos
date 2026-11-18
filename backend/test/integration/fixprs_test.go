//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/scm"
)

// fakePRWriter records fix pull request calls.
type fakePRWriter struct {
	mu        sync.Mutex
	branches  map[string]string // branch → base commit
	commits   map[string][]scm.FileChange
	prs       []scm.PullRequestSpec
	state     string
	branchErr error
}

func (f *fakePRWriter) CreateBranch(_ context.Context, _ scm.RepoRef, branch, from string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.branchErr != nil {
		return f.branchErr
	}
	f.branches[branch] = from
	return nil
}

func (f *fakePRWriter) CommitFiles(_ context.Context, _ scm.RepoRef, branch, parent, _ string, files []scm.FileChange) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits[branch] = files
	return "2222222222222222222222222222222222222222", nil
}

func (f *fakePRWriter) CreatePullRequest(_ context.Context, _ scm.RepoRef, s scm.PullRequestSpec) (scm.PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prs = append(f.prs, s)
	return scm.PullRequest{ID: "42", URL: "https://github.com/acme/x/pull/42", State: scm.PROpen}, nil
}

func (f *fakePRWriter) GetPullRequest(context.Context, scm.RepoRef, string) (scm.PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return scm.PullRequest{ID: "42", State: f.state}, nil
}

func waitFixStatus(t *testing.T, id string, want string) string {
	t.Helper()
	var st, msg string
	for i := 0; i < 100; i++ {
		_ = appPool.QueryRow(t.Context(), `SELECT status, error FROM fix_pull_requests WHERE id = $1`, id).Scan(&st, &msg)
		if st == want {
			return msg
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("fix PR %s: status %q (%s), want %q", id, st, msg, want)
	return ""
}

func TestFixPullRequests(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	pw := &fakePRWriter{branches: map[string]string{}, commits: map[string][]scm.FileChange{}, state: scm.PROpen}
	h.svc.FixPRTarget = func(context.Context, uuid.UUID, uuid.UUID) (scm.PullRequestWriter, scm.RepoRef, string, error) {
		return pw, scm.RepoRef{FullName: "acme/x"}, "main", nil
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "fixpr-"+uuid.NewString()[:6])
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "fix-" + uuid.NewString()[:6], "family": "core"})
	token := reg["token"].(string)
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	job := h.leaseJob(token, q["job_id"].(string))
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+job["job_id"].(string)+"/results", map[string]any{
		"scanner": "trivy-fs", "version": "t", "status": "succeeded", "output_gzip": fixture(t, "trivy-fs.sarif")})
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+job["job_id"].(string)+"/complete", map[string]any{"status": "succeeded"})

	var findingID uuid.UUID
	var pkg, version string
	if err := appPool.QueryRow(ctx, `SELECT id, package_name, package_version FROM findings WHERE repository_id = $1 AND category = 'sca'
		AND fixed_version <> '' ORDER BY title LIMIT 1`, repo).Scan(&findingID, &pkg, &version); err != nil {
		t.Fatalf("no SCA finding with a fixed version: %v", err)
	}
	var samePkg int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND category = 'sca' AND package_name = $2 AND package_version = $3
		AND status = 'open'`, repo, pkg, version).Scan(&samePkg)
	fp := "/api/v1/findings/" + findingID.String() + "/fix-pr"

	// Opt-in per repository.
	code, el := h.user(admin, "GET", fp, nil)
	if code != 200 || el["eligible"] != false || !strings.Contains(el["reason"].(string), "not enabled") || el["ecosystem"] != "npm" {
		t.Fatalf("eligibility while disabled: %d %v", code, el)
	}
	if code, _ := h.user(admin, "POST", fp, map[string]any{}); code != 422 {
		t.Errorf("request while disabled: %d", code)
	}
	settings := "/api/v1/repositories/" + repo.String() + "/fix-pr-settings"
	if code, _ := h.user(scoped("developer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID}), "PUT", settings,
		map[string]any{"enabled": true, "grouping": "package"}); code != 403 {
		t.Errorf("developer cannot enable fix PRs: %d", code)
	}
	if code, st := h.user(admin, "PUT", settings, map[string]any{"enabled": true, "grouping": "package"}); code != 200 || st["enabled"] != true {
		t.Fatalf("enable: %d %v", code, st)
	}
	if code, el = h.user(admin, "GET", fp, nil); code != 200 || el["eligible"] != true || el["can_request"] != true {
		t.Fatalf("eligibility: %d %v", code, el)
	}
	// findings.triage alone is not enough: opening a PR writes to the repository.
	if code, _ := h.user(scoped("developer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID}), "POST", fp, map[string]any{}); code != 403 {
		t.Errorf("developer (triage only) request: %d", code)
	}
	code, fix := h.user(admin, "POST", fp, map[string]any{})
	if code != 202 || fix["status"] != "queued" || len(fix["finding_ids"].([]any)) != samePkg {
		t.Fatalf("request: %d %v (want %d findings)", code, fix, samePkg)
	}
	fixID := fix["id"].(string)
	if code, _ := h.user(admin, "POST", fp, map[string]any{}); code != 409 {
		t.Errorf("duplicate request: %d", code)
	}

	// Worker leases it (scan queue empty) and reports the edited manifest.
	code, lease := h.worker(token, "POST", "/internal/worker/v1/fix-lease", map[string]any{})
	if code != 200 || lease["fix_id"] != fixID || lease["package_name"] != pkg || lease["ref"] != "main" || lease["credential"] == nil {
		t.Fatalf("fix lease: %d %v", code, lease)
	}
	base := "0123456789abcdef0123456789abcdef01234567"
	content := base64.StdEncoding.EncodeToString([]byte(`{"dependencies":{"lodash":"^4.17.21"}}`))
	if code, r := h.worker(token, "POST", "/internal/worker/v1/fix-jobs/"+fixID+"/result", map[string]any{
		"status": "ok", "base_commit": base, "files": []map[string]string{{"path": "../evil", "content_base64": content}}}); code != 204 {
		t.Fatalf("result: %d %v", code, r)
	}
	if msg := waitFixStatus(t, fixID, "failed"); !strings.Contains(msg, "invalid file path") {
		t.Errorf("path traversal must be rejected: %s", msg)
	}

	// A new request (the failed one no longer blocks), done properly.
	code, fix = h.user(admin, "POST", fp, map[string]any{"grouping": "finding"})
	if code != 202 || len(fix["finding_ids"].([]any)) != 1 {
		t.Fatalf("second request: %d %v", code, fix)
	}
	fixID = fix["id"].(string)
	if code, lease = h.worker(token, "POST", "/internal/worker/v1/fix-lease", map[string]any{}); code != 200 || lease["fix_id"] != fixID {
		t.Fatalf("lease 2: %d %v", code, lease)
	}
	// Another worker cannot report it.
	_, reg2 := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "fix2-" + uuid.NewString()[:6], "family": "core"})
	if code, _ := h.worker(reg2["token"].(string), "POST", "/internal/worker/v1/fix-jobs/"+fixID+"/result", map[string]any{"status": "failed"}); code != 409 {
		t.Errorf("foreign worker result: %d", code)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/fix-jobs/"+fixID+"/result", map[string]any{
		"status": "ok", "base_commit": base, "files": []map[string]string{{"path": "package.json", "content_base64": content}}}); code != 204 {
		t.Fatalf("result 2: %d", code)
	}
	waitFixStatus(t, fixID, "open")
	pw.mu.Lock()
	if len(pw.prs) != 1 || !strings.HasPrefix(pw.prs[0].Branch, scm.FixBranchPrefix) || pw.prs[0].BaseBranch != "main" ||
		pw.branches[pw.prs[0].Branch] != base || len(pw.commits[pw.prs[0].Branch]) != 1 || !strings.Contains(pw.prs[0].Body, "later scan") {
		t.Errorf("SCM calls: %+v %v", pw.prs, pw.branches)
	}
	pw.mu.Unlock()
	_, el = h.user(admin, "GET", fp, nil)
	reqs := el["requests"].([]any)
	latest := reqs[0].(map[string]any)
	if latest["status"] != "open" || latest["pr_url"] != "https://github.com/acme/x/pull/42" || latest["pr_number"] != "42" {
		t.Errorf("tracked on the finding: %v", latest)
	}

	// Merged: recorded, but the finding stays open until a scan.
	pw.mu.Lock()
	pw.state = scm.PRMerged
	pw.mu.Unlock()
	if code, r := h.user(admin, "POST", "/api/v1/fix-prs/"+fixID+"/refresh", nil); code != 200 || r["status"] != "merged" {
		t.Fatalf("refresh: %d %v", code, r)
	}
	var status string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, findingID).Scan(&status)
	if status != "open" {
		t.Errorf("a merged PR must not resolve the finding: %s", status)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('fix_pr.request', 'fix_pr.opened', 'fix_pr.merged', 'repository.fix_prs')
		AND (target_id = $1 OR target_id = $2 OR target_id = $3)`, fixID, findingID.String(), repo.String()).Scan(&audits)
	if audits < 4 {
		t.Errorf("audit entries: %d", audits)
	}

	// Missing write permission is reported clearly.
	pw.mu.Lock()
	pw.branchErr = scm.ErrForbidden
	pw.mu.Unlock()
	_, fix = h.user(admin, "POST", fp, map[string]any{})
	fixID = fix["id"].(string)
	h.worker(token, "POST", "/internal/worker/v1/fix-lease", map[string]any{})
	h.worker(token, "POST", "/internal/worker/v1/fix-jobs/"+fixID+"/result", map[string]any{
		"status": "ok", "base_commit": base, "files": []map[string]string{{"path": "package.json", "content_base64": content}}})
	if msg := waitFixStatus(t, fixID, "failed"); !strings.Contains(msg, "lacks permission") {
		t.Errorf("permission message: %s", msg)
	}

	// Unsupported edits are reported as such.
	_, fix = h.user(admin, "POST", fp, map[string]any{})
	fixID = fix["id"].(string)
	h.worker(token, "POST", "/internal/worker/v1/fix-lease", map[string]any{})
	h.worker(token, "POST", "/internal/worker/v1/fix-jobs/"+fixID+"/result", map[string]any{
		"status": "not_supported", "error": "not supported: package-lock.json must be regenerated"})
	waitFixStatus(t, fixID, "not_supported")
	_, list := h.user(admin, "GET", "/api/v1/repositories/"+repo.String()+"/fix-prs", nil)
	if n := len(list["items"].([]any)); n != 4 {
		t.Errorf("repository fix PR list: %d", n)
	}
}
