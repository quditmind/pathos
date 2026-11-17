//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/scm"
)

type fakeStatuses struct {
	mu  sync.Mutex
	got []scm.CommitStatus
	sha []string
}

func (f *fakeStatuses) SetCommitStatus(_ context.Context, _ scm.RepoRef, sha string, st scm.CommitStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got, f.sha = append(f.got, st), append(f.sha, sha)
	return nil
}

// leaseJob leases until jobID comes up, failing other queued jobs.
func (h *scanHarness) leaseJob(token, jobID string) map[string]any {
	h.t.Helper()
	for i := 0; i < 30; i++ {
		code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
		if code != 200 || j["job_id"] == nil {
			break
		}
		if j["job_id"] == jobID {
			return j
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test drain"})
	}
	h.t.Fatalf("job %s not leased", jobID)
	return nil
}

func TestPullRequestChecks(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	statuses := &fakeStatuses{}
	h.svc.StatusWriter = func(context.Context, uuid.UUID, uuid.UUID) (scm.StatusWriter, scm.RepoRef, error) {
		return statuses, scm.RepoRef{FullName: "acme/x"}, nil
	}
	h.svc.PublicURL = "https://pathos.example"
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "prcheck-"+uuid.NewString()[:6])
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "pr-" + uuid.NewString()[:6], "family": "core"})
	token := reg["token"].(string)

	// The scan branch has the Trivy findings.
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	main := h.leaseJob(token, q["job_id"].(string))
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+main["job_id"].(string)+"/results", map[string]any{
		"scanner": "trivy-fs", "version": "t", "status": "succeeded", "output_gzip": fixture(t, "trivy-fs.sarif")})
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+main["job_id"].(string)+"/complete", map[string]any{"status": "succeeded"})
	var before int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND status = 'open'`, repo).Scan(&before)
	if before == 0 {
		t.Fatal("main scan produced no findings")
	}

	// Disabled by default: a PR event does nothing.
	sha := "0123456789abcdef0123456789abcdef01234567"
	ev := scm.WebhookEvent{Kind: "pull_request", Ref: "feature/x", CommitSHA: sha, PullRequest: 7}
	h.svc.OnWebhookEvent(ctx, orgID, repo, ev)
	var n int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM pr_checks WHERE repository_id = $1`, repo).Scan(&n)
	if n != 0 {
		t.Fatal("PR checks must be opt-in")
	}
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	if code, _ := h.user(viewer, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings", map[string]any{"enabled": true, "gate_severity": "low"}); code != 403 {
		t.Errorf("viewer cannot change PR settings: %d", code)
	}
	if code, st := h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings", map[string]any{"enabled": true, "gate_severity": "low"}); code != 200 || st["enabled"] != true {
		t.Fatalf("enable: %d %v", code, st)
	}
	h.svc.OnWebhookEvent(ctx, orgID, repo, ev)
	_, list := h.user(admin, "GET", "/api/v1/pr-checks?repository_id="+repo.String(), nil)
	checks := list["items"].([]any)
	if len(checks) != 1 {
		t.Fatalf("one check: %v", list)
	}
	check := checks[0].(map[string]any)
	if check["status"] != "pending" || check["status_posted"] != "pending" || len(statuses.got) != 1 || statuses.got[0].State != scm.CommitPending || statuses.sha[0] != sha {
		t.Fatalf("pending status: %v %+v", check, statuses.got)
	}
	// A main-branch scan queued meanwhile is a separate execution.
	_, q2 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	if q2["job_id"] == check["scan_job_id"] || q2["coalesced"] == true {
		t.Fatal("main scans must not coalesce with PR scans")
	}

	job := h.leaseJob(token, check["scan_job_id"].(string))
	if job["ref"] != "feature/x" || job["commit_sha"] != sha {
		t.Errorf("PR job scans the PR head: %v %v", job["ref"], job["commit_sha"])
	}
	jid := job["job_id"].(string)
	// Same Trivy results (existing) plus Opengrep results (new).
	for key, file := range map[string]string{"trivy-fs": "trivy-fs.sarif", "opengrep": "opengrep.sarif"} {
		if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{
			"scanner": key, "version": "t", "status": "succeeded", "output_gzip": fixture(t, file)}); code != 200 {
			t.Fatalf("upload %s: %d %v", key, code, r)
		}
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"})

	// The repository's findings are untouched: nothing added, nothing fixed.
	var after, fixed, opengrep int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'open'), count(*) FILTER (WHERE status = 'fixed'),
		count(*) FILTER (WHERE 'opengrep' = ANY(scanner_keys)) FROM findings WHERE repository_id = $1`, repo).Scan(&after, &fixed, &opengrep)
	if after != before || fixed != 0 || opengrep != 0 {
		t.Fatalf("PR scan changed findings: open %d→%d, fixed %d, opengrep %d", before, after, fixed, opengrep)
	}
	code, detail := h.user(admin, "GET", "/api/v1/pr-checks/"+check["id"].(string), nil)
	c := detail["check"].(map[string]any)
	if code != 200 || c["status"] != "failed" || c["new_findings"].(float64) == 0 || c["existing_findings"].(float64) != float64(before) {
		t.Fatalf("check result: %d %v", code, c)
	}
	for _, f := range detail["findings"].([]any) {
		fm := f.(map[string]any)
		if (fm["scanner_key"] == "opengrep") != (fm["is_new"] == true) {
			t.Errorf("new = not on the scan branch: %v", fm)
		}
		if fm["is_new"] == false && fm["existing_finding_id"] == nil {
			t.Errorf("existing finding linked: %v", fm)
		}
	}
	if len(statuses.got) != 2 || statuses.got[1].State != scm.CommitFailure || statuses.got[1].TargetURL != "https://pathos.example/pull-requests?check="+c["id"].(string) {
		t.Fatalf("final status: %+v", statuses.got)
	}
	if c["status_posted"] != "final" {
		t.Errorf("status recorded: %v", c["status_posted"])
	}
	var gate bool
	_ = appPool.QueryRow(ctx, `SELECT gate_failed FROM scan_jobs WHERE id = $1`, jid).Scan(&gate)
	if !gate {
		t.Error("the PR execution records the failed gate")
	}
	// Reposting is allowed for people who can run scans.
	if code, _ := h.user(admin, "POST", "/api/v1/pr-checks/"+c["id"].(string)+"/repost", nil); code != 200 || len(statuses.got) != 3 {
		t.Errorf("repost: %d %d", code, len(statuses.got))
	}
	if code, _ := h.user(viewer, "POST", "/api/v1/pr-checks/"+c["id"].(string)+"/repost", nil); code != 403 {
		t.Errorf("viewer repost: %d", code)
	}
}
