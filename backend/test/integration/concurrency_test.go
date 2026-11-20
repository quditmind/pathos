//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
)

// TestConcurrentExecutionsPerRepository: a target scan and a result import
// run next to a repository scan (VALIDATION_REPORT O2, migration 00066; 00043 in 2.2.x);
// two repository scans of one repository and two scans of one target still
// run one at a time.
func TestConcurrentExecutionsPerRepository(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "conc-"+uuid.NewString()[:6])

	code, ut := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "url", "name": "Staging",
		"reference": "https://conc-" + uuid.NewString()[:6] + ".example.test", "authorized": true})
	if code != 201 {
		t.Fatalf("create target: %d %v", code, ut)
	}
	targetID := ut["id"].(string)
	_, tq := h.user(admin, "POST", "/api/v1/scan-targets/"+targetID+"/scan", nil)
	_, rq := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	targetJob, repoJob := tq["job_id"].(string), rq["job_id"].(string)

	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "conc-" + uuid.NewString()[:6], "family": "core"})
	token := reg["token"].(string)
	// leaseAll leases whatever is runnable now, failing other tests' jobs.
	leaseAll := func() map[string]bool {
		t.Helper()
		got := map[string]bool{}
		for range 40 {
			code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
			if code != 200 || j["job_id"] == nil {
				break
			}
			id := j["job_id"].(string)
			if j["repository_id"] != repo.String() {
				h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "failed", "error": "test drain"})
				continue
			}
			got[id] = true
		}
		return got
	}
	got := leaseAll()
	if !got[targetJob] || !got[repoJob] {
		t.Fatalf("a target scan and a repository scan of one repository run at the same time: leased %v (want %s and %s)", got, targetJob, repoJob)
	}

	// A CI result import while both run: no 409.
	sarif, _ := os.ReadFile("../../internal/scanners/testdata/opengrep.sarif")
	importOnce := func() int {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("repository_id", repo.String())
		_ = mw.WriteField("tool", "CI SAST")
		_ = mw.WriteField("category", "sast")
		fw, _ := mw.CreateFormFile("file", "report.sarif")
		_, _ = fw.Write(sarif)
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/api/v1/imports/results", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		h.api.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(req.Context(), admin)))
		if rec.Code != 201 {
			t.Logf("import: %d %s", rec.Code, rec.Body.String())
		}
		return rec.Code
	}
	// Several imports at once, while the repository's scans upload results:
	// the per-repository lock keeps them consistent (no deadlock, no 409).
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		wg.Go(func() { codes[i] = importOnce() })
	}
	wg.Go(func() {
		if c, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+repoJob+"/results",
			map[string]any{"scanner": "grype", "status": "succeeded", "output_gzip": fixture(t, "grype.json")}); c != 200 && c != 201 {
			t.Errorf("repository scan upload during imports: %d %v", c, out)
		}
	})
	wg.Wait()
	for i, c := range codes {
		if c != 201 {
			t.Errorf("import %d while scans run: %d", i, c)
		}
	}

	// A second repository scan and a second scan of the same target wait.
	_, rq2 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	_, tq2 := h.user(admin, "POST", "/api/v1/scan-targets/"+targetID+"/scan", nil)
	if rq2["job_id"] == repoJob || tq2["job_id"] == targetJob {
		t.Fatalf("new executions were queued: %v %v", rq2, tq2)
	}
	if got := leaseAll(); len(got) != 0 {
		t.Fatalf("a second repository scan or target scan started while the first runs: %v", got)
	}
	var running int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE repository_id = $1 AND status = 'running'`, repo).Scan(&running)
	if running != 2 {
		t.Errorf("running executions of the repository: %d (want the repository scan and the target scan)", running)
	}

	// The database enforces the rule too (a second running repository scan).
	if _, err := appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'running' WHERE id = $1`, rq2["job_id"]); err == nil {
		t.Error("two running repository scans of one repository were accepted by the database")
	}

	// When the first ones finish, the queued ones run (both together).
	for _, id := range []string{repoJob, targetJob} {
		if c, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "succeeded"}); c != 200 {
			t.Fatalf("complete %s: %d %v", id, c, out)
		}
	}
	got = leaseAll()
	if !got[rq2["job_id"].(string)] || !got[tq2["job_id"].(string)] {
		t.Fatalf("queued executions after the first finished: %v", got)
	}
	for id := range got {
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "succeeded"})
	}
	var imported int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE repository_id = $1 AND trigger = 'import' AND status = 'succeeded'`, repo).Scan(&imported)
	if imported != len(codes) {
		t.Errorf("imports recorded: %d", imported)
	}
	raw, _ := json.Marshal(codes)
	t.Logf("import status codes during scans: %s", raw)
}
