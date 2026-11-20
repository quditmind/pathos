//go:build integration

package integration

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/scans"
)

// TestPartialToolReportsAreKept: a tool that timed out or failed but wrote
// a report keeps its findings (a stopped Nuclei run, Dependency-Check on
// cached NVD data); the execution is partial and nothing it covers is
// auto-resolved (VALIDATION_REPORT O14, O17). URL and API target scans get
// at least 90 minutes.
func TestPartialToolReportsAreKept(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "partial-"+uuid.NewString()[:6])
	code, ut := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "url", "name": "Staging",
		"reference": "https://partial-" + uuid.NewString()[:6] + ".example.test", "authorized": true})
	if code != 201 {
		t.Fatalf("create target: %d %v", code, ut)
	}
	_, q := h.user(admin, "POST", "/api/v1/scan-targets/"+ut["id"].(string)+"/scan", nil)
	jobID := q["job_id"].(string)
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "partial-" + uuid.NewString()[:6], "family": "core"})
	token := reg["token"].(string)
	job := h.leaseJob(token, jobID)
	if job["timeout_seconds"].(float64) < scans.LiveTargetMinTimeout {
		t.Errorf("URL target timeout: %v (want at least %d)", job["timeout_seconds"], scans.LiveTargetMinTimeout)
	}
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{"scanner": "nuclei", "status": "timed_out",
		"error": "scan timeout reached", "output_gzip": fixture(t, "nuclei.jsonl")}); code != 200 && code != 201 {
		t.Fatalf("upload: %d %v", code, out)
	}
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
		t.Fatalf("complete: %d %v", code, out)
	}
	var open, count int
	var status, resStatus, resErr string
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1 AND status = 'open'`, ut["id"]).Scan(&open)
	_ = appPool.QueryRow(ctx, `SELECT j.status, r.status, r.findings_count, r.error FROM scan_jobs j JOIN scan_results r ON r.scan_job_id = j.id
		WHERE j.id = $1`, jobID).Scan(&status, &resStatus, &count, &resErr)
	if open != 2 || count != 2 {
		t.Errorf("findings of the partial Nuclei report: open %d, recorded %d", open, count)
	}
	if resStatus != "timed_out" || status != "failed" && status != "partial" {
		t.Errorf("a timed-out tool keeps its status: result %s, execution %s", resStatus, status)
	}
	t.Logf("result error: %s", resErr)
}

// TestSecretDefaultExclusions: secret findings in vendored code, lockfiles
// and minified files are dropped by default; other categories are not
// (VALIDATION_REPORT O6).
func TestSecretDefaultExclusions(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "secx-"+uuid.NewString()[:6])
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	jobID := q["job_id"].(string)
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "secx-" + uuid.NewString()[:6], "family": "core"})
	token := reg["token"].(string)
	h.leaseJob(token, jobID)
	result := func(rule, path string) string {
		return `{"ruleId":"` + rule + `","level":"error","message":{"text":"secret"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` +
			path + `"},"region":{"startLine":3}}}]}`
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"generic-api-key"}]}},"results":[` +
		result("generic-api-key", "src/config.py") + "," + result("generic-api-key", "web/node_modules/lib/key.js") + "," +
		result("generic-api-key", "package-lock.json") + "," + result("generic-api-key", "static/app.min.js") + `]}]}`
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{"scanner": "gitleaks", "status": "succeeded",
		"output_gzip": gzB64([]byte(sarif))}); code != 200 && code != 201 {
		t.Fatalf("upload: %d %v", code, out)
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded"})
	rows, _ := appPool.Query(ctx, `SELECT file_path FROM findings WHERE repository_id = $1 AND category = 'secrets'`, repo)
	var paths []string
	for rows.Next() {
		var p string
		_ = rows.Scan(&p)
		paths = append(paths, p)
	}
	rows.Close()
	if len(paths) != 1 || paths[0] != "src/config.py" {
		t.Errorf("secret findings kept: %v (want only src/config.py)", paths)
	}
	var on bool
	_ = appPool.QueryRow(ctx, `SELECT v.secret_default_exclusions FROM scan_jobs j JOIN scan_profile_versions v ON v.id = j.profile_version_id
		WHERE j.id = $1`, jobID).Scan(&on)
	if !on {
		t.Error("existing profile versions get the default secret exclusions")
	}
}

// TestMissingFamilyToolsArePartial: an execution whose profile tools no
// worker has is partial (failed when nothing ran), with PTH-SCAN-1101,
// never succeeded (VALIDATION_REPORT O15).
func TestMissingFamilyToolsArePartial(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := reviewUser(t, "platform_admin")
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "miss-" + uuid.NewString()[:6], "family": "core"})
	token := reg["token"].(string)
	run := func(results ...map[string]any) (string, string) {
		t.Helper()
		repo := createRepo(t, "miss-"+uuid.NewString()[:6])
		_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
		jobID := q["job_id"].(string)
		h.leaseJob(token, jobID)
		for _, r := range results {
			if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", r); code != 200 && code != 201 {
				t.Fatalf("upload: %d %v", code, out)
			}
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded"})
		var status, errText string
		_ = appPool.QueryRow(ctx, `SELECT status, error FROM scan_jobs WHERE id = $1`, jobID).Scan(&status, &errText)
		return status, errText
	}
	missing := func(key string) map[string]any {
		return map[string]any{"scanner": key, "status": "skipped", "error": scans.ToolUnavailable}
	}
	ok := map[string]any{"scanner": "grype", "status": "succeeded", "output_gzip": gzB64([]byte(`{"matches":[]}`))}
	status, msg := run(ok, missing("gosec"), missing("psalm"))
	if status != "partial" || !strings.Contains(msg, "PTH-SCAN-1101") || !strings.Contains(msg, "2 check(s)") ||
		strings.Contains(msg, "gosec") || strings.Contains(msg, "psalm") { // kinds of check, not tool names (rule 3)
		t.Errorf("some family tools missing: %s %q", status, msg)
	}
	if status, _ := run(missing("gosec")); status != "failed" {
		t.Errorf("no tool ran: %s", status)
	}
	// Ordinary skips (no matching files) still succeed.
	if status, msg := run(ok, map[string]any{"scanner": "psalm", "status": "skipped", "error": "no matching files in the repository (*.php)"}); status != "succeeded" {
		t.Errorf("a tool skipped for lack of files: %s %q", status, msg)
	}
}

// TestWorkerReleaseOnShutdown: a stopping worker returns its job to the
// queue; another worker picks it up (VALIDATION_REPORT O9).
func TestWorkerReleaseOnShutdown(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "rel-"+uuid.NewString()[:6])
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	jobID := q["job_id"].(string)
	_, r1 := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "rel1-" + uuid.NewString()[:6], "family": "core"})
	_, r2 := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "rel2-" + uuid.NewString()[:6], "family": "core"})
	t1, t2 := r1["token"].(string), r2["token"].(string)
	h.leaseJob(t1, jobID)
	if code, _ := h.worker(t2, "POST", "/internal/worker/v1/jobs/"+jobID+"/release", map[string]any{"reason": "x"}); code != 404 && code != 409 {
		t.Errorf("another worker cannot release the job: %d", code)
	}
	code, out := h.worker(t1, "POST", "/internal/worker/v1/jobs/"+jobID+"/release", map[string]any{"reason": "worker w1 stopped (SIGTERM)"})
	if code != 200 || out["status"] != "queued" {
		t.Fatalf("release: %d %v", code, out)
	}
	var status, stage string
	var leased *uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT status, stage, leased_by FROM scan_jobs WHERE id = $1`, jobID).Scan(&status, &stage, &leased)
	if status != "queued" || leased != nil {
		t.Errorf("released job: %s %v", status, leased)
	}
	h.leaseJob(t2, jobID) // picked up by the other worker
	// The last attempt is failed instead of requeued.
	_, _ = appPool.Exec(ctx, `UPDATE scan_jobs SET attempts = max_attempts WHERE id = $1`, jobID)
	if code, out := h.worker(t2, "POST", "/internal/worker/v1/jobs/"+jobID+"/release", map[string]any{"reason": "worker w2 stopped (SIGTERM)"}); code != 200 || out["status"] != "failed" {
		t.Errorf("release of the last attempt: %d %v", code, out)
	}
}
