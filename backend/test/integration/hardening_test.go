//go:build integration

package integration

import (
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
