//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/schedule"
)

var scanKeyRe = regexp.MustCompile(`^QD-SCAN-\d{6,}$`)

// leaseJob leases until the wanted execution is handed out (other tests may
// leave queued jobs behind; those are failed and skipped).
func leaseJob(t *testing.T, h *scanHarness, token, want string) map[string]any {
	t.Helper()
	for range 40 {
		code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
		if code == 204 {
			t.Fatalf("job %s was never leased", want)
		}
		if code != 200 {
			t.Fatalf("lease: %d", code)
		}
		if j["job_id"] == want {
			return j
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "drained by test"})
	}
	t.Fatalf("job %s not leased", want)
	return nil
}

// quietNotifications marks notification events raised by a test as
// processed, so other tests' dispatcher runs do not deliver them.
func quietNotifications(t *testing.T) {
	t.Cleanup(func() {
		_, _ = appPool.Exec(context.Background(), `UPDATE notification_events SET processed_at = now()
			WHERE processed_at IS NULL AND event_key IN ('scan.failed', 'findings.new', 'schedule.failed', 'schedule.completed')`)
	})
}

func get(t *testing.T, h *scanHarness, p *authz.Principal, path string) map[string]any {
	t.Helper()
	code, out := h.user(p, "GET", path, nil)
	if code != 200 {
		t.Fatalf("GET %s: %d %v", path, code, out)
	}
	return out
}

func TestScanningModule(t *testing.T) {
	quietNotifications(t)
	h := newScanHarness(t)
	ctx := t.Context()
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "scanning-"+uuid.NewString()[:6])
	sfx := uuid.NewString()[:4]
	_, profA := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Secrets+SCA " + sfx, "scanners": []map[string]any{{"key": "osv-scanner"}}})
	_, profB := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Trivy " + sfx, "scanners": []map[string]any{{"key": "trivy-fs"}}})
	a, b := profA["id"].(string), profB["id"].(string)

	// Start: chosen profile, name; per-profile coalescing.
	start := func(profile, name string) map[string]any {
		t.Helper()
		code, res := h.user(admin, "POST", "/api/v1/scans", map[string]any{"repository_ids": []string{repo.String()}, "profile_id": profile, "name": name})
		if code != 202 {
			t.Fatalf("start scan: %d %v", code, res)
		}
		return res["items"].([]any)[0].(map[string]any)
	}
	it1 := start(a, "Nightly secrets")
	if again := start(a, ""); again["coalesced"] != true || again["job_id"] != it1["job_id"] {
		t.Errorf("same profile must coalesce: %v", again)
	}
	it2 := start(b, "")
	if it2["job_id"] == it1["job_id"] || it2["coalesced"] == true {
		t.Errorf("another profile must create a separate execution: %v", it2)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/scans", map[string]any{"repository_ids": []string{repo.String()}, "profile_id": uuid.NewString()}); code != 400 {
		t.Errorf("unknown profile: %d", code)
	}
	j1 := get(t, h, admin, "/api/v1/scans/"+it1["job_id"].(string))
	snap, _ := j1["config_snapshot"].(map[string]any)
	if !scanKeyRe.MatchString(j1["scan_key"].(string)) || j1["name"] != "Nightly secrets" || snap == nil || snap["profile_name"] != profA["name"] ||
		j1["progress"].(float64) != 0 || j1["stage"] != "queued" {
		t.Fatalf("execution record: %v", j1)
	}
	if _, err := appPool.Exec(ctx, `UPDATE scan_jobs SET config_snapshot = '{}' WHERE id = $1`, it1["job_id"]); err == nil {
		t.Error("configuration snapshot must be immutable")
	}

	// Worker: events, logs, results.
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "scanmod-" + sfx, "family": "core"})
	token := reg["token"].(string)
	job1 := leaseJob(t, h, token, it1["job_id"].(string))["job_id"].(string)
	if p := get(t, h, admin, "/api/v1/scans/"+job1); p["progress"].(float64) != 5 || p["stage"] != "starting" {
		t.Errorf("after lease: %v %v", p["progress"], p["stage"])
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job1+"/events", map[string]any{
		"events": []map[string]any{{"stage": "source", "status": "started", "at": now}, {"stage": "source", "status": "succeeded", "message": "cloned main", "at": now},
			{"stage": "scanner", "scanner": "gitleaks", "status": "started", "at": now}},
		"logs": []map[string]any{{"at": now, "level": "info", "source": "worker", "message": "starting 2 scanners"},
			{"at": now, "level": "warn", "source": "gitleaks", "message": "slow file skipped"},
			{"at": now, "level": "error", "source": "osv-scanner", "message": "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 rejected"}}})
	if code != 204 {
		t.Fatalf("events: %d", code)
	}
	if p := get(t, h, admin, "/api/v1/scans/"+job1); p["progress"].(float64) != 15 || p["stage"] != "scanning:gitleaks" {
		t.Errorf("after source: %v %v", p["progress"], p["stage"])
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job1+"/events", map[string]any{"events": []map[string]any{{"stage": "bogus", "status": "info"}}}); code != 400 {
		t.Errorf("invalid stage accepted: %d", code)
	}
	for _, k := range []string{"gitleaks", "osv-scanner"} {
		if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job1+"/results", map[string]any{
			"scanner": k, "version": "1.0", "status": "succeeded", "duration_ms": 900, "output_gzip": fixture(t, fixtureFiles[k])}); code != 200 {
			t.Fatalf("upload %s: %d %v", k, code, r)
		}
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+job1+"/complete", map[string]any{"status": "succeeded"})
	done := get(t, h, admin, "/api/v1/scans/"+job1)
	if done["progress"].(float64) != 100 || done["stage"] != "finished" || done["findings_total"].(float64) == 0 {
		t.Fatalf("finished execution: %v", done)
	}

	stages := get(t, h, admin, "/api/v1/scans/"+job1+"/stages")["stages"].([]any)
	byKey := map[string]map[string]any{}
	for _, s := range stages {
		m := s.(map[string]any)
		byKey[m["key"].(string)] = m
	}
	if byKey["source"]["status"] != "succeeded" || byKey["scanner:gitleaks"]["status"] != "succeeded" || byKey["scanner:gitleaks"]["scanner_version"] != "1.0" ||
		byKey["finalize"]["status"] != "succeeded" {
		t.Errorf("stages: %v", byKey)
	}
	logs := get(t, h, admin, "/api/v1/scans/"+job1+"/logs?level=warn")
	if n := len(logs["items"].([]any)); n != 2 {
		t.Errorf("warn+ logs: %d", n)
	}
	raw, _ := json.Marshal(logs)
	if bytes.Contains(raw, []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789")) {
		t.Error("secret in execution log was not redacted")
	}
	if n := len(get(t, h, admin, "/api/v1/scans/"+job1+"/logs?source=gitleaks")["items"].([]any)); n != 1 {
		t.Errorf("logs by engine: %d", n)
	}
	findings := get(t, h, admin, "/api/v1/scans/"+job1+"/findings")["items"].([]any)
	if len(findings) == 0 || findings[0].(map[string]any)["evidence"] == "" || findings[0].(map[string]any)["scanner"] == "" {
		t.Fatalf("execution findings: %v", findings)
	}

	// Profile B fails, then is retried as a new execution.
	job2 := leaseJob(t, h, token, it2["job_id"].(string))["job_id"].(string)
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+job2+"/results", map[string]any{"scanner": "trivy-fs", "status": "failed", "error": "db download failed"})
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+job2+"/complete", map[string]any{"status": "failed", "error": "scanner failed"})
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	if code, _ := h.user(viewer, "POST", "/api/v1/scans/"+job2+"/retry", nil); code != 403 {
		t.Errorf("viewer retry: %d", code)
	}
	code, retry := h.user(admin, "POST", "/api/v1/scans/"+job2+"/retry", nil)
	if code != 202 || retry["retry_of"] != job2 || retry["retry_count"].(float64) != 1 || retry["scan_key"] == done["scan_key"] {
		t.Fatalf("retry: %d %v", code, retry)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/scans/"+job1+"/retry", nil); code != 409 {
		t.Errorf("succeeded scans cannot be retried: %d", code)
	}
	h.user(admin, "POST", "/api/v1/scans/"+retry["id"].(string)+"/cancel", nil)

	// Comparison: a later run where osv-scanner failed must not mark its
	// findings fixed; a complete later run does.
	run := func(statuses map[string]string) string {
		t.Helper()
		it := start(a, "")
		id := leaseJob(t, h, token, it["job_id"].(string))["job_id"].(string)
		for k, st := range statuses {
			body := map[string]any{"scanner": k, "version": "1.1", "status": st, "duration_ms": 500}
			if st == "succeeded" && k == "gitleaks" {
				body["output_gzip"] = fixture(t, fixtureFiles[k])
			}
			h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/results", body)
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "succeeded"})
		return id
	}
	job3 := run(map[string]string{"gitleaks": "succeeded", "osv-scanner": "failed"})
	job4 := run(map[string]string{"gitleaks": "succeeded", "osv-scanner": "succeeded"})
	cmp := get(t, h, admin, "/api/v1/scans/compare?ids="+job4+","+job1+","+job3)
	sc := cmp["scans"].([]any)
	s1, s3, s4 := sc[0].(map[string]any), sc[1].(map[string]any), sc[2].(map[string]any)
	if s1["id"] != job1 || s3["id"] != job3 || s4["id"] != job4 {
		t.Fatalf("comparison must be chronological: %v %v %v", s1["id"], s3["id"], s4["id"])
	}
	if s3["fixed"].(float64) != 0 || s3["not_covered"].(float64) == 0 || s3["unchanged"].(float64) == 0 {
		t.Errorf("failed scanner must not produce fixes: %v", s3)
	}
	if s3["engine_changes"] == nil || len(s3["engine_changes"].([]any)) == 0 {
		t.Errorf("scanner version change not reported: %v", s3["engine_changes"])
	}
	if code, _ := h.user(admin, "GET", "/api/v1/scans/compare?ids="+job1, nil); code != 400 {
		t.Errorf("one scan is not a comparison: %d", code)
	}
	cmp2 := get(t, h, admin, "/api/v1/scans/compare?ids="+job1+","+job4)
	if s := cmp2["scans"].([]any)[1].(map[string]any); s["fixed"].(float64) == 0 {
		t.Errorf("complete later scan should report fixes: %v", s)
	}

	// History, filters, overview.
	if n := len(get(t, h, admin, "/api/v1/scans/"+job1+"/history")["items"].([]any)); n < 5 {
		t.Errorf("history: %d", n)
	}
	if items := get(t, h, admin, "/api/v1/scans?q="+done["scan_key"].(string))["items"].([]any); len(items) != 1 {
		t.Errorf("search by Scan ID: %d", len(items))
	}
	if items := get(t, h, admin, "/api/v1/scans?profile_id="+b+"&from="+time.Now().Format(time.DateOnly))["items"].([]any); len(items) != 2 {
		t.Errorf("filter by profile and date: %d", len(items))
	}
	ov := get(t, h, admin, "/api/v1/scans/overview?days=7")
	if ov["scans"].(map[string]any)["total"].(float64) < 5 || len(ov["recent"].([]any)) == 0 || len(ov["trend"].([]any)) != 7 {
		t.Errorf("overview: %v", ov["scans"])
	}
	if code, _ := h.user(admin, "GET", "/api/v1/scans/overview?days=400", nil); code != 400 {
		t.Errorf("overview window above 360 days: %d", code)
	}
}

func TestSchedulePlansRunsAndRetries(t *testing.T) {
	quietNotifications(t)
	ctx := t.Context()
	h := newScanHarness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	svc := &schedule.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log, Principal: auth.PrincipalFrom}
	mux := http.NewServeMux()
	svc.Register(mux)
	call := func(method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), admin))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	sfx := uuid.NewString()[:4]
	repo := createRepo(t, "sched-"+sfx)
	_, pa := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Plan A " + sfx, "scanners": []map[string]any{}})
	_, pb := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Plan B " + sfx, "scanners": []map[string]any{{"key": "trivy-fs"}}})
	plan := []map[string]any{{"target_type": "repository", "target_id": repo, "profile_id": pa["id"]},
		{"target_type": "repository", "target_id": repo, "profile_id": pb["id"]}}

	// Validation.
	for _, bad := range []map[string]any{
		{"name": "x", "kind": "once", "run_at": time.Now().Add(-time.Hour), "plan": plan},
		{"name": "x", "kind": "interval", "interval_minutes": 5, "plan": plan},
		{"name": "x", "kind": "cron", "cron": "0 2 * * *", "window_start": "22:00", "plan": plan},
		{"name": "x", "kind": "cron", "cron": "0 2 * * *", "plan": []map[string]any{{"target_type": "repository", "target_id": repo, "profile_id": uuid.NewString()}}},
	} {
		if code, out := call("POST", "/api/v1/schedules", bad); code != 400 {
			t.Errorf("invalid schedule accepted: %d %v %v", code, out, bad)
		}
	}
	code, preview := call("POST", "/api/v1/schedules/preview", map[string]any{"kind": "cron", "cron": "0 2 * * 1", "timezone": "Europe/Berlin", "plan": plan})
	if code != 200 || preview["executions"].(float64) != 2 || preview["repositories"].(float64) != 1 || len(preview["next_runs"].([]any)) != 5 {
		t.Errorf("preview: %d %v", code, preview)
	}

	code, sch := call("POST", "/api/v1/schedules", map[string]any{"name": "Weekly plan " + sfx, "kind": "interval", "interval_minutes": 1440,
		"timezone": "UTC", "max_concurrent": 1, "retry_max": 1, "retry_delay_minutes": 5, "notify_on": []string{"failed"}, "plan": plan})
	if code != 201 || len(sch["plan"].([]any)) != 2 || sch["max_concurrent"].(float64) != 1 {
		t.Fatalf("create: %d %v", code, sch)
	}
	sid := sch["id"].(string)

	// Run now: concurrency limit 1 queues one execution, keeps one pending.
	code, res := call("POST", "/api/v1/schedules/"+sid+"/run", nil)
	if code != 200 || res["queued"].(float64) != 1 || res["deferred"].(float64) != 1 {
		t.Fatalf("run now: %d %v", code, res)
	}
	_, runs := call("GET", "/api/v1/schedules/"+sid+"/runs", nil)
	r0 := runs["items"].([]any)[0].(map[string]any)
	if r0["pending"].(float64) != 1 || r0["status"] != "running" || r0["trigger"] != "manual" {
		t.Fatalf("run record: %v", r0)
	}
	jobs := func() []map[string]any {
		rows := get(t, h, admin, "/api/v1/scans?schedule_id="+sid)["items"].([]any)
		var out []map[string]any
		for _, r := range rows {
			out = append(out, r.(map[string]any))
		}
		return out
	}
	first := jobs()
	if len(first) != 1 || first[0]["schedule_run_id"] != r0["id"] || first[0]["name"] != sch["name"] {
		t.Fatalf("first execution: %v", first)
	}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "sched-" + sfx, "family": "core"})
	token := reg["token"].(string)
	fail := func(id string) {
		leaseJob(t, h, token, id)
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "failed", "error": "boom"})
	}
	succeed := func(id string) {
		leaseJob(t, h, token, id)
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/results", map[string]any{"scanner": "gitleaks", "status": "succeeded"})
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "succeeded"})
	}
	succeed(first[0]["id"].(string))
	// The scheduler queues the pending entry once capacity is free.
	if _, err := schedule.Tick(ctx, appPool, time.Now(), log); err != nil {
		t.Fatal(err)
	}
	second := jobs()
	if len(second) != 2 {
		t.Fatalf("pending entry not queued: %d", len(second))
	}
	// It fails; after the retry delay the policy retries it once.
	var pending string
	for _, j := range second {
		if j["status"] == "queued" {
			pending = j["id"].(string)
		}
	}
	fail(pending)
	if _, err := schedule.Tick(ctx, appPool, time.Now(), log); err != nil {
		t.Fatal(err)
	}
	if n := len(jobs()); n != 2 {
		t.Errorf("retry before its delay: %d executions", n)
	}
	if _, err := schedule.Tick(ctx, appPool, time.Now().Add(10*time.Minute), log); err != nil {
		t.Fatal(err)
	}
	var retry map[string]any
	for _, j := range jobs() {
		if j["retry_of"] == pending {
			retry = j
		}
	}
	if retry == nil {
		t.Fatal("retry policy did not create a retry execution")
	}
	fail(retry["id"].(string))
	if _, err := schedule.Tick(ctx, appPool, time.Now().Add(20*time.Minute), log); err != nil {
		t.Fatal(err)
	}
	_, runs = call("GET", "/api/v1/schedules/"+sid+"/runs", nil)
	r0 = runs["items"].([]any)[0].(map[string]any)
	if r0["status"] != "partial" || r0["finished_at"] == nil {
		t.Errorf("run outcome: %v", r0)
	}
	var notified int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'schedule.failed' AND subject_id = $1`, sid).Scan(&notified)
	if notified != 1 {
		t.Errorf("schedule.failed notifications: %d", notified)
	}
	_, _ = appPool.Exec(ctx, `UPDATE notification_events SET processed_at = now() WHERE event_key = 'schedule.failed' AND subject_id = $1`, sid)

	// Scheduled activations are processed once, even when a pass repeats.
	due := time.Now().Add(-time.Minute).Truncate(time.Second)
	if _, err := appPool.Exec(ctx, `UPDATE scan_schedules SET next_run_at = $2, max_concurrent = 0 WHERE id = $1`, sid, due); err != nil {
		t.Fatal(err)
	}
	if _, err := schedule.Tick(ctx, appPool, time.Now(), log); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE scan_schedules SET next_run_at = $2 WHERE id = $1`, sid, due); err != nil {
		t.Fatal(err)
	}
	if _, err := schedule.Tick(ctx, appPool, time.Now(), log); err != nil {
		t.Fatal(err)
	}
	var activations int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scan_schedule_runs WHERE schedule_id = $1 AND due_at = $2`, sid, due).Scan(&activations)
	_, sched := call("GET", "/api/v1/schedules/"+sid, nil)
	if activations != 1 || !strings.Contains(sched["last_status"].(string), "already processed") {
		t.Errorf("duplicate activation: %d %v", activations, sched["last_status"])
	}

	// Pause / resume and the approved scan window.
	if code, p := call("POST", "/api/v1/schedules/"+sid+"/pause", nil); code != 200 || p["enabled"] != false {
		t.Errorf("pause: %d %v", code, p)
	}
	if code, p := call("POST", "/api/v1/schedules/"+sid+"/resume", nil); code != 200 || p["enabled"] != true || p["next_run_at"] == nil {
		t.Errorf("resume: %d %v", code, p)
	}
	closed := time.Now().UTC().Add(3 * time.Hour)
	code, win := call("POST", "/api/v1/schedules", map[string]any{"name": "Window " + sfx, "kind": "cron", "cron": "0 * * * *", "timezone": "UTC",
		"window_start": closed.Format("15:04"), "window_end": closed.Add(time.Hour).Format("15:04"), "plan": plan[:1]})
	if code != 201 {
		t.Fatalf("window schedule: %d %v", code, win)
	}
	next, _ := time.Parse(time.RFC3339, win["next_run_at"].(string))
	if next.Before(closed.Add(-time.Minute)) {
		t.Errorf("next run %s is before the window opens at %s", next, closed)
	}
	for _, id := range []string{sid, win["id"].(string)} {
		if code, _ := call("DELETE", "/api/v1/schedules/"+id, nil); code != 204 {
			t.Errorf("delete: %d", code)
		}
	}
}
