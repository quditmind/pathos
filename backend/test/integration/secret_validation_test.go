//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/risk"
	"pathos/internal/scans"
)

// redactedGitleaks is what "gitleaks dir --redact" reports for three
// secrets: rule and location, never the value.
func redactedGitleaks(n int) []byte {
	var res []string
	for i := 1; i <= n; i++ {
		res = append(res, fmt.Sprintf(`{"ruleId":"github-pat","message":{"text":"github-pat has detected secret for file config/%d.env."},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"config/%d.env"},"region":{"startLine":2,"snippet":{"text":"REDACTED"}}}}],`+
			`"partialFingerprints":{"commitSha":"","email":"","author":"","date":"","commitMessage":""}}`, i, i))
	}
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"github-pat","shortDescription":{"text":"GitHub token"}}]}},` +
		`"results":[` + strings.Join(res, ",") + `]}]}`)
}

func TestSecretValidation(t *testing.T) {
	ctx := t.Context()
	h, token := provenanceHarness(t, false)
	admin := reviewUser(t, "platform_admin")
	viewer := reviewUser(t, "viewer")
	repo := createRepo(t, "sv-"+uuid.NewString()[:6])
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = appPool.Exec(bg, `DELETE FROM secret_validation_settings WHERE organization_id = $1`, orgID)
		// The scans this test fails raise notifications other tests count.
		_, _ = appPool.Exec(bg, `UPDATE notification_events SET processed_at = now() WHERE processed_at IS NULL AND repository_id = $1`, repo)
	})
	_, _ = appPool.Exec(ctx, `DELETE FROM secret_validation_settings WHERE organization_id = $1`, orgID)

	// Off by default.
	code, st := h.user(admin, "GET", "/api/v1/settings/secret-validation", nil)
	if code != 200 || st["rate_per_second"].(float64) != 1 || st["max_checks_per_scan"].(float64) != 50 || st["can_manage"] != true {
		t.Fatalf("settings: %d %v", code, st)
	}
	for _, p := range st["providers"].([]any) {
		if p.(map[string]any)["enabled"] != false {
			t.Fatalf("provider enabled by default: %v", p)
		}
	}
	if code, _ := h.user(viewer, "GET", "/api/v1/settings/secret-validation", nil); code != 403 {
		t.Errorf("viewer reads settings: %d", code)
	}

	type finding struct {
		id, fp, severity, status string
	}
	scan := func(verdicts func([]finding) []map[string]any) (string, map[string]any, []finding) {
		t.Helper()
		res, err := scans.Enqueue(ctx, appPool, orgID, repo, "manual", "main", strings.Repeat("c", 40), nil)
		if err != nil {
			t.Fatal(err)
		}
		job := h.leaseFor(token, repo)
		jid := job["job_id"].(string)
		if jid != res.JobID.String() {
			t.Fatalf("leased %s, queued %s", jid, res.JobID)
		}
		if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "gitleaks",
			"status": "succeeded", "output_gzip": gzB64(redactedGitleaks(3))}); code != 200 {
			t.Fatalf("results: %d %v", code, out)
		}
		rows, err := appPool.Query(ctx, `SELECT id, fingerprint, severity, secret_validation_status FROM findings
			WHERE repository_id = $1 AND category = 'secrets' ORDER BY file_path`, repo)
		if err != nil {
			t.Fatal(err)
		}
		var fs []finding
		for rows.Next() {
			var f finding
			var id uuid.UUID
			_ = rows.Scan(&id, &f.fp, &f.severity, &f.status)
			f.id = id.String()
			fs = append(fs, f)
		}
		rows.Close()
		if len(fs) != 3 {
			t.Fatalf("findings: %v", fs)
		}
		if verdicts != nil {
			if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/secret-validation",
				map[string]any{"version": 1, "providers": []string{"github"}, "results": verdicts(fs)}); code != 200 {
				t.Fatalf("verdicts: %d %v", code, out)
			}
		}
		if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
			t.Fatalf("complete: %d %v", code, out)
		}
		return jid, job, fs
	}
	verdict := func(f finding, status string, extra map[string]any) map[string]any {
		v := map[string]any{"fingerprints": []string{f.fp}, "file": "config/x.env", "line": 2, "provider": "github", "status": status,
			"endpoint": "GET https://api.github.com/user", "detail": "test " + status, "checked_at": "2026-11-19T10:00:00Z"}
		for k, x := range extra {
			v[k] = x
		}
		return v
	}
	reload := func(id string) (severity, status, identity string, before *string, evidence map[string]any) {
		var raw []byte
		if err := appPool.QueryRow(ctx, `SELECT severity, secret_validation_status, secret_validation_identity, secret_validation_severity_before,
			secret_validation_evidence FROM findings WHERE id = $1`, id).Scan(&severity, &status, &identity, &before, &raw); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &evidence)
		return
	}

	// Disabled: the lease carries no providers, and a verdict a worker
	// sends anyway is discarded (fail closed).
	_, job, fs := scan(func(fs []finding) []map[string]any {
		return []map[string]any{verdict(fs[0], "active", map[string]any{"identity": "user octo"})}
	})
	if _, ok := job["secret_validation"]; ok {
		t.Fatalf("lease carries secret validation while it is off: %v", job["secret_validation"])
	}
	if sev, status, _, _, ev := reload(fs[0].id); sev != "high" || status != "not_checked" || !strings.Contains(fmt.Sprint(ev), "not enabled") {
		t.Fatalf("verdict for a disabled provider was applied: %s %s %v", sev, status, ev)
	}

	// Settings validation and permissions.
	for _, bad := range []map[string]any{
		{"providers": []string{"pypi"}, "rate_per_second": 1, "max_checks_per_scan": 10},
		{"providers": []string{"nope"}, "rate_per_second": 1, "max_checks_per_scan": 10},
		{"providers": []string{"github"}, "rate_per_second": 11, "max_checks_per_scan": 10},
		{"providers": []string{"github"}, "rate_per_second": 1, "max_checks_per_scan": 0},
	} {
		if code, out := h.user(admin, "PUT", "/api/v1/settings/secret-validation", bad); code != 400 {
			t.Errorf("%v accepted: %d %v", bad, code, out)
		}
	}
	if code, _ := h.user(viewer, "PUT", "/api/v1/settings/secret-validation", map[string]any{"providers": []string{"github"}, "rate_per_second": 1, "max_checks_per_scan": 10}); code != 403 {
		t.Errorf("viewer changes settings: %d", code)
	}
	code, st = h.user(admin, "PUT", "/api/v1/settings/secret-validation", map[string]any{"providers": []string{"github", "slack"}, "rate_per_second": 2, "max_checks_per_scan": 20})
	if code != 200 || st["rate_per_second"].(float64) != 2 {
		t.Fatalf("enable: %d %v", code, st)
	}
	var audited int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'secret_validation.settings.update' AND organization_id = $1`, orgID).Scan(&audited)
	if audited == 0 {
		t.Error("settings change not audited")
	}

	// Enabled: active raises to critical, inactive keeps the severity, an
	// error is stored as such.
	jid, job, fs := scan(func(fs []finding) []map[string]any {
		return []map[string]any{
			verdict(fs[0], "active", map[string]any{"identity": "user octo", "http_status": 200}),
			verdict(fs[1], "inactive", map[string]any{"identity": "must be dropped", "http_status": 401}),
			verdict(fs[2], "error", map[string]any{"detail": "rate limited by the provider (HTTP 429)"}),
			{"fingerprints": []string{}, "status": "active"}, // invalid: dropped
		}
	})
	sv, _ := job["secret_validation"].(map[string]any)
	if sv == nil || fmt.Sprint(sv["providers"]) != "[github slack]" || sv["rate_per_second"].(float64) != 2 || sv["max_checks"].(float64) != 20 {
		t.Fatalf("lease: %v", job["secret_validation"])
	}
	sev, status, identity, before, ev := reload(fs[0].id)
	if sev != "critical" || status != "active" || identity != "user octo" || before == nil || *before != "high" ||
		ev["severity_raised_from"] != "high" || ev["http_status"].(float64) != 200 || ev["scan_job_id"] != jid {
		t.Fatalf("active: %s %s %s %v %v", sev, status, identity, before, ev)
	}
	if sev, status, identity, _, _ := reload(fs[1].id); sev != "high" || status != "inactive" || identity != "" {
		t.Fatalf("inactive: %s %s %q", sev, status, identity)
	}
	if _, status, _, _, ev := reload(fs[2].id); status != "error" || !strings.Contains(fmt.Sprint(ev["detail"]), "429") {
		t.Fatalf("error: %s %v", status, ev)
	}
	var meta []byte
	if err := appPool.QueryRow(ctx, `SELECT metadata FROM audit_logs WHERE action = 'secret_validation.batch' AND target_id = $1`, jid).Scan(&meta); err != nil {
		t.Fatalf("batch not audited: %v", err)
	}
	if !strings.Contains(string(meta), `"active": 1`) && !strings.Contains(string(meta), `"active":1`) || strings.Contains(string(meta), "octo") {
		t.Errorf("audit metadata: %s", meta)
	}
	// Risk: a live credential is maximal likelihood.
	if _, err := risk.Recompute(ctx, appPool, orgID, 10000); err != nil {
		t.Fatal(err)
	}
	var factors []byte
	_ = appPool.QueryRow(ctx, `SELECT risk_factors FROM findings WHERE id = $1`, fs[0].id).Scan(&factors)
	if !strings.Contains(string(factors), "leaked credential validated as active") {
		t.Errorf("risk factors: %s", factors)
	}

	// API: filter and detail.
	code, list := h.user(admin, "GET", "/api/v1/findings?status=all&secret_validation=active&repository_id="+repo.String(), nil)
	if items, _ := list["items"].([]any); code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != fs[0].id {
		t.Fatalf("filter: %d %v", code, list)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/findings?secret_validation=valid", nil); code != 400 {
		t.Errorf("invalid filter: %d", code)
	}
	_, f := h.user(admin, "GET", "/api/v1/findings/"+fs[0].id, nil)
	v, _ := f["secret_validation"].(map[string]any)
	if v == nil || v["status"] != "active" || v["provider_name"] != "GitHub token" || v["identity"] != "user octo" || v["checked_at"] == nil {
		t.Fatalf("finding view: %v", f["secret_validation"])
	}

	// An inconclusive verdict never replaces a conclusive one; inactive
	// restores the severity.
	scan(func(fs []finding) []map[string]any { return []map[string]any{verdict(fs[0], "error", nil)} })
	if sev, status, _, _, ev := reload(fs[0].id); sev != "critical" || status != "active" || ev["last_attempt"] == nil {
		t.Fatalf("after an error: %s %s %v", sev, status, ev)
	}
	scan(func(fs []finding) []map[string]any { return []map[string]any{verdict(fs[0], "inactive", nil)} })
	if sev, status, _, before, ev := reload(fs[0].id); sev != "high" || status != "inactive" || before != nil || ev["severity_restored_to"] != "high" {
		t.Fatalf("after inactive: %s %s %v %v", sev, status, before, ev)
	}

	// Re-check queues a scan; viewers cannot; only secret findings.
	if code, _ := h.user(viewer, "POST", "/api/v1/findings/"+fs[0].id+"/secret-validation/recheck", nil); code != 403 && code != 404 {
		t.Errorf("viewer re-check: %d", code)
	}
	code, q := h.user(admin, "POST", "/api/v1/findings/"+fs[0].id+"/secret-validation/recheck", nil)
	if code != 202 || q["job_id"] == nil {
		t.Fatalf("re-check: %d %v", code, q)
	}
	if _, _, _, _, ev := reload(fs[0].id); ev["recheck_job_id"] != q["job_id"] {
		t.Errorf("re-check not recorded: %v", ev)
	}
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'secret_validation.recheck' AND target_id = $1`, fs[0].id).Scan(&audited)
	if audited != 1 {
		t.Errorf("re-check audited %d times", audited)
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+h.leaseFor(token, repo)["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test"})
	if code, _ := h.user(admin, "PUT", "/api/v1/settings/secret-validation", map[string]any{"providers": []string{}, "rate_per_second": 1, "max_checks_per_scan": 50}); code != 200 {
		t.Fatal("disable")
	}
	if code, out := h.user(admin, "POST", "/api/v1/findings/"+fs[0].id+"/secret-validation/recheck", nil); code != 409 || !strings.Contains(errMsg(out), "off") {
		t.Errorf("re-check while off: %d %v", code, out)
	}

	// Offline platforms never lease validation.
	if _, err := appPool.Exec(ctx, `INSERT INTO secret_validation_settings (organization_id, providers) VALUES ($1, '{github}')
		ON CONFLICT (organization_id) DO UPDATE SET providers = '{github}'`, orgID); err != nil {
		t.Fatal(err)
	}
	ho, tokenO := provenanceHarness(t, true)
	if _, err := scans.Enqueue(ctx, appPool, orgID, repo, "manual", "main", "", nil); err != nil {
		t.Fatal(err)
	}
	jo := ho.leaseFor(tokenO, repo)
	if _, ok := jo["secret_validation"]; ok {
		t.Errorf("offline lease carries secret validation")
	}
	ho.worker(tokenO, "POST", "/internal/worker/v1/jobs/"+jo["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test"})
}
