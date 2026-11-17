//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/reporting"
)

func TestExecutiveAndCustomReports(t *testing.T) {
	ctx := t.Context()
	rs := &reporting.Service{DB: appPool, Log: log, Principal: auth.PrincipalFrom}
	mux := newMux(rs.Register)
	call := func(p *authz.Principal, method, path string, body any) (int, []byte) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes()
	}
	j := func(b []byte) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	tag := uuid.NewString()[:6]
	repo := createRepo(t, "rep-"+tag)
	for i, f := range []struct{ sev, status, title string }{{"critical", "open", "=HYPERLINK(\"x\") " + tag}, {"high", "open", "SQLi " + tag}, {"high", "fixed", "old " + tag}} {
		if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, severity, status,
			resolved_at, first_seen_at) VALUES ($1, $2, $3, $4, 'sast', '{opengrep}', 'r', $5, $6, $7, CASE WHEN $7 = 'fixed' THEN now() END, now() - make_interval(days => $8))`,
			uuid.New(), orgID, repo, uuid.NewString(), f.title, f.sev, f.status, 5+i); err != nil {
			t.Fatal(err)
		}
	}
	// Executive dashboard: real figures, scoped.
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	code, b := call(admin, "GET", "/api/v1/executive?days=30", nil)
	ex := j(b)
	if code != 200 || ex["open_by_severity"].(map[string]any)["critical"].(float64) < 1 || len(ex["trend"].([]any)) < 4 || ex["fixed_in_period"].(float64) < 1 {
		t.Fatalf("executive: %d %v", code, ex)
	}
	if code, _ := call(admin, "GET", "/api/v1/executive?days=7", nil); code != 400 {
		t.Errorf("period validation: %d", code)
	}
	outsider := scoped("viewer", authz.Scope{Type: authz.ScopeRegion, ID: uuid.New()})
	if code, b := call(outsider, "GET", "/api/v1/executive", nil); code != 200 || j(b)["open_by_severity"].(map[string]any)["critical"].(float64) != 0 {
		t.Errorf("out-of-scope executive view is empty: %d %s", code, b)
	}

	// A user with export rights saves, runs and exports a report.
	u, _ := identity.CreateUser(ctx, appPool, identity.User{OrganizationID: orgID, Email: "rep-" + tag + "@acme.test", Status: identity.StatusActive})
	owner := principalWithRole(t, authz.RoleSuperAdmin)
	owner.UserID, owner.Email = u.ID, u.Email
	def := map[string]any{"name": "Open SAST " + tag, "shared": true, "definition": map[string]any{
		"filters": map[string]any{"repository_id": repo.String(), "category": "sast"}, "columns": []string{"severity", "title", "status"}}}
	code, b = call(owner, "POST", "/api/v1/reports", def)
	rep := j(b)
	if code != 201 || rep["can_edit"] != true {
		t.Fatalf("create: %d %s", code, b)
	}
	if code, _ := call(owner, "POST", "/api/v1/reports", map[string]any{"name": "bad", "definition": map[string]any{"filters": map[string]any{"drop": "x"}}}); code != 400 {
		t.Errorf("unknown filter: %d", code)
	}
	code, b = call(owner, "GET", "/api/v1/reports/"+rep["id"].(string)+"/run", nil)
	res := j(b)
	if code != 200 || res["total"].(float64) != 2 || res["rows"].([]any)[0].([]any)[0] != "critical" {
		t.Fatalf("run (open only, sorted by severity): %d %s", code, b)
	}
	code, b = call(owner, "GET", "/api/v1/reports/"+rep["id"].(string)+"/run?format=csv", nil)
	if code != 200 || !strings.Contains(string(b), "'=HYPERLINK") || !strings.HasPrefix(string(b), "Severity,Title,Status") {
		t.Errorf("CSV with formula protection: %d %s", code, b)
	}
	// Grouped preview.
	code, b = call(owner, "POST", "/api/v1/reports/preview", map[string]any{"filters": map[string]any{"repository_id": repo.String(), "status": "all"}, "group_by": "severity"})
	g := j(b)
	if code != 200 || g["columns"].([]any)[0] != "Severity" || g["total"].(float64) != 3 {
		t.Errorf("grouped: %d %s", code, b)
	}
	// Shared reports run with the reader's own scope.
	if code, b := call(outsider, "GET", "/api/v1/reports/"+rep["id"].(string)+"/run", nil); code != 200 || j(b)["total"].(float64) != 0 {
		t.Errorf("a shared report never shows out-of-scope findings: %d %s", code, b)
	}
	if code, _ := call(outsider, "PUT", "/api/v1/reports/"+rep["id"].(string), def); code != 403 {
		t.Errorf("only the owner edits: %d", code)
	}
	if code, _ := call(outsider, "GET", "/api/v1/reports/"+rep["id"].(string)+"/run?format=csv", nil); code != 403 {
		t.Errorf("CSV needs findings.export: %d", code)
	}
	// Scheduling sends a link-only notification to the recipients.
	def["schedule"] = "weekly"
	if code, b := call(owner, "PUT", "/api/v1/reports/"+rep["id"].(string), def); code != 200 || j(b)["next_run_at"] == nil {
		t.Fatalf("schedule: %d %s", code, b)
	}
	_, _ = appPool.Exec(ctx, `UPDATE saved_reports SET next_run_at = now() - interval '1 minute' WHERE id = $1`, rep["id"])
	if n, err := reporting.RunDue(ctx, appPool); err != nil || n < 1 {
		t.Fatalf("run due: %d %v", n, err)
	}
	var payload map[string]any
	var raw []byte
	_ = appPool.QueryRow(ctx, `SELECT payload FROM notification_events WHERE event_key = 'report.scheduled' AND payload->>'report_id' = $1`, rep["id"]).Scan(&raw)
	_ = json.Unmarshal(raw, &payload)
	if payload["report_name"] != "Open SAST "+tag || len(payload["recipient_ids"].([]any)) != 1 || payload["rows"] != nil {
		t.Errorf("notification payload carries the link data only: %v", payload)
	}
	var next bool
	_ = appPool.QueryRow(ctx, `SELECT next_run_at > now() + interval '6 days' FROM saved_reports WHERE id = $1`, rep["id"]).Scan(&next)
	if !next {
		t.Error("next run moved a week ahead")
	}
	if code, _ := call(owner, "DELETE", "/api/v1/reports/"+rep["id"].(string), nil); code != 204 {
		t.Errorf("delete: %d", code)
	}
}
